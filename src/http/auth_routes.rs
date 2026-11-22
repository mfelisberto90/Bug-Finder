use crate::domain::models::UserRole;
use crate::domain::scrubber::strip_ansi_and_bidi;
use crate::security::auth::{
    constant_time_eq, generate_dsn_public_key, hash_password, random_token_b64, sha256_hex,
    validate_password_strength, verify_password,
};
use crate::security::crypto::{open_secret, seal_secret};
use crate::security::headers::{is_https_request, normalize_host_header, validate_same_origin, ClientIp};
use crate::security::mfa::{
    build_otpauth_uri, decode_base32, generate_recovery_codes, generate_totp_secret_b32,
    render_qr_svg, verify_recovery_code, verify_totp_window,
};
use crate::security::oidc::{open_oidc_tx_cookie, seal_oidc_tx_cookie, OidcTxState};
use crate::security::webauthn::{b64url_decode, verify_assertion, verify_registration};
use crate::storage::{AuthenticatedSession, NewAuditLog};
use crate::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

static DUMMY_HASH: OnceLock<String> = OnceLock::new();

fn dummy_scrypt_hash() -> String {
    DUMMY_HASH
        .get_or_init(|| {
            use scrypt::{
                password_hash::{PasswordHasher, SaltString},
                Params, Scrypt,
            };
            let salt = SaltString::generate(&mut rand::thread_rng());
            let params = Params::new(14, 8, 1, 32).expect("valid scrypt params");
            Scrypt
                .hash_password_customized(b"dummy-timing-guard", None, None, params, &salt)
                .map(|h| h.to_string())
                .unwrap_or_default()
        })
        .clone()
}

#[derive(Deserialize)]
pub struct SetupRequest {
    pub org_name: String,
    pub org_slug: String,
    pub email: String,
    pub name: String,
    pub password: String,
    pub project_name: Option<String>,
    pub project_slug: Option<String>,
    pub website: Option<String>, // honeypot
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub website: Option<String>, // honeypot
}

pub fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let trimmed = part.trim();
        if let Some((k, v)) = trimmed.split_once('=') {
            if k.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

pub fn build_session_cookie(token: &str, max_age_sec: i64, state: &AppState, headers: &HeaderMap) -> String {
    let secure = !state.config.is_dev && is_https_request(headers, &state.config);
    let same_site = if state.config.desktop_app_mode {
        "Strict"
    } else {
        "Lax"
    };
    let mut cookie = format!(
        "bf_session={token}; Path=/; HttpOnly; SameSite={same_site}; Max-Age={max_age_sec}"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub async fn resolve_request_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Option<AuthenticatedSession> {
    let raw = extract_cookie(headers, "bf_session")?;
    let sha = sha256_hex(raw.as_bytes());
    let now_sec = chrono::Utc::now().timestamp();
    state
        .storage
        .resolve_session(&sha, now_sec, state.config.session_idle_sec as i64)
        .await
        .ok()?
}

pub fn request_user_agent(headers: &HeaderMap) -> String {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(strip_ansi_and_bidi)
        .map(|s| s.trim().chars().take(200).collect::<String>())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

pub fn request_client_ip(ext: &axum::http::Extensions) -> String {
    ext.get::<ClientIp>()
        .map(|c| c.0.to_string())
        .unwrap_or_else(|| "127.0.0.1".into())
}

pub fn require_session_mutation(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), Response> {
    if !validate_same_origin(headers, &state.config) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Cross-origin state-changing request rejected" })),
        )
            .into_response());
    }
    Ok(())
}

async fn require_authenticated_session(
    state: &AppState,
    headers: &HeaderMap,
    require_csrf: bool,
) -> Result<(AuthenticatedSession, String), Response> {
    let Some(raw) = extract_cookie(headers, "bf_session") else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Authentication required" })),
        )
            .into_response());
    };
    let sha = sha256_hex(raw.as_bytes());
    let now_sec = chrono::Utc::now().timestamp();
    let Some(sess) = state
        .storage
        .resolve_session(&sha, now_sec, state.config.session_idle_sec as i64)
        .await
        .ok()
        .flatten()
    else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Session expired or invalid" })),
        )
            .into_response());
    };
    if require_csrf {
        require_session_mutation(state, headers)?;
        if !verify_csrf_for_session(&sess, headers) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "Invalid CSRF token" })),
            )
                .into_response());
        }
    }
    Ok((sess, sha))
}

fn webauthn_rp_and_origins(state: &AppState, headers: &HeaderMap) -> (String, Vec<String>) {
    let mut origins = Vec::new();
    let mut rp_id = String::new();
    if let Some(ref pub_url) = state.config.public_url {
        let trimmed = pub_url.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            origins.push(trimmed.to_string());
            let rest = trimmed
                .strip_prefix("https://")
                .or_else(|| trimmed.strip_prefix("http://"))
                .unwrap_or(trimmed)
                .split('/')
                .next()
                .unwrap_or("");
            rp_id = normalize_host_header(rest);
        }
    }
    if let Some(host_hdr) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) {
        let trimmed_host = host_hdr.trim();
        let norm_host = normalize_host_header(trimmed_host);
        if rp_id.is_empty() && !norm_host.is_empty() {
            rp_id = norm_host.trim_matches(|c| c == '[' || c == ']').to_string();
        }
        if !trimmed_host.is_empty() {
            let https_orig = format!("https://{trimmed_host}");
            if !origins.iter().any(|o| o.eq_ignore_ascii_case(&https_orig)) {
                origins.push(https_orig);
            }
            if state.config.is_dev || state.config.desktop_app_mode || !is_https_request(headers, &state.config) {
                let http_orig = format!("http://{trimmed_host}");
                if !origins.iter().any(|o| o.eq_ignore_ascii_case(&http_orig)) {
                    origins.push(http_orig);
                }
            }
        }
    }
    if rp_id.is_empty() {
        rp_id = "localhost".into();
    }
    (rp_id, origins)
}

async fn mint_session_response(
    state: &AppState,
    headers: &HeaderMap,
    client_ip: &str,
    user_id: i64,
    email: &str,
    name: &str,
    role: UserRole,
    org_id: i64,
    org_slug: &str,
    audit_action: &str,
) -> Response {
    let now_sec = chrono::Utc::now().timestamp();
    let ttl_sec = state.config.session_ttl_sec as i64;
    let sess_raw = random_token_b64(32);
    let sess_sha = sha256_hex(sess_raw.as_bytes());
    let csrf = random_token_b64(24);
    let expires_at = now_sec + ttl_sec;
    let ua = request_user_agent(headers);
    let ip_hmac = state.rate_limiter.hash_key("session_ip", client_ip);
    if state
        .storage
        .create_session(
            &sess_sha,
            user_id,
            org_id,
            &csrf,
            &ua,
            &ip_hmac,
            now_sec,
            expires_at,
        )
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Session creation failed" })),
        )
            .into_response();
    }

    let _ = state
        .storage
        .append_audit_log(&NewAuditLog {
            organization_id: org_id,
            actor_user_id: Some(user_id),
            actor_email: email.to_string(),
            action: audit_action.to_string(),
            target_type: "session".into(),
            target_id: user_id.to_string(),
            ip_hmac,
            metadata: json!({ "org": org_slug }),
        })
        .await;

    let cookie = build_session_cookie(&sess_raw, ttl_sec, state, headers);
    let mut resp = Json(json!({
        "user": {
            "id": user_id,
            "email": email,
            "name": name,
            "role": role.as_str(),
        },
        "organization": {
            "id": org_id,
            "slug": org_slug,
        },
        "csrf_token": csrf,
    }))
    .into_response();
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

pub async fn auth_status(State(state): State<Arc<AppState>>) -> Response {
    match state.storage.needs_setup().await {
        Ok(needs_setup) => {
            let (oidc_enabled, oidc_name) = match state.oidc_client.as_ref() {
                Some(c) => (true, c.config().display_name.clone()),
                None => (false, String::new()),
            };
            Json(json!({
                "needs_setup": needs_setup,
                "oidc_enabled": oidc_enabled,
                "oidc_name": oidc_name,
            }))
            .into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

fn build_oidc_tx_cookie(val: &str, max_age_sec: i64, state: &AppState, headers: &HeaderMap) -> String {
    let secure = !state.config.is_dev && is_https_request(headers, &state.config);
    let mut cookie = format!(
        "bf_oidc_tx={val}; Path=/api/auth/oidc; HttpOnly; SameSite=Lax; Max-Age={max_age_sec}"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

fn oidc_error_clearing_tx(
    status: StatusCode,
    msg: &str,
    state: &AppState,
    headers: &HeaderMap,
) -> Response {
    let clear_tx = build_oidc_tx_cookie("", 0, state, headers);
    let mut resp = (status, Json(json!({ "error": msg }))).into_response();
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
    if let Ok(v) = HeaderValue::from_str(&clear_tx) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

pub async fn oidc_login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let Some(oidc) = state.oidc_client.clone() else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "OIDC SSO is not configured" })),
        )
            .into_response();
    };
    let client_ip = request_client_ip(&ext);
    let ip_dec = state
        .rate_limiter
        .check_and_record("oidc_ip", &client_ip, 30, Duration::from_secs(60));
    if !ip_dec.allowed {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "Too many SSO login requests" })),
        )
            .into_response();
    }

    let state_tok = random_token_b64(24);
    let nonce = random_token_b64(24);
    let code_verifier = random_token_b64(32);
    let now_sec = chrono::Utc::now().timestamp();
    let tx_state = OidcTxState {
        state: state_tok.clone(),
        nonce: nonce.clone(),
        code_verifier: code_verifier.clone(),
        issued_at: now_sec,
    };
    let sealed = match seal_oidc_tx_cookie(&state.config.app_key, &tx_state) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e })),
            )
                .into_response();
        }
    };

    let authorize_url = match tokio::task::spawn_blocking(move || {
        oidc.build_authorize_url_blocking(&state_tok, &nonce, &code_verifier)
    })
    .await
    {
        Ok(Ok(u)) => u,
        Ok(Err(e)) => {
            return (StatusCode::BAD_GATEWAY, Json(json!({ "error": e }))).into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("OIDC worker failed: {e}") })),
            )
                .into_response();
        }
    };

    let tx_cookie = build_oidc_tx_cookie(&sealed, 300, &state, &headers);
    let mut resp = StatusCode::FOUND.into_response();
    if let Ok(loc) = HeaderValue::from_str(&authorize_url) {
        resp.headers_mut().insert(header::LOCATION, loc);
    }
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
    if let Ok(v) = HeaderValue::from_str(&tx_cookie) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

pub async fn oidc_callback(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let Some(oidc) = state.oidc_client.clone() else {
        return oidc_error_clearing_tx(
            StatusCode::NOT_FOUND,
            "OIDC SSO is not configured",
            &state,
            &headers,
        );
    };
    let client_ip = request_client_ip(&ext);
    let ip_dec = state
        .rate_limiter
        .check_and_record("oidc_ip", &client_ip, 30, Duration::from_secs(60));
    if !ip_dec.allowed {
        return oidc_error_clearing_tx(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many SSO callback attempts",
            &state,
            &headers,
        );
    }

    if let Some(idp_err) = q.get("error").map(String::as_str).filter(|s| !s.is_empty()) {
        return oidc_error_clearing_tx(
            StatusCode::BAD_REQUEST,
            &format!("OIDC provider rejected login: {idp_err}"),
            &state,
            &headers,
        );
    }

    let Some(sealed) = extract_cookie(&headers, "bf_oidc_tx") else {
        return oidc_error_clearing_tx(
            StatusCode::BAD_REQUEST,
            "Missing OIDC login transaction cookie",
            &state,
            &headers,
        );
    };

    let now_sec = chrono::Utc::now().timestamp();
    let tx = match open_oidc_tx_cookie(&state.config.app_key, &sealed, now_sec) {
        Ok(t) => t,
        Err(msg) => {
            return oidc_error_clearing_tx(StatusCode::BAD_REQUEST, &msg, &state, &headers);
        }
    };

    let got_state = q.get("state").map(String::as_str).unwrap_or("");
    if got_state.is_empty() || !constant_time_eq(got_state.as_bytes(), tx.state.as_bytes()) {
        return oidc_error_clearing_tx(
            StatusCode::BAD_REQUEST,
            "Invalid OIDC state parameter",
            &state,
            &headers,
        );
    }
    let Some(code) = q.get("code").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) else {
        return oidc_error_clearing_tx(
            StatusCode::BAD_REQUEST,
            "Missing OIDC authorization code",
            &state,
            &headers,
        );
    };

    let tx_nonce = tx.nonce.clone();
    let tx_verifier = tx.code_verifier.clone();
    let claims = match tokio::task::spawn_blocking(move || {
        oidc.exchange_and_verify_blocking(&code, &tx_nonce, &tx_verifier, now_sec)
    })
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(msg)) => {
            return oidc_error_clearing_tx(StatusCode::UNAUTHORIZED, &msg, &state, &headers);
        }
        Err(e) => {
            return oidc_error_clearing_tx(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("OIDC worker failed: {e}"),
                &state,
                &headers,
            );
        }
    };

    // Fail-closed: only pre-provisioned active Bug-Finder users may sign in via OIDC SSO
    let user = match state.storage.find_user_for_login(&claims.email).await {
        Ok(Some(u)) if u.is_active => u,
        Ok(_) => {
            return oidc_error_clearing_tx(
                StatusCode::FORBIDDEN,
                "No active Bug-Finder account exists for this SSO email; ask an administrator to invite you first",
                &state,
                &headers,
            );
        }
        Err(e) => {
            return oidc_error_clearing_tx(
                StatusCode::INTERNAL_SERVER_ERROR,
                &e,
                &state,
                &headers,
            );
        }
    };

    let ttl_sec = state.config.session_ttl_sec;
    let sess_raw = random_token_b64(32);
    let sess_sha = sha256_hex(sess_raw.as_bytes());
    let csrf = random_token_b64(24);
    let expires_at = now_sec + ttl_sec;
    let ua = request_user_agent(&headers);
    let ip_hmac = state.rate_limiter.hash_key("session_ip", &client_ip);

    if state
        .storage
        .create_session(
            &sess_sha,
            user.user_id,
            user.organization_id,
            &csrf,
            &ua,
            &ip_hmac,
            now_sec,
            expires_at,
        )
        .await
        .is_err()
    {
        return oidc_error_clearing_tx(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Session creation failed",
            &state,
            &headers,
        );
    }

    let _ = state
        .storage
        .append_audit_log(&NewAuditLog {
            organization_id: user.organization_id,
            actor_user_id: Some(user.user_id),
            actor_email: user.email.clone(),
            action: "auth.oidc_login".into(),
            target_type: "session".into(),
            target_id: user.user_id.to_string(),
            ip_hmac,
            metadata: json!({
                "org": user.organization_slug,
                "issuer": claims.iss,
                "sub": claims.sub,
            }),
        })
        .await;

    let sess_cookie = build_session_cookie(&sess_raw, ttl_sec, &state, &headers);
    let clear_tx = build_oidc_tx_cookie("", 0, &state, &headers);
    let mut resp = StatusCode::FOUND.into_response();
    resp.headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static("/"));
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
    if let Ok(v) = HeaderValue::from_str(&sess_cookie) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    if let Ok(v) = HeaderValue::from_str(&clear_tx) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

pub async fn auth_setup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    Json(req): Json<SetupRequest>,
) -> Response {
    if req.website.as_deref().map(|s| !s.is_empty()).unwrap_or(false) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid submission" }))).into_response();
    }
    let client_ip = ext
        .get::<ClientIp>()
        .map(|c| c.0.to_string())
        .unwrap_or_else(|| "127.0.0.1".into());
    let setup_dec = state.rate_limiter.check_and_record(
        "auth_setup_ip",
        &client_ip,
        10,
        Duration::from_secs(60),
    );
    if !setup_dec.allowed {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "error": "Too many setup requests" }))).into_response();
    }
    match state.storage.needs_setup().await {
        Ok(false) => {
            return (StatusCode::CONFLICT, Json(json!({ "error": "Setup already completed" }))).into_response();
        }
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response();
        }
        Ok(true) => {}
    }

    if !req.email.contains('@') {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Valid email required" })),
        )
            .into_response();
    }
    if let Err(msg) = validate_password_strength(&req.password, &req.email, &req.name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": msg })),
        )
            .into_response();
    }
    let org_slug = sanitize_slug(&req.org_slug);
    let proj_slug = sanitize_slug(req.project_slug.as_deref().unwrap_or("app-main"));
    if org_slug.is_empty() || proj_slug.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Organization and project slugs must be alphanumeric" })),
        )
            .into_response();
    }

    let Ok(pw_hash) = hash_password(req.password).await else {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Password hashing failed" }))).into_response();
    };

    let dsn_pub = generate_dsn_public_key();
    let dsn_sha = sha256_hex(dsn_pub.as_bytes());
    let proj_name = req.project_name.unwrap_or_else(|| "Main App".into());

    let (org, proj) = match state
        .storage
        .initial_setup(
            req.org_name.trim(),
            &org_slug,
            req.email.trim(),
            req.name.trim(),
            &pw_hash,
            proj_name.trim(),
            &proj_slug,
            &dsn_pub,
            &dsn_sha,
        )
        .await
    {
        Ok(res) => res,
        Err(e) => {
            let status = if e.contains("already") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            return (status, Json(json!({ "error": e }))).into_response();
        }
    };

    // Log the new owner in right away
    let Some(user) = state.storage.find_user_for_login(req.email.trim()).await.ok().flatten() else {
        return (StatusCode::CREATED, Json(json!({ "organization": org, "project": proj }))).into_response();
    };

    let now_sec = chrono::Utc::now().timestamp();
    let ttl_sec = state.config.session_ttl_sec as i64;
    let sess_raw = random_token_b64(32);
    let sess_sha = sha256_hex(sess_raw.as_bytes());
    let csrf = random_token_b64(24);
    let exp = now_sec + ttl_sec;
    let ua = request_user_agent(&headers);
    let ip_hmac = state.rate_limiter.hash_key("session_ip", &client_ip);
    if state
        .storage
        .create_session(&sess_sha, user.user_id, org.id, &csrf, &ua, &ip_hmac, now_sec, exp)
        .await
        .is_err()
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Session create failed" }))).into_response();
    }

    let _ = state
        .storage
        .append_audit_log(&NewAuditLog {
            organization_id: org.id,
            actor_user_id: Some(user.user_id),
            actor_email: user.email.clone(),
            action: "auth.setup".into(),
            target_type: "organization".into(),
            target_id: org.id.to_string(),
            ip_hmac,
            metadata: json!({ "org_slug": org.slug, "project_slug": proj.slug }),
        })
        .await;

    let cookie = build_session_cookie(&sess_raw, ttl_sec, &state, &headers);
    let mut resp = (
        StatusCode::CREATED,
        Json(json!({
            "organization": org,
            "project": proj,
            "csrf_token": csrf,
        })),
    )
        .into_response();
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

pub async fn auth_login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    Json(req): Json<LoginRequest>,
) -> Response {
    if req.website.as_deref().map(|s| !s.is_empty()).unwrap_or(false) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid submission" }))).into_response();
    }
    let client_ip = ext
        .get::<ClientIp>()
        .map(|c| c.0.to_string())
        .unwrap_or_else(|| "127.0.0.1".into());
    let email_norm = req.email.trim().to_ascii_lowercase();

    // 1. Check IP rate limiter (preserved even after successful login against password spraying)
    let ip_dec = state.rate_limiter.check_and_record(
        "auth_ip",
        &client_ip,
        60,
        Duration::from_secs(60),
    );
    if !ip_dec.allowed {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "error": "Too many login requests" }))).into_response();
    }

    // 2. Check principal rate limiter
    let prin_dec = state.rate_limiter.check_and_record(
        "auth_principal",
        &email_norm,
        5,
        Duration::from_secs(60),
    );
    if !prin_dec.allowed {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "error": "Too many login attempts for account" }))).into_response();
    }

    // 3. Persistent exponential lockout check
    let now_sec = chrono::Utc::now().timestamp();
    let lock_hmac = state.rate_limiter.hash_key("login_lock", &email_norm);
    if let Ok(Some(wait_sec)) = state.storage.check_login_lockout(&lock_hmac, now_sec).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "Account temporarily locked", "retry_after": wait_sec })),
        )
            .into_response();
    }

    let user = match state.storage.find_user_for_login(&email_norm).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            // Equalize scrypt work & timing against account enumeration before recording strike
            let _ = verify_password(req.password, dummy_scrypt_hash()).await;
            let _ = state.storage.record_login_failure(&lock_hmac, now_sec).await;
            return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Invalid credentials" }))).into_response();
        }
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response();
        }
    };

    if !user.is_active || !verify_password(req.password, user.password_hash).await {
        let locked = state.storage.record_login_failure(&lock_hmac, now_sec).await.ok().flatten();
        if let Some(secs) = locked {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "Account locked due to failed attempts", "retry_after": secs })),
            )
                .into_response();
        }
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Invalid credentials" }))).into_response();
    }

    // Success: clear principal buckets ONLY — never clear the IP spray bucket
    state.rate_limiter.clear_bucket("auth_principal", &email_norm);
    let _ = state.storage.clear_login_failures(&lock_hmac).await;

    // Check if MFA (TOTP or Passkeys) is active for this user
    let mfa_rec = state.storage.get_user_mfa_record(user.user_id).await.ok().flatten();
    let totp_enabled = mfa_rec.as_ref().map(|r| r.is_enabled).unwrap_or(false);
    let passkeys = state
        .storage
        .list_webauthn_credentials(user.user_id)
        .await
        .unwrap_or_default();

    if totp_enabled || !passkeys.is_empty() {
        let chall_raw = random_token_b64(32);
        let chall_sha = sha256_hex(chall_raw.as_bytes());
        let ip_hmac = state.rate_limiter.hash_key("mfa_ip", &client_ip);
        if state
            .storage
            .create_mfa_challenge(&chall_sha, user.user_id, user.organization_id, &ip_hmac, now_sec + 300)
            .await
            .is_err()
        {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "MFA challenge error" }))).into_response();
        }
        let mut methods: Vec<&str> = Vec::new();
        if totp_enabled {
            methods.push("totp");
            methods.push("recovery");
        }
        if !passkeys.is_empty() {
            methods.push("passkey");
        }
        return Json(json!({
            "mfa_required": true,
            "challenge_token": chall_raw,
            "methods": methods,
        }))
        .into_response();
    }

    mint_session_response(
        &state,
        &headers,
        &client_ip,
        user.user_id,
        &user.email,
        &user.name,
        user.role,
        user.organization_id,
        &user.organization_slug,
        "auth.login",
    )
    .await
}

pub async fn auth_logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    if let Err(r) = require_session_mutation(&state, &headers) {
        return r;
    }
    let client_ip = request_client_ip(&ext);
    if let Some(sess) = resolve_request_session(&state, &headers).await {
        if !verify_csrf_for_session(&sess, &headers) {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "Invalid CSRF token" })),
            )
                .into_response();
        }
        if let Some(raw) = extract_cookie(&headers, "bf_session") {
            let sha = sha256_hex(raw.as_bytes());
            let _ = state.storage.delete_session(&sha).await;
        }
        let _ = state
            .storage
            .append_audit_log(&NewAuditLog {
                organization_id: sess.organization_id,
                actor_user_id: Some(sess.user_id),
                actor_email: sess.email,
                action: "auth.logout".into(),
                target_type: "session".into(),
                target_id: sess.session_id.to_string(),
                ip_hmac: state.rate_limiter.hash_key("session_ip", &client_ip),
                metadata: json!({}),
            })
            .await;
    }
    let cookie = build_session_cookie("", 0, &state, &headers);
    let mut resp = Json(json!({ "ok": true })).into_response();
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

pub async fn auth_me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let Some(sess) = resolve_request_session(&state, &headers).await else {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Unauthenticated" }))).into_response();
    };
    let orgs = state
        .storage
        .list_user_organizations(sess.user_id)
        .await
        .unwrap_or_default();
    let now_sec = chrono::Utc::now().timestamp();
    let reauth_fresh = sess
        .reauth_at
        .map(|t| now_sec.saturating_sub(t) <= 600)
        .unwrap_or(false);
    Json(json!({
        "user": {
            "id": sess.user_id,
            "email": sess.email,
            "name": sess.name,
            "role": sess.role.as_str(),
            "totp_enabled": sess.totp_enabled,
            "passkey_count": sess.passkey_count,
            "mfa_enabled": sess.totp_enabled || sess.passkey_count > 0,
            "reauth_fresh": reauth_fresh,
        },
        "organization_slug": sess.organization_slug,
        "organizations": orgs,
        "scopes": sess.role.default_scopes(),
        "csrf_token": sess.csrf_token,
    }))
    .into_response()
}

pub fn verify_csrf_for_session(sess: &AuthenticatedSession, headers: &HeaderMap) -> bool {
    let Some(hdr) = headers.get("x-csrf-token").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    constant_time_eq(hdr.as_bytes(), sess.csrf_token.as_bytes())
}

pub fn sanitize_slug(raw: &str) -> String {
    raw.trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else if c.is_ascii_whitespace() {
                '-'
            } else {
                '\0'
            }
        })
        .filter(|&c| c != '\0')
        .take(50)
        .collect()
}

fn extract_client_data_challenge(client_data_b64: &str) -> Result<String, String> {
    let raw = b64url_decode(client_data_b64)?;
    let val: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| "Malformed clientDataJSON".to_string())?;
    let chall = val
        .get("challenge")
        .and_then(|v| v.as_str())
        .map(|s| s.trim_end_matches('=').to_string())
        .unwrap_or_default();
    if chall.len() < 16 {
        return Err("Missing WebAuthn challenge".into());
    }
    Ok(chall)
}

#[derive(Deserialize)]
pub struct MfaVerifyReq {
    pub challenge_token: String,
    pub code: Option<String>,
    pub recovery_code: Option<String>,
}

pub async fn mfa_verify(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    Json(req): Json<MfaVerifyReq>,
) -> Response {
    let client_ip = request_client_ip(&ext);
    let ip_dec = state
        .rate_limiter
        .check_and_record("auth_ip", &client_ip, 30, Duration::from_secs(60));
    if !ip_dec.allowed {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "Too many MFA verification requests" })),
        )
            .into_response();
    }

    let now_sec = chrono::Utc::now().timestamp();
    let chall_sha = sha256_hex(req.challenge_token.trim().as_bytes());
    let Some(chal) = state
        .storage
        .get_mfa_challenge_user(&chall_sha, now_sec)
        .await
        .ok()
        .flatten()
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "MFA challenge expired or invalid" })),
        )
            .into_response();
    };

    let Some(mfa_rec) = state
        .storage
        .get_user_mfa_record(chal.user_id)
        .await
        .ok()
        .flatten()
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "TOTP MFA is not enabled for this account" })),
        )
            .into_response();
    };
    if !mfa_rec.is_enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "TOTP MFA is not enabled for this account" })),
        )
            .into_response();
    }
    if let Some(until) = mfa_rec.locked_until {
        if until > now_sec {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": "MFA temporarily locked due to failed attempts",
                    "retry_after": until - now_sec
                })),
            )
                .into_response();
        }
    }

    let mut audit_action = "auth.mfa_login";
    let mut verified_step: Option<i64> = None;
    let mut verified_ok = false;

    if let Some(code_raw) = req.code.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let aad = format!("mfa:totp:user:{}", chal.user_id);
        let Ok(b32) = open_secret(&state.config.app_key, aad.as_bytes(), &mfa_rec.totp_secret_enc, false) else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed opening encrypted MFA secret" })),
            )
                .into_response();
        };
        let Ok(secret_bytes) = decode_base32(&b32) else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Corrupt TOTP secret encoding" })),
            )
                .into_response();
        };
        if let Some(step) = verify_totp_window(&secret_bytes, code_raw, now_sec, mfa_rec.last_used_step) {
            verified_step = Some(step);
            verified_ok = true;
        }
    } else if let Some(rc_raw) = req.recovery_code.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let unused = state
            .storage
            .list_unused_recovery_codes(chal.user_id)
            .await
            .unwrap_or_default();
        if let Some(matched) = unused.into_iter().find(|rc| verify_recovery_code(rc_raw, &rc.code_hash)) {
            if state
                .storage
                .mark_recovery_code_used(chal.user_id, matched.id, now_sec)
                .await
                .unwrap_or(false)
            {
                verified_step = Some(mfa_rec.last_used_step.unwrap_or(0));
                audit_action = "auth.recovery_login";
                verified_ok = true;
            }
        }
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Provide TOTP code or recovery_code" })),
        )
            .into_response();
    }

    if !verified_ok {
        let locked = state
            .storage
            .record_mfa_attempt(chal.user_id, None, now_sec)
            .await
            .ok()
            .flatten();
        if let Some(secs) = locked {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "MFA locked due to repeated failures", "retry_after": secs })),
            )
                .into_response();
        }
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid verification code" })),
        )
            .into_response();
    }

    let _ = state
        .storage
        .record_mfa_attempt(chal.user_id, verified_step, now_sec)
        .await;
    let _ = state.storage.consume_mfa_challenge(&chall_sha, now_sec).await;

    let Some((email, name, _)) = state
        .storage
        .find_user_password_hash(chal.user_id)
        .await
        .ok()
        .flatten()
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "User account inactive" })),
        )
            .into_response();
    };
    let orgs = state
        .storage
        .list_user_organizations(chal.user_id)
        .await
        .unwrap_or_default();
    let Some(target_org) = orgs
        .iter()
        .find(|o| o.id == chal.target_org_id)
        .or_else(|| orgs.first())
    else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "No active organization membership" })),
        )
            .into_response();
    };
    let role = UserRole::from_db(&target_org.role).unwrap_or(UserRole::Member);

    mint_session_response(
        &state,
        &headers,
        &client_ip,
        chal.user_id,
        &email,
        &name,
        role,
        target_org.id,
        &target_org.slug,
        audit_action,
    )
    .await
}

pub async fn mfa_status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (sess, _) = match require_authenticated_session(&state, &headers, false).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match state.storage.get_mfa_status(sess.user_id).await {
        Ok(st) => Json(st).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn mfa_totp_enroll(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (sess, _) = match require_authenticated_session(&state, &headers, true).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let now_sec = chrono::Utc::now().timestamp();
    let secret_b32 = generate_totp_secret_b32();
    let aad = format!("mfa:totp:user:{}", sess.user_id);
    let Ok(enc) = seal_secret(&state.config.app_key, aad.as_bytes(), &secret_b32) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed encrypting TOTP secret" })),
        )
            .into_response();
    };
    if let Err(e) = state
        .storage
        .upsert_pending_totp(sess.user_id, &enc, now_sec)
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response();
    }
    let otpauth_uri = build_otpauth_uri("Bug-Finder", &sess.email, &secret_b32);
    let qr_svg = render_qr_svg(&otpauth_uri);
    Json(json!({
        "secret_b32": secret_b32,
        "otpauth_uri": otpauth_uri,
        "qr_svg": qr_svg,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct TotpConfirmReq {
    pub code: String,
}

pub async fn mfa_totp_confirm(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    Json(req): Json<TotpConfirmReq>,
) -> Response {
    let (sess, _) = match require_authenticated_session(&state, &headers, true).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let client_ip = request_client_ip(&ext);
    let now_sec = chrono::Utc::now().timestamp();
    let Some(mfa_rec) = state
        .storage
        .get_user_mfa_record(sess.user_id)
        .await
        .ok()
        .flatten()
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Start TOTP enrollment first" })),
        )
            .into_response();
    };
    let aad = format!("mfa:totp:user:{}", sess.user_id);
    let Ok(b32) = open_secret(&state.config.app_key, aad.as_bytes(), &mfa_rec.totp_secret_enc, false) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed decrypting pending TOTP secret" })),
        )
            .into_response();
    };
    let Ok(secret_bytes) = decode_base32(&b32) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Invalid pending TOTP secret" })),
        )
            .into_response();
    };
    let Some(step) = verify_totp_window(&secret_bytes, &req.code, now_sec, None) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid 6-digit TOTP code" })),
        )
            .into_response();
    };
    let pairs = generate_recovery_codes();
    let plaintexts: Vec<String> = pairs.iter().map(|(p, _)| p.clone()).collect();
    let hashes: Vec<String> = pairs.into_iter().map(|(_, h)| h).collect();
    if let Err(e) = state
        .storage
        .enable_totp_with_recovery_codes(sess.user_id, &hashes, now_sec)
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response();
    }
    let _ = state
        .storage
        .record_mfa_attempt(sess.user_id, Some(step), now_sec)
        .await;
    let _ = state
        .storage
        .append_audit_log(&NewAuditLog {
            organization_id: sess.organization_id,
            actor_user_id: Some(sess.user_id),
            actor_email: sess.email,
            action: "mfa.totp_enabled".into(),
            target_type: "user".into(),
            target_id: sess.user_id.to_string(),
            ip_hmac: state.rate_limiter.hash_key("session_ip", &client_ip),
            metadata: json!({ "recovery_codes_issued": plaintexts.len() }),
        })
        .await;
    Json(json!({ "ok": true, "recovery_codes": plaintexts })).into_response()
}

#[derive(Deserialize)]
pub struct TotpDisableReq {
    pub password: Option<String>,
}

pub async fn mfa_totp_disable(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    body: Option<Json<TotpDisableReq>>,
) -> Response {
    let (sess, _) = match require_authenticated_session(&state, &headers, true).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let client_ip = request_client_ip(&ext);
    let now_sec = chrono::Utc::now().timestamp();
    let mut step_up_ok = sess
        .reauth_at
        .map(|t| now_sec.saturating_sub(t) <= 600)
        .unwrap_or(false);
    if !step_up_ok {
        if let Some(Json(req)) = body {
            if let Some(pw) = req.password {
                if let Some((_, _, pw_hash)) = state
                    .storage
                    .find_user_password_hash(sess.user_id)
                    .await
                    .ok()
                    .flatten()
                {
                    step_up_ok = verify_password(pw, pw_hash).await;
                }
            }
        }
    }
    if !step_up_ok {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Step-up re-authentication or current password required", "reauth_required": true })),
        )
            .into_response();
    }
    if sess.role.can_manage_org() && sess.passkey_count == 0 {
        let tenant_ctx = crate::domain::models::TenantCtx::from_session(
            sess.organization_id,
            sess.organization_slug.clone(),
            sess.user_id,
            sess.role,
            sess.reauth_at,
            Some(sess.session_id),
        );
        if let Ok(org_sec) = state.storage.get_org_security_settings(&tenant_ctx).await {
            if org_sec.require_mfa_for_admins {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "Organization policy requires MFA for administrators (register a Passkey first)" })),
                )
                    .into_response();
            }
        }
    }
    if let Err(e) = state.storage.disable_mfa(sess.user_id, now_sec).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response();
    }
    let _ = state
        .storage
        .append_audit_log(&NewAuditLog {
            organization_id: sess.organization_id,
            actor_user_id: Some(sess.user_id),
            actor_email: sess.email,
            action: "mfa.totp_disabled".into(),
            target_type: "user".into(),
            target_id: sess.user_id.to_string(),
            ip_hmac: state.rate_limiter.hash_key("session_ip", &client_ip),
            metadata: json!({}),
        })
        .await;
    Json(json!({ "ok": true })).into_response()
}

pub async fn mfa_recovery_regenerate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let (sess, _) = match require_authenticated_session(&state, &headers, true).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let client_ip = request_client_ip(&ext);
    let now_sec = chrono::Utc::now().timestamp();
    if !sess
        .reauth_at
        .map(|t| now_sec.saturating_sub(t) <= 600)
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Step-up re-authentication required", "reauth_required": true })),
        )
            .into_response();
    }
    if !sess.totp_enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Enable TOTP MFA before generating recovery codes" })),
        )
            .into_response();
    }
    let pairs = generate_recovery_codes();
    let plaintexts: Vec<String> = pairs.iter().map(|(p, _)| p.clone()).collect();
    let hashes: Vec<String> = pairs.into_iter().map(|(_, h)| h).collect();
    if let Err(e) = state
        .storage
        .replace_recovery_codes(sess.user_id, &hashes, now_sec)
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response();
    }
    let _ = state
        .storage
        .append_audit_log(&NewAuditLog {
            organization_id: sess.organization_id,
            actor_user_id: Some(sess.user_id),
            actor_email: sess.email,
            action: "mfa.recovery_regenerated".into(),
            target_type: "user".into(),
            target_id: sess.user_id.to_string(),
            ip_hmac: state.rate_limiter.hash_key("session_ip", &client_ip),
            metadata: json!({ "count": plaintexts.len() }),
        })
        .await;
    Json(json!({ "recovery_codes": plaintexts })).into_response()
}

pub async fn passkey_register_begin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let (sess, _) = match require_authenticated_session(&state, &headers, true).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let now_sec = chrono::Utc::now().timestamp();
    let challenge = random_token_b64(32);
    if let Err(e) = state
        .storage
        .save_webauthn_challenge(&challenge, Some(sess.user_id), "register", now_sec + 300)
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response();
    }
    let existing = state
        .storage
        .list_webauthn_credentials(sess.user_id)
        .await
        .unwrap_or_default();
    let exclude_creds: Vec<serde_json::Value> = existing
        .into_iter()
        .map(|c| json!({ "type": "public-key", "id": c.credential_id_b64 }))
        .collect();
    let (rp_id, _) = webauthn_rp_and_origins(&state, &headers);
    let user_handle = URL_SAFE_NO_PAD.encode(format!("bf-user-{}", sess.user_id).as_bytes());
    Json(json!({
        "challenge": challenge,
        "rp": { "id": rp_id, "name": "Bug-Finder" },
        "user": {
            "id": user_handle,
            "name": sess.email,
            "displayName": sess.name,
        },
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -7 },
            { "type": "public-key", "alg": -8 }
        ],
        "excludeCredentials": exclude_creds,
        "timeout": 120000,
        "authenticatorSelection": {
            "residentKey": "preferred",
            "userVerification": "preferred"
        },
        "attestation": "none"
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct PasskeyRegisterFinishReq {
    pub name: Option<String>,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

pub async fn passkey_register_finish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    Json(req): Json<PasskeyRegisterFinishReq>,
) -> Response {
    let (sess, _) = match require_authenticated_session(&state, &headers, true).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let client_ip = request_client_ip(&ext);
    let now_sec = chrono::Utc::now().timestamp();
    let chall_b64 = match extract_client_data_challenge(&req.client_data_json) {
        Ok(c) => c,
        Err(msg) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response(),
    };
    let Some(chal_rec) = state
        .storage
        .consume_webauthn_challenge(&chall_b64, "register", now_sec)
        .await
        .ok()
        .flatten()
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "WebAuthn registration challenge expired or invalid" })),
        )
            .into_response();
    };
    if chal_rec.user_id != Some(sess.user_id) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Challenge user mismatch" })),
        )
            .into_response();
    }
    let (rp_id, origins) = webauthn_rp_and_origins(&state, &headers);
    let verified = match verify_registration(
        &chall_b64,
        &origins,
        &rp_id,
        &req.client_data_json,
        &req.attestation_object,
    ) {
        Ok(v) => v,
        Err(msg) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response(),
    };
    let cred_name = req
        .name
        .as_deref()
        .map(strip_ansi_and_bidi)
        .map(|s| s.trim().chars().take(80).collect::<String>())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Security Passkey".into());
    match state
        .storage
        .create_webauthn_credential(
            sess.user_id,
            &cred_name,
            &verified.credential_id_b64,
            verified.cose_alg,
            &verified.public_key_b64,
            verified.sign_count,
        )
        .await
    {
        Ok(dto) => {
            let _ = state
                .storage
                .append_audit_log(&NewAuditLog {
                    organization_id: sess.organization_id,
                    actor_user_id: Some(sess.user_id),
                    actor_email: sess.email,
                    action: "mfa.passkey_registered".into(),
                    target_type: "webauthn_credential".into(),
                    target_id: dto.id.to_string(),
                    ip_hmac: state.rate_limiter.hash_key("session_ip", &client_ip),
                    metadata: json!({ "name": dto.name, "cose_alg": dto.cose_alg }),
                })
                .await;
            (StatusCode::CREATED, Json(dto)).into_response()
        }
        Err(e) => (StatusCode::CONFLICT, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn list_passkeys(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (sess, _) = match require_authenticated_session(&state, &headers, false).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let creds = state
        .storage
        .list_webauthn_credentials(sess.user_id)
        .await
        .unwrap_or_default();
    let dtos: Vec<crate::domain::models::PasskeyDto> = creds
        .into_iter()
        .map(|c| crate::domain::models::PasskeyDto {
            id: c.id,
            name: c.name,
            cose_alg: c.cose_alg,
            sign_count: c.sign_count,
            last_used_at: c.last_used_at.map(|s| crate::domain::models::iso_from_ms(s * 1000)),
            created_at: crate::domain::models::iso_from_ms(c.created_at),
        })
        .collect();
    Json(dtos).into_response()
}

pub async fn delete_passkey(
    State(state): State<Arc<AppState>>,
    Path(cred_id): Path<i64>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let (sess, _) = match require_authenticated_session(&state, &headers, true).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let client_ip = request_client_ip(&ext);
    let now_sec = chrono::Utc::now().timestamp();
    if !sess
        .reauth_at
        .map(|t| now_sec.saturating_sub(t) <= 600)
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Step-up re-authentication required", "reauth_required": true })),
        )
            .into_response();
    }
    if sess.role.can_manage_org() && !sess.totp_enabled && sess.passkey_count <= 1 {
        let tenant_ctx = crate::domain::models::TenantCtx::from_session(
            sess.organization_id,
            sess.organization_slug.clone(),
            sess.user_id,
            sess.role,
            sess.reauth_at,
            Some(sess.session_id),
        );
        if let Ok(org_sec) = state.storage.get_org_security_settings(&tenant_ctx).await {
            if org_sec.require_mfa_for_admins {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "Organization policy requires MFA for administrators" })),
                )
                    .into_response();
            }
        }
    }
    match state.storage.delete_webauthn_credential(sess.user_id, cred_id).await {
        Ok(true) => {
            let _ = state
                .storage
                .append_audit_log(&NewAuditLog {
                    organization_id: sess.organization_id,
                    actor_user_id: Some(sess.user_id),
                    actor_email: sess.email,
                    action: "mfa.passkey_deleted".into(),
                    target_type: "webauthn_credential".into(),
                    target_id: cred_id.to_string(),
                    ip_hmac: state.rate_limiter.hash_key("session_ip", &client_ip),
                    metadata: json!({}),
                })
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, Json(json!({ "error": "Passkey not found" }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct PasskeyLoginBeginReq {
    pub email: Option<String>,
    pub challenge_token: Option<String>,
}

pub async fn passkey_login_begin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    body: Option<Json<PasskeyLoginBeginReq>>,
) -> Response {
    let client_ip = request_client_ip(&ext);
    let ip_dec = state
        .rate_limiter
        .check_and_record("auth_ip", &client_ip, 60, Duration::from_secs(60));
    if !ip_dec.allowed {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "Too many passkey login requests" })),
        )
            .into_response();
    }
    let now_sec = chrono::Utc::now().timestamp();
    let req = body.map(|Json(v)| v).unwrap_or_default();
    let mut target_user_id: Option<i64> = None;

    if let Some(tok) = req.challenge_token.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let sha = sha256_hex(tok.as_bytes());
        if let Ok(Some(chal)) = state.storage.get_mfa_challenge_user(&sha, now_sec).await {
            target_user_id = Some(chal.user_id);
        }
    } else if let Some(email) = req.email.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(Some(u)) = state.storage.find_user_for_login(&email.to_ascii_lowercase()).await {
            target_user_id = Some(u.user_id);
        }
    }

    let allow_creds: Vec<serde_json::Value> = if let Some(uid) = target_user_id {
        state
            .storage
            .list_webauthn_credentials(uid)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|c| json!({ "type": "public-key", "id": c.credential_id_b64 }))
            .collect()
    } else {
        Vec::new()
    };

    let challenge = random_token_b64(32);
    if let Err(e) = state
        .storage
        .save_webauthn_challenge(&challenge, target_user_id, "login", now_sec + 300)
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response();
    }
    let (rp_id, _) = webauthn_rp_and_origins(&state, &headers);
    Json(json!({
        "challenge": challenge,
        "rpId": rp_id,
        "timeout": 120000,
        "userVerification": "preferred",
        "allowCredentials": allow_creds,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct PasskeyLoginFinishReq {
    #[serde(rename = "credentialId")]
    pub credential_id: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    pub challenge_token: Option<String>,
}

pub async fn passkey_login_finish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    Json(req): Json<PasskeyLoginFinishReq>,
) -> Response {
    let client_ip = request_client_ip(&ext);
    let ip_dec = state
        .rate_limiter
        .check_and_record("auth_ip", &client_ip, 30, Duration::from_secs(60));
    if !ip_dec.allowed {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "Too many passkey verification requests" })),
        )
            .into_response();
    }
    let now_sec = chrono::Utc::now().timestamp();
    let chall_b64 = match extract_client_data_challenge(&req.client_data_json) {
        Ok(c) => c,
        Err(msg) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response(),
    };
    let Some(chal_rec) = state
        .storage
        .consume_webauthn_challenge(&chall_b64, "login", now_sec)
        .await
        .ok()
        .flatten()
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "WebAuthn login challenge expired or invalid" })),
        )
            .into_response();
    };
    let Some(cred) = state
        .storage
        .find_webauthn_credential(req.credential_id.trim())
        .await
        .ok()
        .flatten()
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Unrecognized Passkey credential" })),
        )
            .into_response();
    };
    if let Some(expected_uid) = chal_rec.user_id {
        if cred.user_id != expected_uid {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Passkey does not match target account" })),
            )
                .into_response();
        }
    }
    let (rp_id, origins) = webauthn_rp_and_origins(&state, &headers);
    let new_sign_count = match verify_assertion(
        &chall_b64,
        &origins,
        &rp_id,
        cred.cose_alg,
        &cred.public_key_b64,
        cred.sign_count,
        &req.client_data_json,
        &req.authenticator_data,
        &req.signature,
    ) {
        Ok(cnt) => cnt,
        Err(msg) => return (StatusCode::UNAUTHORIZED, Json(json!({ "error": msg }))).into_response(),
    };

    let _ = state
        .storage
        .update_webauthn_sign_count(cred.id, new_sign_count, now_sec)
        .await;

    let mut preferred_org_id: Option<i64> = None;
    if let Some(mfa_tok) = req.challenge_token.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let sha = sha256_hex(mfa_tok.as_bytes());
        if let Ok(Some(mc)) = state.storage.consume_mfa_challenge(&sha, now_sec).await {
            preferred_org_id = Some(mc.target_org_id);
        }
    }

    let Some((email, name, _)) = state
        .storage
        .find_user_password_hash(cred.user_id)
        .await
        .ok()
        .flatten()
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "User account inactive" })),
        )
            .into_response();
    };
    let orgs = state
        .storage
        .list_user_organizations(cred.user_id)
        .await
        .unwrap_or_default();
    let Some(target_org) = preferred_org_id
        .and_then(|oid| orgs.iter().find(|o| o.id == oid))
        .or_else(|| orgs.first())
    else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "No active organization membership" })),
        )
            .into_response();
    };
    let role = UserRole::from_db(&target_org.role).unwrap_or(UserRole::Member);

    mint_session_response(
        &state,
        &headers,
        &client_ip,
        cred.user_id,
        &email,
        &name,
        role,
        target_org.id,
        &target_org.slug,
        "auth.passkey_login",
    )
    .await
}

#[derive(Deserialize)]
pub struct ReauthReq {
    pub password: Option<String>,
    pub totp_code: Option<String>,
}

pub async fn auth_reauth(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    Json(req): Json<ReauthReq>,
) -> Response {
    let (sess, sess_sha) = match require_authenticated_session(&state, &headers, true).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let client_ip = request_client_ip(&ext);
    let now_sec = chrono::Utc::now().timestamp();
    let mut ok = false;

    if let Some(pw) = req.password.filter(|s| !s.is_empty()) {
        if let Some((_, _, pw_hash)) = state
            .storage
            .find_user_password_hash(sess.user_id)
            .await
            .ok()
            .flatten()
        {
            ok = verify_password(pw, pw_hash).await;
        }
    } else if let Some(code) = req.totp_code.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(Some(mfa_rec)) = state.storage.get_user_mfa_record(sess.user_id).await {
            if mfa_rec.is_enabled {
                let aad = format!("mfa:totp:user:{}", sess.user_id);
                if let Ok(b32) = open_secret(&state.config.app_key, aad.as_bytes(), &mfa_rec.totp_secret_enc, false) {
                    if let Ok(sec) = decode_base32(&b32) {
                        if let Some(step) = verify_totp_window(&sec, code, now_sec, mfa_rec.last_used_step) {
                            let _ = state.storage.record_mfa_attempt(sess.user_id, Some(step), now_sec).await;
                            ok = true;
                        }
                    }
                }
            }
        }
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Provide password or totp_code for re-authentication" })),
        )
            .into_response();
    }

    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Re-authentication failed" })),
        )
            .into_response();
    }

    if let Err(e) = state
        .storage
        .mark_session_reauth(&sess_sha, sess.organization_id, now_sec)
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response();
    }

    let _ = state
        .storage
        .append_audit_log(&NewAuditLog {
            organization_id: sess.organization_id,
            actor_user_id: Some(sess.user_id),
            actor_email: sess.email,
            action: "auth.reauth".into(),
            target_type: "session".into(),
            target_id: sess.session_id.to_string(),
            ip_hmac: state.rate_limiter.hash_key("session_ip", &client_ip),
            metadata: json!({}),
        })
        .await;

    Json(json!({ "ok": true, "reauth_ttl_sec": 600 })).into_response()
}

#[derive(Deserialize)]
pub struct PasswordChangeReq {
    pub current_password: String,
    pub new_password: String,
}

pub async fn change_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    Json(req): Json<PasswordChangeReq>,
) -> Response {
    let (sess, old_sha) = match require_authenticated_session(&state, &headers, true).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let client_ip = request_client_ip(&ext);
    let Some((email, name, current_hash)) = state
        .storage
        .find_user_password_hash(sess.user_id)
        .await
        .ok()
        .flatten()
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "User account unavailable" })),
        )
            .into_response();
    };
    if !verify_password(req.current_password, current_hash).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Current password is incorrect" })),
        )
            .into_response();
    }
    if let Err(msg) = validate_password_strength(&req.new_password, &email, &name) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response();
    }
    let Ok(new_hash) = hash_password(req.new_password).await else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Password hashing failed" })),
        )
            .into_response();
    };

    let now_sec = chrono::Utc::now().timestamp();
    let ttl_sec = state.config.session_ttl_sec as i64;
    let new_sess_raw = random_token_b64(32);
    let new_sess_sha = sha256_hex(new_sess_raw.as_bytes());
    let new_csrf = random_token_b64(24);
    let ua = request_user_agent(&headers);
    let ip_hmac = state.rate_limiter.hash_key("session_ip", &client_ip);

    if let Err(e) = state
        .storage
        .change_user_password(
            sess.user_id,
            sess.organization_id,
            &new_hash,
            &old_sha,
            &new_sess_sha,
            &new_csrf,
            &ua,
            &ip_hmac,
            now_sec,
            now_sec + ttl_sec,
        )
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response();
    }

    let _ = state
        .storage
        .append_audit_log(&NewAuditLog {
            organization_id: sess.organization_id,
            actor_user_id: Some(sess.user_id),
            actor_email: email,
            action: "auth.password_changed".into(),
            target_type: "user".into(),
            target_id: sess.user_id.to_string(),
            ip_hmac,
            metadata: json!({ "sessions_rotated": true }),
        })
        .await;

    let cookie = build_session_cookie(&new_sess_raw, ttl_sec, &state, &headers);
    let mut resp = Json(json!({
        "ok": true,
        "csrf_token": new_csrf,
    }))
    .into_response();
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

pub async fn list_sessions(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (sess, sess_sha) = match require_authenticated_session(&state, &headers, false).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let now_sec = chrono::Utc::now().timestamp();
    match state
        .storage
        .list_user_sessions(sess.user_id, sess.organization_id, &sess_sha, now_sec)
        .await
    {
        Ok(list) => Json(list).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn revoke_session(
    State(state): State<Arc<AppState>>,
    Path(target_id): Path<i64>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let (sess, _) = match require_authenticated_session(&state, &headers, true).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let client_ip = request_client_ip(&ext);
    match state
        .storage
        .revoke_session_by_id(sess.user_id, sess.organization_id, target_id)
        .await
    {
        Ok(true) => {
            let _ = state
                .storage
                .append_audit_log(&NewAuditLog {
                    organization_id: sess.organization_id,
                    actor_user_id: Some(sess.user_id),
                    actor_email: sess.email,
                    action: "auth.session_revoked".into(),
                    target_type: "session".into(),
                    target_id: target_id.to_string(),
                    ip_hmac: state.rate_limiter.hash_key("session_ip", &client_ip),
                    metadata: json!({}),
                })
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, Json(json!({ "error": "Session not found" }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn revoke_other_sessions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let (sess, sess_sha) = match require_authenticated_session(&state, &headers, true).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let client_ip = request_client_ip(&ext);
    match state
        .storage
        .revoke_other_sessions(sess.user_id, sess.organization_id, &sess_sha)
        .await
    {
        Ok(revoked) => {
            let _ = state
                .storage
                .append_audit_log(&NewAuditLog {
                    organization_id: sess.organization_id,
                    actor_user_id: Some(sess.user_id),
                    actor_email: sess.email,
                    action: "auth.other_sessions_revoked".into(),
                    target_type: "session".into(),
                    target_id: sess.user_id.to_string(),
                    ip_hmac: state.rate_limiter.hash_key("session_ip", &client_ip),
                    metadata: json!({ "revoked": revoked }),
                })
                .await;
            Json(json!({ "ok": true, "revoked": revoked })).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn get_public_invitation(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> Response {
    let sha = sha256_hex(token.trim().as_bytes());
    let now_sec = chrono::Utc::now().timestamp();
    let Some(info) = state.storage.lookup_invitation(&sha).await.ok().flatten() else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Invitation link not found" })),
        )
            .into_response();
    };
    if info.accepted_at.is_some() {
        return (
            StatusCode::GONE,
            Json(json!({ "error": "Invitation link has already been accepted", "valid": false })),
        )
            .into_response();
    }
    if info.expires_at <= now_sec {
        return (
            StatusCode::GONE,
            Json(json!({ "error": "Invitation link has expired", "valid": false })),
        )
            .into_response();
    }
    Json(json!({
        "valid": true,
        "organization_slug": info.organization_slug,
        "organization_name": info.organization_name,
        "email": info.email,
        "role": info.role,
        "expires_at": crate::domain::models::iso_from_ms(info.expires_at * 1000),
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct AcceptInviteReq {
    pub name: String,
    pub password: String,
    pub website: Option<String>,
}

pub async fn accept_public_invitation(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    Json(req): Json<AcceptInviteReq>,
) -> Response {
    if req.website.as_deref().map(|s| !s.is_empty()).unwrap_or(false) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid submission" }))).into_response();
    }
    let client_ip = request_client_ip(&ext);
    let ip_dec = state
        .rate_limiter
        .check_and_record("auth_invite_ip", &client_ip, 20, Duration::from_secs(60));
    if !ip_dec.allowed {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "Too many invitation acceptance requests" })),
        )
            .into_response();
    }
    let sha = sha256_hex(token.trim().as_bytes());
    let now_sec = chrono::Utc::now().timestamp();
    let Some(info) = state.storage.lookup_invitation(&sha).await.ok().flatten() else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Invitation link not found" })),
        )
            .into_response();
    };
    if info.accepted_at.is_some() || info.expires_at <= now_sec {
        return (
            StatusCode::GONE,
            Json(json!({ "error": "Invitation link expired or already accepted" })),
        )
            .into_response();
    }
    let clean_name = strip_ansi_and_bidi(req.name.trim()).chars().take(120).collect::<String>();
    if clean_name.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Name is required" }))).into_response();
    }
    if let Err(msg) = validate_password_strength(&req.password, &info.email, &clean_name) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response();
    }
    let Ok(pw_hash) = hash_password(req.password).await else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Password hashing failed" })),
        )
            .into_response();
    };
    match state
        .storage
        .accept_invitation(&sha, &clean_name, &pw_hash, now_sec)
        .await
    {
        Ok(Ok((uid, org_id, org_slug, email, role))) => {
            let _ = state
                .storage
                .append_audit_log(&NewAuditLog {
                    organization_id: org_id,
                    actor_user_id: Some(uid),
                    actor_email: email.clone(),
                    action: "member.invite_accepted".into(),
                    target_type: "user".into(),
                    target_id: uid.to_string(),
                    ip_hmac: state.rate_limiter.hash_key("session_ip", &client_ip),
                    metadata: json!({ "role": role.as_str() }),
                })
                .await;
            let mut resp = mint_session_response(
                &state,
                &headers,
                &client_ip,
                uid,
                &email,
                &clean_name,
                role,
                org_id,
                &org_slug,
                "auth.invite_login",
            )
            .await;
            *resp.status_mut() = StatusCode::CREATED;
            resp
        }
        Ok(Err(msg)) => (StatusCode::GONE, Json(json!({ "error": msg }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}
