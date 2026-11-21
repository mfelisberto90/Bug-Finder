use crate::security::auth::{
    constant_time_eq, generate_dsn_public_key, hash_password, random_token_b64, sha256_hex,
    verify_password,
};
use crate::security::headers::{is_https_request, ClientIp};
use crate::storage::AuthenticatedSession;
use crate::AppState;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

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
    state.storage.resolve_session(&sha, now_sec).await.ok()?
}

pub async fn auth_status(State(state): State<Arc<AppState>>) -> Response {
    match state.storage.needs_setup().await {
        Ok(needs_setup) => Json(json!({ "needs_setup": needs_setup })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn auth_setup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SetupRequest>,
) -> Response {
    if req.website.as_deref().map(|s| !s.is_empty()).unwrap_or(false) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid submission" }))).into_response();
    }
    if req.password.len() < 8 || req.password.len() > 256 || !req.email.contains('@') {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Valid email and password (8+ chars) required" })),
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

    let sess_raw = random_token_b64(32);
    let sess_sha = sha256_hex(sess_raw.as_bytes());
    let csrf = random_token_b64(24);
    let exp = chrono::Utc::now().timestamp() + 86400 * 7;
    if state
        .storage
        .create_session(&sess_sha, user.user_id, org.id, &csrf, exp)
        .await
        .is_err()
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Session create failed" }))).into_response();
    }

    let cookie = build_session_cookie(&sess_raw, 86400 * 7, &state, &headers);
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
            // Persist strike counter before returning 401
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

    let sess_raw = random_token_b64(32);
    let sess_sha = sha256_hex(sess_raw.as_bytes());
    let csrf = random_token_b64(24);
    let exp = now_sec + 86400 * 7;
    if state
        .storage
        .create_session(&sess_sha, user.user_id, user.organization_id, &csrf, exp)
        .await
        .is_err()
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Session error" }))).into_response();
    }

    let cookie = build_session_cookie(&sess_raw, 86400 * 7, &state, &headers);
    let mut resp = Json(json!({
        "user": {
            "id": user.user_id,
            "email": user.email,
            "name": user.name,
            "role": user.role.as_str(),
        },
        "organization": {
            "id": user.organization_id,
            "slug": user.organization_slug,
        },
        "csrf_token": csrf,
    }))
    .into_response();
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

pub async fn auth_logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Some(raw) = extract_cookie(&headers, "bf_session") {
        let sha = sha256_hex(raw.as_bytes());
        let _ = state.storage.delete_session(&sha).await;
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
    Json(json!({
        "user": {
            "id": sess.user_id,
            "email": sess.email,
            "name": sess.name,
            "role": sess.role.as_str(),
        },
        "organization_slug": sess.organization_slug,
        "organizations": orgs,
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
