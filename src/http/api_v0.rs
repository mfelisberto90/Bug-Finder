use crate::alerts::dispatcher::{dispatch_alert, AlertDispatchJob};
use crate::domain::models::*;
use crate::http::auth_routes::{resolve_request_session, sanitize_slug, verify_csrf_for_session};
use crate::security::anti_rea::derive_project_ip_hmac_key;
use crate::security::auth::{
    canonical_json_sha256, generate_api_token, generate_dsn_public_key, hash_password,
    random_token_b64, sha256_hex, validate_password_strength,
};
use crate::security::csv::sanitize_csv_cell;
use crate::security::headers::{validate_same_origin, ClientIp, PeerIp};
use crate::security::ssrf::validate_webhook_url;
use crate::selfcheck::{evaluate_self_check, run_live_self_probe};
use crate::storage::{
    IdempotencyCheck, IssueQueryParams, LogQueryParams, NewAlertRule, NewApiTokenInput,
    NewAuditLog, SaveSourceMapInput,
};
use crate::AppState;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use flate2::write::GzEncoder;
use flate2::Compression;
use futures_util::stream::Stream;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

fn require_scope(ctx: &TenantCtx, scope: &str) -> Result<(), Box<Response>> {
    if ctx.has_scope(scope) {
        Ok(())
    } else {
        Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": format!("Missing required scope: {scope}") })),
            )
                .into_response(),
        ))
    }
}

fn client_accepts_gzip(headers: &HeaderMap) -> bool {
    let Some(raw) = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    raw.split(',').any(|part| {
        let mut it = part.trim().split(';');
        let enc = it.next().unwrap_or("").trim();
        if !enc.eq_ignore_ascii_case("gzip") {
            return false;
        }
        !it.any(|p| p.trim().eq_ignore_ascii_case("q=0"))
    })
}

fn fnv1a_u64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn etag_matches(headers: &HeaderMap, etag: &str) -> bool {
    let Some(raw) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    raw.split(',')
        .map(str::trim)
        .any(|tag| tag == etag || tag == "*")
}

fn json_bytes_response_maybe_gzip(headers: &HeaderMap, bytes: Vec<u8>) -> Response {
    if bytes.len() > 2048 && client_accepts_gzip(headers) {
        let mut enc = GzEncoder::new(Vec::with_capacity(bytes.len() / 3), Compression::fast());
        if enc.write_all(&bytes).is_ok() {
            if let Ok(gz) = enc.finish() {
                let mut resp = (StatusCode::OK, gz).into_response();
                resp.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                resp.headers_mut()
                    .insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
                resp.headers_mut()
                    .insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
                return resp;
            }
        }
    }
    let mut resp = (StatusCode::OK, bytes).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp.headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    resp
}

fn json_response_maybe_gzip<T: serde::Serialize>(headers: &HeaderMap, value: &T) -> Response {
    match serde_json::to_vec(value) {
        Ok(bytes) => json_bytes_response_maybe_gzip(headers, bytes),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

fn is_valid_telegram_chat_id(raw: &str) -> bool {
    if let Some(username) = raw.strip_prefix('@') {
        let len = username.len();
        return (5..=32).contains(&len)
            && username.as_bytes()[0].is_ascii_alphabetic()
            && username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_');
    }
    let digits = raw.strip_prefix('-').unwrap_or(raw);
    (5..=20).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit())
}

fn require_session_only(ctx: &TenantCtx) -> Result<(), Box<Response>> {
    if ctx.is_session_auth {
        Ok(())
    } else {
        Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "Interactive session required; API tokens cannot access this endpoint" })),
            )
                .into_response(),
        ))
    }
}

fn require_step_up(ctx: &TenantCtx) -> Result<(), Box<Response>> {
    let now_sec = chrono::Utc::now().timestamp();
    if ctx.has_recent_reauth(now_sec) {
        Ok(())
    } else {
        Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "Step-up re-authentication required",
                    "reauth_required": true
                })),
            )
                .into_response(),
        ))
    }
}

async fn record_audit(
    state: &AppState,
    ctx: &TenantCtx,
    ext: &axum::http::Extensions,
    action: &str,
    target_type: &str,
    target_id: &str,
    metadata: Value,
) {
    let actor_email = if let Some(uid) = ctx.user_id {
        state
            .storage
            .find_user_password_hash(uid)
            .await
            .ok()
            .flatten()
            .map(|(email, _, _)| email)
            .unwrap_or_else(|| format!("user:{uid}"))
    } else {
        "system".into()
    };
    let client_ip = ext
        .get::<ClientIp>()
        .map(|c| c.0)
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let ip_hmac = state
        .rate_limiter
        .hash_key("audit_ip", &client_ip.to_string());
    let _ = state
        .storage
        .append_audit_log(&NewAuditLog {
            organization_id: ctx.organization_id,
            actor_user_id: ctx.user_id,
            actor_email,
            action: action.to_string(),
            target_type: target_type.to_string(),
            target_id: target_id.to_string(),
            ip_hmac,
            metadata,
        })
        .await;
}

async fn authenticate_api_tenant(
    state: &AppState,
    headers: &HeaderMap,
    ext: &axum::http::Extensions,
    method: &Method,
    org_slug_opt: Option<&str>,
) -> Result<TenantCtx, Box<Response>> {
    let is_mutation = matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    );
    let now_sec = chrono::Utc::now().timestamp();

    let ctx = if let Some(tok) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        }) {
        let sha = sha256_hex(tok.trim().as_bytes());
        let c = if let Some(cached) = state.api_token_cache.get(&sha, org_slug_opt, now_sec) {
            cached
        } else if let Some(fresh) = state
            .storage
            .resolve_api_token(&sha, org_slug_opt, now_sec)
            .await
            .ok()
            .flatten()
        {
            state
                .api_token_cache
                .insert(&sha, org_slug_opt, fresh.clone());
            fresh
        } else {
            return Err(Box::new(
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "Invalid or expired API token" })),
                )
                    .into_response(),
            ));
        };
        c
    } else {
        let Some(sess) = resolve_request_session(state, headers).await else {
            return Err(Box::new(
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "Authentication required" })),
                )
                    .into_response(),
            ));
        };

        if is_mutation {
            let peer_ip = ext
                .get::<PeerIp>()
                .map(|p| p.0)
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
            if !validate_same_origin(headers, peer_ip, &state.config) {
                return Err(Box::new(
                    (
                        StatusCode::FORBIDDEN,
                        Json(json!({ "error": "Cross-origin state-changing request rejected" })),
                    )
                        .into_response(),
                ));
            }
            if !verify_csrf_for_session(&sess, headers) {
                return Err(Box::new(
                    (
                        StatusCode::FORBIDDEN,
                        Json(json!({ "error": "Invalid CSRF token" })),
                    )
                        .into_response(),
                ));
            }
        }

        if let Some(want_slug) = org_slug_opt {
            if sess.organization_slug == want_slug {
                TenantCtx::from_session(
                    sess.organization_id,
                    sess.organization_slug,
                    sess.user_id,
                    sess.role,
                    sess.reauth_at,
                    Some(sess.session_id),
                )
            } else {
                let mut resolved = match state
                    .storage
                    .resolve_tenant_for_user(sess.user_id, want_slug)
                    .await
                {
                    Ok(Some(c)) => c,
                    _ => {
                        return Err(Box::new(
                            (
                                StatusCode::NOT_FOUND,
                                Json(json!({ "error": "Organization not found" })),
                            )
                                .into_response(),
                        ));
                    }
                };
                resolved.reauth_at = sess.reauth_at;
                resolved.session_id = Some(sess.session_id);
                resolved
            }
        } else {
            TenantCtx::from_session(
                sess.organization_id,
                sess.organization_slug,
                sess.user_id,
                sess.role,
                sess.reauth_at,
                Some(sess.session_id),
            )
        }
    };

    if is_mutation {
        let rate_key = format!("u:{}:o:{}", ctx.user_id.unwrap_or(0), ctx.organization_id);
        let dec = state.rate_limiter.check_and_record(
            "api_mutate_actor",
            &rate_key,
            120,
            Duration::from_secs(60),
        );
        if !dec.allowed {
            return Err(Box::new(
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    [(header::RETRY_AFTER, dec.retry_after_sec.to_string())],
                    Json(json!({ "error": "Too many mutating API requests" })),
                )
                    .into_response(),
            ));
        }
    }

    Ok(ctx)
}

async fn check_idempotency(
    state: &AppState,
    ctx: &TenantCtx,
    headers: &HeaderMap,
    action: &str,
    payload: &Value,
) -> Result<Option<(String, String)>, Box<Response>> {
    let Some(raw_key) = headers.get("idempotency-key").and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    let key = raw_key.trim();
    if key.is_empty() || key.len() > 128 {
        return Err(Box::new(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Invalid Idempotency-Key" })),
            )
                .into_response(),
        ));
    }
    let payload_sha = canonical_json_sha256(payload);
    match state
        .storage
        .begin_idempotency(ctx, action, key, &payload_sha)
        .await
    {
        Ok(IdempotencyCheck::Proceed) => Ok(Some((key.to_string(), payload_sha))),
        Ok(IdempotencyCheck::Replay { status_code, body }) => {
            let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::OK);
            let mut resp =
                (status, [(header::CONTENT_TYPE, "application/json")], body).into_response();
            resp.headers_mut()
                .insert("x-idempotent-replay", HeaderValue::from_static("true"));
            Err(Box::new(resp))
        }
        Ok(IdempotencyCheck::Conflict(msg)) => Err(Box::new(
            (StatusCode::CONFLICT, Json(json!({ "error": msg }))).into_response(),
        )),
        Err(e) => Err(Box::new(
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e })),
            )
                .into_response(),
        )),
    }
}

fn parse_stats_period_ms(period: Option<&str>) -> Option<i64> {
    let p = period?.trim();
    if let Some(h) = p.strip_suffix('h').and_then(|s| s.parse::<i64>().ok()) {
        return Some(now_ms() - h.clamp(1, 720) * 3_600_000);
    }
    if let Some(d) = p.strip_suffix('d').and_then(|s| s.parse::<i64>().ok()) {
        return Some(now_ms() - d.clamp(1, 365) * 86_400_000);
    }
    if let Some(m) = p.strip_suffix('m').and_then(|s| s.parse::<i64>().ok()) {
        return Some(now_ms() - m.clamp(1, 1440) * 60_000);
    }
    None
}

// ----------------------------------------------------------------------------
// Organizations & Projects
// ----------------------------------------------------------------------------

pub async fn list_organizations(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, None).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "org:read") {
        return *r;
    }
    let Some(uid) = ctx.user_id else {
        return Json(json!([])).into_response();
    };
    match state.storage.list_user_organizations(uid).await {
        Ok(orgs) => Json(orgs).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn list_projects(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "project:read") {
        return *r;
    }
    match state.storage.list_projects(&ctx).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct CreateProjectReq {
    pub name: String,
    pub slug: Option<String>,
    pub platform: Option<String>,
}

pub async fn create_project(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
    Json(req): Json<CreateProjectReq>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "project:write") {
        return *r;
    }
    if !ctx.role.can_write_project() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Requires admin or owner role" })),
        )
            .into_response();
    }
    let slug = sanitize_slug(req.slug.as_deref().unwrap_or(&req.name));
    if req.name.trim().is_empty() || slug.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid project name/slug" })),
        )
            .into_response();
    }
    let platform = req.platform.unwrap_or_else(|| "other".into());
    let payload_val = json!({
        "name": req.name.trim(),
        "slug": slug,
        "platform": platform,
    });
    let idem = match check_idempotency(&state, &ctx, &headers, "create_project", &payload_val).await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let dsn_pub = generate_dsn_public_key();
    let dsn_sha = sha256_hex(dsn_pub.as_bytes());
    let (status_code, body_str) = match state
        .storage
        .create_project(&ctx, req.name.trim(), &slug, &platform, &dsn_pub, &dsn_sha)
        .await
    {
        Ok(p) => {
            record_audit(
                &state,
                &ctx,
                &ext,
                "project.created",
                "project",
                &p.id.to_string(),
                json!({ "slug": p.slug, "platform": p.platform }),
            )
            .await;
            (
                StatusCode::CREATED,
                serde_json::to_string(&p).unwrap_or_else(|_| "{}".into()),
            )
        }
        Err(e) => (
            StatusCode::CONFLICT,
            serde_json::to_string(&json!({ "error": e })).unwrap_or_else(|_| "{}".into()),
        ),
    };
    if let Some((k, _)) = idem {
        let _ = state
            .storage
            .finish_idempotency(&ctx, "create_project", &k, status_code.as_u16(), &body_str)
            .await;
    }
    (
        status_code,
        [(header::CONTENT_TYPE, "application/json")],
        body_str,
    )
        .into_response()
}

pub async fn update_project_settings(
    State(state): State<Arc<AppState>>,
    Path((org, proj)): Path<(String, String)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
    Json(mut filters): Json<ProjectFilters>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "project:write") {
        return *r;
    }
    if !ctx.role.can_write_project() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Requires admin or owner role" })),
        )
            .into_response();
    }
    filters.event_throttle_rate = filters.event_throttle_rate.min(100);
    match state
        .storage
        .update_project_filters(&ctx, &proj, &filters)
        .await
    {
        Ok(Some(dto)) => {
            state.dsn_auth_cache.invalidate_project(dto.id);
            record_audit(
                &state,
                &ctx,
                &ext,
                "project.settings_updated",
                "project",
                &dto.id.to_string(),
                json!({
                    "slug": dto.slug,
                    "event_throttle_rate": dto.filters.event_throttle_rate,
                    "aggressive_key_match": dto.filters.aggressive_key_match,
                    "shield_mode": dto.filters.shield.mode,
                }),
            )
            .await;
            Json(dto).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Project not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn list_project_keys(
    State(state): State<Arc<AppState>>,
    Path((org, proj)): Path<(String, String)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "project:read") {
        return *r;
    }
    match state.storage.list_project_keys(&ctx, &proj).await {
        Ok(keys) => Json(keys).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct CreateKeyReq {
    pub label: Option<String>,
}

pub async fn create_project_key(
    State(state): State<Arc<AppState>>,
    Path((org, proj)): Path<(String, String)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
    Json(req): Json<CreateKeyReq>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "project:write") {
        return *r;
    }
    if !ctx.role.can_write_project() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    let pubk = generate_dsn_public_key();
    let sha = sha256_hex(pubk.as_bytes());
    let label = req.label.unwrap_or_else(|| "API Key".into());
    match state
        .storage
        .create_project_key(&ctx, &proj, label.trim(), &pubk, &sha)
        .await
    {
        Ok(Some(k)) => {
            record_audit(
                &state,
                &ctx,
                &ext,
                "dsn_key.created",
                "project_key",
                &k.id.to_string(),
                json!({ "project": proj, "label": k.label }),
            )
            .await;
            (StatusCode::CREATED, Json(k)).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Project not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct UpdateKeyReq {
    pub rate_limit_per_min: u32,
    pub is_active: bool,
}

pub async fn update_project_key(
    State(state): State<Arc<AppState>>,
    Path((org, proj, key_id)): Path<(String, String, i64)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
    Json(req): Json<UpdateKeyReq>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "project:write") {
        return *r;
    }
    if !ctx.role.can_write_project() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    let rate = req.rate_limit_per_min.clamp(1, 100_000);
    match state
        .storage
        .update_project_key(&ctx, &proj, key_id, rate, req.is_active)
        .await
    {
        Ok(Some(dto)) => {
            let key_sha = sha256_hex(dto.public_key.as_bytes());
            state.invalid_dsn_cache.invalidate(dto.project_id, &key_sha);
            state.dsn_auth_cache.invalidate_project(dto.project_id);
            record_audit(
                &state,
                &ctx,
                &ext,
                "dsn_key.updated",
                "project_key",
                &dto.id.to_string(),
                json!({ "project": proj, "rate_limit_per_min": dto.rate_limit_per_min, "is_active": dto.is_active }),
            )
            .await;
            Json(dto).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Key not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn delete_project_key(
    State(state): State<Arc<AppState>>,
    Path((org, proj, key_id)): Path<(String, String, i64)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "project:admin") {
        return *r;
    }
    if !ctx.role.can_write_project() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    match state.storage.delete_project_key(&ctx, &proj, key_id).await {
        Ok(true) => {
            state.dsn_auth_cache.invalidate_org(ctx.organization_id);
            record_audit(
                &state,
                &ctx,
                &ext,
                "dsn_key.deleted",
                "project_key",
                &key_id.to_string(),
                json!({ "project": proj }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Key not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn enable_project_tunnel(
    State(state): State<Arc<AppState>>,
    Path((org, proj)): Path<(String, String)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "project:write") {
        return *r;
    }
    if !ctx.role.can_write_project() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    let slug = random_token_b64(10).to_ascii_lowercase();
    match state
        .storage
        .enable_project_tunnel(&ctx, &proj, &slug)
        .await
    {
        Ok(Some(s)) => {
            state.dsn_auth_cache.invalidate_org(ctx.organization_id);
            Json(json!({ "tunnel_slug": s, "path": format!("/t/{s}") })).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Project not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

// ----------------------------------------------------------------------------
// Issues, Events, Export CSV & Stats v2 (GlitchTip & Sentry Compatible)
// ----------------------------------------------------------------------------

fn parse_issue_query(q: &HashMap<String, String>) -> IssueQueryParams {
    let mut status = None;
    let mut level = q.get("level").cloned().filter(|s| !s.is_empty());
    let mut environment = q.get("environment").cloned().filter(|s| !s.is_empty());
    let mut release = q.get("release").cloned().filter(|s| !s.is_empty());
    let mut free_terms = Vec::new();

    if let Some(raw_q) = q.get("query") {
        for tok in raw_q.split_whitespace() {
            if let Some(st) = tok.strip_prefix("is:") {
                if matches!(st, "unresolved" | "resolved" | "ignored") {
                    status = Some(st.to_string());
                }
            } else if let Some(l) = tok.strip_prefix("level:") {
                level = Some(l.to_string());
            } else if let Some(e) = tok.strip_prefix("environment:") {
                environment = Some(e.to_string());
            } else if let Some(r) = tok.strip_prefix("release:") {
                release = Some(r.to_string());
            } else {
                free_terms.push(tok.to_string());
            }
        }
    }

    let search_query = if free_terms.is_empty() {
        None
    } else {
        Some(free_terms.join(" "))
    };
    let project_id = q.get("project").and_then(|s| s.parse::<i64>().ok());
    let sort = q.get("sort").cloned().unwrap_or_else(|| "date".into());
    let since_ms = parse_stats_period_ms(q.get("statsPeriod").map(String::as_str));
    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    let offset = q
        .get("offset")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0)
        .clamp(0, 100_000);

    IssueQueryParams {
        status,
        level,
        environment,
        release,
        project_id,
        search_query,
        sort,
        since_ms,
        limit,
        offset,
    }
}

pub async fn list_issues(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "event:read") {
        return *r;
    }
    let params = parse_issue_query(&query);
    let unfiltered_first_page = params.status.is_none()
        && params.level.is_none()
        && params.environment.is_none()
        && params.release.is_none()
        && params.search_query.is_none()
        && params.since_ms.is_none()
        && params.offset == 0;

    if unfiltered_first_page && headers.contains_key(header::IF_NONE_MATCH) {
        if let Ok(wm) = state
            .storage
            .issues_etag_watermark(&ctx, params.project_id)
            .await
        {
            let wm_etag = format!("W/\"u-{}-{}-{}-{}\"", wm.0, wm.1, params.sort, params.limit);
            if etag_matches(&headers, &wm_etag) {
                let mut resp = StatusCode::NOT_MODIFIED.into_response();
                if let Ok(v) = HeaderValue::from_str(&wm_etag) {
                    resp.headers_mut().insert(header::ETAG, v);
                }
                resp.headers_mut()
                    .insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
                if let Ok(v) = HeaderValue::from_str(&wm.0.to_string()) {
                    resp.headers_mut().insert("x-hits", v);
                }
                return resp;
            }
        }
    }

    match state.storage.list_issues(&ctx, &params).await {
        Ok((items, total_hits, wm_sig)) => {
            let body_bytes = match serde_json::to_vec(&items) {
                Ok(b) => b,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": e.to_string() })),
                    )
                        .into_response();
                }
            };
            let etag = if unfiltered_first_page {
                format!(
                    "W/\"u-{total_hits}-{wm_sig}-{}-{}\"",
                    params.sort, params.limit
                )
            } else {
                format!("W/\"f-{:016x}\"", fnv1a_u64(&body_bytes))
            };
            if etag_matches(&headers, &etag) {
                let mut resp = StatusCode::NOT_MODIFIED.into_response();
                if let Ok(v) = HeaderValue::from_str(&etag) {
                    resp.headers_mut().insert(header::ETAG, v);
                }
                resp.headers_mut()
                    .insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
                if let Ok(v) = HeaderValue::from_str(&total_hits.to_string()) {
                    resp.headers_mut().insert("x-hits", v);
                }
                return resp;
            }
            let mut resp = json_bytes_response_maybe_gzip(&headers, body_bytes);
            if let Ok(v) = HeaderValue::from_str(&etag) {
                resp.headers_mut().insert(header::ETAG, v);
            }
            if let Ok(v) = HeaderValue::from_str(&total_hits.to_string()) {
                resp.headers_mut().insert("x-hits", v);
            }
            resp
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn get_issue(
    State(state): State<Arc<AppState>>,
    Path((org, issue_id)): Path<(String, i64)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "event:read") {
        return *r;
    }
    match state.storage.get_issue(&ctx, issue_id).await {
        Ok(Some(i)) => Json(i).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Issue not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct UpdateIssueReq {
    pub status: String,
    pub resolved_in_release: Option<String>,
}

pub async fn update_issue(
    State(state): State<Arc<AppState>>,
    Path((org, issue_id)): Path<(String, i64)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
    Json(req): Json<UpdateIssueReq>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "event:write") {
        return *r;
    }
    if !ctx.role.can_mutate_issues() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Viewers cannot mutate issues" })),
        )
            .into_response();
    }
    let Some(status) = IssueStatus::from_str_opt(&req.status) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid status" })),
        )
            .into_response();
    };
    let payload_val = json!({
        "issue_id": issue_id,
        "status": req.status,
        "resolved_in_release": req.resolved_in_release,
    });
    let idem = match check_idempotency(&state, &ctx, &headers, "update_issue", &payload_val).await {
        Ok(v) => v,
        Err(r) => return *r,
    };

    let (status_code, body_str) = match state
        .storage
        .update_issue_status(&ctx, issue_id, status, req.resolved_in_release.as_deref())
        .await
    {
        Ok(Some(updated)) => {
            record_audit(
                &state,
                &ctx,
                &ext,
                "issue.updated",
                "issue",
                &issue_id.to_string(),
                json!({ "status": req.status, "resolved_in_release": req.resolved_in_release }),
            )
            .await;
            (
                StatusCode::OK,
                serde_json::to_string(&updated).unwrap_or_else(|_| "{}".into()),
            )
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            serde_json::to_string(&json!({ "error": "Issue not found" }))
                .unwrap_or_else(|_| "{}".into()),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::to_string(&json!({ "error": e })).unwrap_or_else(|_| "{}".into()),
        ),
    };

    if let Some((k, _)) = idem {
        let _ = state
            .storage
            .finish_idempotency(&ctx, "update_issue", &k, status_code.as_u16(), &body_str)
            .await;
    }

    (
        status_code,
        [(header::CONTENT_TYPE, "application/json")],
        body_str,
    )
        .into_response()
}

pub async fn list_issue_events(
    State(state): State<Arc<AppState>>,
    Path((org, issue_id)): Path<(String, i64)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "event:read") {
        return *r;
    }
    let issue = state.storage.get_issue(&ctx, issue_id).await.ok().flatten();
    match state.storage.list_issue_events(&ctx, issue_id, 25).await {
        Ok(mut list) => {
            for ev in &mut list {
                ev.diagnosis = Some(crate::domain::diagnosis::diagnose_issue_event(
                    issue.as_ref(),
                    ev,
                ));
            }
            Json(list).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn get_issue_event(
    State(state): State<Arc<AppState>>,
    Path((org, issue_id, ev_id)): Path<(String, i64, String)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "event:read") {
        return *r;
    }
    let issue = state.storage.get_issue(&ctx, issue_id).await.ok().flatten();
    match state.storage.get_issue_event(&ctx, issue_id, &ev_id).await {
        Ok(Some(mut ev)) => {
            ev.diagnosis = Some(crate::domain::diagnosis::diagnose_issue_event(
                issue.as_ref(),
                &ev,
            ));
            Json(ev).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Event not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn export_issues_csv(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "event:read") {
        return *r;
    }
    let mut params = parse_issue_query(&query);
    params.limit = 200;
    let (items, _, _) = match state.storage.list_issues(&ctx, &params).await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e })),
            )
                .into_response()
        }
    };
    record_audit(
        &state,
        &ctx,
        &ext,
        "issues.exported_csv",
        "organization",
        &ctx.organization_id.to_string(),
        json!({ "count": items.len() }),
    )
    .await;
    let mut csv = String::from("short_id,project,level,status,count,title,culprit,last_seen\n");
    for it in items {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            sanitize_csv_cell(&it.short_id),
            sanitize_csv_cell(&it.project_slug),
            sanitize_csv_cell(&it.level),
            sanitize_csv_cell(&it.status),
            it.count,
            sanitize_csv_cell(&it.title),
            sanitize_csv_cell(&it.culprit),
            sanitize_csv_cell(&it.last_seen),
        ));
    }
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"issues-export.csv\"",
            ),
        ],
        csv,
    )
        .into_response()
}

pub async fn get_stats_v2(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "event:read") {
        return *r;
    }
    let category = query.get("category").map(String::as_str).unwrap_or("error");
    let until_ms = now_ms();
    let since_ms = parse_stats_period_ms(query.get("statsPeriod").map(String::as_str))
        .unwrap_or(until_ms - 86_400_000);
    match state
        .storage
        .get_stats_v2(&ctx, category, since_ms, until_ms)
        .await
    {
        Ok(v) => Json(v).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

// ----------------------------------------------------------------------------
// Structured Logs & Live Tail SSE
// ----------------------------------------------------------------------------

pub async fn list_logs(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "event:read") {
        return *r;
    }
    let project_ids = query
        .get("project")
        .map(|s| {
            s.split(',')
                .filter_map(|p| p.trim().parse::<i64>().ok())
                .take(20)
                .collect()
        })
        .unwrap_or_default();
    let level_list = query
        .get("level")
        .map(|s| {
            s.split(',')
                .filter(|l| !l.trim().is_empty())
                .take(20)
                .map(|l| LogLevel::from_str_loose(l).num())
                .collect()
        })
        .unwrap_or_default();
    let cap_str = |k: &str| {
        query
            .get(k)
            .map(|s| s.trim().chars().take(128).collect::<String>())
            .filter(|s| !s.is_empty())
    };
    let params = LogQueryParams {
        project_ids,
        min_level_num: query
            .get("minLevel")
            .map(|l| LogLevel::from_str_loose(l).num()),
        level_list,
        service: cap_str("service"),
        environment: cap_str("environment"),
        host: cap_str("host"),
        trace_id: cap_str("traceId").or_else(|| cap_str("trace_id")),
        search_query: cap_str("query"),
        start_ms: parse_stats_period_ms(query.get("statsPeriod").map(String::as_str)),
        end_ms: None,
        cursor_id: cap_str("cursor"),
        limit: query
            .get("limit")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(100),
    };
    match state.storage.query_logs(&ctx, &params).await {
        Ok(logs) => json_response_maybe_gzip(&headers, &logs),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn stream_logs_sse(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "event:read") {
        return *r;
    }
    let Ok(permit) = state.sse_sem.clone().try_acquire_owned() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "Too many concurrent log streams" })),
        )
            .into_response();
    };
    let rx = state.live_tx.subscribe();
    let org_id = ctx.organization_id;
    let project_filter = query.get("project").and_then(|s| s.parse::<i64>().ok());
    let level_filter = query.get("level").cloned().filter(|s| !s.is_empty());
    let q_filter = query
        .get("query")
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| !s.is_empty());

    let stream: std::pin::Pin<Box<dyn Stream<Item = Result<SseEvent, Infallible>> + Send>> =
        Box::pin(BroadcastStream::new(rx).filter_map(move |msg| {
            let _sse_permit = &permit;
            let ev = msg.ok()?;
            if ev.organization_id != org_id {
                return None;
            }
            if let Some(pid) = project_filter {
                if ev.project_id != pid {
                    return None;
                }
            }
            if let Some(ref lf) = level_filter {
                if !ev.level.eq_ignore_ascii_case(lf) {
                    return None;
                }
            }
            if let Some(ref qf) = q_filter {
                if !ev.title_or_body.to_ascii_lowercase().contains(qf)
                    && !ev.service.to_ascii_lowercase().contains(qf)
                {
                    return None;
                }
            }
            let json_str = serde_json::to_string(&ev).ok()?;
            Some(Ok(SseEvent::default().event(ev.kind).data(json_str)))
        }));

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("ping"),
        )
        .into_response()
}

pub async fn list_log_resources(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "event:read") {
        return *r;
    }
    match state.storage.list_log_resources(&ctx).await {
        Ok(res) => Json(res).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn get_log_stats(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "event:read") {
        return *r;
    }
    let until = now_ms();
    let since = parse_stats_period_ms(query.get("statsPeriod").map(String::as_str))
        .unwrap_or(until - 86_400_000);
    match state.storage.get_log_stats(&ctx, since, until).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

// ----------------------------------------------------------------------------
// Performance, Traces, Release Health & Source Maps
// ----------------------------------------------------------------------------

pub async fn list_transactions(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "event:read") {
        return *r;
    }
    let since = parse_stats_period_ms(query.get("statsPeriod").map(String::as_str))
        .unwrap_or_else(|| now_ms() - 86_400_000);
    match state.storage.list_transactions(&ctx, since).await {
        Ok(list) => json_response_maybe_gzip(&headers, &list),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn get_trace_context(
    State(state): State<Arc<AppState>>,
    Path((org, trace_id)): Path<(String, String)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "event:read") {
        return *r;
    }
    match state.storage.get_trace_context(&ctx, &trace_id).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn list_releases(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "project:read") {
        return *r;
    }
    match state.storage.list_releases(&ctx).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn upload_sourcemap(
    State(state): State<Arc<AppState>>,
    Path((org, proj, version)): Path<(String, String, String)>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
    body: Bytes,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if !(ctx.has_scope("project:releases") || ctx.has_scope("project:write")) {
        if let Err(r) = require_scope(&ctx, "project:releases") {
            return *r;
        }
    }
    if !ctx.role.can_mutate_issues() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    let project_exists = state
        .storage
        .list_projects(&ctx)
        .await
        .map(|ps| ps.iter().any(|p| p.slug == proj))
        .unwrap_or(false);
    if !project_exists {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Project not found" })),
        )
            .into_response();
    }
    if body.len() > 10 * 1024 * 1024 {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({ "error": "Source map exceeds 10 MiB" })),
        )
            .into_response();
    }
    let filename = query
        .get("filename")
        .map(|s| s.rsplit('/').next().unwrap_or(s).to_string())
        .filter(|s| !s.is_empty() && !s.contains(".."))
        .unwrap_or_else(|| "bundle.js.map".into());
    let q_debug_id = query.get("debug_id").cloned();

    let blob_sha = sha256_hex(&body);
    let dir = state.config.sourcemaps_dir();
    let target_path = dir.join(&blob_sha);
    let tmp_name = format!(".{blob_sha}.{}.tmp", random_token_b64(6));
    let tmp_path = dir.join(tmp_name);
    let bytes_vec = body.to_vec();
    let prep_res = tokio::task::spawn_blocking(
        move || -> Result<Option<String>, (StatusCode, &'static str)> {
            let val = serde_json::from_slice::<Value>(&bytes_vec)
                .ok()
                .filter(|v| {
                    v.get("version").and_then(|x| x.as_u64()) == Some(3)
                        && v.get("mappings").is_some()
                })
                .ok_or((StatusCode::BAD_REQUEST, "Invalid SourceMap v3 JSON"))?;
            let parsed_did = val
                .get("debugId")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            std::fs::create_dir_all(&dir).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed creating sourcemaps directory",
                )
            })?;
            if !target_path.exists() {
                use std::io::Write;
                #[cfg(unix)]
                use std::os::unix::fs::OpenOptionsExt;
                let mut opts = std::fs::OpenOptions::new();
                opts.create_new(true).write(true);
                #[cfg(unix)]
                opts.mode(0o600);
                let mut f = opts.open(&tmp_path).map_err(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed creating temporary sourcemap file",
                    )
                })?;
                f.write_all(&bytes_vec).map_err(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed writing sourcemap file",
                    )
                })?;
                f.sync_all().map_err(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed syncing sourcemap file",
                    )
                })?;
                std::fs::rename(&tmp_path, &target_path).map_err(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed committing sourcemap file",
                    )
                })?;
            }
            Ok(parsed_did)
        },
    )
    .await;
    let parsed_debug_id = match prep_res {
        Ok(Ok(d)) => d,
        Ok(Err((st, msg))) => return (st, Json(json!({ "error": msg }))).into_response(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    };
    let debug_id = q_debug_id.or(parsed_debug_id).unwrap_or_default();

    match state
        .storage
        .save_source_map(
            &ctx,
            &SaveSourceMapInput {
                project_slug: &proj,
                release_version: &version,
                debug_id: &debug_id,
                filename: &filename,
                blob_sha256: &blob_sha,
                size_bytes: body.len() as i64,
            },
        )
        .await
    {
        Ok(rec) => (
            StatusCode::CREATED,
            Json(json!({
                "id": rec.id,
                "release": rec.release_version,
                "debug_id": rec.debug_id,
                "filename": rec.filename,
                "sha256": rec.blob_sha256,
                "size_bytes": rec.size_bytes,
            })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
    }
}

// ----------------------------------------------------------------------------
// Uptime Monitors & Heartbeat Check
// ----------------------------------------------------------------------------

pub async fn list_monitors(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "project:read") {
        return *r;
    }
    match state.storage.list_monitors(&ctx).await {
        Ok(m) => Json(m).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct CreateMonitorReq {
    pub project_id: i64,
    pub name: String,
    pub expected_interval_sec: Option<i64>,
}

pub async fn create_monitor(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
    Json(req): Json<CreateMonitorReq>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "project:write") {
        return *r;
    }
    if !ctx.role.can_write_project() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    let interval = req.expected_interval_sec.unwrap_or(60).clamp(10, 86400);
    let payload_val = json!({
        "project_id": req.project_id,
        "name": req.name.trim(),
        "expected_interval_sec": interval,
    });
    let idem = match check_idempotency(&state, &ctx, &headers, "create_monitor", &payload_val).await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let uuid = uuid::Uuid::new_v4().to_string();
    let (status_code, body_str) = match state
        .storage
        .create_monitor(&ctx, req.project_id, req.name.trim(), &uuid, interval)
        .await
    {
        Ok(m) => (
            StatusCode::CREATED,
            serde_json::to_string(&m).unwrap_or_else(|_| "{}".into()),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            serde_json::to_string(&json!({ "error": e })).unwrap_or_else(|_| "{}".into()),
        ),
    };
    if let Some((k, _)) = idem {
        let _ = state
            .storage
            .finish_idempotency(&ctx, "create_monitor", &k, status_code.as_u16(), &body_str)
            .await;
    }
    (
        status_code,
        [(header::CONTENT_TYPE, "application/json")],
        body_str,
    )
        .into_response()
}

pub async fn delete_monitor(
    State(state): State<Arc<AppState>>,
    Path((org, mon_id)): Path<(String, i64)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "project:write") {
        return *r;
    }
    if !ctx.role.can_write_project() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    match state.storage.delete_monitor(&ctx, mon_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Monitor not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

/// Compatible with GlitchTipReadClient.php `GET /api/0/organizations/{org}/heartbeat_check/{uuid}/`
pub async fn get_heartbeat_check(
    State(state): State<Arc<AppState>>,
    Path((org, uuid)): Path<(String, String)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "event:read") {
        return *r;
    }
    match state.storage.get_heartbeat(&ctx, &uuid).await {
        Ok(Some(m)) => Json(m).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Monitor not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn post_heartbeat_check(
    State(state): State<Arc<AppState>>,
    Path((org, uuid)): Path<(String, String)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "event:write") {
        return *r;
    }
    if !ctx.role.can_mutate_issues() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Viewers cannot record heartbeats" })),
        )
            .into_response();
    }
    match state
        .storage
        .record_heartbeat(&ctx, &uuid, true, "OK")
        .await
    {
        Ok(Some(m)) => Json(m).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Monitor not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

// ----------------------------------------------------------------------------
// Alert Rules, API Tokens & Members (RBAC + Anti-Last-Owner)
// ----------------------------------------------------------------------------

pub async fn list_alerts(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "project:read") {
        return *r;
    }
    match state.storage.list_alert_rules(&ctx).await {
        Ok(rules) => Json(rules).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct CreateAlertReq {
    pub project_id: i64,
    pub name: String,
    pub trigger_type: String,
    pub threshold_count: Option<i64>,
    pub window_sec: Option<i64>,
    pub cooldown_sec: Option<i64>,
    pub channel_type: String,
    pub target_url: Option<String>,
    pub webhook_secret: Option<String>,
    pub email_to: Option<String>,
}

pub async fn create_alert(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
    Json(req): Json<CreateAlertReq>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "project:write") {
        return *r;
    }
    if !ctx.role.can_write_project() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Requires admin or owner role" })),
        )
            .into_response();
    }
    if !matches!(
        req.trigger_type.as_str(),
        "new_issue"
            | "regression"
            | "threshold"
            | "fatal_log"
            | "uptime_down"
            | "security_threat"
            | "secret_leak"
    ) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid trigger_type" })),
        )
            .into_response();
    }
    if !matches!(
        req.channel_type.as_str(),
        "webhook" | "slack" | "discord" | "telegram" | "email"
    ) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid channel_type" })),
        )
            .into_response();
    }
    let mut target_url = req.target_url.unwrap_or_default();
    let webhook_secret = req.webhook_secret.unwrap_or_default().trim().to_string();
    let email_to = req.email_to.unwrap_or_default().trim().to_string();
    if req.channel_type == "email" {
        if email_to.is_empty()
            || !email_to.contains('@')
            || email_to.len() > 254
            || email_to.contains(['\r', '\n', '<', '>'])
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Valid email_to address is required for email alerts" })),
            )
                .into_response();
        }
    } else if req.channel_type == "telegram" {
        if webhook_secret.is_empty()
            || webhook_secret.len() > 256
            || !webhook_secret.contains(':')
            || !webhook_secret
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'-'))
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Valid Telegram Bot Token (webhook_secret) is required" })),
            )
                .into_response();
        }
        let trimmed_target = target_url.trim().to_string();
        if trimmed_target.starts_with("https://") || trimmed_target.starts_with("http://") {
            let allow_http = state.config.dev_allow_http_webhooks;
            let t_copy = trimmed_target.clone();
            let check_res =
                tokio::task::spawn_blocking(move || validate_webhook_url(&t_copy, allow_http))
                    .await
                    .map_err(|e| e.to_string())
                    .and_then(|r| r.map_err(|e| e.0));
            if let Err(msg) = check_res {
                return (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response();
            }
            target_url = trimmed_target;
        } else {
            let cid = trimmed_target
                .strip_prefix("telegram:")
                .unwrap_or(&trimmed_target)
                .trim();
            if !is_valid_telegram_chat_id(cid) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "Telegram target_url must be a numeric Chat ID (e.g. -1001234567890), @channel username, or HTTPS proxy URL" })),
                )
                    .into_response();
            }
            target_url = format!("telegram:{cid}");
        }
    } else {
        let target_copy = target_url.clone();
        let allow_http = state.config.dev_allow_http_webhooks;
        let check_res =
            tokio::task::spawn_blocking(move || validate_webhook_url(&target_copy, allow_http))
                .await
                .map_err(|e| e.to_string())
                .and_then(|r| r.map_err(|e| e.0));
        if let Err(msg) = check_res {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response();
        }
    }

    let rule = NewAlertRule {
        project_id: req.project_id,
        name: req.name.trim().to_string(),
        trigger_type: req.trigger_type,
        threshold_count: req.threshold_count.unwrap_or(1).max(1),
        window_sec: req.window_sec.unwrap_or(60).clamp(10, 86400),
        cooldown_sec: req.cooldown_sec.unwrap_or(300).clamp(10, 86400),
        channel_type: req.channel_type,
        target_url,
        webhook_secret,
        email_to,
    };
    let payload_val = json!({
        "project_id": rule.project_id,
        "name": rule.name,
        "trigger_type": rule.trigger_type,
        "channel_type": rule.channel_type,
        "target_url": rule.target_url,
        "email_to": rule.email_to,
    });
    let idem = match check_idempotency(&state, &ctx, &headers, "create_alert", &payload_val).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let (status_code, body_str) = match state.storage.create_alert_rule(&ctx, &rule).await {
        Ok(created) => {
            record_audit(
                &state,
                &ctx,
                &ext,
                "alert.created",
                "alert_rule",
                &created.id.to_string(),
                json!({ "name": created.name, "trigger": created.trigger_type, "channel": created.channel_type }),
            )
            .await;
            (
                StatusCode::CREATED,
                serde_json::to_string(&created).unwrap_or_else(|_| "{}".into()),
            )
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            serde_json::to_string(&json!({ "error": e })).unwrap_or_else(|_| "{}".into()),
        ),
    };
    if let Some((k, _)) = idem {
        let _ = state
            .storage
            .finish_idempotency(&ctx, "create_alert", &k, status_code.as_u16(), &body_str)
            .await;
    }
    (
        status_code,
        [(header::CONTENT_TYPE, "application/json")],
        body_str,
    )
        .into_response()
}

pub async fn delete_alert(
    State(state): State<Arc<AppState>>,
    Path((org, rule_id)): Path<(String, i64)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "project:write") {
        return *r;
    }
    if !ctx.role.can_write_project() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    match state.storage.delete_alert_rule(&ctx, rule_id).await {
        Ok(true) => {
            record_audit(
                &state,
                &ctx,
                &ext,
                "alert.deleted",
                "alert_rule",
                &rule_id.to_string(),
                json!({}),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Rule not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn test_alert(
    State(state): State<Arc<AppState>>,
    Path((org, rule_id)): Path<(String, i64)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "project:write") {
        return *r;
    }
    if !ctx.role.can_write_project() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    let (rule, webhook_secret) = match state
        .storage
        .get_alert_rule_for_dispatch(&ctx, rule_id)
        .await
    {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Rule not found" })),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e })),
            )
                .into_response()
        }
    };
    let job = AlertDispatchJob {
        organization_id: ctx.organization_id,
        rule_id: rule.id,
        rule_name: rule.name,
        channel_type: rule.channel_type,
        target_url: rule.target_url,
        webhook_secret,
        email_to: rule.email_to,
        title: "Test alert from Bug-Finder".into(),
        message: "Verification test payload".into(),
        level: "info".into(),
        project_slug: org,
        short_id: Some("TEST-1".into()),
    };
    match dispatch_alert(state.config.clone(), job).await {
        Ok(()) => Json(json!({ "sent": true })).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn list_api_tokens(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, None).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_session_only(&ctx) {
        return *r;
    }
    match state.storage.list_api_tokens(&ctx).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct CreateTokenReq {
    pub name: String,
    pub role: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub expires_in_days: Option<i64>,
}

pub async fn create_api_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
    Json(req): Json<CreateTokenReq>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, None).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_session_only(&ctx) {
        return *r;
    }
    if !ctx.role.can_manage_org() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Requires owner/manager/admin role" })),
        )
            .into_response();
    }
    if let Err(r) = require_step_up(&ctx) {
        return *r;
    }
    let requested_role = req
        .role
        .as_deref()
        .and_then(UserRole::from_db)
        .unwrap_or(UserRole::Member);
    // Prevent privilege escalation: cannot mint token with higher role than actor
    if requested_role.rank() > ctx.role.rank() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Cannot mint token with higher privilege" })),
        )
            .into_response();
    }

    let effective_scopes = if let Some(ref raw_list) = req.scopes {
        let joined = raw_list.join(" ");
        let filtered = intersect_scopes(requested_role, &joined);
        if filtered.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "At least one valid scope permitted by the token role is required" })),
            )
                .into_response();
        }
        filtered
    } else {
        requested_role
            .default_scopes()
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    };
    let scopes_str = effective_scopes.join(" ");
    let now_sec = chrono::Utc::now().timestamp();
    let expires_at = req
        .expires_in_days
        .filter(|&d| d > 0)
        .map(|d| now_sec + d.clamp(1, 365) * 86400);

    let payload_val = json!({
        "name": req.name,
        "role": requested_role.as_str(),
        "scopes": scopes_str,
        "expires_in_days": req.expires_in_days,
    });
    let idem =
        match check_idempotency(&state, &ctx, &headers, "create_api_token", &payload_val).await {
            Ok(v) => v,
            Err(r) => return *r,
        };

    let (plaintext, prefix, sha) = generate_api_token();
    let token_input = NewApiTokenInput {
        name: req.name.trim(),
        token_sha256: &sha,
        token_prefix: &prefix,
        role: requested_role,
        scopes: &scopes_str,
        expires_at,
    };
    let (status_code, body_str, replay_safe_str) =
        match state.storage.create_api_token(&ctx, &token_input).await {
            Ok(dto) => {
                record_audit(
                    &state,
                    &ctx,
                    &ext,
                    "api_token.created",
                    "api_token",
                    &dto.id.to_string(),
                    json!({ "role": dto.role, "scopes": dto.scopes, "expires_at": dto.expires_at }),
                )
                .await;
                (
                    StatusCode::CREATED,
                    serde_json::to_string(&json!({ "token": plaintext, "meta": dto })).unwrap(),
                    serde_json::to_string(
                        &json!({ "token": "[REDACTED_ON_REPLAY]", "meta": dto, "replayed": true }),
                    )
                    .unwrap(),
                )
            }
            Err(e) => {
                let err_s = serde_json::to_string(&json!({ "error": e })).unwrap();
                (StatusCode::BAD_REQUEST, err_s.clone(), err_s)
            }
        };
    if let Some((k, _)) = idem {
        let _ = state
            .storage
            .finish_idempotency(
                &ctx,
                "create_api_token",
                &k,
                status_code.as_u16(),
                &replay_safe_str,
            )
            .await;
    }
    (
        status_code,
        [(header::CONTENT_TYPE, "application/json")],
        body_str,
    )
        .into_response()
}

pub async fn delete_api_token(
    State(state): State<Arc<AppState>>,
    Path(token_id): Path<i64>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, None).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_session_only(&ctx) {
        return *r;
    }
    if !ctx.role.can_manage_org() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    if let Err(r) = require_step_up(&ctx) {
        return *r;
    }
    match state.storage.get_api_token_role(&ctx, token_id).await {
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Token not found" })),
            )
                .into_response();
        }
        Ok(Some(token_role))
            if token_role.rank() > ctx.role.rank()
                || (token_role == UserRole::Owner && ctx.role != UserRole::Owner) =>
        {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "Cannot revoke token with higher privilege than your own" })),
            )
                .into_response();
        }
        Ok(Some(_)) => {}
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e })),
            )
                .into_response();
        }
    }
    match state.storage.delete_api_token(&ctx, token_id).await {
        Ok(true) => {
            state.api_token_cache.invalidate_org(ctx.organization_id);
            record_audit(
                &state,
                &ctx,
                &ext,
                "api_token.deleted",
                "api_token",
                &token_id.to_string(),
                json!({}),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Token not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn list_members(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "member:read") {
        return *r;
    }
    match state.storage.list_members(&ctx).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct InviteMemberReq {
    pub email: String,
    pub name: String,
    pub password: String,
    pub role: String,
}

pub async fn invite_member(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
    Json(req): Json<InviteMemberReq>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "member:write") {
        return *r;
    }
    if !ctx.role.can_manage_org() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Requires owner, manager, or admin role" })),
        )
            .into_response();
    }
    let Some(target_role) = UserRole::from_db(&req.role) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid role" })),
        )
            .into_response();
    };
    if target_role.rank() > ctx.role.rank()
        || (target_role == UserRole::Owner && ctx.role != UserRole::Owner)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Cannot assign higher role than your own" })),
        )
            .into_response();
    }
    if let Err(msg) = validate_password_strength(&req.password, &req.email, &req.name) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response();
    }
    let clean_email = req.email.trim().to_ascii_lowercase();
    let idem_payload = json!({
        "email": clean_email,
        "role": target_role.as_str(),
    });
    let idem = match check_idempotency(&state, &ctx, &headers, "invite_member", &idem_payload).await
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Ok(pw_hash) = hash_password(req.password).await else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Hash failed" })),
        )
            .into_response();
    };
    let (status_code, body_str) = match state
        .storage
        .invite_member(
            &ctx,
            req.email.trim(),
            req.name.trim(),
            &pw_hash,
            target_role,
        )
        .await
    {
        Ok(m) => {
            record_audit(
                &state,
                &ctx,
                &ext,
                "member.invited",
                "user",
                &m.user_id.to_string(),
                json!({ "email": m.email, "role": m.role }),
            )
            .await;
            (StatusCode::CREATED, serde_json::to_string(&m).unwrap())
        }
        Err(e) if e == "ALREADY_MEMBER" => (
            StatusCode::CONFLICT,
            serde_json::to_string(
                &json!({ "error": "User is already a member of this organization" }),
            )
            .unwrap(),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            serde_json::to_string(&json!({ "error": e })).unwrap(),
        ),
    };
    if let Some((k, _)) = idem {
        let _ = state
            .storage
            .finish_idempotency(&ctx, "invite_member", &k, status_code.as_u16(), &body_str)
            .await;
    }
    (
        status_code,
        [(header::CONTENT_TYPE, "application/json")],
        body_str,
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct UpdateMemberRoleReq {
    pub role: String,
}

pub async fn update_member_role(
    State(state): State<Arc<AppState>>,
    Path((org, target_uid)): Path<(String, i64)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
    Json(req): Json<UpdateMemberRoleReq>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "member:admin") {
        return *r;
    }
    if !ctx.role.can_manage_org() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    if ctx.user_id == Some(target_uid) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Cannot modify your own role" })),
        )
            .into_response();
    }
    let Some(target_role) = UserRole::from_db(&req.role) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid role" })),
        )
            .into_response();
    };
    let members = state.storage.list_members(&ctx).await.unwrap_or_default();
    let target_is_owner = members
        .iter()
        .find(|m| m.user_id == target_uid)
        .map(|m| m.role == "owner")
        .unwrap_or(false);
    if target_role == UserRole::Owner || target_is_owner || target_role.rank() > ctx.role.rank() {
        if ctx.role != UserRole::Owner {
            return (StatusCode::FORBIDDEN, Json(json!({ "error": "Only owners can grant or modify owner/higher privilege roles" }))).into_response();
        }
        if let Err(r) = require_step_up(&ctx) {
            return *r;
        }
    }
    match state
        .storage
        .update_member_role(&ctx, target_uid, target_role)
        .await
    {
        Ok(Ok(dto)) => {
            state.api_token_cache.invalidate_user(target_uid);
            record_audit(
                &state,
                &ctx,
                &ext,
                "member.role_updated",
                "user",
                &target_uid.to_string(),
                json!({ "role": dto.role }),
            )
            .await;
            Json(dto).into_response()
        }
        Ok(Err(msg)) => (StatusCode::CONFLICT, Json(json!({ "error": msg }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn remove_member(
    State(state): State<Arc<AppState>>,
    Path((org, target_uid)): Path<(String, i64)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "member:admin") {
        return *r;
    }
    if !ctx.role.can_manage_org() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    let members = state.storage.list_members(&ctx).await.unwrap_or_default();
    let target_is_owner = members
        .iter()
        .find(|m| m.user_id == target_uid)
        .map(|m| m.role == "owner")
        .unwrap_or(false);
    if target_is_owner {
        if ctx.role != UserRole::Owner {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "Only owners can remove another owner" })),
            )
                .into_response();
        }
        if let Err(r) = require_step_up(&ctx) {
            return *r;
        }
    }
    match state.storage.remove_member(&ctx, target_uid).await {
        Ok(Ok(true)) => {
            state.api_token_cache.invalidate_user(target_uid);
            record_audit(
                &state,
                &ctx,
                &ext,
                "member.removed",
                "user",
                &target_uid.to_string(),
                json!({ "sessions_tokens_revoked": true }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Ok(false)) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Member not found" })),
        )
            .into_response(),
        Ok(Err(msg)) => (StatusCode::CONFLICT, Json(json!({ "error": msg }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

// ----------------------------------------------------------------------------
// Self-Check & Internal Error Monitoring
// ----------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
pub struct RunProbeReq {
    #[serde(default = "default_true")]
    pub send_test_log: bool,
}

#[derive(Deserialize)]
pub struct ClientSelfErrorReq {
    pub message: String,
    #[serde(default)]
    pub component: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
}

#[derive(Deserialize)]
pub struct AckSelfCheckReq {
    #[serde(default)]
    pub clear: bool,
}

pub async fn get_self_check(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "org:read") {
        return *r;
    }
    if !ctx.role.can_manage_org() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Requires manager, admin, or owner role" })),
        )
            .into_response();
    }
    let report = evaluate_self_check(&state, &ctx).await;
    Json(report).into_response()
}

pub async fn run_self_check_probe(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
    maybe_req: Option<Json<RunProbeReq>>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "event:write") {
        return *r;
    }
    if !ctx.role.can_manage_org() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Requires manager, admin, or owner role" })),
        )
            .into_response();
    }
    let send_test_log = maybe_req.map(|r| r.send_test_log).unwrap_or(true);
    let result = run_live_self_probe(&state, &ctx, send_test_log).await;
    Json(result).into_response()
}

pub async fn report_client_self_error(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
    Json(req): Json<ClientSelfErrorReq>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if !ctx.role.can_mutate_issues() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Viewers cannot submit UI self-check errors" })),
        )
            .into_response();
    }
    let decision = state.rate_limiter.check_and_record(
        "ui_self_err",
        &ctx.organization_id.to_string(),
        20,
        Duration::from_secs(60),
    );
    if !decision.allowed {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", decision.retry_after_sec.to_string())],
            Json(json!({ "error": "Rate limit exceeded" })),
        )
            .into_response();
    }
    let msg = req.message.trim();
    if msg.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "message is required" })),
        )
            .into_response();
    }
    let component = req
        .component
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("spa");
    let severity = req
        .severity
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("error");
    state.self_monitor.record_for_org(
        ctx.organization_id,
        "ui_client",
        severity,
        component,
        msg,
        req.detail.as_deref(),
    );
    state
        .metrics
        .self_errors_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    (StatusCode::ACCEPTED, Json(json!({ "accepted": true }))).into_response()
}

pub async fn ack_self_check_errors(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
    maybe_req: Option<Json<AckSelfCheckReq>>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "event:write") {
        return *r;
    }
    if !ctx.role.can_manage_org() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Requires manager, admin, or owner role" })),
        )
            .into_response();
    }
    let clear = maybe_req.map(|r| r.clear).unwrap_or(false);
    let include_global = ctx.role == UserRole::Owner;
    if clear {
        state
            .self_monitor
            .clear_for_org(ctx.organization_id, include_global);
    } else {
        state
            .self_monitor
            .acknowledge_for_org(ctx.organization_id, include_global);
    }
    let report = evaluate_self_check(&state, &ctx).await;
    Json(report).into_response()
}

// ----------------------------------------------------------------------------
// Anti-REA Shield Events, Quarantine & Cached Blocklist Feed
// ----------------------------------------------------------------------------

pub async fn list_shield_events(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "shield:read") {
        return *r;
    }
    let project_id = query.get("project_id").and_then(|s| s.parse::<i64>().ok());
    let limit = query
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    match state
        .storage
        .list_security_events(&ctx, project_id, limit)
        .await
    {
        Ok((events, summary)) => {
            Json(json!({ "summary": summary, "events": events })).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn list_shield_quarantine(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "shield:read") {
        return *r;
    }
    let project_id = query.get("project_id").and_then(|s| s.parse::<i64>().ok());
    match state.storage.list_quarantine(&ctx, project_id).await {
        Ok(entries) => Json(entries).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn delete_shield_quarantine(
    State(state): State<Arc<AppState>>,
    Path((org, entry_id)): Path<(String, i64)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "shield:write") {
        return *r;
    }
    if !ctx.role.can_write_project() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Requires admin or owner role" })),
        )
            .into_response();
    }
    match state.storage.delete_quarantine(&ctx, entry_id).await {
        Ok(true) => {
            record_audit(
                &state,
                &ctx,
                &ext,
                "shield.quarantine_deleted",
                "quarantine",
                &entry_id.to_string(),
                json!({}),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Quarantine entry not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn get_shield_blocklist(
    State(state): State<Arc<AppState>>,
    Path((org, proj)): Path<(String, String)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "shield:read") {
        return *r;
    }
    let projects = match state.storage.list_projects(&ctx).await {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e })),
            )
                .into_response()
        }
    };
    let Some(project) = projects.into_iter().find(|p| p.slug == proj) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Project not found" })),
        )
            .into_response();
    };
    let entries = match state.storage.list_quarantine(&ctx, Some(project.id)).await {
        Ok(e) => e,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e })),
            )
                .into_response()
        }
    };

    let compact: Vec<Value> = entries
        .iter()
        .map(|e| {
            json!({
                "subject_type": e.subject_type,
                "subject_hmac": e.subject_hmac,
                "reason": e.reason,
                "risk_score": e.risk_score,
                "expires_at": e.expires_at,
            })
        })
        .collect();
    let ip_hmac_key = if ctx.has_scope("shield:write") || ctx.role.can_manage_org() {
        json!(derive_project_ip_hmac_key(
            &state.config.app_key,
            project.id
        ))
    } else {
        Value::Null
    };
    let payload = json!({
        "project_id": project.id,
        "project_slug": project.slug,
        "ip_hmac_key": ip_hmac_key,
        "session_hash_alg": "sha256",
        "entries": compact,
    });
    let bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
    let etag = format!("\"{}\"", &sha256_hex(&bytes)[..24]);

    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|inm| inm.trim() == etag)
        .unwrap_or(false)
    {
        return (
            StatusCode::NOT_MODIFIED,
            [
                (header::ETAG, etag),
                (header::CACHE_CONTROL, "private, max-age=10".to_string()),
            ],
        )
            .into_response();
    }

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (header::ETAG, etag),
            (header::CACHE_CONTROL, "private, max-age=10".to_string()),
        ],
        bytes,
    )
        .into_response()
}

// ----------------------------------------------------------------------------
// Tamper-Evident Audit Logs, Org Security Settings & Expiring Invitations
// ----------------------------------------------------------------------------

pub async fn list_audit_logs(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "org:read") {
        return *r;
    }
    if !ctx.role.can_manage_org() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Requires owner, manager, or admin role" })),
        )
            .into_response();
    }
    let action_filter = query
        .get("action")
        .map(String::as_str)
        .filter(|s| !s.is_empty());
    let limit = query
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    let offset = query
        .get("offset")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0)
        .clamp(0, 100_000);
    match state
        .storage
        .list_audit_logs(&ctx, action_filter, limit, offset)
        .await
    {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn verify_audit_logs(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "org:read") {
        return *r;
    }
    if !ctx.role.can_manage_org() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Requires owner, manager, or admin role" })),
        )
            .into_response();
    }
    match state.storage.verify_audit_chain(&ctx).await {
        Ok(rep) => Json(rep).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn get_org_security_settings(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "org:read") {
        return *r;
    }
    match state.storage.get_org_security_settings(&ctx).await {
        Ok(s) => Json(s).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn update_org_security_settings(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
    Json(mut settings): Json<OrgSecuritySettings>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "org:write") {
        return *r;
    }
    if !ctx.role.can_manage_org() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Requires owner, manager, or admin role" })),
        )
            .into_response();
    }
    if let Err(r) = require_step_up(&ctx) {
        return *r;
    }
    settings.event_throttle_rate = settings.event_throttle_rate.min(100);
    if settings.require_mfa_for_admins {
        match state.storage.count_owners_without_mfa(&ctx).await {
            Ok(0) => {}
            Ok(n) => {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": format!("{n} owner account(s) have no MFA enabled; enable TOTP or Passkey on owner accounts first")
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": e })),
                )
                    .into_response()
            }
        }
    }
    match state
        .storage
        .update_org_security_settings(&ctx, &settings)
        .await
    {
        Ok(updated) => {
            state.dsn_auth_cache.invalidate_org(ctx.organization_id);
            record_audit(
                &state,
                &ctx,
                &ext,
                "org.security_settings_updated",
                "organization",
                &ctx.organization_id.to_string(),
                json!({
                    "scrub_ip_addresses": updated.scrub_ip_addresses,
                    "event_throttle_rate": updated.event_throttle_rate,
                    "require_mfa_for_admins": updated.require_mfa_for_admins,
                }),
            )
            .await;
            Json(updated).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn list_invitations(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "member:read") {
        return *r;
    }
    if !ctx.role.can_manage_org() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    match state.storage.list_invitations(&ctx).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct CreateInvitationReq {
    pub email: String,
    pub role: String,
}

pub async fn create_invitation(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
    Json(req): Json<CreateInvitationReq>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "member:write") {
        return *r;
    }
    if !ctx.role.can_manage_org() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    let clean_email = req.email.trim().to_ascii_lowercase();
    if clean_email.len() < 5
        || !clean_email.contains('@')
        || clean_email.contains(['\r', '\n', ' '])
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Valid email required" })),
        )
            .into_response();
    }
    let Some(target_role) = UserRole::from_db(&req.role) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid role" })),
        )
            .into_response();
    };
    if target_role.rank() > ctx.role.rank()
        || (target_role == UserRole::Owner && ctx.role != UserRole::Owner)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Cannot invite with higher privilege than your own" })),
        )
            .into_response();
    }
    let idem_payload = json!({
        "email": clean_email,
        "role": target_role.as_str(),
    });
    let idem =
        match check_idempotency(&state, &ctx, &headers, "create_invitation", &idem_payload).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    let raw_token = random_token_b64(32);
    let token_sha = sha256_hex(raw_token.as_bytes());
    let expires_at = chrono::Utc::now().timestamp() + 72 * 3600;
    let (status_code, body_str, replay_safe_str) = match state
        .storage
        .create_invitation(&ctx, &clean_email, target_role, &token_sha, expires_at)
        .await
    {
        Ok(inv) => {
            record_audit(
                &state,
                &ctx,
                &ext,
                "invitation.created",
                "org_invitation",
                &inv.id.to_string(),
                json!({ "email": inv.email, "role": inv.role, "expires_at": inv.expires_at }),
            )
            .await;
            (
                StatusCode::CREATED,
                serde_json::to_string(&json!({
                    "invitation": inv,
                    "token": raw_token,
                    "invite_url": format!("/invite/{raw_token}"),
                }))
                .unwrap(),
                serde_json::to_string(&json!({
                    "invitation": inv,
                    "token": "[REDACTED_ON_REPLAY]",
                    "invite_url": Value::Null,
                    "replayed": true,
                }))
                .unwrap(),
            )
        }
        Err(e) => {
            let err_s = serde_json::to_string(&json!({ "error": e })).unwrap();
            (StatusCode::BAD_REQUEST, err_s.clone(), err_s)
        }
    };
    if let Some((k, _)) = idem {
        let _ = state
            .storage
            .finish_idempotency(
                &ctx,
                "create_invitation",
                &k,
                status_code.as_u16(),
                &replay_safe_str,
            )
            .await;
    }
    (
        status_code,
        [(header::CONTENT_TYPE, "application/json")],
        body_str,
    )
        .into_response()
}

pub async fn revoke_invitation(
    State(state): State<Arc<AppState>>,
    Path((org, inv_id)): Path<(String, i64)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "member:write") {
        return *r;
    }
    if !ctx.role.can_manage_org() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    match state.storage.revoke_invitation(&ctx, inv_id).await {
        Ok(true) => {
            record_audit(
                &state,
                &ctx,
                &ext,
                "invitation.revoked",
                "org_invitation",
                &inv_id.to_string(),
                json!({}),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Invitation not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn get_sdk_meta(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    if let Err(r) = authenticate_api_tenant(&state, &headers, &ext, &method, None).await {
        return *r;
    }
    let (mini_sri, shield_sri) = crate::http::router::sdk_sri_hashes();
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "mini_sdk_sri": mini_sri,
        "shield_sdk_sri": shield_sri,
        "public_url": state.config.public_url,
    }))
    .into_response()
}

pub async fn send_project_test_event(
    State(state): State<Arc<AppState>>,
    Path((org, proj)): Path<(String, String)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "event:write") {
        return *r;
    }
    if !ctx.role.can_mutate_issues() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Viewers cannot send test events" })),
        )
            .into_response();
    }
    let client_ip = ext
        .get::<ClientIp>()
        .map(|c| c.0)
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let bucket_key = format!("{}:{}", ctx.organization_id, client_ip);
    let dec = state.rate_limiter.check_and_record(
        "project_test_event",
        &bucket_key,
        10,
        Duration::from_secs(60),
    );
    if !dec.allowed {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "Too many test events; wait a moment", "retry_after": dec.retry_after_sec })),
        )
            .into_response();
    }

    let projects = match state.storage.list_projects(&ctx).await {
        Ok(list) => list,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e })),
            )
                .into_response()
        }
    };
    let Some(project) = projects.into_iter().find(|p| p.slug == proj) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Project not found" })),
        )
            .into_response();
    };

    let event_id = uuid::Uuid::new_v4().simple().to_string();
    let now_s = chrono::Utc::now().timestamp() as f64;
    let payload = json!({
        "event_id": event_id,
        "timestamp": now_s,
        "platform": if project.platform.is_empty() { "other" } else { project.platform.as_str() },
        "level": "info",
        "environment": "onboarding",
        "culprit": "bugfinder::wizard::test_event",
        "exception": {
            "values": [{
                "type": "BugFinderOnboardingTest",
                "value": format!("Connection verified for {}", project.name),
                "stacktrace": {
                    "frames": [{
                        "filename": "onboarding/wizard.rs",
                        "function": "send_project_test_event",
                        "lineno": 1,
                        "in_app": true
                    }]
                }
            }]
        }
    });
    let meta = crate::domain::fingerprint::extract_issue_metadata(&payload);
    let payload_json = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
    let received_ms = now_ms();
    let auth = ProjectAuthInfo {
        project_id: project.id,
        organization_id: ctx.organization_id,
        organization_slug: ctx.organization_slug.clone(),
        project_slug: project.slug.clone(),
        first_event_at: project.first_event_at,
        rate_limit_per_min: 1000,
        filters: project.filters,
        org_scrub_ip_addresses: false,
        org_event_throttle_rate: 0,
    };

    let live_ev = LiveStreamEvent {
        organization_id: ctx.organization_id,
        project_id: project.id,
        kind: "issue".into(),
        level: meta.level.clone(),
        title_or_body: meta.title.clone(),
        service: project.slug.clone(),
        environment: meta.environment.clone(),
        trace_id: meta.trace_id.clone(),
        timestamp_ms: received_ms,
        payload: json!({
            "event_id": event_id,
            "culprit": meta.culprit,
            "release": meta.release,
        }),
    };

    if state
        .batch_writer
        .try_enqueue(crate::storage::IngestWriteItem::Event {
            auth: Box::new(auth),
            meta: Box::new(meta),
            payload_json,
            received_ms,
        })
        .is_err()
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "Ingestion queue saturated" })),
        )
            .into_response();
    }

    state
        .metrics
        .ingest_events_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let _ = state.live_tx.send(live_ev);

    (
        StatusCode::ACCEPTED,
        Json(json!({
            "ok": true,
            "event_id": event_id,
            "project_id": project.id,
        })),
    )
        .into_response()
}

pub async fn get_project_ai_blueprint(
    State(state): State<Arc<AppState>>,
    Path((org, proj)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &ext, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    if let Err(r) = require_scope(&ctx, "project:read") {
        return *r;
    }
    let projects = match state.storage.list_projects(&ctx).await {
        Ok(list) => list,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e })),
            )
                .into_response()
        }
    };
    let Some(project) = projects.into_iter().find(|p| p.slug == proj) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Project not found" })),
        )
            .into_response();
    };

    let base_url = state
        .config
        .public_url
        .as_deref()
        .map(|u| u.trim_end_matches('/').to_string())
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| {
            let host = headers
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("127.0.0.1:8080")
                .trim();
            let peer_ip = ext
                .get::<PeerIp>()
                .map(|p| p.0)
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
            let scheme =
                if crate::security::headers::is_https_request(&headers, peer_ip, &state.config) {
                    "https"
                } else {
                    "http"
                };
            format!("{scheme}://{host}")
        });

    let key = project
        .dsn_public_key
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("<PUBLIC_KEY>");
    let dsn = if let Some((scheme, rest)) = base_url.split_once("://") {
        format!("{scheme}://{key}@{rest}/{}", project.id)
    } else {
        format!("https://{key}@bugs.example.com/{}", project.id)
    };
    let stack = crate::ai_blueprint::normalize_stack(
        query.get("stack").map(String::as_str).unwrap_or("auto"),
    );
    let app_url = query.get("app_url").map(String::as_str);
    let (mini_sri, shield_sri) = crate::http::router::sdk_sri_hashes();
    let prompt = crate::ai_blueprint::render_project_ai_blueprint(
        &crate::ai_blueprint::ProjectBlueprintParams {
            base_url: &base_url,
            org_slug: &ctx.organization_slug,
            project_slug: &project.slug,
            project_id: project.id,
            dsn: &dsn,
            tunnel_slug: project.tunnel_slug.as_deref(),
            app_url,
            stack,
            mini_sdk_sri: mini_sri,
            shield_sdk_sri: shield_sri,
        },
    );
    let app_url_display = app_url
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("https://app.example.com");
    let check_command = format!("bugfinder check --dsn \"{dsn}\" --app-url \"{app_url_display}\"");
    let shell_command =
        format!("./scripts/check.sh --dsn \"{dsn}\" --app-url \"{app_url_display}\"");
    let org_clean = crate::ai_blueprint::sanitize_slug(&ctx.organization_slug);
    let proj_clean = crate::ai_blueprint::sanitize_slug(&project.slug);
    let tunnel_ep = project
        .tunnel_slug
        .as_deref()
        .map(|t| format!("{base_url}/t/{}", crate::ai_blueprint::sanitize_slug(t)));

    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store, private")],
        Json(json!({
            "project_id": project.id,
            "org_slug": org_clean,
            "project_slug": proj_clean,
            "stack": stack,
            "dsn": dsn,
            "base_url": base_url,
            "check_command": check_command,
            "shell_command": shell_command,
            "prompt": prompt,
            "endpoints": {
                "health": format!("{base_url}/api/health"),
                "llms_txt": format!("{base_url}/llms.txt"),
                "mini_sdk": format!("{base_url}/sdk/bugfinder-mini.js"),
                "shield_sdk": format!("{base_url}/sdk/bugfinder-shield.js"),
                "envelope": format!("{base_url}/api/{}/envelope/", project.id),
                "tunnel": tunnel_ep,
                "otlp_logs": format!("{base_url}/api/{}/otlp/v1/logs", project.id),
                "shield": format!("{base_url}/api/{}/shield/", project.id),
                "blocklist": format!("{base_url}/api/0/projects/{org_clean}/{proj_clean}/shield/blocklist/"),
                "sourcemaps": format!("{base_url}/api/0/projects/{org_clean}/{proj_clean}/releases/<RELEASE>/sourcemaps/"),
            }
        })),
    )
        .into_response()
}
