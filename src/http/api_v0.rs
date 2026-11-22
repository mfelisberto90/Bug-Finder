use crate::alerts::dispatcher::{dispatch_alert, AlertDispatchJob};
use crate::domain::models::*;
use crate::http::auth_routes::{resolve_request_session, sanitize_slug, verify_csrf_for_session};
use crate::security::auth::{
    canonical_json_sha256, generate_api_token, generate_dsn_public_key, hash_password,
    random_token_b64, sha256_hex,
};
use crate::security::csv::sanitize_csv_cell;
use crate::security::ssrf::validate_webhook_url;
use crate::selfcheck::{evaluate_self_check, run_live_self_probe};
use crate::storage::{IdempotencyCheck, IssueQueryParams, LogQueryParams, NewAlertRule};
use crate::AppState;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::stream::Stream;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

async fn authenticate_api_tenant(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    org_slug_opt: Option<&str>,
) -> Result<TenantCtx, Response> {
    if let Some(auth_hdr) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(tok) = auth_hdr
            .strip_prefix("Bearer ")
            .or_else(|| auth_hdr.strip_prefix("bearer "))
        {
            let sha = sha256_hex(tok.trim().as_bytes());
            if let Ok(Some(ctx)) = state.storage.resolve_api_token(&sha, org_slug_opt).await {
                return Ok(ctx);
            }
            return Err((StatusCode::UNAUTHORIZED, Json(json!({ "error": "Invalid API token" }))).into_response());
        }
    }

    let Some(sess) = resolve_request_session(state, headers).await else {
        return Err((StatusCode::UNAUTHORIZED, Json(json!({ "error": "Authentication required" }))).into_response());
    };

    if matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) && !verify_csrf_for_session(&sess, headers)
    {
        return Err((StatusCode::FORBIDDEN, Json(json!({ "error": "Invalid CSRF token" }))).into_response());
    }

    if let Some(want_slug) = org_slug_opt {
        if sess.organization_slug == want_slug {
            return Ok(TenantCtx {
                organization_id: sess.organization_id,
                organization_slug: sess.organization_slug,
                user_id: Some(sess.user_id),
                role: sess.role,
            });
        }
        return match state.storage.resolve_tenant_for_user(sess.user_id, want_slug).await {
            Ok(Some(ctx)) => Ok(ctx),
            _ => Err((StatusCode::NOT_FOUND, Json(json!({ "error": "Organization not found" }))).into_response()),
        };
    }

    Ok(TenantCtx {
        organization_id: sess.organization_id,
        organization_slug: sess.organization_slug,
        user_id: Some(sess.user_id),
        role: sess.role,
    })
}

async fn check_idempotency(
    state: &AppState,
    ctx: &TenantCtx,
    headers: &HeaderMap,
    action: &str,
    payload: &Value,
) -> Result<Option<(String, String)>, Response> {
    let Some(raw_key) = headers.get("idempotency-key").and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    let key = raw_key.trim();
    if key.is_empty() || key.len() > 128 {
        return Err((StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid Idempotency-Key" }))).into_response());
    }
    let payload_sha = canonical_json_sha256(payload);
    match state.storage.begin_idempotency(ctx, action, key, &payload_sha).await {
        Ok(IdempotencyCheck::Proceed) => Ok(Some((key.to_string(), payload_sha))),
        Ok(IdempotencyCheck::Replay { status_code, body }) => {
            let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::OK);
            let mut resp = (status, [(header::CONTENT_TYPE, "application/json")], body).into_response();
            resp.headers_mut()
                .insert("x-idempotent-replay", HeaderValue::from_static("true"));
            Err(resp)
        }
        Ok(IdempotencyCheck::Conflict(msg)) => {
            Err((StatusCode::CONFLICT, Json(json!({ "error": msg }))).into_response())
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response()),
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
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, None).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Some(uid) = ctx.user_id else {
        return Json(json!([])).into_response();
    };
    match state.storage.list_user_organizations(uid).await {
        Ok(orgs) => Json(orgs).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn list_projects(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match state.storage.list_projects(&ctx).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
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
    method: Method,
    Json(req): Json<CreateProjectReq>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !ctx.role.can_write_project() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Requires admin or owner role" }))).into_response();
    }
    let slug = sanitize_slug(req.slug.as_deref().unwrap_or(&req.name));
    if req.name.trim().is_empty() || slug.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid project name/slug" }))).into_response();
    }
    let platform = req.platform.unwrap_or_else(|| "other".into());
    let dsn_pub = generate_dsn_public_key();
    let dsn_sha = sha256_hex(dsn_pub.as_bytes());
    match state
        .storage
        .create_project(&ctx, req.name.trim(), &slug, &platform, &dsn_pub, &dsn_sha)
        .await
    {
        Ok(p) => (StatusCode::CREATED, Json(p)).into_response(),
        Err(e) => (StatusCode::CONFLICT, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn update_project_settings(
    State(state): State<Arc<AppState>>,
    Path((org, proj)): Path<(String, String)>,
    headers: HeaderMap,
    method: Method,
    Json(filters): Json<ProjectFilters>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !ctx.role.can_write_project() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Requires admin or owner role" }))).into_response();
    }
    match state.storage.update_project_filters(&ctx, &proj, &filters).await {
        Ok(Some(dto)) => Json(dto).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({ "error": "Project not found" }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn list_project_keys(
    State(state): State<Arc<AppState>>,
    Path((org, proj)): Path<(String, String)>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match state.storage.list_project_keys(&ctx, &proj).await {
        Ok(keys) => Json(keys).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
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
    method: Method,
    Json(req): Json<CreateKeyReq>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
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
        Ok(Some(k)) => (StatusCode::CREATED, Json(k)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({ "error": "Project not found" }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn delete_project_key(
    State(state): State<Arc<AppState>>,
    Path((org, proj, key_id)): Path<(String, String, i64)>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !ctx.role.can_write_project() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    match state.storage.delete_project_key(&ctx, &proj, key_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, Json(json!({ "error": "Key not found" }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn enable_project_tunnel(
    State(state): State<Arc<AppState>>,
    Path((org, proj)): Path<(String, String)>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !ctx.role.can_write_project() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    let slug = random_token_b64(10).to_ascii_lowercase();
    match state.storage.enable_project_tunnel(&ctx, &proj, &slug).await {
        Ok(Some(s)) => Json(json!({ "tunnel_slug": s, "path": format!("/t/{s}") })).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({ "error": "Project not found" }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

// ----------------------------------------------------------------------------
// Issues, Events, Export CSV & Stats v2 (RoleLane + GlitchTip Compatible)
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
    }
}

pub async fn list_issues(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let params = parse_issue_query(&query);
    match state.storage.list_issues(&ctx, &params).await {
        Ok((items, total_hits)) => {
            let mut resp = Json(items).into_response();
            if let Ok(v) = HeaderValue::from_str(&total_hits.to_string()) {
                resp.headers_mut().insert("x-hits", v);
            }
            resp
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn get_issue(
    State(state): State<Arc<AppState>>,
    Path((org, issue_id)): Path<(String, i64)>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match state.storage.get_issue(&ctx, issue_id).await {
        Ok(Some(i)) => Json(i).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({ "error": "Issue not found" }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
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
    method: Method,
    Json(req): Json<UpdateIssueReq>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !ctx.role.can_mutate_issues() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Viewers cannot mutate issues" }))).into_response();
    }
    let Some(status) = IssueStatus::from_str_opt(&req.status) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid status" }))).into_response();
    };
    let payload_val = json!({
        "issue_id": issue_id,
        "status": req.status,
        "resolved_in_release": req.resolved_in_release,
    });
    let idem = match check_idempotency(&state, &ctx, &headers, "update_issue", &payload_val).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let (status_code, body_str) = match state
        .storage
        .update_issue_status(&ctx, issue_id, status, req.resolved_in_release.as_deref())
        .await
    {
        Ok(Some(updated)) => (
            StatusCode::OK,
            serde_json::to_string(&updated).unwrap_or_else(|_| "{}".into()),
        ),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            serde_json::to_string(&json!({ "error": "Issue not found" })).unwrap(),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::to_string(&json!({ "error": e })).unwrap(),
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
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match state.storage.list_issue_events(&ctx, issue_id, 25).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn get_issue_event(
    State(state): State<Arc<AppState>>,
    Path((org, issue_id, ev_id)): Path<(String, i64, String)>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match state.storage.get_issue_event(&ctx, issue_id, &ev_id).await {
        Ok(Some(ev)) => Json(ev).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({ "error": "Event not found" }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn export_issues_csv(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut params = parse_issue_query(&query);
    params.limit = 200;
    let (items, _) = match state.storage.list_issues(&ctx, &params).await {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    };
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
            (header::CONTENT_DISPOSITION, "attachment; filename=\"issues-export.csv\""),
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
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let category = query.get("category").map(String::as_str).unwrap_or("error");
    let until_ms = now_ms();
    let since_ms = parse_stats_period_ms(query.get("statsPeriod").map(String::as_str))
        .unwrap_or(until_ms - 86_400_000);
    match state.storage.get_stats_v2(&ctx, category, since_ms, until_ms).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
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
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let project_ids = query
        .get("project")
        .map(|s| s.split(',').filter_map(|p| p.trim().parse::<i64>().ok()).collect())
        .unwrap_or_default();
    let level_list = query
        .get("level")
        .map(|s| {
            s.split(',')
                .map(|l| LogLevel::from_str_loose(l).num())
                .collect()
        })
        .unwrap_or_default();
    let params = LogQueryParams {
        project_ids,
        min_level_num: query
            .get("minLevel")
            .map(|l| LogLevel::from_str_loose(l).num()),
        level_list,
        service: query.get("service").cloned().filter(|s| !s.is_empty()),
        environment: query.get("environment").cloned().filter(|s| !s.is_empty()),
        host: query.get("host").cloned().filter(|s| !s.is_empty()),
        trace_id: query
            .get("traceId")
            .or_else(|| query.get("trace_id"))
            .cloned()
            .filter(|s| !s.is_empty()),
        search_query: query.get("query").cloned().filter(|s| !s.is_empty()),
        start_ms: parse_stats_period_ms(query.get("statsPeriod").map(String::as_str)),
        end_ms: None,
        cursor_id: query.get("cursor").cloned().filter(|s| !s.is_empty()),
        limit: query
            .get("limit")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(100),
    };
    match state.storage.query_logs(&ctx, &params).await {
        Ok(logs) => Json(logs).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn stream_logs_sse(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
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
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)).text("ping"))
        .into_response()
}

pub async fn list_log_resources(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match state.storage.list_log_resources(&ctx).await {
        Ok(res) => Json(res).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn get_log_stats(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let until = now_ms();
    let since = parse_stats_period_ms(query.get("statsPeriod").map(String::as_str))
        .unwrap_or(until - 86_400_000);
    match state.storage.get_log_stats(&ctx, since, until).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
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
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let since = parse_stats_period_ms(query.get("statsPeriod").map(String::as_str))
        .unwrap_or_else(|| now_ms() - 86_400_000);
    match state.storage.list_transactions(&ctx, since).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn get_trace_context(
    State(state): State<Arc<AppState>>,
    Path((org, trace_id)): Path<(String, String)>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match state.storage.get_trace_context(&ctx, &trace_id).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn list_releases(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match state.storage.list_releases(&ctx).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn upload_sourcemap(
    State(state): State<Arc<AppState>>,
    Path((org, proj, version)): Path<(String, String, String)>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    method: Method,
    body: Bytes,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !ctx.role.can_mutate_issues() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    if body.len() > 10 * 1024 * 1024 {
        return (StatusCode::PAYLOAD_TOO_LARGE, Json(json!({ "error": "Source map exceeds 10 MiB" }))).into_response();
    }
    let val: Value = match serde_json::from_slice::<Value>(&body) {
        Ok(v) if v.get("version").and_then(|x| x.as_u64()) == Some(3) && v.get("mappings").is_some() => v,
        _ => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid SourceMap v3 JSON" }))).into_response(),
    };
    let filename = query
        .get("filename")
        .map(|s| s.rsplit('/').next().unwrap_or(s).to_string())
        .filter(|s| !s.is_empty() && !s.contains(".."))
        .unwrap_or_else(|| "bundle.js.map".into());
    let debug_id = query
        .get("debug_id")
        .cloned()
        .or_else(|| val.get("debugId").and_then(|v| v.as_str()).map(ToString::to_string))
        .unwrap_or_default();

    let blob_sha = sha256_hex(&body);
    let dir = state.config.sourcemaps_dir();
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))).into_response();
    }
    let target_path = dir.join(&blob_sha);
    if !target_path.exists() {
        let tmp_path = dir.join(format!(".{blob_sha}.tmp"));
        let bytes_vec = body.to_vec();
        let write_res = tokio::task::spawn_blocking(move || -> Result<(), String> {
            use std::io::Write;
            #[cfg(unix)]
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.create(true).write(true).truncate(true);
            #[cfg(unix)]
            opts.mode(0o600);
            let mut f = opts.open(&tmp_path).map_err(|e| e.to_string())?;
            f.write_all(&bytes_vec).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
            std::fs::rename(&tmp_path, &target_path).map_err(|e| e.to_string())?;
            Ok(())
        })
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r);
        if let Err(e) = write_res {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response();
        }
    }

    match state
        .storage
        .save_source_map(&ctx, &proj, &version, &debug_id, &filename, &blob_sha, body.len() as i64)
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
// Uptime Monitors & RoleLane Heartbeat Check
// ----------------------------------------------------------------------------

pub async fn list_monitors(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match state.storage.list_monitors(&ctx).await {
        Ok(m) => Json(m).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
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
    method: Method,
    Json(req): Json<CreateMonitorReq>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !ctx.role.can_write_project() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    let uuid = uuid::Uuid::new_v4().to_string();
    let interval = req.expected_interval_sec.unwrap_or(60).clamp(10, 86400);
    match state
        .storage
        .create_monitor(&ctx, req.project_id, req.name.trim(), &uuid, interval)
        .await
    {
        Ok(m) => (StatusCode::CREATED, Json(m)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn delete_monitor(
    State(state): State<Arc<AppState>>,
    Path((org, mon_id)): Path<(String, i64)>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !ctx.role.can_write_project() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    match state.storage.delete_monitor(&ctx, mon_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, Json(json!({ "error": "Monitor not found" }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

/// Compatible with GlitchTipReadClient.php `GET /api/0/organizations/{org}/heartbeat_check/{uuid}/`
pub async fn get_heartbeat_check(
    State(state): State<Arc<AppState>>,
    Path((org, uuid)): Path<(String, String)>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match state.storage.get_heartbeat(&ctx, &uuid).await {
        Ok(Some(m)) => Json(m).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({ "error": "Monitor not found" }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn post_heartbeat_check(
    State(state): State<Arc<AppState>>,
    Path((org, uuid)): Path<(String, String)>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match state.storage.record_heartbeat(&ctx, &uuid, true, "OK").await {
        Ok(Some(m)) => Json(m).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({ "error": "Monitor not found" }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

// ----------------------------------------------------------------------------
// Alert Rules, API Tokens & Members (RBAC + Anti-Last-Owner)
// ----------------------------------------------------------------------------

pub async fn list_alerts(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match state.storage.list_alert_rules(&ctx).await {
        Ok(rules) => Json(rules).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
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
    method: Method,
    Json(req): Json<CreateAlertReq>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !ctx.role.can_write_project() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Requires admin or owner role" }))).into_response();
    }
    if !matches!(
        req.trigger_type.as_str(),
        "new_issue" | "regression" | "threshold" | "fatal_log" | "uptime_down"
    ) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid trigger_type" }))).into_response();
    }
    if !matches!(
        req.channel_type.as_str(),
        "webhook" | "slack" | "discord" | "email"
    ) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid channel_type" }))).into_response();
    }
    let target_url = req.target_url.unwrap_or_default();
    if req.channel_type != "email" {
        if let Err(e) = validate_webhook_url(&target_url, state.config.dev_allow_http_webhooks) {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.0 }))).into_response();
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
        webhook_secret: req.webhook_secret.unwrap_or_default(),
        email_to: req.email_to.unwrap_or_default(),
    };
    match state.storage.create_alert_rule(&ctx, &rule).await {
        Ok(created) => (StatusCode::CREATED, Json(created)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn delete_alert(
    State(state): State<Arc<AppState>>,
    Path((org, rule_id)): Path<(String, i64)>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !ctx.role.can_write_project() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    match state.storage.delete_alert_rule(&ctx, rule_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, Json(json!({ "error": "Rule not found" }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn test_alert(
    State(state): State<Arc<AppState>>,
    Path((org, rule_id)): Path<(String, i64)>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !ctx.role.can_write_project() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    let rule = match state.storage.get_alert_rule(&ctx, rule_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(json!({ "error": "Rule not found" }))).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    };
    let job = AlertDispatchJob {
        rule_id: rule.id,
        rule_name: rule.name,
        channel_type: rule.channel_type,
        target_url: rule.target_url,
        webhook_secret: String::new(),
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
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, None).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match state.storage.list_api_tokens(&ctx).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct CreateTokenReq {
    pub name: String,
    pub role: Option<String>,
}

pub async fn create_api_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    Json(req): Json<CreateTokenReq>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, None).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !ctx.role.can_manage_org() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Requires owner/admin role" }))).into_response();
    }
    let requested_role = req
        .role
        .as_deref()
        .and_then(UserRole::from_db)
        .unwrap_or(UserRole::Member);
    // Prevent privilege escalation: non-owner cannot mint owner token
    if requested_role == UserRole::Owner && ctx.role != UserRole::Owner {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Cannot mint token with higher privilege" }))).into_response();
    }

    let payload_val = json!({ "name": req.name, "role": requested_role.as_str() });
    let idem = match check_idempotency(&state, &ctx, &headers, "create_api_token", &payload_val).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let (plaintext, prefix, sha) = generate_api_token();
    let (status_code, body_str) = match state
        .storage
        .create_api_token(&ctx, req.name.trim(), &sha, &prefix, requested_role)
        .await
    {
        Ok(dto) => (
            StatusCode::CREATED,
            serde_json::to_string(&json!({ "token": plaintext, "meta": dto })).unwrap(),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            serde_json::to_string(&json!({ "error": e })).unwrap(),
        ),
    };
    if let Some((k, _)) = idem {
        let _ = state
            .storage
            .finish_idempotency(&ctx, "create_api_token", &k, status_code.as_u16(), &body_str)
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
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, None).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !ctx.role.can_manage_org() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    match state.storage.delete_api_token(&ctx, token_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, Json(json!({ "error": "Token not found" }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn list_members(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match state.storage.list_members(&ctx).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
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
    method: Method,
    Json(req): Json<InviteMemberReq>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !ctx.role.can_manage_org() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Requires owner or admin role" }))).into_response();
    }
    let Some(target_role) = UserRole::from_db(&req.role) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid role" }))).into_response();
    };
    if target_role == UserRole::Owner && ctx.role != UserRole::Owner {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Only owners can invite owners" }))).into_response();
    }
    if req.password.len() < 8 {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Password must be at least 8 characters" }))).into_response();
    }
    let Ok(pw_hash) = hash_password(req.password).await else {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Hash failed" }))).into_response();
    };
    match state
        .storage
        .invite_member(&ctx, req.email.trim(), req.name.trim(), &pw_hash, target_role)
        .await
    {
        Ok(m) => (StatusCode::CREATED, Json(m)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct UpdateMemberRoleReq {
    pub role: String,
}

pub async fn update_member_role(
    State(state): State<Arc<AppState>>,
    Path((org, target_uid)): Path<(String, i64)>,
    headers: HeaderMap,
    method: Method,
    Json(req): Json<UpdateMemberRoleReq>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !ctx.role.can_manage_org() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    if ctx.user_id == Some(target_uid) {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Cannot modify your own role" }))).into_response();
    }
    let Some(target_role) = UserRole::from_db(&req.role) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid role" }))).into_response();
    };
    if target_role == UserRole::Owner && ctx.role != UserRole::Owner {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Only owners can promote to owner" }))).into_response();
    }
    match state.storage.update_member_role(&ctx, target_uid, target_role).await {
        Ok(Ok(dto)) => Json(dto).into_response(),
        Ok(Err(msg)) => (StatusCode::CONFLICT, Json(json!({ "error": msg }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn remove_member(
    State(state): State<Arc<AppState>>,
    Path((org, target_uid)): Path<(String, i64)>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !ctx.role.can_manage_org() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Forbidden" }))).into_response();
    }
    match state.storage.remove_member(&ctx, target_uid).await {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => (StatusCode::NOT_FOUND, Json(json!({ "error": "Member not found" }))).into_response(),
        Ok(Err(msg)) => (StatusCode::CONFLICT, Json(json!({ "error": msg }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
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
    method: Method,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let report = evaluate_self_check(&state, &ctx).await;
    Json(report).into_response()
}

pub async fn run_self_check_probe(
    State(state): State<Arc<AppState>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    method: Method,
    maybe_req: Option<Json<RunProbeReq>>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !ctx.role.can_write_project() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Requires admin or owner role" })),
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
    method: Method,
    Json(req): Json<ClientSelfErrorReq>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
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
    state
        .self_monitor
        .record("ui_client", severity, component, msg, req.detail.as_deref());
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
    method: Method,
    maybe_req: Option<Json<AckSelfCheckReq>>,
) -> Response {
    let ctx = match authenticate_api_tenant(&state, &headers, &method, Some(&org)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !ctx.role.can_write_project() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Requires admin or owner role" })),
        )
            .into_response();
    }
    let clear = maybe_req.map(|r| r.clear).unwrap_or(false);
    if clear {
        state.self_monitor.clear_all();
    } else {
        state.self_monitor.acknowledge_all();
    }
    let report = evaluate_self_check(&state, &ctx).await;
    Json(report).into_response()
}
