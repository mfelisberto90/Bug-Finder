use crate::http::{api_v0, auth_routes, ingest};
use crate::security::auth::constant_time_eq;
use crate::security::headers::{inject_csp_nonce_into_html, security_headers_middleware, ClientIp, CspNonce};
use crate::AppState;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use flate2::read::GzDecoder;
use ring::digest::{digest, SHA384};
use serde_json::json;
use std::io::Read;
use std::sync::{Arc, OnceLock};

mod embedded_ui {
    include!(concat!(env!("OUT_DIR"), "/embedded_ui.rs"));
}

async fn health(State(state): State<Arc<AppState>>) -> Response {
    let healthy = match state.storage.check_health().await {
        Ok(info) => info.ok && (info.engine != "postgres" || info.wal_or_rls_verified),
        Err(_) => false,
    };
    if healthy {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"status":"ok","service":"bugfinder"}"#,
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"status":"degraded","service":"bugfinder"}"#,
        )
            .into_response()
    }
}

async fn robots_txt() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "User-agent: *\nAllow: /\n",
    )
        .into_response()
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

fn serve_precompressed_bytes(
    headers: &HeaderMap,
    bytes: &'static [u8],
    gzipped: bool,
    content_type: &'static str,
    etag: &'static str,
    cache_control: Option<&'static str>,
) -> Response {
    let quoted_etag = format!("\"{etag}\"");
    if let Some(if_none_match) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        if if_none_match
            .split(',')
            .any(|tag| tag.trim() == quoted_etag || tag.trim() == "*")
        {
            let mut resp = StatusCode::NOT_MODIFIED.into_response();
            if let Ok(v) = HeaderValue::from_str(&quoted_etag) {
                resp.headers_mut().insert(header::ETAG, v);
            }
            resp.headers_mut()
                .insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
            if let Some(cc) = cache_control {
                resp.headers_mut()
                    .insert(header::CACHE_CONTROL, HeaderValue::from_static(cc));
            }
            return resp;
        }
    }

    let mut resp = if gzipped && client_accepts_gzip(headers) {
        let mut r = (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], bytes).into_response();
        r.headers_mut()
            .insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        r.headers_mut()
            .insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
        r
    } else if gzipped {
        let mut dec = GzDecoder::new(bytes);
        let mut raw = Vec::with_capacity(bytes.len() * 3);
        if dec.read_to_end(&mut raw).is_err() {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Asset decode error").into_response();
        }
        let mut r = (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], raw).into_response();
        r.headers_mut()
            .insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
        r
    } else {
        (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], bytes).into_response()
    };

    if let Ok(v) = HeaderValue::from_str(&quoted_etag) {
        resp.headers_mut().insert(header::ETAG, v);
    }
    if let Some(cc) = cache_control {
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static(cc));
    }
    resp
}

fn gunzip_sri_sha384(gz: &[u8]) -> String {
    let mut dec = GzDecoder::new(gz);
    let mut raw = Vec::with_capacity(gz.len() * 3);
    dec.read_to_end(&mut raw).expect("embedded SDK gzip valid");
    let d = digest(&SHA384, &raw);
    format!("sha384-{}", STANDARD.encode(d.as_ref()))
}

pub fn sdk_sri_hashes() -> (&'static str, &'static str) {
    static SRI: OnceLock<(String, String)> = OnceLock::new();
    let pair = SRI.get_or_init(|| {
        (
            gunzip_sri_sha384(embedded_ui::MINI_SDK_JS_GZ),
            gunzip_sri_sha384(embedded_ui::SHIELD_SDK_JS_GZ),
        )
    });
    (&pair.0, &pair.1)
}

async fn mini_sdk_js(headers: HeaderMap) -> Response {
    let mut resp = serve_precompressed_bytes(
        &headers,
        embedded_ui::MINI_SDK_JS_GZ,
        true,
        "application/javascript; charset=utf-8",
        embedded_ui::MINI_SDK_ETAG,
        Some("public, max-age=300"),
    );
    resp.headers_mut()
        .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    resp
}

async fn shield_sdk_js(headers: HeaderMap) -> Response {
    let mut resp = serve_precompressed_bytes(
        &headers,
        embedded_ui::SHIELD_SDK_JS_GZ,
        true,
        "application/javascript; charset=utf-8",
        embedded_ui::SHIELD_SDK_ETAG,
        Some("public, max-age=300"),
    );
    resp.headers_mut()
        .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    resp
}

async fn prometheus_metrics(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    if let Some(ref tok) = state.config.metrics_token {
        let provided = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer ").or_else(|| s.strip_prefix("bearer ")))
            .unwrap_or("");
        if !constant_time_eq(provided.as_bytes(), tok.as_bytes()) {
            return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        }
    } else {
        let is_loopback = ext
            .get::<ClientIp>()
            .map(|c| c.0.is_loopback())
            .unwrap_or(false);
        if !is_loopback {
            return (StatusCode::FORBIDDEN, "Metrics restricted to loopback unless BUGFINDER_METRICS_TOKEN is set").into_response();
        }
    }
    let db_bytes = state.storage.db_size_bytes().await;
    let body = state.metrics.render_prometheus(db_bytes);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}

async fn serve_spa(uri: Uri, ext: axum::http::Extensions, headers: HeaderMap) -> Response {
    let raw_path = uri.path().trim_start_matches('/');
    if raw_path.starts_with("api/") || raw_path.starts_with("v1/") {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Endpoint not found" })),
        )
            .into_response();
    }

    let lookup = if raw_path.is_empty() {
        "index.html"
    } else {
        raw_path
    };

    if !lookup.contains("..") {
        if let Some(asset) = embedded_ui::get_asset(lookup) {
            if lookup == "index.html" {
                return render_index_with_nonce(asset.bytes, ext);
            }
            let cache_control = if lookup.starts_with("assets/") {
                Some("public, max-age=0, must-revalidate")
            } else {
                None
            };
            return serve_precompressed_bytes(
                &headers,
                asset.bytes,
                asset.gzipped,
                asset.content_type,
                asset.etag,
                cache_control,
            );
        }
    }

    // SPA client-side route fallback -> index.html with fresh per-request CSP nonce (NEVER gzip HTML — BREACH defense)
    if let Some(asset) = embedded_ui::get_asset("index.html") {
        return render_index_with_nonce(asset.bytes, ext);
    }

    (StatusCode::NOT_FOUND, "Not found").into_response()
}

fn render_index_with_nonce(bytes: &[u8], ext: axum::http::Extensions) -> Response {
    let html = String::from_utf8_lossy(bytes);
    let nonce = ext
        .get::<CspNonce>()
        .map(|n| n.0.as_str())
        .unwrap_or("fallbacknonce");
    let injected = inject_csp_nonce_into_html(&html, nonce);
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store, private"),
        ],
        injected,
    )
        .into_response()
}

pub fn build_router(state: Arc<AppState>) -> Router {
    let ingest_routes = Router::new()
        .route("/api/:project_id/envelope/", post(ingest::ingest_envelope).options(ingest::options_ingest))
        .route("/api/:project_id/envelope", post(ingest::ingest_envelope).options(ingest::options_ingest))
        .route("/api/:project_id/store/", post(ingest::ingest_store).options(ingest::options_ingest))
        .route("/api/:project_id/store", post(ingest::ingest_store).options(ingest::options_ingest))
        .route("/api/:project_id/security/", post(ingest::ingest_security).options(ingest::options_ingest))
        .route("/api/:project_id/security", post(ingest::ingest_security).options(ingest::options_ingest))
        .route("/api/:project_id/otlp/v1/logs", post(ingest::ingest_otlp_logs).options(ingest::options_ingest))
        .route("/v1/logs", post(ingest::ingest_otlp_logs).options(ingest::options_ingest))
        .route("/api/v1/logs", post(ingest::ingest_direct_logs).options(ingest::options_ingest))
        .route("/api/:project_id/shield/", post(ingest::ingest_shield).options(ingest::options_ingest))
        .route("/api/:project_id/shield", post(ingest::ingest_shield).options(ingest::options_ingest))
        .route("/t/:slug", post(ingest::ingest_tunnel).options(ingest::options_ingest))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024));

    let sourcemap_route = Router::new()
        .route(
            "/api/0/projects/:org/:proj/releases/:version/sourcemaps/",
            post(api_v0::upload_sourcemap),
        )
        .route(
            "/api/0/projects/:org/:proj/releases/:version/sourcemaps",
            post(api_v0::upload_sourcemap),
        )
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024 + 4096));

    let client_self_error_route = Router::new()
        .route(
            "/api/0/organizations/:org/self-check/client-error/",
            post(api_v0::report_client_self_error),
        )
        .layer(DefaultBodyLimit::max(8192));

    let api_routes = Router::new()
        .route("/api/health", get(health))
        .route("/robots.txt", get(robots_txt))
        .route("/metrics", get(prometheus_metrics))
        .route("/sdk/bugfinder-mini.js", get(mini_sdk_js))
        .route("/sdk/bugfinder-shield.js", get(shield_sdk_js))
        .route("/api/auth/status", get(auth_routes::auth_status))
        .route("/api/auth/oidc/login", get(auth_routes::oidc_login))
        .route("/api/auth/oidc/callback", get(auth_routes::oidc_callback))
        .route("/api/auth/setup", post(auth_routes::auth_setup))
        .route("/api/auth/login", post(auth_routes::auth_login))
        .route("/api/auth/logout", post(auth_routes::auth_logout))
        .route("/api/auth/me", get(auth_routes::auth_me))
        .route("/api/auth/mfa/verify", post(auth_routes::mfa_verify))
        .route("/api/auth/mfa/status", get(auth_routes::mfa_status))
        .route("/api/auth/mfa/totp/enroll", post(auth_routes::mfa_totp_enroll))
        .route("/api/auth/mfa/totp/confirm", post(auth_routes::mfa_totp_confirm))
        .route("/api/auth/mfa/totp/disable", post(auth_routes::mfa_totp_disable))
        .route("/api/auth/mfa/recovery/regenerate", post(auth_routes::mfa_recovery_regenerate))
        .route("/api/auth/passkey/register/begin", post(auth_routes::passkey_register_begin))
        .route("/api/auth/passkey/register/finish", post(auth_routes::passkey_register_finish))
        .route("/api/auth/passkeys", get(auth_routes::list_passkeys))
        .route("/api/auth/passkeys/:id", delete(auth_routes::delete_passkey))
        .route("/api/auth/passkey/login/begin", post(auth_routes::passkey_login_begin))
        .route("/api/auth/passkey/login/finish", post(auth_routes::passkey_login_finish))
        .route("/api/auth/reauth", post(auth_routes::auth_reauth))
        .route("/api/auth/password/change", post(auth_routes::change_password))
        .route("/api/auth/sessions", get(auth_routes::list_sessions))
        .route("/api/auth/sessions/revoke-others", post(auth_routes::revoke_other_sessions))
        .route("/api/auth/sessions/:id", delete(auth_routes::revoke_session))
        .route("/api/auth/invites/:token", get(auth_routes::get_public_invitation))
        .route("/api/auth/invites/:token/accept", post(auth_routes::accept_public_invitation))
        .route("/api/0/organizations/:org/self-check/", get(api_v0::get_self_check))
        .route("/api/0/organizations/:org/self-check/probe/", post(api_v0::run_self_check_probe))
        .route("/api/0/organizations/:org/self-check/ack/", post(api_v0::ack_self_check_errors))
        .route("/api/0/organizations/", get(api_v0::list_organizations))
        .route("/api/0/sdk-meta/", get(api_v0::get_sdk_meta))
        .route("/api/0/organizations/:org/projects/", get(api_v0::list_projects).post(api_v0::create_project))
        .route("/api/0/projects/:org/:proj/settings/", put(api_v0::update_project_settings))
        .route("/api/0/projects/:org/:proj/test-event/", post(api_v0::send_project_test_event))
        .route("/api/0/projects/:org/:proj/keys/", get(api_v0::list_project_keys).post(api_v0::create_project_key))
        .route(
            "/api/0/projects/:org/:proj/keys/:key_id/",
            put(api_v0::update_project_key).delete(api_v0::delete_project_key),
        )
        .route("/api/0/projects/:org/:proj/tunnel/", post(api_v0::enable_project_tunnel))
        .route("/api/0/organizations/:org/audit-logs/", get(api_v0::list_audit_logs))
        .route("/api/0/organizations/:org/audit-logs/verify/", get(api_v0::verify_audit_logs))
        .route(
            "/api/0/organizations/:org/security-settings/",
            get(api_v0::get_org_security_settings).put(api_v0::update_org_security_settings),
        )
        .route(
            "/api/0/organizations/:org/invitations/",
            get(api_v0::list_invitations).post(api_v0::create_invitation),
        )
        .route(
            "/api/0/organizations/:org/invitations/:inv_id/",
            delete(api_v0::revoke_invitation),
        )
        .route("/api/0/organizations/:org/issues/", get(api_v0::list_issues))
        .route("/api/0/organizations/:org/issues/export.csv", get(api_v0::export_issues_csv))
        .route("/api/0/organizations/:org/issues/:issue_id/", get(api_v0::get_issue).put(api_v0::update_issue))
        .route("/api/0/organizations/:org/issues/:issue_id/events/", get(api_v0::list_issue_events))
        .route("/api/0/organizations/:org/issues/:issue_id/events/:ev_id/", get(api_v0::get_issue_event))
        .route("/api/0/organizations/:org/stats_v2/", get(api_v0::get_stats_v2))
        .route("/api/0/organizations/:org/logs/", get(api_v0::list_logs))
        .route("/api/0/organizations/:org/logs/stream", get(api_v0::stream_logs_sse))
        .route("/api/0/organizations/:org/logs/resources/", get(api_v0::list_log_resources))
        .route("/api/0/organizations/:org/logs/stats/", get(api_v0::get_log_stats))
        .route("/api/0/organizations/:org/transactions/", get(api_v0::list_transactions))
        .route("/api/0/organizations/:org/traces/:trace_id/", get(api_v0::get_trace_context))
        .route("/api/0/organizations/:org/releases/", get(api_v0::list_releases))
        .route("/api/0/organizations/:org/monitors/", get(api_v0::list_monitors).post(api_v0::create_monitor))
        .route("/api/0/organizations/:org/monitors/:mon_id/", delete(api_v0::delete_monitor))
        .route(
            "/api/0/organizations/:org/heartbeat_check/:uuid/",
            get(api_v0::get_heartbeat_check).post(api_v0::post_heartbeat_check),
        )
        .route(
            "/api/0/organizations/:org/heartbeat_check/:uuid",
            get(api_v0::get_heartbeat_check).post(api_v0::post_heartbeat_check),
        )
        .route("/api/0/organizations/:org/alerts/", get(api_v0::list_alerts).post(api_v0::create_alert))
        .route("/api/0/organizations/:org/alerts/:rule_id/", delete(api_v0::delete_alert))
        .route("/api/0/organizations/:org/alerts/:rule_id/test/", post(api_v0::test_alert))
        .route("/api/0/organizations/:org/shield/events/", get(api_v0::list_shield_events))
        .route("/api/0/organizations/:org/shield/quarantine/", get(api_v0::list_shield_quarantine))
        .route("/api/0/organizations/:org/shield/quarantine/:entry_id/", delete(api_v0::delete_shield_quarantine))
        .route("/api/0/projects/:org/:proj/shield/blocklist/", get(api_v0::get_shield_blocklist))
        .route("/api/0/api-tokens/", get(api_v0::list_api_tokens).post(api_v0::create_api_token))
        .route("/api/0/api-tokens/:token_id/", delete(api_v0::delete_api_token))
        .route("/api/0/organizations/:org/members/", get(api_v0::list_members).post(api_v0::invite_member))
        .route(
            "/api/0/organizations/:org/members/:uid/",
            put(api_v0::update_member_role).delete(api_v0::remove_member),
        );

    Router::new()
        .merge(ingest_routes)
        .merge(sourcemap_route)
        .merge(client_self_error_route)
        .merge(api_routes)
        .fallback(any(serve_spa))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers_middleware,
        ))
        .with_state(state)
}
