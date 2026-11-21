use crate::domain::decompress::{decompress_bounded, DecompressError};
use crate::domain::envelope::{
    extract_dsn_key, normalize_csp_report, parse_dsn_url, parse_envelope, EnvelopeItem,
};
use crate::domain::fingerprint::{
    evaluate_inbound_filters, extract_issue_metadata, FilterDecision,
};
use crate::domain::models::{now_ms, LiveStreamEvent, LogLevel, NormalizedLog, ProjectAuthInfo};
use crate::domain::otlp::decode_otlp_logs;
use crate::domain::scrubber::Scrubber;
use crate::domain::sourcemap::demangle_event_with_maps;
use crate::security::auth::sha256_hex;
use crate::security::headers::ClientIp;
use crate::security::ratelimit::sentry_rate_limit_header;
use crate::storage::IngestWriteItem;
use crate::AppState;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

fn cors_preflight_response() -> Response {
    let mut resp = StatusCode::NO_CONTENT.into_response();
    attach_ingest_cors(resp.headers_mut());
    resp
}

pub fn attach_ingest_cors(headers: &mut HeaderMap) {
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(
            "Content-Type, Content-Encoding, Authorization, X-Sentry-Auth, X-Requested-With",
        ),
    );
    headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("X-Sentry-Rate-Limits, Retry-After"),
    );
}

pub async fn options_ingest() -> Response {
    cors_preflight_response()
}

fn error_response(status: StatusCode, msg: &str) -> Response {
    let mut r = (status, Json(json!({ "error": msg }))).into_response();
    attach_ingest_cors(r.headers_mut());
    r
}

fn rate_limited_response(retry_after: u64, category: &str) -> Response {
    let mut r = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({ "error": "Rate limit exceeded" })),
    )
        .into_response();
    if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
        r.headers_mut().insert(header::RETRY_AFTER, v);
    }
    if let Ok(v) = HeaderValue::from_str(&sentry_rate_limit_header(retry_after, category)) {
        r.headers_mut()
            .insert("x-sentry-rate-limits", v);
    }
    attach_ingest_cors(r.headers_mut());
    r
}

async fn authenticate_project(
    state: &AppState,
    project_id: i64,
    query: &HashMap<String, String>,
    headers: &HeaderMap,
) -> Result<ProjectAuthInfo, Response> {
    let auth_hdr = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let x_sentry = headers.get("x-sentry-auth").and_then(|v| v.to_str().ok());
    let Some(raw_key) = extract_dsn_key(query, auth_hdr, x_sentry) else {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "Missing DSN authentication",
        ));
    };
    let key_sha = sha256_hex(raw_key.as_bytes());
    match state.storage.resolve_dsn(project_id, &key_sha).await {
        Ok(Some(info)) => Ok(info),
        Ok(None) => Err(error_response(StatusCode::UNAUTHORIZED, "Invalid DSN")),
        Err(e) => Err(error_response(StatusCode::INTERNAL_SERVER_ERROR, &e)),
    }
}

fn check_ingest_rate_limit(
    state: &AppState,
    auth: &ProjectAuthInfo,
    client_ip: &str,
    category: &str,
) -> Result<(), Response> {
    let bucket_key = format!("{}:{client_ip}", auth.project_id);
    let decision = state.rate_limiter.check_and_record(
        "ingest_project_ip",
        &bucket_key,
        auth.rate_limit_per_min,
        Duration::from_secs(60),
    );
    if !decision.allowed {
        state
            .metrics
            .dropped_rate_limit_total
            .fetch_add(1, Ordering::Relaxed);
        return Err(rate_limited_response(decision.retry_after_sec, category));
    }
    Ok(())
}

fn decompress_ingest_body(
    state: &AppState,
    headers: &HeaderMap,
    raw: &[u8],
) -> Result<Vec<u8>, Response> {
    let enc = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok());
    match decompress_bounded(raw, enc, state.config.max_unzipped_bytes) {
        Ok(v) => Ok(v),
        Err(DecompressError::TooLarge { .. }) => {
            state
                .metrics
                .dropped_zip_bomb_total
                .fetch_add(1, Ordering::Relaxed);
            Err(error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Payload exceeds maximum allowed size",
            ))
        }
        Err(DecompressError::UnsupportedEncoding(e)) => Err(error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            &format!("Unsupported encoding: {e}"),
        )),
        Err(DecompressError::CorruptStream(e)) => {
            Err(error_response(StatusCode::BAD_REQUEST, &e))
        }
    }
}

async fn maybe_demangle_event(state: &AppState, auth: &ProjectAuthInfo, ev: &mut Value) {
    let platform = ev.get("platform").and_then(|v| v.as_str()).unwrap_or("");
    if platform != "javascript" && platform != "node" && platform != "browser" {
        return;
    }
    let release = ev
        .get("release")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);

    let mut needed_files: Vec<(Option<String>, String)> = Vec::new();
    let debug_id_map: HashMap<String, String> = ev
        .get("debug_meta")
        .and_then(|d| d.get("images"))
        .and_then(|i| i.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|img| {
                    Some((
                        img.get("code_file")?.as_str()?.to_string(),
                        img.get("debug_id")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();

    if let Some(vals) = ev
        .get("exception")
        .and_then(|e| e.get("values"))
        .and_then(|v| v.as_array())
    {
        for exc in vals {
            if let Some(frames) = exc
                .get("stacktrace")
                .and_then(|s| s.get("frames"))
                .and_then(|f| f.as_array())
            {
                for fr in frames {
                    if let Some(fname) = fr
                        .get("filename")
                        .or_else(|| fr.get("abs_path"))
                        .and_then(|v| v.as_str())
                    {
                        let base = fname.rsplit('/').next().unwrap_or(fname).to_string();
                        let did = debug_id_map
                            .get(fname)
                            .or_else(|| debug_id_map.get(&base))
                            .cloned();
                        needed_files.push((did, base));
                    }
                }
            }
        }
    }

    if needed_files.is_empty() {
        return;
    }

    let mut parsed_maps = HashMap::new();
    for (did, base) in needed_files {
        let key = format!("{}:{}:{}", auth.project_id, did.as_deref().unwrap_or(""), base);
        if parsed_maps.contains_key(&key) {
            continue;
        }
        if let Ok(Some(rec)) = state
            .storage
            .find_source_map(
                auth.organization_id,
                auth.project_id,
                release.as_deref(),
                did.as_deref(),
                &base,
            )
            .await
        {
            let blob_path = state.config.sourcemaps_dir().join(&rec.blob_sha256);
            if let Ok(bytes) = tokio::fs::read(&blob_path).await {
                if let Some(sm) = state.sourcemap_cache.get_or_parse(&rec.blob_sha256, &bytes) {
                    parsed_maps.insert(key, sm);
                }
            }
        }
    }

    if parsed_maps.is_empty() {
        return;
    }

    let pid = auth.project_id;
    demangle_event_with_maps(ev, |did, base| {
        let key = format!("{pid}:{}:{}", did.unwrap_or(""), base);
        parsed_maps.get(&key).cloned()
    });
}

async fn process_single_event(
    state: &AppState,
    auth: &ProjectAuthInfo,
    headers: &HeaderMap,
    mut ev: Value,
) -> Result<Option<String>, Response> {
    let origin = headers
        .get(header::ORIGIN)
        .or_else(|| headers.get(header::REFERER))
        .and_then(|v| v.to_str().ok());
    let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok());

    if let FilterDecision::Drop(_) = evaluate_inbound_filters(&ev, origin, ua, &auth.filters) {
        state
            .metrics
            .dropped_inbound_filter_total
            .fetch_add(1, Ordering::Relaxed);
        return Ok(None);
    }

    maybe_demangle_event(state, auth, &mut ev).await;

    let scrubber = Scrubber::from_filters(&auth.filters);
    scrubber.scrub_event_in_place(&mut ev);

    let meta = extract_issue_metadata(&ev);
    if state.event_dedupe.check_and_mark(auth.project_id, &meta.event_id) {
        state
            .metrics
            .dropped_dedupe_total
            .fetch_add(1, Ordering::Relaxed);
        return Ok(Some(meta.event_id));
    }

    let payload_json = serde_json::to_vec(&ev).unwrap_or_else(|_| b"{}".to_vec());
    let received_ms = now_ms();
    let event_id = meta.event_id.clone();

    let live_ev = LiveStreamEvent {
        organization_id: auth.organization_id,
        project_id: auth.project_id,
        kind: "issue".into(),
        level: meta.level.clone(),
        title_or_body: meta.title.clone(),
        service: auth.project_slug.clone(),
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
        .try_enqueue(IngestWriteItem::Event {
            auth: auth.clone(),
            meta,
            payload_json,
            received_ms,
        })
        .is_err()
    {
        return Err(rate_limited_response(5, "error"));
    }

    state
        .metrics
        .ingest_events_total
        .fetch_add(1, Ordering::Relaxed);
    let _ = state.live_tx.send(live_ev);
    Ok(Some(event_id))
}

fn process_logs_batch(
    state: &AppState,
    auth: &ProjectAuthInfo,
    mut logs: Vec<NormalizedLog>,
) -> Result<(), Response> {
    if logs.is_empty() {
        return Ok(());
    }
    let scrubber = Scrubber::from_filters(&auth.filters);
    let mut live_items = Vec::with_capacity(logs.len());

    for l in logs.iter_mut() {
        scrubber.scrub_log_in_place(&mut l.body, &mut l.attributes);
        if l.environment.is_empty() {
            l.environment = "production".into();
        }
        if l.service.is_empty() {
            l.service = auth.project_slug.clone();
        }
        live_items.push(LiveStreamEvent {
            organization_id: auth.organization_id,
            project_id: auth.project_id,
            kind: "log".into(),
            level: l.level.as_str().to_string(),
            title_or_body: l.body.clone(),
            service: l.service.clone(),
            environment: l.environment.clone(),
            trace_id: l.trace_id.clone(),
            timestamp_ms: l.timestamp_ms,
            payload: l.attributes.clone(),
        });
    }

    let auto_promote = auth
        .filters
        .auto_promote_log_level
        .as_deref()
        .map(LogLevel::from_str_loose);
    let count = logs.len() as u64;

    if state
        .batch_writer
        .try_enqueue(IngestWriteItem::Logs {
            organization_id: auth.organization_id,
            project_id: auth.project_id,
            project_slug: auth.project_slug.clone(),
            auto_promote_level: auto_promote,
            logs,
        })
        .is_err()
    {
        return Err(rate_limited_response(5, "log_item"));
    }

    state
        .metrics
        .ingest_logs_total
        .fetch_add(count, Ordering::Relaxed);
    for ev in live_items {
        let _ = state.live_tx.send(ev);
    }
    Ok(())
}

async fn handle_envelope_bytes(
    state: &AppState,
    auth: &ProjectAuthInfo,
    headers: &HeaderMap,
    decompressed: &[u8],
) -> Result<Value, Response> {
    let parsed = parse_envelope(decompressed)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.0))?;

    let mut primary_event_id = parsed
        .header
        .event_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string());

    let received_ms = now_ms();
    for item in parsed.items {
        match item {
            EnvelopeItem::Event(ev) => {
                if let Some(eid) = process_single_event(state, auth, headers, ev).await? {
                    primary_event_id = eid;
                }
            }
            EnvelopeItem::Logs(logs) => {
                process_logs_batch(state, auth, logs)?;
            }
            EnvelopeItem::Transaction(tr) => {
                if state
                    .batch_writer
                    .try_enqueue(IngestWriteItem::Transaction {
                        organization_id: auth.organization_id,
                        project_id: auth.project_id,
                        tx: tr,
                    })
                    .is_err()
                {
                    return Err(rate_limited_response(5, "transaction"));
                }
                state
                    .metrics
                    .ingest_transactions_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            EnvelopeItem::Session(sess) => {
                let _ = state.batch_writer.try_enqueue(IngestWriteItem::Session {
                    organization_id: auth.organization_id,
                    project_id: auth.project_id,
                    session: sess,
                    received_ms,
                });
            }
            EnvelopeItem::CheckIn(ci) => {
                let _ = state.batch_writer.try_enqueue(IngestWriteItem::CheckIn {
                    organization_id: auth.organization_id,
                    project_id: auth.project_id,
                    check_in: ci,
                    received_ms,
                });
            }
            EnvelopeItem::Attachment { .. } | EnvelopeItem::Ignored => {}
        }
    }

    Ok(json!({ "id": primary_event_id }))
}

pub async fn ingest_envelope(
    State(state): State<Arc<AppState>>,
    Path(project_id): Path<i64>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    body: Bytes,
) -> Response {
    let client_ip = ext
        .get::<ClientIp>()
        .map(|c| c.0.to_string())
        .unwrap_or_else(|| "127.0.0.1".into());
    let auth = match authenticate_project(&state, project_id, &query, &headers).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Err(r) = check_ingest_rate_limit(&state, &auth, &client_ip, "error") {
        return r;
    }
    let decompressed = match decompress_ingest_body(&state, &headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    match handle_envelope_bytes(&state, &auth, &headers, &decompressed).await {
        Ok(resp) => {
            let mut r = (StatusCode::OK, Json(resp)).into_response();
            attach_ingest_cors(r.headers_mut());
            r
        }
        Err(r) => r,
    }
}

/// Anti-AdBlocker Sentry Tunnel endpoint: `POST /t/:slug`.
/// Validates the envelope's `dsn` header against the project bound to `:slug`.
pub async fn ingest_tunnel(
    State(state): State<Arc<AppState>>,
    Path(tunnel_slug): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    body: Bytes,
) -> Response {
    let client_ip = ext
        .get::<ClientIp>()
        .map(|c| c.0.to_string())
        .unwrap_or_else(|| "127.0.0.1".into());
    let decompressed = match decompress_ingest_body(&state, &headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let parsed = match parse_envelope(&decompressed) {
        Ok(p) => p,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &e.0),
    };
    let Some(dsn_str) = parsed.header.dsn.as_deref() else {
        return error_response(StatusCode::BAD_REQUEST, "Tunnel envelope missing dsn header");
    };
    let Some((pub_key, project_id)) = parse_dsn_url(dsn_str) else {
        return error_response(StatusCode::BAD_REQUEST, "Malformed DSN in tunnel header");
    };
    let key_sha = sha256_hex(pub_key.as_bytes());
    let auth = match state
        .storage
        .resolve_tunnel(&tunnel_slug, project_id, &key_sha)
        .await
    {
        Ok(Some(a)) => a,
        Ok(None) => return error_response(StatusCode::UNAUTHORIZED, "Invalid tunnel DSN"),
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };
    if let Err(r) = check_ingest_rate_limit(&state, &auth, &client_ip, "error") {
        return r;
    }
    match handle_envelope_bytes(&state, &auth, &headers, &decompressed).await {
        Ok(resp) => {
            let mut r = (StatusCode::OK, Json(resp)).into_response();
            attach_ingest_cors(r.headers_mut());
            r
        }
        Err(r) => r,
    }
}

/// Drop-in Sentry/GlitchTip `/api/:project_id/store/` used by RoleLane `GlitchTipClient.php`.
pub async fn ingest_store(
    State(state): State<Arc<AppState>>,
    Path(project_id): Path<i64>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    body: Bytes,
) -> Response {
    let client_ip = ext
        .get::<ClientIp>()
        .map(|c| c.0.to_string())
        .unwrap_or_else(|| "127.0.0.1".into());
    let auth = match authenticate_project(&state, project_id, &query, &headers).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Err(r) = check_ingest_rate_limit(&state, &auth, &client_ip, "error") {
        return r;
    }
    let decompressed = match decompress_ingest_body(&state, &headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let ev: Value = match serde_json::from_slice(&decompressed) {
        Ok(v) => v,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "Invalid JSON event body"),
    };
    match process_single_event(&state, &auth, &headers, ev).await {
        Ok(Some(eid)) => {
            let mut r = (StatusCode::OK, Json(json!({ "id": eid, "event_id": eid }))).into_response();
            attach_ingest_cors(r.headers_mut());
            r
        }
        Ok(None) => {
            let mut r = (StatusCode::OK, Json(json!({ "id": null, "filtered": true }))).into_response();
            attach_ingest_cors(r.headers_mut());
            r
        }
        Err(r) => r,
    }
}

pub async fn ingest_security(
    State(state): State<Arc<AppState>>,
    Path(project_id): Path<i64>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    body: Bytes,
) -> Response {
    let client_ip = ext
        .get::<ClientIp>()
        .map(|c| c.0.to_string())
        .unwrap_or_else(|| "127.0.0.1".into());
    let auth = match authenticate_project(&state, project_id, &query, &headers).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Err(r) = check_ingest_rate_limit(&state, &auth, &client_ip, "security") {
        return r;
    }
    let decompressed = match decompress_ingest_body(&state, &headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let raw: Value = match serde_json::from_slice(&decompressed) {
        Ok(v) => v,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "Invalid CSP JSON"),
    };
    let ev = normalize_csp_report(raw);
    match process_single_event(&state, &auth, &headers, ev).await {
        Ok(_) => {
            let mut r = StatusCode::CREATED.into_response();
            attach_ingest_cors(r.headers_mut());
            r
        }
        Err(r) => r,
    }
}

async fn resolve_log_project_auth(
    state: &AppState,
    project_id_hint: Option<i64>,
    query: &HashMap<String, String>,
    headers: &HeaderMap,
) -> Result<ProjectAuthInfo, Response> {
    if let Some(pid) = project_id_hint {
        return authenticate_project(state, pid, query, headers).await;
    }
    if let Some(pid_q) = query.get("project_id").and_then(|s| s.parse::<i64>().ok()) {
        return authenticate_project(state, pid_q, query, headers).await;
    }
    // Check X-BugFinder-Project or DSN in Authorization Bearer
    if let Some(pid_hdr) = headers
        .get("x-bugfinder-project")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok())
    {
        return authenticate_project(state, pid_hdr, query, headers).await;
    }
    if let Some(auth_hdr) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(tok) = auth_hdr.strip_prefix("Bearer ").or_else(|| auth_hdr.strip_prefix("bearer ")) {
            if let Some((pub_key, pid)) = parse_dsn_url(tok.trim()) {
                let key_sha = sha256_hex(pub_key.as_bytes());
                if let Ok(Some(info)) = state.storage.resolve_dsn(pid, &key_sha).await {
                    return Ok(info);
                }
            }
        }
    }
    Err(error_response(
        StatusCode::UNAUTHORIZED,
        "Provide project_id (path /api/:id/otlp/v1/logs, ?project_id=, or Bearer DSN URL) + valid DSN key",
    ))
}

pub async fn ingest_otlp_logs(
    State(state): State<Arc<AppState>>,
    project_opt: Option<Path<i64>>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    body: Bytes,
) -> Response {
    let client_ip = ext
        .get::<ClientIp>()
        .map(|c| c.0.to_string())
        .unwrap_or_else(|| "127.0.0.1".into());
    let pid_hint = project_opt.map(|Path(id)| id);
    let auth = match resolve_log_project_auth(&state, pid_hint, &query, &headers).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Err(r) = check_ingest_rate_limit(&state, &auth, &client_ip, "log_item") {
        return r;
    }
    let decompressed = match decompress_ingest_body(&state, &headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/x-protobuf");
    let logs = match decode_otlp_logs(&decompressed, ct) {
        Ok(l) => l,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &e.0),
    };
    match process_logs_batch(&state, &auth, logs) {
        Ok(()) => {
            let mut r = (StatusCode::OK, Json(json!({ "partialSuccess": {} }))).into_response();
            attach_ingest_cors(r.headers_mut());
            r
        }
        Err(r) => r,
    }
}

pub async fn ingest_direct_logs(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    body: Bytes,
) -> Response {
    let client_ip = ext
        .get::<ClientIp>()
        .map(|c| c.0.to_string())
        .unwrap_or_else(|| "127.0.0.1".into());
    let auth = match resolve_log_project_auth(&state, None, &query, &headers).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Err(r) = check_ingest_rate_limit(&state, &auth, &client_ip, "log_item") {
        return r;
    }
    let decompressed = match decompress_ingest_body(&state, &headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let val: Value = match serde_json::from_slice(&decompressed) {
        Ok(v) => v,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "Invalid JSON logs"),
    };
    let items = if let Some(arr) = val.get("items").and_then(|v| v.as_array()) {
        arr.clone()
    } else if let Some(arr) = val.as_array() {
        arr.clone()
    } else {
        vec![val]
    };
    let mut normalized = Vec::with_capacity(items.len());
    for item in items {
        let level_s = item.get("level").and_then(|v| v.as_str()).unwrap_or("info");
        let level = LogLevel::from_str_loose(level_s);
        let body_s = item
            .get("body")
            .or_else(|| item.get("message"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let ts_ms = item
            .get("timestamp_ms")
            .and_then(|v| v.as_i64())
            .unwrap_or_else(now_ms);
        normalized.push(NormalizedLog {
            timestamp_ms: ts_ms,
            level,
            severity_number: Some(level.num() as u16),
            body: body_s,
            service: item
                .get("service")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            environment: item
                .get("environment")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            host: item
                .get("host")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            trace_id: item
                .get("trace_id")
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            span_id: item
                .get("span_id")
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            attributes: item
                .get("attributes")
                .cloned()
                .unwrap_or_else(|| json!({})),
        });
    }
    match process_logs_batch(&state, &auth, normalized) {
        Ok(()) => {
            let mut r = (StatusCode::ACCEPTED, Json(json!({ "accepted": true }))).into_response();
            attach_ingest_cors(r.headers_mut());
            r
        }
        Err(r) => r,
    }
}
