use crate::domain::decompress::{decompress_bounded, DecompressError};
use crate::domain::envelope::{
    extract_dsn_key, normalize_csp_report, parse_dsn_url, parse_envelope, EnvelopeItem,
    ParsedEnvelope,
};
use crate::domain::fingerprint::{
    evaluate_inbound_filters, extract_issue_metadata, is_origin_allowed, FilterDecision,
};
use crate::domain::models::{
    now_ms, LiveStreamEvent, LogLevel, NewSecurityEvent, NormalizedLog, ProjectAuthInfo,
};
use crate::domain::otlp::decode_otlp_logs;
use crate::domain::scrubber::{strip_ansi_and_bidi, Scrubber};
use crate::domain::sourcemap::{demangle_event_with_maps, strip_url_basename};
use crate::security::anti_rea::{
    decide_quarantine, inspect_csp_for_tamper, score_signals, shield_ip_hmac,
};
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
    headers.insert(header::VARY, HeaderValue::from_static("Origin"));
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

pub fn attach_ingest_cors_for_request(
    resp_headers: &mut HeaderMap,
    req_headers: &HeaderMap,
    allowed_domains: &[String],
) {
    attach_ingest_cors(resp_headers);
    if !allowed_domains.is_empty() {
        resp_headers.remove(header::ACCESS_CONTROL_ALLOW_ORIGIN);
        if let Some(orig) = req_headers
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
        {
            let trimmed = orig.trim();
            if is_origin_allowed(trimmed, allowed_domains) {
                if let Ok(val) = HeaderValue::from_str(trimmed) {
                    resp_headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, val);
                }
            }
        }
    }
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
        r.headers_mut().insert("x-sentry-rate-limits", v);
    }
    attach_ingest_cors(r.headers_mut());
    r
}

async fn authenticate_project(
    state: &AppState,
    project_id: i64,
    query: &HashMap<String, String>,
    headers: &HeaderMap,
) -> Result<ProjectAuthInfo, Box<Response>> {
    let auth_hdr = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let x_sentry = headers.get("x-sentry-auth").and_then(|v| v.to_str().ok());
    let Some(raw_key) = extract_dsn_key(query, auth_hdr, x_sentry) else {
        return Err(Box::new(error_response(
            StatusCode::UNAUTHORIZED,
            "Missing DSN authentication",
        )));
    };
    let key_sha = sha256_hex(raw_key.as_bytes());
    if state.invalid_dsn_cache.is_blocked(project_id, &key_sha) {
        return Err(Box::new(error_response(
            StatusCode::UNAUTHORIZED,
            "Invalid DSN",
        )));
    }
    if let Some(info) = state.dsn_auth_cache.get(project_id, &key_sha) {
        return Ok(info);
    }
    match state.storage.resolve_dsn(project_id, &key_sha).await {
        Ok(Some(info)) => {
            state
                .dsn_auth_cache
                .insert(project_id, &key_sha, info.clone());
            Ok(info)
        }
        Ok(None) => {
            state.invalid_dsn_cache.mark_invalid(project_id, &key_sha);
            Err(Box::new(error_response(
                StatusCode::UNAUTHORIZED,
                "Invalid DSN",
            )))
        }
        Err(e) => Err(Box::new(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &e,
        ))),
    }
}

fn check_ingest_rate_limit(
    state: &AppState,
    auth: &ProjectAuthInfo,
    client_ip: &str,
    category: &str,
) -> Result<(), Box<Response>> {
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
        return Err(Box::new(rate_limited_response(
            decision.retry_after_sec,
            category,
        )));
    }
    Ok(())
}

fn decompress_ingest_body(
    state: &AppState,
    headers: &HeaderMap,
    raw: &[u8],
) -> Result<Vec<u8>, Box<Response>> {
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
            Err(Box::new(error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Payload exceeds maximum allowed size",
            )))
        }
        Err(DecompressError::UnsupportedEncoding(e)) => Err(Box::new(error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            &format!("Unsupported encoding: {e}"),
        ))),
        Err(DecompressError::CorruptStream(e)) => {
            Err(Box::new(error_response(StatusCode::BAD_REQUEST, &e)))
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
                        let base = strip_url_basename(fname).to_string();
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
        let key = format!(
            "{}:{}:{}",
            auth.project_id,
            did.as_deref().unwrap_or(""),
            base
        );
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
            if let Some(cached) = state.sourcemap_cache.get_cached(&rec.blob_sha256) {
                parsed_maps.insert(key, cached);
                continue;
            }
            let blob_path = state.config.sourcemaps_dir().join(&rec.blob_sha256);
            let parsed_opt = tokio::task::spawn_blocking(move || {
                let bytes = std::fs::read(&blob_path).ok()?;
                crate::domain::sourcemap::SourceMapV3::parse(&bytes)
                    .ok()
                    .map(Arc::new)
            })
            .await
            .ok()
            .flatten();
            if let Some(sm) = parsed_opt {
                let stored = state.sourcemap_cache.insert_parsed(&rec.blob_sha256, sm);
                parsed_maps.insert(key, stored);
            }
        }
    }

    if parsed_maps.is_empty() {
        return;
    }

    let pid = auth.project_id;
    demangle_event_with_maps(ev, |did, base| {
        let key = format!("{pid}:{}:{base}", did.unwrap_or(""));
        parsed_maps.get(&key).cloned()
    });
}

async fn emit_shield_security_event(state: &AppState, ev: NewSecurityEvent) {
    if let Ok((_, jobs)) = state.storage.record_security_event(&ev).await {
        if !jobs.is_empty() {
            crate::storage::batch_writer::spawn_alert_jobs(
                &state.config,
                &state.metrics,
                &state.self_monitor,
                jobs,
            );
        }
    }
}

fn is_event_throttled(auth: &ProjectAuthInfo) -> bool {
    let eff = auth
        .filters
        .event_throttle_rate
        .max(auth.org_event_throttle_rate)
        .min(100);
    if eff >= 100 {
        return true;
    }
    if eff == 0 {
        return false;
    }
    rand::random::<u8>() % 100 < eff
}

async fn process_single_event(
    state: &AppState,
    auth: &ProjectAuthInfo,
    headers: &HeaderMap,
    client_ip: &str,
    mut ev: Value,
) -> Result<Option<String>, Box<Response>> {
    let origin = headers
        .get(header::ORIGIN)
        .or_else(|| headers.get(header::REFERER))
        .and_then(|v| v.to_str().ok());
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());

    if let FilterDecision::Drop(_) = evaluate_inbound_filters(&ev, origin, ua, &auth.filters) {
        state
            .metrics
            .dropped_inbound_filter_total
            .fetch_add(1, Ordering::Relaxed);
        return Ok(None);
    }

    if is_event_throttled(auth) {
        state
            .metrics
            .dropped_inbound_filter_total
            .fetch_add(1, Ordering::Relaxed);
        return Ok(None);
    }

    maybe_demangle_event(state, auth, &mut ev).await;

    let scrubber = Scrubber::from_filters_with_org(&auth.filters, auth.org_scrub_ip_addresses);
    let scrub_report = scrubber.scrub_event_with_report(&mut ev);

    let meta = extract_issue_metadata(&ev);
    if state.event_dedupe.contains(auth.project_id, &meta.event_id) {
        state
            .metrics
            .dropped_dedupe_total
            .fetch_add(1, Ordering::Relaxed);
        return Ok(Some(meta.event_id));
    }

    let payload_json = serde_json::to_vec(&ev).unwrap_or_else(|_| b"{}".to_vec());
    let received_ms = now_ms();
    let event_id = meta.event_id.clone();

    if auth.filters.shield.enabled
        && auth.filters.shield.secret_leak_alerts
        && !scrub_report.categories.is_empty()
        && state.shield_engine.allow_cooldown(
            auth.project_id,
            "secret_leak:event",
            60_000,
            received_ms,
        )
    {
        let ev_path = ev
            .get("request")
            .and_then(|r| r.get("url"))
            .and_then(|v| v.as_str())
            .map(strip_ansi_and_bidi)
            .unwrap_or_default();
        emit_shield_security_event(
            state,
            NewSecurityEvent {
                organization_id: auth.organization_id,
                project_id: auth.project_id,
                project_slug: auth.project_slug.clone(),
                signal_type: "secret_leak".into(),
                category: "secret_leak".into(),
                severity: "medium".into(),
                risk_score: 60,
                source_kind: "log_ids".into(),
                actor_hmac: shield_ip_hmac(&state.config.app_key, auth.project_id, client_ip),
                session_id: String::new(),
                path: ev_path.chars().take(200).collect(),
                details_json: json!({
                    "categories": scrub_report.categories,
                    "event_id": event_id,
                }),
                action_taken: "redacted_and_alerted".into(),
                timestamp_ms: received_ms,
                quarantine: None,
            },
        )
        .await;
    }

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
            auth: Box::new(auth.clone()),
            meta: Box::new(meta),
            payload_json,
            received_ms,
        })
        .is_err()
    {
        return Err(Box::new(rate_limited_response(5, "error")));
    }

    state.event_dedupe.mark(auth.project_id, &event_id);
    state
        .metrics
        .ingest_events_total
        .fetch_add(1, Ordering::Relaxed);
    let _ = state.live_tx.send(live_ev);
    Ok(Some(event_id))
}

async fn process_logs_batch(
    state: &AppState,
    auth: &ProjectAuthInfo,
    client_ip: &str,
    mut logs: Vec<NormalizedLog>,
) -> Result<(), Box<Response>> {
    if logs.is_empty() {
        return Ok(());
    }
    let scrubber = Scrubber::from_filters_with_org(&auth.filters, auth.org_scrub_ip_addresses);
    let mut live_items = Vec::with_capacity(logs.len());
    let mut detected_threats = Vec::new();
    let mut leaked_cats: Vec<&'static str> = Vec::new();

    for l in logs.iter_mut() {
        let rep = scrubber.scrub_log_with_report(&mut l.body, &mut l.attributes);
        if auth.filters.shield.enabled && auth.filters.shield.secret_leak_alerts {
            for c in rep.categories {
                if !leaked_cats.contains(&c) {
                    leaked_cats.push(c);
                }
            }
        }
        if l.environment.is_empty() {
            l.environment = "production".into();
        }
        if l.service.is_empty() {
            l.service = auth.project_slug.clone();
        }
        if let Some(threat) = state.shield_engine.inspect_log_for_threats(
            auth.project_id,
            &auth.filters.shield,
            l.timestamp_ms,
            |actor| shield_ip_hmac(&state.config.app_key, auth.project_id, actor),
            l,
        ) {
            detected_threats.push(threat);
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

    let now = now_ms();
    if !leaked_cats.is_empty()
        && state
            .shield_engine
            .allow_cooldown(auth.project_id, "secret_leak:log", 60_000, now)
    {
        emit_shield_security_event(
            state,
            NewSecurityEvent {
                organization_id: auth.organization_id,
                project_id: auth.project_id,
                project_slug: auth.project_slug.clone(),
                signal_type: "secret_leak".into(),
                category: "secret_leak".into(),
                severity: "medium".into(),
                risk_score: 60,
                source_kind: "log_ids".into(),
                actor_hmac: shield_ip_hmac(&state.config.app_key, auth.project_id, client_ip),
                session_id: String::new(),
                path: String::new(),
                details_json: json!({ "categories": leaked_cats }),
                action_taken: "redacted_and_alerted".into(),
                timestamp_ms: now,
                quarantine: None,
            },
        )
        .await;
    }

    for threat in detected_threats {
        let q = decide_quarantine(
            &auth.filters.shield,
            "log_ids",
            threat.risk_score,
            &threat.actor_hmac,
            None,
        )
        .map(|(st, sh)| {
            (
                st,
                sh,
                now / 1000 + auth.filters.shield.quarantine_ttl_sec as i64,
            )
        });
        let action = if q.is_some() {
            "quarantined"
        } else {
            "alerted"
        };
        emit_shield_security_event(
            state,
            NewSecurityEvent {
                organization_id: auth.organization_id,
                project_id: auth.project_id,
                project_slug: auth.project_slug.clone(),
                signal_type: threat.signal_type,
                category: threat.category,
                severity: threat.severity,
                risk_score: threat.risk_score,
                source_kind: "log_ids".into(),
                actor_hmac: threat.actor_hmac,
                session_id: String::new(),
                path: strip_ansi_and_bidi(&threat.path)
                    .chars()
                    .take(200)
                    .collect(),
                details_json: threat.details,
                action_taken: action.into(),
                timestamp_ms: now,
                quarantine: q,
            },
        )
        .await;
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
        return Err(Box::new(rate_limited_response(5, "log_item")));
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

async fn handle_parsed_envelope(
    state: &AppState,
    auth: &ProjectAuthInfo,
    headers: &HeaderMap,
    client_ip: &str,
    parsed: ParsedEnvelope,
) -> Result<Value, Box<Response>> {
    let mut primary_event_id = parsed
        .header
        .event_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string());

    let received_ms = now_ms();
    let tx_scrubber = Scrubber::from_filters_with_org(&auth.filters, auth.org_scrub_ip_addresses);
    for item in parsed.items {
        match item {
            EnvelopeItem::Event(ev) => {
                if let Some(eid) = process_single_event(state, auth, headers, client_ip, ev).await?
                {
                    primary_event_id = eid;
                }
            }
            EnvelopeItem::Logs(logs) => {
                process_logs_batch(state, auth, client_ip, logs).await?;
            }
            EnvelopeItem::Transaction(mut tr) => {
                tx_scrubber.scrub_log_in_place(&mut tr.name, &mut tr.spans);
                if state
                    .batch_writer
                    .try_enqueue(IngestWriteItem::Transaction {
                        organization_id: auth.organization_id,
                        project_id: auth.project_id,
                        tx: tr,
                    })
                    .is_err()
                {
                    return Err(Box::new(rate_limited_response(5, "transaction")));
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

async fn handle_envelope_bytes(
    state: &AppState,
    auth: &ProjectAuthInfo,
    headers: &HeaderMap,
    client_ip: &str,
    decompressed: &[u8],
) -> Result<Value, Box<Response>> {
    let parsed = parse_envelope(decompressed)
        .map_err(|e| Box::new(error_response(StatusCode::BAD_REQUEST, &e.0)))?;
    handle_parsed_envelope(state, auth, headers, client_ip, parsed).await
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
        Err(r) => return *r,
    };
    if let Err(r) = check_ingest_rate_limit(&state, &auth, &client_ip, "error") {
        return *r;
    }
    let decompressed = match decompress_ingest_body(&state, &headers, &body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    match handle_envelope_bytes(&state, &auth, &headers, &client_ip, &decompressed).await {
        Ok(resp) => {
            let mut r = (StatusCode::OK, Json(resp)).into_response();
            attach_ingest_cors_for_request(
                r.headers_mut(),
                &headers,
                &auth.filters.allowed_domains,
            );
            r
        }
        Err(r) => *r,
    }
}

/// Anti-AdBlocker Sentry Tunnel endpoint: `POST /t/:slug`.
/// Rate-limits and validates tunnel existence BEFORE decompression, parses envelope once,
/// and validates the envelope's `dsn` header against the project bound to `:slug`.
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
    let pre_dec = state.rate_limiter.check_and_record(
        "tunnel_pre",
        &format!("{tunnel_slug}:{client_ip}"),
        600,
        Duration::from_secs(60),
    );
    if !pre_dec.allowed {
        state
            .metrics
            .dropped_rate_limit_total
            .fetch_add(1, Ordering::Relaxed);
        return rate_limited_response(pre_dec.retry_after_sec, "error");
    }
    match state.storage.tunnel_slug_exists(&tunnel_slug).await {
        Ok(true) => {}
        Ok(false) => return error_response(StatusCode::UNAUTHORIZED, "Invalid tunnel"),
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }

    let decompressed = match decompress_ingest_body(&state, &headers, &body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let parsed = match parse_envelope(&decompressed) {
        Ok(p) => p,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &e.0),
    };
    let Some(dsn_str) = parsed.header.dsn.as_deref() else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "Tunnel envelope missing dsn header",
        );
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
        return *r;
    }
    match handle_parsed_envelope(&state, &auth, &headers, &client_ip, parsed).await {
        Ok(resp) => {
            let mut r = (StatusCode::OK, Json(resp)).into_response();
            attach_ingest_cors_for_request(
                r.headers_mut(),
                &headers,
                &auth.filters.allowed_domains,
            );
            r
        }
        Err(r) => *r,
    }
}

/// Drop-in Sentry/GlitchTip `/api/:project_id/store/` endpoint.
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
        Err(r) => return *r,
    };
    if let Err(r) = check_ingest_rate_limit(&state, &auth, &client_ip, "error") {
        return *r;
    }
    let decompressed = match decompress_ingest_body(&state, &headers, &body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let ev: Value = match serde_json::from_slice(&decompressed) {
        Ok(v) => v,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "Invalid JSON event body"),
    };
    match process_single_event(&state, &auth, &headers, &client_ip, ev).await {
        Ok(Some(eid)) => {
            let mut r =
                (StatusCode::OK, Json(json!({ "id": eid, "event_id": eid }))).into_response();
            attach_ingest_cors_for_request(
                r.headers_mut(),
                &headers,
                &auth.filters.allowed_domains,
            );
            r
        }
        Ok(None) => {
            let mut r = (
                StatusCode::OK,
                Json(json!({ "id": null, "filtered": true })),
            )
                .into_response();
            attach_ingest_cors_for_request(
                r.headers_mut(),
                &headers,
                &auth.filters.allowed_domains,
            );
            r
        }
        Err(r) => *r,
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
        Err(r) => return *r,
    };
    if let Err(r) = check_ingest_rate_limit(&state, &auth, &client_ip, "security") {
        return *r;
    }
    let decompressed = match decompress_ingest_body(&state, &headers, &body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let raw: Value = match serde_json::from_slice(&decompressed) {
        Ok(v) => v,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "Invalid CSP JSON"),
    };
    if auth.filters.shield.enabled {
        if let Some(blocked) = inspect_csp_for_tamper(&raw) {
            let now = now_ms();
            if state.shield_engine.allow_cooldown(
                auth.project_id,
                &format!("csp:{blocked}"),
                60_000,
                now,
            ) {
                emit_shield_security_event(
                    &state,
                    NewSecurityEvent {
                        organization_id: auth.organization_id,
                        project_id: auth.project_id,
                        project_slug: auth.project_slug.clone(),
                        signal_type: "csp_script_tamper".into(),
                        category: "csp".into(),
                        severity: "medium".into(),
                        risk_score: 40,
                        source_kind: "browser".into(),
                        actor_hmac: shield_ip_hmac(
                            &state.config.app_key,
                            auth.project_id,
                            &client_ip,
                        ),
                        session_id: String::new(),
                        path: String::new(),
                        details_json: json!({ "blocked_uri": strip_ansi_and_bidi(&blocked) }),
                        action_taken: "logged".into(),
                        timestamp_ms: now,
                        quarantine: None,
                    },
                )
                .await;
            }
        }
    }
    let ev = normalize_csp_report(raw);
    match process_single_event(&state, &auth, &headers, &client_ip, ev).await {
        Ok(_) => {
            let mut r = StatusCode::CREATED.into_response();
            attach_ingest_cors_for_request(
                r.headers_mut(),
                &headers,
                &auth.filters.allowed_domains,
            );
            r
        }
        Err(r) => *r,
    }
}

async fn resolve_log_project_auth(
    state: &AppState,
    project_id_hint: Option<i64>,
    query: &HashMap<String, String>,
    headers: &HeaderMap,
) -> Result<ProjectAuthInfo, Box<Response>> {
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
    if let Some(auth_hdr) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(tok) = auth_hdr
            .strip_prefix("Bearer ")
            .or_else(|| auth_hdr.strip_prefix("bearer "))
        {
            if let Some((pub_key, pid)) = parse_dsn_url(tok.trim()) {
                let key_sha = sha256_hex(pub_key.as_bytes());
                if !state.invalid_dsn_cache.is_blocked(pid, &key_sha) {
                    if let Some(cached) = state.dsn_auth_cache.get(pid, &key_sha) {
                        return Ok(cached);
                    }
                    match state.storage.resolve_dsn(pid, &key_sha).await {
                        Ok(Some(info)) => {
                            state.dsn_auth_cache.insert(pid, &key_sha, info.clone());
                            return Ok(info);
                        }
                        Ok(None) => state.invalid_dsn_cache.mark_invalid(pid, &key_sha),
                        Err(_) => {}
                    }
                }
            }
        }
    }
    Err(Box::new(error_response(
        StatusCode::UNAUTHORIZED,
        "Provide project_id (path /api/:id/otlp/v1/logs, ?project_id=, or Bearer DSN URL) + valid DSN key",
    )))
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
        Err(r) => return *r,
    };
    if let Err(r) = check_ingest_rate_limit(&state, &auth, &client_ip, "log_item") {
        return *r;
    }
    let decompressed = match decompress_ingest_body(&state, &headers, &body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/x-protobuf");
    let logs = match decode_otlp_logs(&decompressed, ct) {
        Ok(l) => l,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &e.0),
    };
    match process_logs_batch(&state, &auth, &client_ip, logs).await {
        Ok(()) => {
            let mut r = (StatusCode::OK, Json(json!({ "partialSuccess": {} }))).into_response();
            attach_ingest_cors_for_request(
                r.headers_mut(),
                &headers,
                &auth.filters.allowed_domains,
            );
            r
        }
        Err(r) => *r,
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
        Err(r) => return *r,
    };
    if let Err(r) = check_ingest_rate_limit(&state, &auth, &client_ip, "log_item") {
        return *r;
    }
    let decompressed = match decompress_ingest_body(&state, &headers, &body) {
        Ok(b) => b,
        Err(r) => return *r,
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
    if items.len() > 500 {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Batch exceeds 500 log items per request",
        );
    }
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
            attributes: item.get("attributes").cloned().unwrap_or_else(|| json!({})),
        });
    }
    match process_logs_batch(&state, &auth, &client_ip, normalized).await {
        Ok(()) => {
            let mut r = (StatusCode::ACCEPTED, Json(json!({ "accepted": true }))).into_response();
            attach_ingest_cors_for_request(
                r.headers_mut(),
                &headers,
                &auth.filters.allowed_domains,
            );
            r
        }
        Err(r) => *r,
    }
}

#[derive(serde::Deserialize)]
pub struct ShieldIngestReq {
    pub signals: Vec<String>,
    pub session_id: Option<String>,
    pub actor_ip: Option<String>,
    pub path: Option<String>,
    pub details: Option<Value>,
}

async fn authenticate_shield_request(
    state: &AppState,
    project_id: i64,
    query: &HashMap<String, String>,
    headers: &HeaderMap,
) -> Result<(ProjectAuthInfo, &'static str), Box<Response>> {
    if let Some(auth_hdr) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(tok) = auth_hdr
            .strip_prefix("Bearer ")
            .or_else(|| auth_hdr.strip_prefix("bearer "))
            .map(str::trim)
        {
            if tok.starts_with("bf_") {
                let sha = sha256_hex(tok.as_bytes());
                let now_sec = chrono::Utc::now().timestamp();
                let ctx = match state.storage.resolve_api_token(&sha, None, now_sec).await {
                    Ok(Some(c)) => c,
                    Ok(None) => {
                        return Err(Box::new(error_response(
                            StatusCode::UNAUTHORIZED,
                            "Invalid or expired API token",
                        )))
                    }
                    Err(e) => {
                        return Err(Box::new(error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &e,
                        )))
                    }
                };
                if !ctx.has_any_scope(&["shield:write", "event:write"]) {
                    return Err(Box::new(error_response(
                        StatusCode::FORBIDDEN,
                        "Token missing shield:write or event:write scope",
                    )));
                }
                if !ctx.role.can_mutate_issues() {
                    return Err(Box::new(error_response(
                        StatusCode::FORBIDDEN,
                        "Insufficient token role",
                    )));
                }
                let projs =
                    state.storage.list_projects(&ctx).await.map_err(|e| {
                        Box::new(error_response(StatusCode::INTERNAL_SERVER_ERROR, &e))
                    })?;
                let Some(proj) = projs.into_iter().find(|p| p.id == project_id) else {
                    return Err(Box::new(error_response(
                        StatusCode::NOT_FOUND,
                        "Project not found",
                    )));
                };
                let org_sec = state
                    .storage
                    .get_org_security_settings(&ctx)
                    .await
                    .unwrap_or_default();
                return Ok((
                    ProjectAuthInfo {
                        project_id: proj.id,
                        organization_id: proj.organization_id,
                        organization_slug: ctx.organization_slug,
                        project_slug: proj.slug,
                        first_event_at: proj.first_event_at,
                        rate_limit_per_min: 300,
                        filters: proj.filters,
                        org_scrub_ip_addresses: org_sec.scrub_ip_addresses,
                        org_event_throttle_rate: org_sec.event_throttle_rate,
                    },
                    "backend_verified",
                ));
            }
        }
    }
    let auth = authenticate_project(state, project_id, query, headers).await?;
    Ok((auth, "browser"))
}

pub async fn ingest_shield(
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
    let (auth, source_kind) =
        match authenticate_shield_request(&state, project_id, &query, &headers).await {
            Ok(res) => res,
            Err(r) => return *r,
        };

    if source_kind == "browser"
        && auth.filters.shield.enforce_origin_check
        && !auth.filters.allowed_domains.is_empty()
    {
        let origin_hdr = headers
            .get(header::ORIGIN)
            .or_else(|| headers.get(header::REFERER))
            .and_then(|v| v.to_str().ok());
        match origin_hdr {
            Some(orig) if is_origin_allowed(orig, &auth.filters.allowed_domains) => {}
            _ => {
                return error_response(
                    StatusCode::FORBIDDEN,
                    "Disallowed origin for Shield telemetry",
                )
            }
        }
    }

    let rate_dec = state.rate_limiter.check_and_record(
        "shield_project_ip",
        &format!("{project_id}:{client_ip}"),
        120,
        Duration::from_secs(60),
    );
    if !rate_dec.allowed {
        return rate_limited_response(rate_dec.retry_after_sec, "security");
    }

    if !auth.filters.shield.enabled {
        let mut r = (
            StatusCode::ACCEPTED,
            Json(json!({ "ok": true, "skipped": true })),
        )
            .into_response();
        attach_ingest_cors_for_request(r.headers_mut(), &headers, &auth.filters.allowed_domains);
        return r;
    }

    let req: ShieldIngestReq = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "Invalid Shield JSON payload"),
    };
    if req.signals.is_empty() || req.signals.len() > 32 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "Provide between 1 and 32 security signals",
        );
    }
    let Some(scored) = score_signals(&req.signals) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "No recognized security signals provided",
        );
    };

    let actor_raw = if source_kind == "backend_verified" {
        req.actor_ip
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(&client_ip)
    } else {
        &client_ip
    };
    let actor_hmac = shield_ip_hmac(&state.config.app_key, auth.project_id, actor_raw);
    let now = now_ms();
    let quarantine = decide_quarantine(
        &auth.filters.shield,
        source_kind,
        scored.risk_score,
        &actor_hmac,
        req.session_id.as_deref(),
    )
    .map(|(st, sh)| {
        (
            st,
            sh,
            now / 1000 + auth.filters.shield.quarantine_ttl_sec as i64,
        )
    });

    let action = if quarantine.is_some() {
        "quarantined"
    } else if scored.risk_score >= auth.filters.shield.quarantine_threshold
        && auth.filters.shield.mode != "detect"
    {
        "defended"
    } else {
        "logged"
    };

    let scrubber = Scrubber::from_filters_with_org(&auth.filters, auth.org_scrub_ip_addresses);
    let mut details_val = req.details.unwrap_or_else(|| json!({}));
    let _ = scrubber.scrub_log_with_report(&mut String::new(), &mut details_val);
    let details_capped = if serde_json::to_vec(&details_val)
        .map(|b| b.len() <= 8192)
        .unwrap_or(false)
    {
        details_val
    } else {
        json!({ "truncated": true, "reason": "shield details exceeded 8192 byte cap" })
    };
    let clean_path: String = req
        .path
        .as_deref()
        .map(strip_ansi_and_bidi)
        .unwrap_or_default()
        .chars()
        .take(200)
        .collect();
    let clean_sid: String = req
        .session_id
        .as_deref()
        .map(strip_ansi_and_bidi)
        .unwrap_or_default()
        .chars()
        .take(64)
        .collect();

    emit_shield_security_event(
        &state,
        NewSecurityEvent {
            organization_id: auth.organization_id,
            project_id: auth.project_id,
            project_slug: auth.project_slug.clone(),
            signal_type: scored.primary_signal,
            category: scored.category,
            severity: scored.severity.clone(),
            risk_score: scored.risk_score,
            source_kind: source_kind.to_string(),
            actor_hmac,
            session_id: clean_sid,
            path: clean_path,
            details_json: details_capped,
            action_taken: action.to_string(),
            timestamp_ms: now,
            quarantine,
        },
    )
    .await;

    let mut r = (
        StatusCode::ACCEPTED,
        Json(json!({
            "ok": true,
            "risk_score": scored.risk_score,
            "severity": scored.severity,
            "action": action,
        })),
    )
        .into_response();
    attach_ingest_cors_for_request(r.headers_mut(), &headers, &auth.filters.allowed_domains);
    r
}
