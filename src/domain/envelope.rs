use crate::domain::models::{now_ms, LogLevel, NormalizedLog, NormalizedTransaction};
use serde_json::{json, Value};
use std::collections::HashMap;

pub const MAX_ENVELOPE_ITEMS: usize = 100;
pub const MAX_SENTRY_LOGS_PER_ITEM: usize = 500;

#[derive(Debug, Clone)]
pub struct EnvelopeHeader {
    pub event_id: Option<String>,
    pub sent_at: Option<String>,
    pub dsn: Option<String>,
    pub sdk_name: Option<String>,
    pub sdk_version: Option<String>,
    pub trace: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct SessionUpdate {
    pub release: String,
    pub environment: String,
    pub status: String,
    pub errors: i64,
    pub init: bool,
}

#[derive(Debug, Clone)]
pub struct CheckInItem {
    pub monitor_slug: String,
    pub status: String,
    pub duration_ms: Option<i64>,
}

#[derive(Debug, Clone)]
pub enum EnvelopeItem {
    Event(Value),
    Logs(Vec<NormalizedLog>),
    Transaction(NormalizedTransaction),
    Session(SessionUpdate),
    CheckIn(CheckInItem),
    Attachment { filename: String, size: usize },
    Ignored,
}

#[derive(Debug, Clone)]
pub struct ParsedEnvelope {
    pub header: EnvelopeHeader,
    pub items: Vec<EnvelopeItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeError(pub String);

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn trim_cr(slice: &[u8]) -> &[u8] {
    if slice.ends_with(b"\r") {
        &slice[..slice.len() - 1]
    } else {
        slice
    }
}

fn next_line<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    while *pos < data.len() && (data[*pos] == b'\n' || data[*pos] == b'\r') {
        *pos += 1;
    }
    if *pos >= data.len() {
        return None;
    }
    let start = *pos;
    let rel_end = data[start..]
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(data.len() - start);
    *pos = start + rel_end;
    if *pos < data.len() && data[*pos] == b'\n' {
        *pos += 1;
    }
    Some(trim_cr(&data[start..start + rel_end]))
}

/// Zero-copy slice-based Sentry NDJSON envelope parser supporting:
/// - `event`
/// - `log` (Sentry Logs v2 `application/vnd.sentry.items.log+json`)
/// - `transaction`
/// - `session` / `sessions`
/// - `check_in`
/// - `attachment` (binary-safe via explicit `length`)
/// - `client_report` (ignored cleanly)
pub fn parse_envelope(data: &[u8]) -> Result<ParsedEnvelope, EnvelopeError> {
    let mut pos = 0;
    let header_line =
        next_line(data, &mut pos).ok_or_else(|| EnvelopeError("Empty envelope body".into()))?;
    let header_val: Value = serde_json::from_slice(header_line)
        .map_err(|_| EnvelopeError("Invalid envelope header JSON".into()))?;

    let sdk_obj = header_val.get("sdk").and_then(|v| v.as_object());
    let header = EnvelopeHeader {
        event_id: header_val
            .get("event_id")
            .and_then(|v| v.as_str())
            .map(ToString::to_string),
        sent_at: header_val
            .get("sent_at")
            .and_then(|v| v.as_str())
            .map(ToString::to_string),
        dsn: header_val
            .get("dsn")
            .and_then(|v| v.as_str())
            .map(ToString::to_string),
        sdk_name: sdk_obj
            .and_then(|o| o.get("name"))
            .and_then(|v| v.as_str())
            .map(ToString::to_string),
        sdk_version: sdk_obj
            .and_then(|o| o.get("version"))
            .and_then(|v| v.as_str())
            .map(ToString::to_string),
        trace: header_val.get("trace").cloned(),
    };

    let mut items = Vec::new();
    while let Some(item_header_line) = next_line(data, &mut pos) {
        if item_header_line.is_empty() {
            continue;
        }
        if items.len() >= MAX_ENVELOPE_ITEMS {
            return Err(EnvelopeError("Envelope item count exceeds limit".into()));
        }
        let item_header: Value = serde_json::from_slice(item_header_line)
            .map_err(|_| EnvelopeError("Invalid envelope item header JSON".into()))?;
        let item_type = item_header
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let explicit_len = match item_header.get("length").and_then(|v| v.as_u64()) {
            Some(n) => Some(
                usize::try_from(n)
                    .map_err(|_| EnvelopeError("Envelope item length overflow".into()))?,
            ),
            None => None,
        };

        let payload_bytes: &[u8] = if let Some(len) = explicit_len {
            let Some(end) = pos.checked_add(len) else {
                return Err(EnvelopeError("Envelope item length overflow".into()));
            };
            if end > data.len() {
                return Err(EnvelopeError("Truncated envelope item payload".into()));
            }
            let slice = &data[pos..end];
            pos = end;
            if pos < data.len() && data[pos] == b'\r' {
                pos += 1;
            }
            if pos < data.len() && data[pos] == b'\n' {
                pos += 1;
            }
            slice
        } else {
            next_line(data, &mut pos).unwrap_or(&[])
        };

        match item_type {
            "event" => {
                if let Ok(mut ev) = serde_json::from_slice::<Value>(payload_bytes) {
                    if let Some(obj) = ev.as_object_mut() {
                        if !obj.contains_key("event_id") {
                            if let Some(eid) = &header.event_id {
                                obj.insert("event_id".into(), Value::String(eid.clone()));
                            }
                        }
                    }
                    items.push(EnvelopeItem::Event(ev));
                }
            }
            "log" => {
                if let Ok(parsed) = parse_sentry_log_container(payload_bytes, &header) {
                    if !parsed.is_empty() {
                        items.push(EnvelopeItem::Logs(parsed));
                    }
                }
            }
            "transaction" => {
                if let Ok(val) = serde_json::from_slice::<Value>(payload_bytes) {
                    if let Some(tx) = parse_transaction_value(&val) {
                        items.push(EnvelopeItem::Transaction(tx));
                    }
                }
            }
            "session" => {
                if let Ok(val) = serde_json::from_slice::<Value>(payload_bytes) {
                    if let Some(sess) = parse_session_value(&val) {
                        items.push(EnvelopeItem::Session(sess));
                    }
                }
            }
            "check_in" => {
                if let Ok(val) = serde_json::from_slice::<Value>(payload_bytes) {
                    if let Some(slug) = val.get("monitor_slug").and_then(|v| v.as_str()) {
                        let status = val
                            .get("status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("ok")
                            .to_string();
                        let duration_ms = val
                            .get("duration")
                            .and_then(|v| v.as_f64())
                            .map(|s| (s * 1000.0) as i64);
                        items.push(EnvelopeItem::CheckIn(CheckInItem {
                            monitor_slug: slug.to_string(),
                            status,
                            duration_ms,
                        }));
                    }
                }
            }
            "attachment" => {
                let filename = item_header
                    .get("filename")
                    .and_then(|v| v.as_str())
                    .unwrap_or("attachment.bin")
                    .to_string();
                items.push(EnvelopeItem::Attachment {
                    filename,
                    size: payload_bytes.len(),
                });
            }
            _ => {
                items.push(EnvelopeItem::Ignored);
            }
        }
    }

    Ok(ParsedEnvelope { header, items })
}

/// Parses `@sentry/core@11.16.0` Structured Logs v2 (`{"version": 2, "items": [...]}`).
pub fn parse_sentry_log_container(
    payload: &[u8],
    header: &EnvelopeHeader,
) -> Result<Vec<NormalizedLog>, EnvelopeError> {
    let val: Value = serde_json::from_slice(payload)
        .map_err(|_| EnvelopeError("Invalid Sentry log JSON".into()))?;
    let mut raw_items = if let Some(arr) = val.get("items").and_then(|v| v.as_array()) {
        arr.clone()
    } else if let Some(arr) = val.as_array() {
        arr.clone()
    } else if val.is_object() {
        vec![val]
    } else {
        Vec::new()
    };
    if raw_items.len() > MAX_SENTRY_LOGS_PER_ITEM {
        return Err(EnvelopeError("Sentry log batch exceeds limit".into()));
    }

    let mut out = Vec::with_capacity(raw_items.len());
    for item in raw_items.drain(..) {
        let Some(obj) = item.as_object() else {
            continue;
        };
        let ts_ms = obj
            .get("timestamp")
            .and_then(|v| v.as_f64())
            .map(|secs| (secs * 1000.0) as i64)
            .unwrap_or_else(now_ms);
        let severity_number = obj
            .get("severity_number")
            .and_then(|v| v.as_u64())
            .map(|n| n as u16);
        let level = obj
            .get("level")
            .and_then(|v| v.as_str())
            .map(LogLevel::from_str_loose)
            .or_else(|| severity_number.map(LogLevel::from_otel_severity))
            .unwrap_or(LogLevel::Info);
        let body = obj
            .get("body")
            .or_else(|| obj.get("message"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let trace_id = obj
            .get("trace_id")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let mut span_id = obj
            .get("span_id")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let mut flat_attrs = serde_json::Map::new();
        let mut service = header.sdk_name.clone().unwrap_or_default();
        let mut environment = String::new();
        let mut host = String::new();

        if let Some(attrs) = obj.get("attributes").and_then(|v| v.as_object()) {
            for (k, raw_v) in attrs {
                let unwrapped = unwrap_typed_attr(raw_v);
                match k.as_str() {
                    "sentry.environment" | "deployment.environment" | "environment" => {
                        if let Some(s) = unwrapped.as_str() {
                            environment = s.to_string();
                        }
                    }
                    "service.name" | "service" | "sentry.sdk.name" => {
                        if let Some(s) = unwrapped.as_str() {
                            if k != "sentry.sdk.name" || service.is_empty() {
                                service = s.to_string();
                            }
                        }
                    }
                    "host.name" | "host" | "server.address" => {
                        if let Some(s) = unwrapped.as_str() {
                            host = s.to_string();
                        }
                    }
                    "sentry.trace.parent_span_id" => {
                        if let (None, Some(s)) = (&span_id, unwrapped.as_str()) {
                            span_id = Some(s.to_string());
                        }
                    }
                    _ => {}
                }
                flat_attrs.insert(k.clone(), unwrapped);
            }
        }

        if service.is_empty() {
            if let Some(s) = obj.get("service").and_then(|v| v.as_str()) {
                service = s.to_string();
            }
        }
        if environment.is_empty() {
            if let Some(s) = obj.get("environment").and_then(|v| v.as_str()) {
                environment = s.to_string();
            }
        }
        if host.is_empty() {
            if let Some(s) = obj.get("host").and_then(|v| v.as_str()) {
                host = s.to_string();
            }
        }

        out.push(NormalizedLog {
            timestamp_ms: ts_ms,
            level,
            severity_number,
            body,
            service,
            environment,
            host,
            trace_id,
            span_id,
            attributes: Value::Object(flat_attrs),
        });
    }

    Ok(out)
}

fn unwrap_typed_attr(v: &Value) -> Value {
    if let Some(obj) = v.as_object() {
        if obj.contains_key("value") && obj.contains_key("type") {
            return obj.get("value").cloned().unwrap_or(Value::Null);
        }
    }
    v.clone()
}

pub fn parse_transaction_value(val: &Value) -> Option<NormalizedTransaction> {
    let name = val
        .get("transaction")
        .and_then(|v| v.as_str())
        .unwrap_or("unnamed")
        .to_string();
    let start_sec = val
        .get("start_timestamp")
        .and_then(|v| v.as_f64())
        .unwrap_or_else(|| (now_ms() as f64) / 1000.0);
    let end_sec = val
        .get("timestamp")
        .and_then(|v| v.as_f64())
        .unwrap_or(start_sec);
    let duration_ms = ((end_sec - start_sec) * 1000.0).max(0.0);
    let timestamp_ms = (start_sec * 1000.0) as i64;

    let trace_ctx = val
        .get("contexts")
        .and_then(|c| c.get("trace"))
        .and_then(|t| t.as_object());
    let trace_id = trace_ctx
        .and_then(|t| t.get("trace_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let span_id = trace_ctx
        .and_then(|t| t.get("span_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let op = trace_ctx
        .and_then(|t| t.get("op"))
        .and_then(|v| v.as_str())
        .unwrap_or("http.server")
        .to_string();
    let status = trace_ctx
        .and_then(|t| t.get("status"))
        .and_then(|v| v.as_str())
        .unwrap_or("ok")
        .to_string();

    let environment = val
        .get("environment")
        .and_then(|v| v.as_str())
        .unwrap_or("production")
        .to_string();
    let release = val
        .get("release")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let spans = val
        .get("spans")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));

    Some(NormalizedTransaction {
        timestamp_ms,
        name,
        op,
        status,
        duration_ms,
        trace_id,
        span_id,
        environment,
        release,
        spans,
    })
}

fn parse_session_value(val: &Value) -> Option<SessionUpdate> {
    let attrs = val.get("attrs").and_then(|v| v.as_object());
    let release = attrs
        .and_then(|a| a.get("release"))
        .and_then(|v| v.as_str())
        .or_else(|| val.get("release").and_then(|v| v.as_str()))?
        .to_string();
    let environment = attrs
        .and_then(|a| a.get("environment"))
        .and_then(|v| v.as_str())
        .or_else(|| val.get("environment").and_then(|v| v.as_str()))
        .unwrap_or("production")
        .to_string();
    let status = val
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("ok")
        .to_string();
    let errors = val.get("errors").and_then(|v| v.as_i64()).unwrap_or(0);
    let init = val.get("init").and_then(|v| v.as_bool()).unwrap_or(false);
    Some(SessionUpdate {
        release,
        environment,
        status,
        errors,
        init,
    })
}

/// Extract Sentry DSN public key following GlitchTip / Sentry precedence:
/// 1. `?sentry_key=` / `?glitchtip_key=` query parameter
/// 2. `Authorization: Bearer <key>`
/// 3. `X-Sentry-Auth` or `Authorization: Sentry sentry_key=...`
pub fn extract_dsn_key(
    query_params: &HashMap<String, String>,
    auth_header: Option<&str>,
    x_sentry_auth: Option<&str>,
) -> Option<String> {
    if let Some(k) = query_params
        .get("sentry_key")
        .or_else(|| query_params.get("glitchtip_key"))
    {
        let trimmed = k.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    if let Some(auth) = auth_header {
        let trimmed = auth.trim();
        if trimmed.len() > 7 && trimmed[..7].eq_ignore_ascii_case("bearer ") {
            let tok = trimmed[7..].trim();
            if !tok.is_empty() {
                return Some(tok.to_string());
            }
        }
    }

    let raw_sentry = x_sentry_auth.or(auth_header)?;
    for part in raw_sentry.split(',') {
        let cleaned = part
            .trim()
            .strip_prefix("Sentry ")
            .or_else(|| part.trim().strip_prefix("sentry "))
            .unwrap_or(part.trim())
            .trim();
        if let Some((k, v)) = cleaned.split_once('=') {
            let key_name = k.trim();
            if key_name == "sentry_key" || key_name == "glitchtip_key" {
                let val = v.trim().trim_matches('"');
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

/// Parse DSN string `https://<public_key>@<host>/<project_id>` into `(public_key, project_id)`.
pub fn parse_dsn_url(dsn: &str) -> Option<(String, i64)> {
    let without_scheme = dsn
        .strip_prefix("https://")
        .or_else(|| dsn.strip_prefix("http://"))?;
    let (userinfo, rest) = without_scheme.split_once('@')?;
    let key = userinfo.split(':').next()?.trim();
    if key.is_empty() {
        return None;
    }
    let path_part = rest.split_once('/')?.1.trim_matches('/');
    let project_id = path_part.rsplit('/').next()?.parse::<i64>().ok()?;
    Some((key.to_string(), project_id))
}

/// Normalize browser CSP violation report into standard Sentry-like event payload.
pub fn normalize_csp_report(raw: Value) -> Value {
    let report = raw.get("csp-report").cloned().unwrap_or(raw);
    let directive = report
        .get("effective-directive")
        .or_else(|| report.get("violated-directive"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let blocked = report
        .get("blocked-uri")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let doc_uri = report
        .get("document-uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    json!({
        "type": "csp",
        "level": "warning",
        "message": format!("Blocked '{blocked}' from '{directive}'"),
        "culprit": directive,
        "csp": report,
        "request": { "url": doc_uri },
        "platform": "other"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multi_item_envelope_event_log_tx_session() {
        let body = concat!(
            r#"{"event_id":"9ec79c33ec9942ab83535e9fcb9faeec","sent_at":"2026-11-21T22:52:00Z","sdk":{"name":"sentry.javascript.browser","version":"11.16.0"}}"#,
            "\n",
            r#"{"type":"event","content_type":"application/json"}"#,
            "\n",
            r#"{"level":"error","message":"Boom","exception":{"values":[{"type":"TypeError","value":"Cannot read x"}]}}"#,
            "\n",
            r#"{"type":"log","item_count":1,"content_type":"application/vnd.sentry.items.log+json"}"#,
            "\n",
            r#"{"version":2,"items":[{"timestamp":1700000000.5,"level":"warn","severity_number":13,"body":"Slow query","trace_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","attributes":{"sentry.environment":{"value":"production","type":"string"},"duration_ms":{"value":412,"type":"integer"}}}]}"#,
            "\n",
            r#"{"type":"session"}"#,
            "\n",
            r#"{"init":true,"status":"ok","errors":0,"attrs":{"release":"1.0.0","environment":"production"}}"#,
            "\n"
        );
        let parsed = parse_envelope(body.as_bytes()).unwrap();
        assert_eq!(parsed.items.len(), 3);
        match &parsed.items[1] {
            EnvelopeItem::Logs(logs) => {
                assert_eq!(logs.len(), 1);
                assert_eq!(logs[0].level, LogLevel::Warn);
                assert_eq!(logs[0].body, "Slow query");
                assert_eq!(logs[0].environment, "production");
                assert_eq!(logs[0].attributes["duration_ms"], 412);
            }
            _ => panic!("expected Logs item"),
        }
    }

    #[test]
    fn parses_custom_x_sentry_auth_header_and_dsn() {
        let mut q = HashMap::new();
        let hdr = "Sentry sentry_version=7, sentry_client=acme-observability/1.0, sentry_key=abc123def456"; // gitleaks:allow
        assert_eq!(
            extract_dsn_key(&q, None, Some(hdr)).as_deref(),
            Some("abc123def456")
        );
        q.insert("sentry_key".into(), "fromquery".into());
        assert_eq!(
            extract_dsn_key(&q, None, Some(hdr)).as_deref(),
            Some("fromquery")
        );
        assert_eq!(
            parse_dsn_url("https://abc123@bugs.example.com/42"),
            Some(("abc123".into(), 42))
        );
    }

    #[test]
    fn rejects_integer_overflow_length_and_item_count_overflow() {
        let huge = format!("{{\"sent_at\":\"2026-01-01T00:00:00Z\"}}\n{{\"type\":\"attachment\",\"length\":{}}}\nhello\n", u64::MAX);
        let err = parse_envelope(huge.as_bytes()).unwrap_err();
        assert!(
            err.0.contains("overflow") || err.0.contains("Truncated"),
            "got: {err}"
        );

        let mut many = String::from("{\"sent_at\":\"2026-01-01T00:00:00Z\"}\n");
        for _ in 0..=MAX_ENVELOPE_ITEMS {
            many.push_str("{\"type\":\"client_report\"}\n{}\n");
        }
        assert!(parse_envelope(many.as_bytes()).is_err());

        let too_many_logs: Vec<serde_json::Value> = (0..=MAX_SENTRY_LOGS_PER_ITEM)
            .map(|i| json!({"timestamp": 1700000000.0, "level": "info", "body": format!("m{i}")}))
            .collect();
        let log_body = serde_json::to_vec(&json!({"version": 2, "items": too_many_logs})).unwrap();
        let hdr = EnvelopeHeader {
            event_id: None,
            sent_at: None,
            dsn: None,
            sdk_name: None,
            sdk_version: None,
            trace: None,
        };
        assert!(parse_sentry_log_container(&log_body, &hdr).is_err());
    }
}
