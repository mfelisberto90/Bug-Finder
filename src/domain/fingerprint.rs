use crate::domain::models::{IssueStatus, IssueType, ProjectFilters};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::{Regex, RegexBuilder};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

struct GroupingRegexes {
    uuid: Regex,
    hex_long: Regex,
    num_long: Regex,
}

static GROUP_RX: OnceLock<GroupingRegexes> = OnceLock::new();

fn group_rx() -> &'static GroupingRegexes {
    GROUP_RX.get_or_init(|| GroupingRegexes {
        uuid: RegexBuilder::new(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        )
        .unicode(false)
        .build()
        .unwrap(),
        hex_long: RegexBuilder::new(r"\b0x[0-9a-fA-F]{4,}\b|\b[0-9a-fA-F]{12,}\b")
            .unicode(false)
            .build()
            .unwrap(),
        num_long: RegexBuilder::new(r"\b\d{4,}\b")
            .unicode(false)
            .build()
            .unwrap(),
    })
}

pub fn normalize_volatile_tokens(input: &str) -> String {
    let rx = group_rx();
    let s = rx.uuid.replace_all(input, "<uuid>");
    let s = rx.hex_long.replace_all(&s, "<hex>");
    rx.num_long.replace_all(&s, "<num>").into_owned()
}

#[derive(Debug, Clone)]
pub struct ComputedIssueMetadata {
    pub event_id: String,
    pub fingerprint: String,
    pub title: String,
    pub culprit: String,
    pub level: String,
    pub issue_type: IssueType,
    pub environment: String,
    pub release: Option<String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub user_hash: Option<String>,
    pub tags: Value,
    pub search_text: String,
}

pub fn format_logentry(ev: &Value) -> Option<String> {
    if let Some(le) = ev.get("logentry").and_then(|v| v.as_object()) {
        if let Some(formatted) = le.get("formatted").and_then(|v| v.as_str()) {
            if !formatted.is_empty() {
                return Some(formatted.to_string());
            }
        }
        if let Some(tmpl) = le.get("message").and_then(|v| v.as_str()) {
            if let Some(params) = le.get("params").and_then(|v| v.as_array()) {
                let mut out = tmpl.to_string();
                for p in params {
                    let rep = match p {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    if let Some(idx) = out.find("%s") {
                        out.replace_range(idx..idx + 2, &rep);
                    } else if let Some(idx) = out.find("{}") {
                        out.replace_range(idx..idx + 2, &rep);
                    }
                }
                return Some(out);
            }
            return Some(tmpl.to_string());
        }
    }
    if let Some(msg) = ev.get("message") {
        if let Some(s) = msg.as_str() {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        } else if let Some(formatted) = msg.get("formatted").and_then(|v| v.as_str()) {
            return Some(formatted.to_string());
        } else if let Some(tmpl) = msg.get("message").and_then(|v| v.as_str()) {
            return Some(tmpl.to_string());
        }
    }
    None
}

pub fn extract_issue_metadata(ev: &Value) -> ComputedIssueMetadata {
    let event_id = ev
        .get("event_id")
        .and_then(|v| v.as_str())
        .map(|s| s.replace('-', "").to_ascii_lowercase())
        .filter(|s| s.len() >= 16)
        .unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string());

    let level = ev
        .get("level")
        .and_then(|v| v.as_str())
        .unwrap_or("error")
        .to_ascii_lowercase();

    let environment = ev
        .get("environment")
        .and_then(|v| v.as_str())
        .unwrap_or("production")
        .chars()
        .take(64)
        .collect::<String>();

    let release = ev
        .get("release")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().chars().take(128).collect::<String>())
        .filter(|s| !s.is_empty());

    let trace_ctx = ev.get("contexts").and_then(|c| c.get("trace"));
    let trace_id = trace_ctx
        .and_then(|t| t.get("trace_id"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .filter(|s| !s.is_empty());
    let span_id = trace_ctx
        .and_then(|t| t.get("span_id"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .filter(|s| !s.is_empty());

    let mut issue_type = match ev.get("type").and_then(|v| v.as_str()) {
        Some("csp") => IssueType::Csp,
        Some("log") => IssueType::Log,
        _ => IssueType::Default,
    };

    let mut title = String::new();
    let mut culprit = ev
        .get("culprit")
        .or_else(|| ev.get("transaction"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let mut frame_names = Vec::new();
    if let Some(exc_vals) = ev
        .get("exception")
        .and_then(|e| e.get("values"))
        .and_then(|v| v.as_array())
    {
        if !exc_vals.is_empty() {
            if issue_type == IssueType::Default {
                issue_type = IssueType::Error;
            }
            let first = &exc_vals[0];
            let exc_type = first
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("Error");
            let exc_val = first.get("value").and_then(|v| v.as_str()).unwrap_or("");
            title = if exc_val.is_empty() {
                exc_type.to_string()
            } else {
                format!("{exc_type}: {exc_val}")
            };

            if culprit.is_empty() {
                for exc in exc_vals.iter().rev() {
                    if let Some(frames) = exc
                        .get("stacktrace")
                        .and_then(|s| s.get("frames"))
                        .and_then(|f| f.as_array())
                    {
                        for fr in frames.iter().rev().take(5) {
                            if let Some(fn_file) = fr.get("filename").and_then(|v| v.as_str()) {
                                let base = fn_file.rsplit('/').next().unwrap_or(fn_file);
                                frame_names.push(base.to_string());
                            }
                        }
                        let chosen = frames
                            .iter()
                            .rev()
                            .find(|f| {
                                let name = f
                                    .get("filename")
                                    .or_else(|| f.get("abs_path"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                f.get("in_app").and_then(|v| v.as_bool()) == Some(true)
                                    && !is_internal_or_non_app_frame(name)
                            })
                            .or_else(|| {
                                frames.iter().rev().find(|f| {
                                    let name = f
                                        .get("filename")
                                        .or_else(|| f.get("abs_path"))
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("");
                                    f.get("in_app").and_then(|v| v.as_bool()) != Some(false)
                                        && !is_internal_or_non_app_frame(name)
                                })
                            })
                            .or_else(|| frames.last());
                        if let Some(frame) = chosen {
                            let file = frame
                                .get("filename")
                                .or_else(|| frame.get("module"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let func = frame.get("function").and_then(|v| v.as_str()).unwrap_or("");
                            culprit = match (file.is_empty(), func.is_empty()) {
                                (false, false) => format!("{file} in {func}"),
                                (false, true) => file.to_string(),
                                (true, false) => func.to_string(),
                                (true, true) => String::new(),
                            };
                            break;
                        }
                    }
                }
            }
        }
    }

    if title.is_empty() {
        title = format_logentry(ev).unwrap_or_else(|| "<unlabeled event>".to_string());
    }
    if title.len() > 255 {
        title = title.chars().take(255).collect();
    }
    if culprit.len() > 255 {
        culprit = culprit.chars().take(255).collect();
    }

    let default_seed = format!(
        "{}|{}|{}",
        normalize_volatile_tokens(&title),
        normalize_volatile_tokens(&culprit),
        issue_type.as_str()
    );

    let fp_seed = if let Some(fp_arr) = ev.get("fingerprint").and_then(|v| v.as_array()) {
        if fp_arr.is_empty() {
            default_seed
        } else {
            fp_arr
                .iter()
                .map(|part| match part.as_str() {
                    Some("{{ default }}") => default_seed.clone(),
                    Some(s) => s.to_string(),
                    None => part.to_string(),
                })
                .collect::<Vec<_>>()
                .join("|")
        }
    } else {
        default_seed
    };

    let mut hasher = Sha256::new();
    hasher.update(fp_seed.as_bytes());
    let fp_hex = hex::encode(hasher.finalize());
    let fingerprint = fp_hex[..32].to_string();

    let user_hash = ev.get("user").and_then(|u| u.as_object()).and_then(|u| {
        let raw = u
            .get("id")
            .or_else(|| u.get("email"))
            .or_else(|| u.get("username"))
            .or_else(|| u.get("ip_address"))
            .and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            })?;
        let mut h = Sha256::new();
        h.update(raw.as_bytes());
        Some(hex::encode(h.finalize())[..16].to_string())
    });

    let mut tags = Map::new();
    if let Some(t) = ev.get("tags").and_then(|v| v.as_object()) {
        for (k, v) in t.iter().take(64) {
            tags.insert(k.clone(), v.clone());
        }
    }
    tags.insert("level".into(), Value::String(level.clone()));
    tags.insert("environment".into(), Value::String(environment.clone()));
    if let Some(r) = &release {
        tags.insert("release".into(), Value::String(r.clone()));
    }

    let req_url = ev
        .get("request")
        .and_then(|r| r.get("url"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let search_text = format!("{title} {culprit} {req_url} {}", frame_names.join(" "))
        .chars()
        .take(1024)
        .collect();

    ComputedIssueMetadata {
        event_id,
        fingerprint,
        title,
        culprit,
        level,
        issue_type,
        environment,
        release,
        trace_id,
        span_id,
        user_hash,
        tags: Value::Object(tags),
        search_text,
    }
}

/// Smart Regression Detector: if issue was resolved in a specific release `resolved_in_release`,
/// ignore stale events still coming from that exact older release to prevent false regressions.
pub fn should_reopen_on_regression(
    current_status: IssueStatus,
    resolved_in_release: Option<&str>,
    event_release: Option<&str>,
) -> bool {
    if current_status != IssueStatus::Resolved {
        return false;
    }
    match (resolved_in_release, event_release) {
        (Some(resolved), Some(ev_rel)) if !resolved.is_empty() => resolved != ev_rel,
        _ => true,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterDecision {
    Accept,
    Drop(&'static str),
}

const CRAWLER_SUBSTRINGS: &[&str] = &[
    "googlebot",
    "bingbot",
    "bytespider",
    "ahrefsbot",
    "semrushbot",
    "baiduspider",
    "yandexbot",
    "duckduckbot",
];

const EXTENSION_PREFIXES: &[&str] = &[
    "chrome-extension://",
    "moz-extension://",
    "safari-extension://",
    "safari-web-extension://",
    "ms-browser-extension://",
    "edge-extension://",
];

const THIRD_PARTY_WIDGET_HOSTS: &[&str] = &[
    "translate.googleapis.com",
    "translate-pa.googleapis.com",
    "googletagmanager.com",
    "google-analytics.com",
    "connect.facebook.net",
    "doubleclick.net",
    "googlesyndication.com",
    "cloudflareinsights.com",
    "static.cloudflareinsights.com",
    "hotjar.com",
    "intercom.io",
    "tawk.to",
    "crisp.chat",
];

static CRAWLER_AC: OnceLock<AhoCorasick> = OnceLock::new();
static THIRD_PARTY_WIDGET_AC: OnceLock<AhoCorasick> = OnceLock::new();

fn crawler_ac() -> &'static AhoCorasick {
    CRAWLER_AC.get_or_init(|| {
        AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(CRAWLER_SUBSTRINGS)
            .expect("Crawler AhoCorasick must compile")
    })
}

fn third_party_widget_ac() -> &'static AhoCorasick {
    THIRD_PARTY_WIDGET_AC.get_or_init(|| {
        AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(THIRD_PARTY_WIDGET_HOSTS)
            .expect("Third-party widget AhoCorasick must compile")
    })
}

/// Returns true if a frame path/URL clearly belongs to a third-party widget/tracker.
pub fn is_third_party_widget_url(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    third_party_widget_ac().is_match(trimmed)
}

/// Returns true if a stack frame belongs to the telemetry SDK, browser automation eval,
/// browser extensions, `node_modules`, or an external third-party widget.
pub fn is_internal_or_non_app_frame(raw: &str) -> bool {
    let low = raw.trim().to_ascii_lowercase();
    if low.is_empty() {
        return true;
    }
    if EXTENSION_PREFIXES.iter().any(|p| low.starts_with(p)) {
        return true;
    }
    if is_third_party_widget_url(&low) {
        return true;
    }
    low.contains("bugfinder-mini.js")
        || low.contains("bugfinder-shield.js")
        || low.contains("/_obs/m.js")
        || low.contains("/_obs/s.js")
        || low.starts_with("pptr:")
        || low.contains("puppeteer")
        || low.contains("playwright")
        || low.contains("node_modules")
}

pub fn is_origin_allowed(origin_or_referer: &str, allowed_domains: &[String]) -> bool {
    if allowed_domains.is_empty() {
        return true;
    }
    let host = origin_or_referer
        .split("://")
        .nth(1)
        .unwrap_or(origin_or_referer)
        .split(&['/', '?', '#'][..])
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    allowed_domains.iter().any(|d| {
        let d_raw = d.trim().to_ascii_lowercase();
        let d_low = d_raw
            .split("://")
            .last()
            .unwrap_or(&d_raw)
            .split(&['/', '?', '#'][..])
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("");
        if d_low.is_empty() {
            return false;
        }
        if let Some(suffix) = d_low.strip_prefix("*.") {
            host == suffix || host.ends_with(&format!(".{suffix}"))
        } else {
            host == d_low
        }
    })
}

/// Edge Inbound Filters protecting quota & noise before DB batching.
pub fn evaluate_inbound_filters(
    ev: &Value,
    origin_or_referer: Option<&str>,
    user_agent: Option<&str>,
    filters: &ProjectFilters,
) -> FilterDecision {
    if filters.ignore_crawlers {
        if let Some(ua) = user_agent {
            if crawler_ac().is_match(ua) {
                return FilterDecision::Drop("crawler");
            }
        }
    }

    let req_url = ev
        .get("request")
        .and_then(|r| r.get("url"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if filters.ignore_localhost {
        let check_target = origin_or_referer.unwrap_or(req_url).to_ascii_lowercase();
        if check_target.contains("://localhost") || check_target.contains("://127.0.0.1") {
            return FilterDecision::Drop("localhost");
        }
    }

    if !filters.allowed_domains.is_empty() {
        let source = origin_or_referer.or(if req_url.is_empty() {
            None
        } else {
            Some(req_url)
        });
        if let Some(src) = source {
            if !is_origin_allowed(src, &filters.allowed_domains) {
                return FilterDecision::Drop("disallowed_domain");
            }
        }
    }

    if filters.ignore_browser_extensions {
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
                        for key in ["filename", "abs_path"] {
                            if let Some(f) = fr.get(key).and_then(|v| v.as_str()) {
                                let low = f.to_ascii_lowercase();
                                if EXTENSION_PREFIXES.iter().any(|p| low.starts_with(p)) {
                                    return FilterDecision::Drop("browser_extension");
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if filters.ignore_third_party_scripts {
        if let Some(vals) = ev
            .get("exception")
            .and_then(|e| e.get("values"))
            .and_then(|v| v.as_array())
        {
            let mut saw_third_party = false;
            let mut saw_app_frame = false;
            for exc in vals {
                if let Some(frames) = exc
                    .get("stacktrace")
                    .and_then(|s| s.get("frames"))
                    .and_then(|f| f.as_array())
                {
                    for fr in frames {
                        let fname = fr
                            .get("filename")
                            .or_else(|| fr.get("abs_path"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        if fname.is_empty() {
                            continue;
                        }
                        if is_third_party_widget_url(fname) {
                            saw_third_party = true;
                        } else if !is_internal_or_non_app_frame(fname) {
                            saw_app_frame = true;
                        }
                    }
                }
            }
            if saw_third_party && !saw_app_frame {
                return FilterDecision::Drop("third_party_script");
            }
        }
    }

    if !filters.ignore_messages.is_empty() {
        let meta = extract_issue_metadata(ev);
        let lower_title = meta.title.to_ascii_lowercase();
        for pat in &filters.ignore_messages {
            let p = pat.trim().to_ascii_lowercase();
            if !p.is_empty() && lower_title.contains(&p) {
                return FilterDecision::Drop("ignored_message");
            }
        }
    }

    FilterDecision::Accept
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn groups_volatile_ids_into_same_fingerprint() {
        let e1 = json!({
            "exception": {
                "values": [{
                    "type": "CheckoutError",
                    "value": "Order 981234 failed for user 550e8400-e29b-41d4-a716-446655440000",
                    "stacktrace": {"frames": [{"filename": "src/checkout.ts", "function": "pay", "in_app": true}]}
                }]
            }
        });
        let e2 = json!({
            "exception": {
                "values": [{
                    "type": "CheckoutError",
                    "value": "Order 112233 failed for user 123e4567-e89b-12d3-a456-426614174000",
                    "stacktrace": {"frames": [{"filename": "src/checkout.ts", "function": "pay", "in_app": true}]}
                }]
            }
        });
        let m1 = extract_issue_metadata(&e1);
        let m2 = extract_issue_metadata(&e2);
        assert_eq!(m1.fingerprint, m2.fingerprint);
        assert_eq!(m1.culprit, "src/checkout.ts in pay");
    }

    #[test]
    fn smart_regression_and_inbound_filters() {
        assert!(!should_reopen_on_regression(
            IssueStatus::Resolved,
            Some("v1.0.0"),
            Some("v1.0.0")
        ));
        assert!(should_reopen_on_regression(
            IssueStatus::Resolved,
            Some("v1.0.0"),
            Some("v1.0.1")
        ));

        let filters = ProjectFilters {
            allowed_domains: vec!["*.acme.example".into()],
            ..Default::default()
        };
        let ext_ev = json!({
            "exception": {"values": [{"stacktrace": {"frames": [{"filename": "chrome-extension://abc/content.js"}]}}]}
        });
        assert_eq!(
            evaluate_inbound_filters(&ext_ev, Some("https://app.acme.example"), None, &filters),
            FilterDecision::Drop("browser_extension")
        );
        let ok_ev = json!({"message": "ok"});
        assert_eq!(
            evaluate_inbound_filters(&ok_ev, Some("https://evil.com"), None, &filters),
            FilterDecision::Drop("disallowed_domain")
        );
        assert_eq!(
            evaluate_inbound_filters(
                &ok_ev,
                Some("https://app.acme.example"),
                Some("Googlebot/2.1"),
                &filters
            ),
            FilterDecision::Drop("crawler")
        );
        assert_eq!(
            evaluate_inbound_filters(
                &ok_ev,
                Some("https://app.acme.example"),
                Some("Mozilla/5.0"),
                &filters
            ),
            FilterDecision::Accept
        );

        let widget_only = json!({
            "exception": {
                "values": [{
                    "type": "TypeError",
                    "value": "NetworkError",
                    "stacktrace": {
                        "frames": [
                            { "filename": "https://app.acme.example/sdk/bugfinder-mini.js", "in_app": true },
                            { "filename": "https://translate.googleapis.com/translate_a/element.js", "in_app": true }
                        ]
                    }
                }]
            }
        });
        assert_eq!(
            evaluate_inbound_filters(
                &widget_only,
                Some("https://app.acme.example"),
                None,
                &filters
            ),
            FilterDecision::Drop("third_party_script")
        );

        let sdk_plus_app = json!({
            "exception": {
                "values": [{
                    "type": "TypeError",
                    "value": "Failed to fetch",
                    "stacktrace": {
                        "frames": [
                            { "filename": "https://app.acme.example/assets/app.js", "function": "submitLead", "in_app": true },
                            { "filename": "https://app.acme.example/sdk/bugfinder-mini.js", "function": "root.fetch", "in_app": true }
                        ]
                    }
                }]
            }
        });
        let meta = extract_issue_metadata(&sdk_plus_app);
        assert_eq!(
            meta.culprit,
            "https://app.acme.example/assets/app.js in submitLead"
        );
    }
}
