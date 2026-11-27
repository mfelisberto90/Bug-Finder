use crate::domain::models::{NormalizedLog, ShieldPolicy};
use crate::security::auth::sha256_hex;
use crate::security::ratelimit::ShardedBoundedMap;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::HashSet;

type HmacSha256 = Hmac<Sha256>;

const STATIC_ASSET_EXTS: &[&str] = &[
    ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".woff", ".woff2", ".css",
];

#[derive(Debug, Clone)]
pub struct ScoredSignals {
    pub risk_score: u32,
    pub primary_signal: String,
    pub category: String,
    pub severity: String,
}

#[derive(Debug, Clone)]
pub struct DetectedLogThreat {
    pub signal_type: String,
    pub category: String,
    pub risk_score: u32,
    pub severity: String,
    pub actor_hmac: String,
    pub path: String,
    pub details: Value,
}

#[derive(Debug, Clone)]
pub struct RuntimeIntegrityReport {
    pub ok: bool,
    pub detail: String,
    pub indicators: Vec<String>,
}

pub struct ShieldEngine {
    auth_bursts: ShardedBoundedMap<(i64, String), (i64, u32), 16>,
    cooldowns: ShardedBoundedMap<(i64, String), i64, 16>,
}

impl Default for ShieldEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ShieldEngine {
    pub fn new() -> Self {
        Self {
            auth_bursts: ShardedBoundedMap::new(4096),
            cooldowns: ShardedBoundedMap::new(4096),
        }
    }

    pub fn allow_cooldown(
        &self,
        project_id: i64,
        key: &str,
        cooldown_ms: i64,
        now_ms: i64,
    ) -> bool {
        let k = (project_id, key.to_string());
        self.cooldowns.with_shard_mut(&k, |guard| {
            if let Some(last) = guard.get_mut(&k) {
                if now_ms - *last < cooldown_ms {
                    return false;
                }
            }
            guard.insert(k.clone(), now_ms);
            true
        })
    }

    /// Evaluates logs/errors already ingested using deterministic signatures + bounded O(1) burst counters.
    pub fn inspect_log_for_threats<F>(
        &self,
        project_id: i64,
        policy: &ShieldPolicy,
        now_ms: i64,
        actor_hmac_fn: F,
        log: &NormalizedLog,
    ) -> Option<DetectedLogThreat>
    where
        F: Fn(&str) -> String,
    {
        if !policy.enabled || !policy.log_ids_enabled {
            return None;
        }
        if log.service == "bugfinder-selfcheck" || log.service == "bugfinder-self-probe" {
            return None;
        }

        let path = extract_log_path(&log.attributes);
        let raw_actor = extract_log_actor(&log.attributes);
        let actor_hmac = raw_actor
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(&actor_hmac_fn)
            .unwrap_or_default();

        // 1. High-confidence injection / traversal / SSRF exploit probe check
        let probe_kind = detect_probe_in_text(&log.body)
            .or_else(|| path.as_deref().and_then(detect_probe_in_text));
        if let Some(kind) = probe_kind {
            let cooldown_key = format!("probe:{kind}:{}", path.as_deref().unwrap_or("-"));
            if self.allow_cooldown(project_id, &cooldown_key, 60_000, now_ms) {
                return Some(DetectedLogThreat {
                    signal_type: "injection_probe".to_string(),
                    category: "log_ids".to_string(),
                    risk_score: 75,
                    severity: "high".to_string(),
                    actor_hmac,
                    path: path.unwrap_or_default(),
                    details: json!({
                        "probe_kind": kind,
                        "service": log.service,
                    }),
                });
            }
            return None;
        }

        // 2. Structured 401/403/404 IDOR & enumeration burst check (>= 20 hits in 60s)
        if raw_actor.is_none() || actor_hmac.is_empty() {
            return None;
        }
        let status = extract_http_status(&log.attributes)?;
        if !matches!(status, 401 | 403 | 404) {
            return None;
        }
        if let Some(ref p) = path {
            let low = p.split('?').next().unwrap_or("").to_ascii_lowercase();
            if low == "/favicon.ico" || STATIC_ASSET_EXTS.iter().any(|ext| low.ends_with(ext)) {
                return None;
            }
        }

        let burst_hit = {
            let key = (project_id, actor_hmac.clone());
            self.auth_bursts.with_shard_mut(&key, |guard| {
                let mut reached = false;
                match guard.get_mut(&key) {
                    Some((win_start, count)) if now_ms - *win_start <= 60_000 => {
                        *count = count.saturating_add(1);
                        if *count >= 20 {
                            reached = true;
                            *count = 0;
                            *win_start = now_ms;
                        }
                    }
                    _ => {
                        guard.insert(key.clone(), (now_ms, 1));
                    }
                }
                reached
            })
        };

        if burst_hit
            && self.allow_cooldown(project_id, &format!("burst:{actor_hmac}"), 300_000, now_ms)
        {
            return Some(DetectedLogThreat {
                signal_type: "idor_or_enum_burst".to_string(),
                category: "log_ids".to_string(),
                risk_score: 65,
                severity: "medium".to_string(),
                actor_hmac,
                path: path.unwrap_or_default(),
                details: json!({
                    "http_status": status,
                    "hits_60s": 20,
                    "service": log.service,
                }),
            });
        }

        None
    }
}

pub fn score_signals(signals: &[String]) -> Option<ScoredSignals> {
    if signals.is_empty() {
        return None;
    }
    let mut seen = HashSet::new();
    let mut total = 0u32;
    let mut best_sig = "";
    let mut best_weight = 0u32;
    let mut best_cat = "anti_rea";

    for raw in signals {
        let norm = raw.trim().to_ascii_lowercase();
        if norm.is_empty() || !seen.insert(norm.clone()) {
            continue;
        }
        let (weight, cat) = match norm.as_str() {
            "runtime_debugger_attached" => (80, "anti_rea"),
            "canary_route_hit" => (75, "anti_rea"),
            "injection_probe" => (75, "log_ids"),
            "honeypot_access" => (70, "anti_rea"),
            "scanner_user_agent" => (70, "edge_waf"),
            "anomalous_http_probe" => (70, "edge_waf"),
            "sourcemap_harvest" => (65, "anti_rea"),
            "idor_or_enum_burst" => (65, "log_ids"),
            "secret_leak" => (60, "secret_leak"),
            "cdp_automation" => (50, "anti_rea"),
            "webdriver_detected" => (45, "anti_rea"),
            "runtime_hook_tamper" => (40, "anti_rea"),
            "csp_script_tamper" => (40, "csp"),
            "dom_script_injection" => (35, "anti_rea"),
            _ => continue,
        };
        total = total.saturating_add(weight).min(100);
        if weight > best_weight {
            best_weight = weight;
            best_sig = match norm.as_str() {
                "runtime_debugger_attached" => "runtime_debugger_attached",
                "canary_route_hit" => "canary_route_hit",
                "injection_probe" => "injection_probe",
                "honeypot_access" => "honeypot_access",
                "scanner_user_agent" => "scanner_user_agent",
                "anomalous_http_probe" => "anomalous_http_probe",
                "sourcemap_harvest" => "sourcemap_harvest",
                "idor_or_enum_burst" => "idor_or_enum_burst",
                "secret_leak" => "secret_leak",
                "cdp_automation" => "cdp_automation",
                "webdriver_detected" => "webdriver_detected",
                "runtime_hook_tamper" => "runtime_hook_tamper",
                "csp_script_tamper" => "csp_script_tamper",
                _ => "dom_script_injection",
            };
            best_cat = cat;
        }
    }

    if best_weight == 0 {
        return None;
    }

    let severity = if total >= 85 {
        "critical"
    } else if total >= 70 {
        "high"
    } else if total >= 40 {
        "medium"
    } else {
        "low"
    };

    Some(ScoredSignals {
        risk_score: total,
        primary_signal: best_sig.to_string(),
        category: best_cat.to_string(),
        severity: severity.to_string(),
    })
}

/// CGNAT-safe quarantine decision:
/// Unverified browser reports NEVER ban shared client IPs — only `session` tokens.
/// Verified backend middleware / Log-IDS triggers may quarantine the `ip` HMAC.
pub fn decide_quarantine(
    policy: &ShieldPolicy,
    source_kind: &str,
    risk_score: u32,
    actor_hmac: &str,
    session_id: Option<&str>,
) -> Option<(String, String)> {
    if !policy.enabled || risk_score < policy.quarantine_threshold {
        return None;
    }
    let clean_sid = session_id.map(str::trim).filter(|s| s.len() >= 8);
    match source_kind {
        "browser" => clean_sid.map(|sid| ("session".to_string(), sha256_hex(sid.as_bytes()))),
        "backend_verified" | "log_ids" => {
            if !actor_hmac.is_empty() {
                Some(("ip".to_string(), actor_hmac.to_string()))
            } else {
                clean_sid.map(|sid| ("session".to_string(), sha256_hex(sid.as_bytes())))
            }
        }
        _ => None,
    }
}

pub fn inspect_csp_for_tamper(raw_csp: &Value) -> Option<String> {
    let report = raw_csp.get("csp-report").unwrap_or(raw_csp);
    let directive = report
        .get("effective-directive")
        .or_else(|| report.get("violated-directive"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if !directive.starts_with("script-src") {
        return None;
    }
    let blocked = report
        .get("blocked-uri")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let low = blocked.to_ascii_lowercase();
    if low.starts_with("chrome-extension:")
        || low.starts_with("moz-extension:")
        || low.starts_with("safari-extension:")
        || low.starts_with("safari-web-extension:")
        || low == "about"
        || low == "data"
        || low == "blob"
    {
        return None;
    }
    if low == "eval" || low.starts_with("http://") || low.starts_with("https://") {
        return Some(blocked.chars().take(160).collect());
    }
    None
}

fn detect_probe_in_text(text: &str) -> Option<&'static str> {
    if text.len() < 8 {
        return None;
    }
    crate::security::waf::detect_probe_in_bytes(text.as_bytes())
}

/// Bounded `< 1 µs` SIMD HTTP URI/query exploit inspector (delegated to `security::waf`).
pub fn detect_http_exploit_probe(raw_uri: &str) -> Option<&'static str> {
    crate::security::waf::detect_http_exploit_probe(raw_uri)
}

fn extract_http_status(attrs: &Value) -> Option<u16> {
    let obj = attrs.as_object()?;
    for key in [
        "http.response.status_code",
        "http.status_code",
        "status_code",
        "status",
    ] {
        if let Some(v) = obj.get(key) {
            if let Some(n) = v
                .as_u64()
                .or_else(|| v.get("value").and_then(|x| x.as_u64()))
            {
                if (100..=599).contains(&n) {
                    return Some(n as u16);
                }
            }
            if let Some(s) = v
                .as_str()
                .or_else(|| v.get("value").and_then(|x| x.as_str()))
            {
                if let Ok(n) = s.trim().parse::<u16>() {
                    if (100..=599).contains(&n) {
                        return Some(n);
                    }
                }
            }
        }
    }
    None
}

fn extract_log_path(attrs: &Value) -> Option<String> {
    let obj = attrs.as_object()?;
    for key in ["url.path", "http.target", "http.route", "path", "url"] {
        if let Some(v) = obj.get(key) {
            if let Some(s) = v
                .as_str()
                .or_else(|| v.get("value").and_then(|x| x.as_str()))
            {
                let t = s.trim();
                if !t.is_empty() {
                    return Some(t.chars().take(200).collect());
                }
            }
        }
    }
    None
}

fn extract_log_actor(attrs: &Value) -> Option<String> {
    let obj = attrs.as_object()?;
    for key in [
        "client.address",
        "http.client_ip",
        "user.id",
        "actor_id",
        "session_id",
    ] {
        if let Some(v) = obj.get(key) {
            if let Some(s) = v
                .as_str()
                .or_else(|| v.get("value").and_then(|x| x.as_str()))
            {
                let t = s.trim();
                if !t.is_empty() {
                    return Some(t.chars().take(128).collect());
                }
            }
            if let Some(n) = v
                .as_i64()
                .or_else(|| v.get("value").and_then(|x| x.as_i64()))
            {
                return Some(n.to_string());
            }
        }
    }
    None
}

pub fn probe_self_runtime_integrity() -> RuntimeIntegrityReport {
    let mut indicators = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(val) = line.strip_prefix("TracerPid:") {
                    if let Ok(pid) = val.trim().parse::<u32>() {
                        if pid != 0 {
                            indicators.push(format!("TracerPid={pid}"));
                        }
                    }
                }
            }
        }
        if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
            let low = maps.to_ascii_lowercase();
            for pat in ["frida-agent", "frida-gadget", "libfrida", "gdbserver"] {
                if low.contains(pat) {
                    indicators.push(format!("mapped:{pat}"));
                }
            }
        }
    }

    for env_key in ["LD_PRELOAD", "LD_AUDIT"] {
        if let Ok(val) = std::env::var(env_key) {
            if !val.trim().is_empty() {
                indicators.push(format!("env:{env_key}"));
            }
        }
    }

    if indicators.is_empty() {
        RuntimeIntegrityReport {
            ok: true,
            detail: "Zero active debugger TracerPid, Frida/hook shared objects, or LD_PRELOAD injections detected.".into(),
            indicators,
        }
    } else {
        RuntimeIntegrityReport {
            ok: false,
            detail: format!(
                "Runtime instrumentation / debugger indicator(s): {}",
                indicators.join(", ")
            ),
            indicators,
        }
    }
}

pub fn apply_anti_ptrace_if_enabled(enabled: bool) {
    if !enabled {
        return;
    }
    #[cfg(target_os = "linux")]
    unsafe {
        let _ = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

/// Derives a per-project IP HMAC key from the master `app_key` so monitored backends
/// consuming `/shield/blocklist/` can match `req.ip` deterministically without `app_key` exposure.
pub fn derive_project_ip_hmac_key(app_key: &[u8; 32], project_id: i64) -> String {
    let mut mac = HmacSha256::new_from_slice(app_key).expect("HMAC key accepts 32-byte key");
    mac.update(format!("shield-ip-key:{project_id}").as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn shield_ip_hmac(app_key: &[u8; 32], project_id: i64, raw_ip: &str) -> String {
    let project_key = derive_project_ip_hmac_key(app_key, project_id);
    let mut mac = HmacSha256::new_from_slice(project_key.as_bytes()).expect("HMAC accepts hex key");
    mac.update(raw_ip.trim().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::LogLevel;

    #[test]
    fn scoring_and_cgnat_safe_quarantine_behavior() {
        let single = score_signals(&["cdp_automation".into()]).unwrap();
        assert_eq!(single.risk_score, 50);
        assert_eq!(single.severity, "medium");

        let combo = score_signals(&[
            "cdp_automation".into(),
            "cdp_automation".into(),
            "honeypot_access".into(),
        ])
        .unwrap();
        assert_eq!(combo.risk_score, 100);
        assert_eq!(combo.severity, "critical");

        let policy = ShieldPolicy::default();
        // Browser report NEVER bans IP globally; only quarantines session
        assert_eq!(
            decide_quarantine(&policy, "browser", 90, "ip_hmac_1", None),
            None
        );
        let br_q =
            decide_quarantine(&policy, "browser", 90, "ip_hmac_1", Some("sess_12345678")).unwrap();
        assert_eq!(br_q.0, "session");

        // Backend verified signal quarantines actor IP HMAC
        let be_q = decide_quarantine(
            &policy,
            "backend_verified",
            90,
            "ip_hmac_1",
            Some("sess_12345678"),
        )
        .unwrap();
        assert_eq!(be_q, ("ip".to_string(), "ip_hmac_1".to_string()));
    }

    #[test]
    fn log_ids_detects_real_attacks_and_avoids_false_positives() {
        let engine = ShieldEngine::new();
        let policy = ShieldPolicy::default();
        let hash = |s: &str| format!("h_{s}");

        // False-positive checks: normal SQL prose, relative source stacktrace, selfcheck logs
        let normal_log = NormalizedLog {
            timestamp_ms: 1000,
            level: LogLevel::Info,
            severity_number: None,
            body: "User selected plan A or B from ../../src/app.ts".into(),
            service: "web".into(),
            environment: "production".into(),
            host: String::new(),
            trace_id: None,
            span_id: None,
            attributes: json!({ "url.path": "/checkout" }),
        };
        assert!(engine
            .inspect_log_for_threats(1, &policy, 1000, hash, &normal_log)
            .is_none());

        // Static favicon 404s x 30 must NOT trigger IDOR burst
        for i in 0..30 {
            let icon_log = NormalizedLog {
                timestamp_ms: 1000 + i,
                level: LogLevel::Warn,
                severity_number: None,
                body: "not found".into(),
                service: "web".into(),
                environment: "production".into(),
                host: String::new(),
                trace_id: None,
                span_id: None,
                attributes: json!({ "http.status_code": 404, "url.path": "/favicon.ico", "client.address": "1.2.3.4" }),
            };
            assert!(engine
                .inspect_log_for_threats(1, &policy, 1000 + i, hash, &icon_log)
                .is_none());
        }

        // 19 API 403s < 20 threshold -> no burst yet; 20th triggers idor_or_enum_burst
        for i in 0..19 {
            let api_403 = NormalizedLog {
                timestamp_ms: 2000 + i,
                level: LogLevel::Warn,
                severity_number: None,
                body: "forbidden".into(),
                service: "api".into(),
                environment: "production".into(),
                host: String::new(),
                trace_id: None,
                span_id: None,
                attributes: json!({ "http.status_code": 403, "url.path": "/api/users/12", "client.address": "9.9.9.9" }),
            };
            assert!(engine
                .inspect_log_for_threats(1, &policy, 2000 + i, hash, &api_403)
                .is_none());
        }
        let burst_20 = NormalizedLog {
            timestamp_ms: 2020,
            level: LogLevel::Warn,
            severity_number: None,
            body: "forbidden".into(),
            service: "api".into(),
            environment: "production".into(),
            host: String::new(),
            trace_id: None,
            span_id: None,
            attributes: json!({ "http.status_code": 403, "url.path": "/api/users/20", "client.address": "9.9.9.9" }),
        };
        let detected = engine
            .inspect_log_for_threats(1, &policy, 2020, hash, &burst_20)
            .unwrap();
        assert_eq!(detected.signal_type, "idor_or_enum_burst");

        // Positive exploit signatures
        let sqli_log = NormalizedLog {
            timestamp_ms: 3000,
            level: LogLevel::Error,
            severity_number: None,
            body: "GET /search?q=1 UNION ALL SELECT NULL,NULL".into(),
            service: "api".into(),
            environment: "production".into(),
            host: String::new(),
            trace_id: None,
            span_id: None,
            attributes: json!({}),
        };
        let sqli = engine
            .inspect_log_for_threats(1, &policy, 3000, hash, &sqli_log)
            .unwrap();
        assert_eq!(sqli.signal_type, "injection_probe");

        let trav_log = NormalizedLog {
            timestamp_ms: 3100,
            level: LogLevel::Warn,
            severity_number: None,
            body: "GET /download?f=../../../etc/passwd".into(),
            service: "api".into(),
            environment: "production".into(),
            host: String::new(),
            trace_id: None,
            span_id: None,
            attributes: json!({}),
        };
        assert_eq!(
            engine
                .inspect_log_for_threats(1, &policy, 3100, hash, &trav_log)
                .unwrap()
                .signal_type,
            "injection_probe"
        );
    }

    #[test]
    fn csp_filter_ignores_extensions_and_catches_script_injection() {
        let ext = json!({ "csp-report": { "violated-directive": "script-src", "blocked-uri": "chrome-extension://abc/x.js" } });
        assert!(inspect_csp_for_tamper(&ext).is_none());

        let evil = json!({ "csp-report": { "effective-directive": "script-src-elem", "blocked-uri": "https://evil.example/hook.js" } });
        assert_eq!(
            inspect_csp_for_tamper(&evil).as_deref(),
            Some("https://evil.example/hook.js")
        );
    }

    #[test]
    fn runtime_integrity_probe_runs_cleanly() {
        let rep = probe_self_runtime_integrity();
        assert!(!rep.detail.is_empty());
    }

    #[test]
    fn shield_ip_hmac_is_deterministic_per_project_and_isolated() {
        let app_key = [42u8; 32];
        let h1a = shield_ip_hmac(&app_key, 1, " 203.0.113.10 ");
        let h1b = shield_ip_hmac(&app_key, 1, "203.0.113.10");
        let h2 = shield_ip_hmac(&app_key, 2, "203.0.113.10");
        assert_eq!(h1a, h1b);
        assert_eq!(h1a.len(), 64);
        assert_ne!(h1a, h2);
    }

    #[test]
    fn http_exploit_probe_catches_double_encoded_attacks_and_allows_normal_queries() {
        assert_eq!(
            detect_http_exploit_probe("/items?id=1%27%20UNION%20SELECT%20NULL,NULL"),
            Some("sqli")
        );
        assert_eq!(
            detect_http_exploit_probe("/download?f=%252e%252e%252fetc%252fpasswd"),
            Some("path_traversal")
        );
        assert_eq!(
            detect_http_exploit_probe("/file?name=report.pdf%00.png"),
            Some("null_byte")
        );
        assert_eq!(
            detect_http_exploit_probe(&format!("/search?q={}", "a".repeat(4100))),
            Some("uri_overflow")
        );
        assert!(detect_http_exploit_probe(
            "/api/0/organizations/acme/issues/?query=TypeError+Failed+to+fetch&limit=50"
        )
        .is_none());

        let scored = score_signals(&[
            "scanner_user_agent".to_string(),
            "anomalous_http_probe".to_string(),
        ])
        .expect("edge_waf signals must score");
        assert_eq!(scored.category, "edge_waf");
        assert_eq!(scored.risk_score, 100);
        assert_eq!(scored.severity, "critical");
    }
}
