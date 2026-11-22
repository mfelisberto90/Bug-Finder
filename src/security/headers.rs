use crate::config::AppConfig;
use crate::security::auth::random_token_b64;
use crate::security::ratelimit::BoundedMap;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct CspNonce(pub String);

#[derive(Debug, Clone)]
pub struct ClientIp(pub IpAddr);

const SCANNER_USER_AGENTS: &[&str] = &[
    "sqlmap", "nuclei", "nikto", "ffuf", "gobuster", "masscan", "zgrab", "dirbuster",
];

const CANARY_PATHS: &[&str] = &[
    "/.env",
    "/.git/config",
    "/wp-login.php",
    "/xmlrpc.php",
    "/phpmyadmin",
    "/admin.php",
];

pub struct ScannerGuard {
    bans: Mutex<BoundedMap<String, Instant>>,
}

impl ScannerGuard {
    pub fn new() -> Self {
        Self {
            bans: Mutex::new(BoundedMap::new(4096)),
        }
    }

    pub fn is_banned(&self, ip_hmac: &str) -> bool {
        let mut guard = self.bans.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(until) = guard.get_mut(&ip_hmac.to_string()) {
            if Instant::now() < *until {
                return true;
            }
            guard.remove(&ip_hmac.to_string());
        }
        false
    }

    pub fn ban_15m(&self, ip_hmac: &str) {
        let mut guard = self.bans.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(ip_hmac.to_string(), Instant::now() + Duration::from_secs(900));
    }
}

pub fn resolve_client_ip(
    headers: &HeaderMap,
    peer_ip: IpAddr,
    config: &AppConfig,
) -> IpAddr {
    if !config.is_trusted_proxy(peer_ip) {
        return peer_ip;
    }
    if let Some(cf) = headers.get("cf-connecting-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = cf.trim().parse::<IpAddr>() {
            return ip;
        }
    }
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        // Rightmost untrusted IP if multi-hop (bounded to 16 hops matching GlitchTip proxy_headers.py)
        for raw in xff.split(',').rev().take(16) {
            if let Ok(ip) = raw.trim().parse::<IpAddr>() {
                if !config.is_trusted_proxy(ip) {
                    return ip;
                }
            }
        }
    }
    peer_ip
}

pub fn normalize_host_header(host_header: &str) -> String {
    let trimmed = host_header.trim();
    if trimmed.starts_with('[') {
        trimmed
            .split(']')
            .next()
            .map(|s| format!("{}]", s.to_ascii_lowercase()))
            .unwrap_or_default()
    } else {
        trimmed
            .split(':')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase()
    }
}

pub fn is_allowed_desktop_host(host_header: &str) -> bool {
    let host_no_port = normalize_host_header(host_header);
    matches!(host_no_port.as_str(), "127.0.0.1" | "localhost" | "[::1]")
}

pub fn is_allowed_host(host_header: &str, config: &AppConfig) -> bool {
    if config.desktop_app_mode {
        return !host_header.is_empty() && is_allowed_desktop_host(host_header);
    }
    if config.allowed_hosts.is_empty() {
        return true;
    }
    if host_header.trim().is_empty() {
        return false;
    }
    let host = normalize_host_header(host_header);
    if config.is_dev && matches!(host.as_str(), "127.0.0.1" | "localhost" | "[::1]") {
        return true;
    }
    config.allowed_hosts.iter().any(|h| h == &host)
}

pub fn is_https_request(headers: &HeaderMap, config: &AppConfig) -> bool {
    if config.force_secure_cookies {
        return true;
    }
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|p| p.eq_ignore_ascii_case("https"))
        .unwrap_or(false)
}

/// Validates browser Origin / Sec-Fetch-Site on state-mutating cookie-authenticated requests.
pub fn validate_same_origin(headers: &HeaderMap, config: &AppConfig) -> bool {
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let orig = origin.trim().trim_end_matches('/');
        if orig.is_empty() {
            return false;
        }
        let orig_lower = orig.to_ascii_lowercase();
        let orig_host_port = orig_lower
            .strip_prefix("https://")
            .or_else(|| orig_lower.strip_prefix("http://"))
            .unwrap_or("")
            .split('/')
            .next()
            .unwrap_or("");
        if orig_host_port.is_empty() {
            return false;
        }
        if let Some(ref pub_url) = config.public_url {
            if pub_url.trim_end_matches('/').eq_ignore_ascii_case(orig) {
                return true;
            }
        }
        if let Some(req_host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) {
            if orig_host_port.eq_ignore_ascii_case(req_host.trim()) {
                return true;
            }
            let req_norm = normalize_host_header(req_host);
            let orig_norm = normalize_host_header(orig_host_port);
            if !req_norm.is_empty() && req_norm == orig_norm {
                return true;
            }
        }
        if config.is_dev && is_allowed_desktop_host(orig_host_port) {
            return true;
        }
        return false;
    }
    if let Some(sfs) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        let v = sfs.trim().to_ascii_lowercase();
        return v == "same-origin" || v == "none";
    }
    true
}

pub fn inject_csp_nonce_into_html(html: &str, nonce: &str) -> String {
    // Re-inject fresh per-request nonce into Vite-built <script, <link rel="stylesheet", <style tags
    let nonce_attr = format!(" nonce=\"{nonce}\"");
    let mut out = String::with_capacity(html.len() + 256);
    let mut rest = html;

    while let Some(pos) = rest.find('<') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos..];
        let lower_prefix: String = after.chars().take(48).collect::<String>().to_ascii_lowercase();

        if lower_prefix.starts_with("<script ")
            || lower_prefix.starts_with("<script>")
        {
            let tag_prefix_len = if lower_prefix.starts_with("<script>") { 7 } else { 7 };
            out.push_str(&after[..tag_prefix_len]);
            if !lower_prefix.contains("nonce=") {
                out.push_str(&nonce_attr);
            }
            rest = &after[tag_prefix_len..];
        } else if lower_prefix.starts_with("<style ")
            || lower_prefix.starts_with("<style>")
        {
            out.push_str(&after[..6]);
            if !lower_prefix.contains("nonce=") {
                out.push_str(&nonce_attr);
            }
            rest = &after[6..];
        } else if lower_prefix.starts_with("<link ") {
            if let Some(gt) = after.find('>') {
                let tag = &after[..gt];
                let tag_low = tag.to_ascii_lowercase();
                if tag_low.contains("stylesheet") && !tag_low.contains("nonce=") {
                    out.push_str("<link");
                    out.push_str(&nonce_attr);
                    out.push_str(&tag[5..]);
                } else {
                    out.push_str(tag);
                }
                rest = &after[gt..];
            } else {
                out.push('<');
                rest = &after[1..];
            }
        } else {
            out.push('<');
            rest = &after[1..];
        }
    }
    out.push_str(rest);
    out
}

pub async fn security_headers_middleware(
    State(state): State<Arc<crate::AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();

    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !is_allowed_host(host, &state.config) {
        return (StatusCode::FORBIDDEN, "Forbidden host").into_response();
    }

    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));
    let client_ip = resolve_client_ip(&headers, peer_ip, &state.config);

    let has_session_cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| {
            raw.split(';').find_map(|part| {
                let (k, v) = part.trim().split_once('=')?;
                if k.trim() == "bf_session" {
                    Some(v.trim())
                } else {
                    None
                }
            })
        })
        .map(|val| {
            val.len() >= 32
                && val
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .unwrap_or(false);
    let has_ingest_auth = headers.contains_key("x-sentry-auth")
        || headers.contains_key(header::AUTHORIZATION)
        || req.uri().query().map(|q| q.contains("sentry_key=") || q.contains("glitchtip_key=")).unwrap_or(false);

    // CGNAT-safe scanner & honeypot guard: always exempt active authenticated sessions and signed/DSN ingest
    if !has_session_cookie && !has_ingest_auth {
        let ip_hmac = state.rate_limiter.hash_key("honeypot", &client_ip.to_string());
        if state.scanner_guard.is_banned(&ip_hmac) {
            return (StatusCode::TOO_MANY_REQUESTS, "Temporarily blocked").into_response();
        }
        let ua = headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_canary = CANARY_PATHS.iter().any(|c| path.eq_ignore_ascii_case(c));
        let is_scanner = SCANNER_USER_AGENTS.iter().any(|s| ua.contains(s));
        if is_canary || is_scanner {
            state.scanner_guard.ban_15m(&ip_hmac);
            return (StatusCode::NOT_FOUND, "Not found").into_response();
        }
    }

    let nonce = random_token_b64(18);
    let mut req = req;
    req.extensions_mut().insert(CspNonce(nonce.clone()));
    req.extensions_mut().insert(ClientIp(client_ip));

    let is_https = is_https_request(&headers, &state.config);
    let mut resp = next.run(req).await;
    if resp.status().is_server_error() {
        state.self_monitor.record(
            "http_5xx",
            "error",
            "http",
            &format!("HTTP {} on {}", resp.status().as_u16(), path),
            None,
        );
        state
            .metrics
            .self_errors_total
            .fetch_add(1, Ordering::Relaxed);
    }
    let h = resp.headers_mut();

    let csp = format!(
        "default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'nonce-{nonce}'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    );
    if let Ok(v) = HeaderValue::from_str(&csp) {
        h.insert("content-security-policy", v);
    }
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    h.remove("x-powered-by");
    h.remove("server");

    if is_https {
        h.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        );
    }

    if path.starts_with("/api/") {
        h.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, private"),
        );
    }
    if path != "/robots.txt" && !path.starts_with("/sdk/") {
        h.insert(
            "x-robots-tag",
            HeaderValue::from_static("noindex, nofollow, noarchive"),
        );
    }

    if path == "/robots.txt" || path == "/api/health" {
        h.remove(header::SET_COOKIE);
    }

    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injects_csp_nonce_into_vite_tags_without_unsafe_inline() {
        let html = r#"<!doctype html><html><head><link rel="stylesheet" href="/assets/app.css"><style>:root{}</style><script type="module" src="/assets/app.js"></script><script>init();</script></head></html>"#;
        let out = inject_csp_nonce_into_html(html, "NONCE123");
        assert!(out.contains(r#"<link nonce="NONCE123" rel="stylesheet""#));
        assert!(out.contains(r#"<style nonce="NONCE123">"#));
        assert!(out.contains(r#"<script nonce="NONCE123" type="module""#));
        assert!(out.contains(r#"<script nonce="NONCE123">"#));
    }

    #[test]
    fn desktop_host_allowlist_blocks_rebinding() {
        assert!(is_allowed_desktop_host("127.0.0.1:8080"));
        assert!(is_allowed_desktop_host("localhost:3000"));
        assert!(is_allowed_desktop_host("[::1]:8080"));
        assert!(!is_allowed_desktop_host("evil.attacker.com:8080"));
    }
}
