use crate::config::AppConfig;
use crate::http::auth_routes::extract_cookie;
use crate::security::auth::{random_token_b64, sha256_hex};
use crate::security::ratelimit::ShardedBoundedMap;
use crate::security::waf::{
    detect_http_exploit_probe, is_anomalous_http_method, is_canary_or_dotfile_probe,
    is_scanner_user_agent, is_sourcemap_probe,
};
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct CspNonce(pub String);

#[derive(Debug, Clone)]
pub struct ClientIp(pub IpAddr);

#[derive(Debug, Clone)]
pub struct PeerIp(pub IpAddr);

const BENIGN_404_ASSET_SUFFIXES: &[&str] = &[
    ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".woff", ".woff2", ".css", ".txt",
];

pub struct ScannerGuard {
    bans: ShardedBoundedMap<String, Instant, 16>,
    strikes: ShardedBoundedMap<String, u32, 16>,
    probe_bursts: ShardedBoundedMap<String, (Instant, u32), 16>,
    active_sessions: ShardedBoundedMap<String, i64, 16>,
}

impl Default for ScannerGuard {
    fn default() -> Self {
        Self::new()
    }
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl ScannerGuard {
    pub fn new() -> Self {
        Self {
            bans: ShardedBoundedMap::new(4096),
            strikes: ShardedBoundedMap::new(4096),
            probe_bursts: ShardedBoundedMap::new(4096),
            active_sessions: ShardedBoundedMap::new(16384),
        }
    }

    pub fn track_session(&self, session_sha256: &str, expires_at: i64) {
        if session_sha256.is_empty() {
            return;
        }
        let key = session_sha256.to_string();
        self.active_sessions.with_shard_mut(&key, |guard| {
            guard.insert(key.clone(), expires_at);
        });
    }

    pub fn untrack_session(&self, session_sha256: &str) {
        if session_sha256.is_empty() {
            return;
        }
        let key = session_sha256.to_string();
        self.active_sessions.with_shard_mut(&key, |guard| {
            guard.remove(&key);
        });
    }

    pub fn is_active_session(&self, session_sha256: &str) -> bool {
        if session_sha256.is_empty() {
            return false;
        }
        let now = now_unix_secs();
        let key = session_sha256.to_string();
        self.active_sessions.with_shard_mut(&key, |guard| {
            if let Some(exp) = guard.get_mut(&key) {
                if *exp > now {
                    return true;
                }
                guard.remove(&key);
            }
            false
        })
    }

    pub fn is_banned(&self, ip_hmac: &str) -> bool {
        let key = ip_hmac.to_string();
        self.bans.with_shard_mut(&key, |guard| {
            if let Some(until) = guard.get_mut(&key) {
                if Instant::now() < *until {
                    return true;
                }
                guard.remove(&key);
            }
            false
        })
    }

    pub fn ban_15m(&self, ip_hmac: &str) {
        let key = ip_hmac.to_string();
        let strike_num = self.strikes.with_shard_mut(&key, |s_guard| {
            if let Some(cnt) = s_guard.get_mut(&key) {
                *cnt = cnt.saturating_add(1);
                *cnt
            } else {
                s_guard.insert(key.clone(), 1);
                1
            }
        });
        let ttl_secs = if strike_num >= 2 { 3600 } else { 900 };
        self.bans.with_shard_mut(&key, |guard| {
            guard.insert(key.clone(), Instant::now() + Duration::from_secs(ttl_secs));
        });
    }

    /// Behavioral enumeration scorer: quarantines unauthenticated IPs that trigger `>= 20` non-asset
    /// `404` responses within `60s` (catching custom recon scripts that spoof browser User-Agents).
    pub fn record_unauth_404_and_should_ban(&self, ip_hmac: &str, path: &str) -> bool {
        let low = path.trim().to_ascii_lowercase();
        if low == "/favicon.ico"
            || low.starts_with("/.well-known/")
            || low.starts_with("/apple-touch-icon")
            || BENIGN_404_ASSET_SUFFIXES
                .iter()
                .any(|ext| low.ends_with(ext))
        {
            return false;
        }
        let now = Instant::now();
        let key = ip_hmac.to_string();
        let reached = self
            .probe_bursts
            .with_shard_mut(&key, |guard| match guard.get_mut(&key) {
                Some((win_start, count))
                    if now.duration_since(*win_start) <= Duration::from_secs(60) =>
                {
                    *count = count.saturating_add(1);
                    if *count >= 20 {
                        *count = 0;
                        *win_start = now;
                        true
                    } else {
                        false
                    }
                }
                _ => {
                    guard.insert(key.clone(), (now, 1));
                    false
                }
            });
        if reached {
            self.ban_15m(ip_hmac);
        }
        reached
    }
}

fn parse_ip_or_socket_addr(raw: &str) -> Option<IpAddr> {
    let trimmed = raw.trim();
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(ip);
    }
    trimmed.parse::<SocketAddr>().ok().map(|sa| sa.ip())
}

pub fn resolve_client_ip(headers: &HeaderMap, peer_ip: IpAddr, config: &AppConfig) -> IpAddr {
    if !config.is_trusted_proxy(peer_ip) {
        return peer_ip;
    }
    if config.trust_cf_header && config.is_cloudflare_peer(peer_ip) {
        if let Some(cf) = headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
        {
            if let Some(ip) = parse_ip_or_socket_addr(cf) {
                return ip;
            }
        }
    }
    // RFC 9113 multi-header safe: iterate all X-Forwarded-For header lines right-to-left (bounded to 16 hops)
    let xff_vals: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let mut hops_checked = 0usize;
    for xff in xff_vals.into_iter().rev() {
        for raw in xff.split(',').rev() {
            if hops_checked >= 16 {
                return peer_ip;
            }
            hops_checked += 1;
            let Some(ip) = parse_ip_or_socket_addr(raw) else {
                // Fail closed on unparseable hop instead of continuing leftward into untrusted entries
                return peer_ip;
            };
            if !config.is_trusted_proxy(ip) {
                return ip;
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
        trimmed.split(':').next().unwrap_or("").to_ascii_lowercase()
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

fn rightmost_header_csv<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let vals: Vec<&'a str> = headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    for v in vals.into_iter().rev() {
        for part in v.rsplit(',') {
            let t = part.trim();
            if !t.is_empty() {
                return Some(t);
            }
        }
    }
    None
}

pub fn is_https_request(headers: &HeaderMap, peer_ip: IpAddr, config: &AppConfig) -> bool {
    if config.force_secure_cookies {
        return true;
    }
    if config.is_trusted_proxy(peer_ip) {
        if let Some(proto) = rightmost_header_csv(headers, "x-forwarded-proto") {
            if proto.eq_ignore_ascii_case("https") {
                return true;
            }
            if proto.eq_ignore_ascii_case("http") {
                return false;
            }
        }
    }
    config
        .public_url
        .as_deref()
        .is_some_and(|u| u.trim_start().to_ascii_lowercase().starts_with("https://"))
}

fn split_host_and_port(authority: &str) -> Option<(String, Option<u16>)> {
    let trimmed = authority.trim();
    if trimmed.is_empty() || trimmed.contains(['/', '?', '#', '@', ' ', '\t']) {
        return None;
    }
    if trimmed.starts_with('[') {
        let close = trimmed.find(']')?;
        let host = trimmed[..=close].to_ascii_lowercase();
        let rest = &trimmed[close + 1..];
        if rest.is_empty() {
            Some((host, None))
        } else if let Some(port_str) = rest.strip_prefix(':') {
            let port = port_str.parse::<u16>().ok()?;
            Some((host, Some(port)))
        } else {
            None
        }
    } else if let Some((host, port_str)) = trimmed.rsplit_once(':') {
        if host.is_empty() || host.contains(':') {
            return None;
        }
        let port = port_str.parse::<u16>().ok()?;
        Some((host.to_ascii_lowercase(), Some(port)))
    } else {
        Some((trimmed.to_ascii_lowercase(), None))
    }
}

fn parse_origin_tuple(url_or_origin: &str) -> Option<(&'static str, String, u16)> {
    let trimmed = url_or_origin.trim().trim_end_matches('/');
    let lower = trimmed.to_ascii_lowercase();
    let (scheme, default_port, rest) = lower
        .strip_prefix("https://")
        .map(|r| ("https", 443u16, r))
        .or_else(|| lower.strip_prefix("http://").map(|r| ("http", 80u16, r)))?;
    let (host, port_opt) = split_host_and_port(rest)?;
    Some((scheme, host, port_opt.unwrap_or(default_port)))
}

/// Validates browser Origin / Sec-Fetch-Site on state-mutating cookie-authenticated requests.
pub fn validate_same_origin(headers: &HeaderMap, peer_ip: IpAddr, config: &AppConfig) -> bool {
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let Some((orig_scheme, orig_host, orig_port)) = parse_origin_tuple(origin) else {
            return false;
        };
        if let Some(ref pub_url) = config.public_url {
            let pub_origin = pub_url
                .trim()
                .split('/')
                .take(3)
                .collect::<Vec<_>>()
                .join("/");
            if let Some((ps, ph, pp)) = parse_origin_tuple(&pub_origin) {
                if orig_scheme == ps && orig_host == ph && orig_port == pp {
                    return true;
                }
                if !config.is_dev {
                    return false;
                }
            }
        }
        let req_is_https = is_https_request(headers, peer_ip, config);
        let req_scheme = if req_is_https { "https" } else { "http" };
        let req_default_port = if req_is_https { 443u16 } else { 80u16 };
        let req_host_hdr = if config.is_trusted_proxy(peer_ip) {
            rightmost_header_csv(headers, "x-forwarded-host")
                .or_else(|| headers.get(header::HOST).and_then(|v| v.to_str().ok()))
        } else {
            headers.get(header::HOST).and_then(|v| v.to_str().ok())
        };
        if let Some(raw_host) = req_host_hdr {
            if let Some((req_host, req_port_opt)) = split_host_and_port(raw_host) {
                let req_port = req_port_opt.unwrap_or(req_default_port);
                if orig_scheme == req_scheme && orig_host == req_host && orig_port == req_port {
                    return true;
                }
            }
        }
        if config.is_dev
            && orig_scheme == "http"
            && matches!(orig_host.as_str(), "127.0.0.1" | "localhost" | "[::1]")
        {
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

pub fn is_cross_origin_public_path(path: &str) -> bool {
    if matches!(
        path,
        "/sdk/bugfinder-mini.js"
            | "/sdk/bugfinder-shield.js"
            | "/v1/logs"
            | "/v1/traces"
            | "/v1/metrics"
            | "/api/v1/logs"
    ) {
        return true;
    }
    if path.starts_with("/t/") && path.len() > 3 {
        return true;
    }
    if let Some(rest) = path.strip_prefix("/api/") {
        if let Some((pid_str, sub)) = rest.split_once('/') {
            if pid_str.parse::<i64>().ok().is_some_and(|id| id > 0) {
                let norm = sub.trim_end_matches('/');
                return matches!(
                    norm,
                    "envelope" | "store" | "security" | "shield" | "otlp/v1/logs"
                );
            }
        }
    }
    false
}

pub fn inject_csp_nonce_into_html(html: &str, nonce: &str) -> String {
    // Re-inject fresh per-request nonce into Vite-built <script, <link rel="stylesheet", <style tags
    let nonce_attr = format!(" nonce=\"{nonce}\"");
    let mut out = String::with_capacity(html.len() + 256);
    let mut rest = html;

    while let Some(pos) = rest.find('<') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos..];
        let lower_prefix: String = after
            .chars()
            .take(48)
            .collect::<String>()
            .to_ascii_lowercase();

        if lower_prefix.starts_with("<script ") || lower_prefix.starts_with("<script>") {
            if let Some(gt) = after.find('>') {
                let tag = &after[..gt];
                if !tag.to_ascii_lowercase().contains("nonce=") {
                    out.push_str("<script");
                    out.push_str(&nonce_attr);
                    out.push_str(&tag[7..]);
                } else {
                    out.push_str(tag);
                }
                rest = &after[gt..];
            } else {
                out.push('<');
                rest = &after[1..];
            }
        } else if lower_prefix.starts_with("<style ") || lower_prefix.starts_with("<style>") {
            if let Some(gt) = after.find('>') {
                let tag = &after[..gt];
                if !tag.to_ascii_lowercase().contains("nonce=") {
                    out.push_str("<style");
                    out.push_str(&nonce_attr);
                    out.push_str(&tag[6..]);
                } else {
                    out.push_str(tag);
                }
                rest = &after[gt..];
            } else {
                out.push('<');
                rest = &after[1..];
            }
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

fn apply_security_headers(resp: &mut Response, path: &str, nonce: &str, is_https: bool) {
    let h = resp.headers_mut();
    let https_upgrade = if is_https {
        "; upgrade-insecure-requests"
    } else {
        ""
    };
    let csp = format!(
        "default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'nonce-{nonce}'; style-src-elem 'self' 'nonce-{nonce}'; style-src-attr 'none'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'{https_upgrade}"
    );
    if let Ok(v) = HeaderValue::from_str(&csp) {
        h.insert("content-security-policy", v);
    }
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
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
        HeaderValue::from_static(if is_cross_origin_public_path(path) {
            "cross-origin"
        } else {
            "same-origin"
        }),
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

    if (path.starts_with("/api/") || path == "/metrics") && !h.contains_key(header::CACHE_CONTROL) {
        h.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, private"),
        );
    }
    if path != "/robots.txt" && path != "/llms.txt" && !path.starts_with("/sdk/") {
        h.insert(
            "x-robots-tag",
            HeaderValue::from_static("noindex, nofollow, noarchive"),
        );
    }

    if path == "/robots.txt" || path == "/llms.txt" || path == "/api/health" {
        h.remove(header::SET_COOKIE);
    }
}

pub async fn security_headers_middleware(
    State(state): State<Arc<crate::AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let full_uri = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| path.clone());
    let method_str = req.method().as_str().to_string();
    let headers = req.headers().clone();

    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));
    let client_ip = resolve_client_ip(&headers, peer_ip, &state.config);
    let nonce = random_token_b64(18);
    let is_https = is_https_request(&headers, peer_ip, &state.config);

    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let is_loopback_health =
        path == "/api/health" && peer_ip.is_loopback() && is_allowed_desktop_host(host);
    if !is_loopback_health && !is_allowed_host(host, &state.config) {
        let mut resp = (StatusCode::FORBIDDEN, "Forbidden host").into_response();
        apply_security_headers(&mut resp, &path, &nonce, is_https);
        return resp;
    }

    let raw_session_cookie = extract_cookie(&headers, "__Host-bf_session")
        .or_else(|| extract_cookie(&headers, "bf_session"))
        .filter(|val| {
            val.len() >= 32
                && val
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    let session_sha = raw_session_cookie
        .as_deref()
        .map(|s| sha256_hex(s.as_bytes()));
    let mut has_active_session = session_sha
        .as_deref()
        .is_some_and(|s| state.scanner_guard.is_active_session(s));

    let bearer_api_token_sha = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| {
            raw.trim()
                .strip_prefix("Bearer ")
                .or_else(|| raw.trim().strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|tok| tok.starts_with("bf_") && tok.len() >= 32)
        .map(|tok| sha256_hex(tok.as_bytes()));

    let is_public_ingest = is_cross_origin_public_path(&path);
    let is_tunnel_post = method_str == "POST" && path.starts_with("/t/") && path.len() > 3;
    let is_public_preflight = method_str == "OPTIONS" && is_public_ingest;
    let has_ingest_auth = is_public_preflight
        || is_tunnel_post
        || (is_public_ingest
            && (headers.contains_key("x-sentry-auth")
                || headers.contains_key(header::AUTHORIZATION)
                || req
                    .uri()
                    .query()
                    .is_some_and(|q| q.contains("sentry_key=") || q.contains("glitchtip_key="))));

    // Browser DevTools `.js.map` / `.css.map` requests return 404 without banning shared CGNAT IPs.
    if !has_active_session && is_sourcemap_probe(&path) {
        let mut resp = (StatusCode::NOT_FOUND, "Not found").into_response();
        apply_security_headers(&mut resp, &path, &nonce, is_https);
        return resp;
    }

    // CGNAT-safe deterministic SIMD Edge WAF & honeypot guard (< 1 µs, zero OOM):
    // Only verified active sessions, verified API tokens, and public-ingest DSN auth skip checks.
    let unauth_ip_hmac = if !has_active_session && !has_ingest_auth {
        let ip_hmac = state
            .rate_limiter
            .hash_key("honeypot", &client_ip.to_string());
        let already_banned = state.scanner_guard.is_banned(&ip_hmac);
        let ua = headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let is_canary = is_canary_or_dotfile_probe(&path);
        let is_scanner = is_scanner_user_agent(ua);
        let is_bad_method = is_anomalous_http_method(&method_str);
        let exploit_probe = detect_http_exploit_probe(&full_uri);

        if (already_banned || is_canary || is_scanner || is_bad_method || exploit_probe.is_some())
            && (session_sha.is_some() || bearer_api_token_sha.is_some())
        {
            if let Some(ref sha) = session_sha {
                if let Ok(Some(_sess)) = state
                    .storage
                    .resolve_session(sha, now_unix_secs(), state.config.session_idle_sec)
                    .await
                {
                    state
                        .scanner_guard
                        .track_session(sha, now_unix_secs() + 900);
                    has_active_session = true;
                }
            }
            if !has_active_session {
                if let Some(ref tok_sha) = bearer_api_token_sha {
                    if let Ok(Some(_tok)) = state
                        .storage
                        .resolve_api_token(tok_sha, None, now_unix_secs())
                        .await
                    {
                        has_active_session = true;
                    }
                }
            }
        }

        if !has_active_session {
            if already_banned {
                let mut resp =
                    (StatusCode::TOO_MANY_REQUESTS, "Temporarily blocked").into_response();
                apply_security_headers(&mut resp, &path, &nonce, is_https);
                return resp;
            }
            if is_bad_method {
                state.scanner_guard.ban_15m(&ip_hmac);
                let mut resp =
                    (StatusCode::METHOD_NOT_ALLOWED, "Method not allowed").into_response();
                apply_security_headers(&mut resp, &path, &nonce, is_https);
                return resp;
            }
            if is_canary || is_scanner || exploit_probe.is_some() {
                state.scanner_guard.ban_15m(&ip_hmac);
                let mut resp = (StatusCode::NOT_FOUND, "Not found").into_response();
                apply_security_headers(&mut resp, &path, &nonce, is_https);
                return resp;
            }
            Some(ip_hmac)
        } else {
            None
        }
    } else {
        None
    };

    let mut req = req;
    req.extensions_mut().insert(CspNonce(nonce.clone()));
    req.extensions_mut().insert(ClientIp(client_ip));
    req.extensions_mut().insert(PeerIp(peer_ip));

    let mut resp = next.run(req).await;
    if resp.status() == StatusCode::NOT_FOUND {
        if let Some(ref ip_hmac) = unauth_ip_hmac {
            let _ = state
                .scanner_guard
                .record_unauth_404_and_should_ban(ip_hmac, &path);
        }
    }
    if resp.status().is_server_error() {
        state.self_monitor.record(
            "http_5xx",
            "error",
            "http",
            &format!("Internal HTTP {} error", resp.status().as_u16()),
            None,
        );
        state
            .metrics
            .self_errors_total
            .fetch_add(1, Ordering::Relaxed);
    }
    apply_security_headers(&mut resp, &path, &nonce, is_https);
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

    #[test]
    fn cross_origin_corp_policy_is_strictly_scoped() {
        assert!(is_cross_origin_public_path("/sdk/bugfinder-mini.js"));
        assert!(is_cross_origin_public_path("/sdk/bugfinder-shield.js"));
        assert!(is_cross_origin_public_path("/api/1/envelope/"));
        assert!(is_cross_origin_public_path("/api/42/store"));
        assert!(is_cross_origin_public_path("/api/7/shield/"));
        assert!(is_cross_origin_public_path("/t/tunnel123"));
        assert!(is_cross_origin_public_path("/v1/logs"));

        // Dashboard, auth, and API v0 MUST remain same-origin
        assert!(!is_cross_origin_public_path("/"));
        assert!(!is_cross_origin_public_path("/assets/app.js"));
        assert!(!is_cross_origin_public_path("/api/auth/me"));
        assert!(!is_cross_origin_public_path(
            "/api/0/organizations/acme/issues/"
        ));
        assert!(!is_cross_origin_public_path("/api/0/sdk-meta/"));
        assert!(!is_cross_origin_public_path("/api/0/envelope/"));
        assert!(!is_cross_origin_public_path("/metrics"));
    }

    #[test]
    fn validate_same_origin_checks_scheme_and_port() {
        let tmp = std::env::temp_dir().join(format!("bf_hdr_test1_{}", random_token_b64(6)));
        let mut cfg = AppConfig::from_env_and_overrides(None, Some(tmp.clone()), None, false)
            .expect("config init");
        cfg.is_dev = false;
        cfg.public_url = Some("https://bf.example.com".to_string());

        let mut hdrs = HeaderMap::new();
        hdrs.insert(header::HOST, HeaderValue::from_static("bf.example.com"));
        hdrs.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        hdrs.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://bf.example.com"),
        );
        let loopback = IpAddr::from([127, 0, 0, 1]);
        assert!(validate_same_origin(&hdrs, loopback, &cfg));

        // Different port or http:// downgrade must be rejected
        hdrs.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://bf.example.com"),
        );
        assert!(!validate_same_origin(&hdrs, loopback, &cfg));

        hdrs.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://bf.example.com:8443"),
        );
        assert!(!validate_same_origin(&hdrs, loopback, &cfg));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn is_https_request_ignores_untrusted_proxy_headers() {
        let tmp = std::env::temp_dir().join(format!("bf_hdr_test2_{}", random_token_b64(6)));
        let mut cfg = AppConfig::from_env_and_overrides(None, Some(tmp.clone()), None, false)
            .expect("config init");
        cfg.force_secure_cookies = false;
        cfg.public_url = None;
        cfg.trusted_proxies.clear();

        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        let attacker = IpAddr::from([203, 0, 113, 9]);
        assert!(!is_https_request(&hdrs, attacker, &cfg));

        cfg.trusted_proxies.extend(
            crate::config::CidrBlock::expand_keyword_or_cidr("203.0.113.9/32")
                .expect("valid test cidr"),
        );
        assert!(is_https_request(&hdrs, attacker, &cfg));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn scanner_guard_tracks_and_untracks_sessions() {
        let guard = ScannerGuard::new();
        let sha = sha256_hex(b"session_secret_value_0123456789abcdef");
        assert!(!guard.is_active_session(&sha));
        guard.track_session(&sha, now_unix_secs() + 60);
        assert!(guard.is_active_session(&sha));
        guard.untrack_session(&sha);
        assert!(!guard.is_active_session(&sha));
    }

    #[test]
    fn edge_waf_catches_nested_dotfiles_dumps_and_methods_while_allowing_well_known() {
        assert!(is_canary_or_dotfile_probe("/.env"));
        assert!(is_canary_or_dotfile_probe("/.env.production"));
        assert!(is_canary_or_dotfile_probe("/api/v1/.env"));
        assert!(is_canary_or_dotfile_probe("/.git/HEAD"));
        assert!(is_canary_or_dotfile_probe("/wp-admin/install.php"));
        assert!(is_canary_or_dotfile_probe("/db/dump-2026.sql.gz"));
        assert!(is_canary_or_dotfile_probe("/config.php.bak"));
        assert!(is_canary_or_dotfile_probe("/.pypirc"));
        assert!(is_canary_or_dotfile_probe("/.npmrc"));
        assert!(is_canary_or_dotfile_probe("/.netrc?v=1"));

        // RFC 8615 /.well-known/ routes (WebAuthn, security.txt, DevTools) must never be blocked
        assert!(!is_canary_or_dotfile_probe("/.well-known/webauthn"));
        assert!(!is_canary_or_dotfile_probe(
            "/.well-known/appspecific/com.chrome.devtools.json"
        ));
        assert!(!is_canary_or_dotfile_probe(
            "/api/0/organizations/acme/issues/"
        ));

        assert!(is_anomalous_http_method("PROPFIND"));
        assert!(is_anomalous_http_method("TRACE"));
        assert!(is_anomalous_http_method("CONNECT"));
        assert!(!is_anomalous_http_method("GET"));
        assert!(!is_anomalous_http_method("POST"));

        let guard = ScannerGuard::new();
        // Static icon misses never trigger behavioral 404 ban
        for _ in 0..30 {
            assert!(!guard.record_unauth_404_and_should_ban("hmac_benign", "/favicon.ico"));
        }
        assert!(!guard.is_banned("hmac_benign"));

        // 20 unknown route probes within 60s quarantine the attacker IP HMAC
        for i in 0..19 {
            assert!(
                !guard.record_unauth_404_and_should_ban("hmac_enum", &format!("/hidden-admin-{i}"))
            );
        }
        assert!(guard.record_unauth_404_and_should_ban("hmac_enum", "/hidden-admin-20"));
        assert!(guard.is_banned("hmac_enum"));
    }
}
