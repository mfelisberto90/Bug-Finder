use crate::domain::models::ProjectFilters;
use regex::{Regex, RegexBuilder};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::OnceLock;

pub const PLACEHOLDER: &str = "[Filtered]";
const MAX_SCRUB_DEPTH: usize = 48;

const DEFAULT_KEY_TOKENS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "pin",
    "secret",
    "auth",
    "bearer",
    "credentials",
    "token",
    "session",
    "cookie",
    "csrf",
    "xsrf",
    "ssn",
    "cvv",
    "cvc",
];

const DEFAULT_WHOLE_KEYS: &[&str] = &[
    "apikey",
    "xapikey",
    "authorization",
    "csrftoken",
    "xcsrftoken",
    "sessionid",
    "setcookie",
    "connectsid",
    "aiohttpsession",
    "mysqlpwd",
    "xforwardedfor",
    "privatekey",
    "creditcard",
    "cardnumber",
    "socialsecurity",
];

const EVENT_SECTIONS: &[&str] = &[
    "request",
    "extra",
    "user",
    "contexts",
    "breadcrumbs",
    "exception",
    "threads",
    "tags",
    "logentry",
    "message",
    "csp",
    "spans",
];

struct ScrubRegexes {
    pem_block: Regex,
    auth_header: Regex,
    jwt: Regex,
    prefixed_secret: Regex,
    query_secret: Regex,
    card_candidate: Regex,
    email: Regex,
}

static SCRUB_REGEXES: OnceLock<ScrubRegexes> = OnceLock::new();

fn build_ascii_regex(pat: &str) -> Regex {
    RegexBuilder::new(pat)
        .unicode(false)
        .build()
        .expect("ASCII scrubber regex must compile cleanly")
}

fn regexes() -> &'static ScrubRegexes {
    SCRUB_REGEXES.get_or_init(|| ScrubRegexes {
        // Strictly positive ASCII character ranges (never [^...] under unicode(false))
        pem_block: build_ascii_regex(
            r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----[A-Za-z0-9+/=\r\n \t]+-----END [A-Z0-9 ]+PRIVATE KEY-----",
        ),
        auth_header: build_ascii_regex(
            r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9\-._~+/]+=*",
        ),
        jwt: build_ascii_regex(
            r"\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b",
        ),
        prefixed_secret: build_ascii_regex(
            r"\b(?:sk_live_|sk_test_|rk_live_|rk_test_|whsec_|ghp_|gho_|glpat-|xoxb-|xoxp-|bf_)[A-Za-z0-9_\-]{12,}\b",
        ),
        query_secret: build_ascii_regex(
            r"(?i)([?&](?:token|api_key|apikey|secret|password|passwd|auth|access_token|sentry_key)=)[A-Za-z0-9%._\-~+/]+",
        ),
        card_candidate: build_ascii_regex(
            r"\b(?:\d[ \-]?){12,18}\d\b",
        ),
        email: build_ascii_regex(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,16}\b",
        ),
    })
}

pub fn is_luhn_valid(digits: &str) -> bool {
    let nums: Vec<u32> = digits
        .bytes()
        .filter(|b| b.is_ascii_digit())
        .map(|b| (b - b'0') as u32)
        .collect();
    if !(13..=19).contains(&nums.len()) {
        return false;
    }
    let mut sum = 0u32;
    let mut alt = false;
    for &d in nums.iter().rev() {
        let mut v = d;
        if alt {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        alt = !alt;
    }
    sum % 10 == 0
}

fn normalize_whole_key(key: &str) -> String {
    key.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn split_key_tokens(key: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;

    for ch in key.chars() {
        if !ch.is_ascii_alphanumeric() {
            if !cur.is_empty() {
                tokens.push(cur.to_ascii_lowercase());
                cur.clear();
            }
            prev_lower = false;
            continue;
        }
        if ch.is_ascii_uppercase() && prev_lower && !cur.is_empty() {
            tokens.push(cur.to_ascii_lowercase());
            cur.clear();
        }
        prev_lower = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        cur.push(ch);
    }
    if !cur.is_empty() {
        tokens.push(cur.to_ascii_lowercase());
    }
    tokens
}

pub struct Scrubber {
    safe_keys: HashSet<String>,
    sensitive_keys: HashSet<String>,
    scrub_emails: bool,
    scrub_ips: bool,
}

impl Scrubber {
    pub fn from_filters(filters: &ProjectFilters) -> Self {
        Self {
            safe_keys: filters.safe_keys.iter().map(|k| normalize_whole_key(k)).collect(),
            sensitive_keys: filters
                .sensitive_keys
                .iter()
                .map(|k| normalize_whole_key(k))
                .collect(),
            scrub_emails: filters.scrub_emails,
            scrub_ips: filters.scrub_ip_addresses,
        }
    }

    fn is_sensitive_key(&self, key: &str) -> bool {
        let whole = normalize_whole_key(key);
        if whole.is_empty() || self.safe_keys.contains(&whole) {
            return false;
        }
        if self.sensitive_keys.contains(&whole) || DEFAULT_WHOLE_KEYS.contains(&whole.as_str()) {
            return true;
        }
        let tokens = split_key_tokens(key);
        tokens
            .iter()
            .any(|t| DEFAULT_KEY_TOKENS.contains(&t.as_str()))
    }

    pub fn scrub_string(&self, input: &str) -> String {
        let mut s = if input.contains('\0') {
            input.replace('\0', "")
        } else {
            input.to_string()
        };

        let rx = regexes();
        if s.contains("PRIVATE KEY") {
            s = rx.pem_block.replace_all(&s, PLACEHOLDER).into_owned();
        }
        if s.contains("Bearer ") || s.contains("bearer ") || s.contains("Basic ") || s.contains("basic ") {
            s = rx.auth_header.replace_all(&s, "$1 [Filtered]").into_owned();
        }
        if s.contains("eyJ") {
            s = rx.jwt.replace_all(&s, PLACEHOLDER).into_owned();
        }
        if s.contains('_') || s.contains('-') {
            s = rx.prefixed_secret.replace_all(&s, PLACEHOLDER).into_owned();
        }
        if s.contains('=') && (s.contains('?') || s.contains('&')) {
            s = rx.query_secret.replace_all(&s, "$1[Filtered]").into_owned();
        }
        if s.bytes().filter(|b| b.is_ascii_digit()).count() >= 13 {
            s = rx
                .card_candidate
                .replace_all(&s, |caps: &regex::Captures| {
                    let m = caps.get(0).map(|m| m.as_str()).unwrap_or("");
                    if is_luhn_valid(m) {
                        PLACEHOLDER.to_string()
                    } else {
                        m.to_string()
                    }
                })
                .into_owned();
        }
        if self.scrub_emails && s.contains('@') {
            s = rx.email.replace_all(&s, PLACEHOLDER).into_owned();
        }
        s
    }

    fn scrub_value(&self, val: &mut Value, depth: usize) {
        if depth >= MAX_SCRUB_DEPTH {
            return;
        }
        match val {
            Value::String(s) => {
                *s = self.scrub_string(s);
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.scrub_value(item, depth + 1);
                }
            }
            Value::Object(map) => {
                let keys: Vec<String> = map.keys().cloned().collect();
                for k in keys {
                    if self.is_sensitive_key(&k) {
                        if let Some(entry) = map.get_mut(&k) {
                            if !entry.is_null() {
                                *entry = Value::String(PLACEHOLDER.to_string());
                            }
                        }
                    } else if self.scrub_ips && (k == "ip_address" || k == "ipAddress") {
                        if let Some(Value::String(ip)) = map.get_mut(&k) {
                            *ip = anonymize_ip(ip);
                        }
                    } else if let Some(entry) = map.get_mut(&k) {
                        self.scrub_value(entry, depth + 1);
                    }
                }
            }
            _ => {}
        }
    }

    pub fn scrub_event_in_place(&self, event: &mut Value) {
        let Some(obj) = event.as_object_mut() else {
            return;
        };
        for section in EVENT_SECTIONS {
            if let Some(val) = obj.get_mut(*section) {
                self.scrub_value(val, 0);
            }
        }
        if let Some(Value::String(rel)) = obj.get_mut("release") {
            *rel = rel.replace('\0', "");
        }
        if let Some(Value::String(env)) = obj.get_mut("environment") {
            *env = env.replace('\0', "");
        }
    }

    pub fn scrub_log_in_place(&self, body: &mut String, attrs: &mut Value) {
        *body = self.scrub_string(body);
        self.scrub_value(attrs, 0);
    }
}

pub fn anonymize_ip(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                format!("{}.{}.{}.0", o[0], o[1], o[2])
            }
            std::net::IpAddr::V6(v6) => {
                let seg = v6.segments();
                format!("{:x}:{:x}:{:x}::", seg[0], seg[1], seg[2])
            }
        }
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn regexes_compile_without_unicode_negated_panic() {
        let _ = regexes();
    }

    #[test]
    fn scrubs_secrets_luhn_and_preserves_safe_identifiers() {
        let scrubber = Scrubber::from_filters(&ProjectFilters::default());
        let mut ev = json!({
            "request": {
                "url": "https://app.example.com/cb?token=secret123&page=2",
                "headers": {
                    "Authorization": "Bearer super_secret_token_999",
                    "User-Agent": "Mozilla/5.0"
                },
                "data": {
                    "userPassword": "my-password",
                    "author": "Jane Doe",
                    "card": "4111-1111-1111-1111",
                    "orderId": "12345678901234"
                }
            },
            "user": {
                "ip_address": "192.0.2.154"
            },
            "message": "Fail with sk_live_abcdefghijklmnop and jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\u{0000}" // gitleaks:allow
        });

        scrubber.scrub_event_in_place(&mut ev);

        assert_eq!(ev["request"]["url"], "https://app.example.com/cb?token=[Filtered]&page=2");
        assert_eq!(ev["request"]["headers"]["Authorization"], PLACEHOLDER);
        assert_eq!(ev["request"]["headers"]["User-Agent"], "Mozilla/5.0");
        assert_eq!(ev["request"]["data"]["userPassword"], PLACEHOLDER);
        assert_eq!(ev["request"]["data"]["author"], "Jane Doe");
        assert_eq!(ev["request"]["data"]["card"], PLACEHOLDER);
        // Non-Luhn 14-digit order ID must NOT be flagged
        assert_eq!(ev["request"]["data"]["orderId"], "12345678901234");
        assert_eq!(ev["user"]["ip_address"], "192.0.2.0");

        let msg = ev["message"].as_str().unwrap();
        assert!(!msg.contains("sk_live_"));
        assert!(!msg.contains("eyJhbGci"));
        assert!(!msg.contains('\0'));
    }
}
