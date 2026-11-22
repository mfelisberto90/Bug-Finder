use crate::domain::models::ProjectFilters;
use regex::{Regex, RegexBuilder};
use serde_json::Value;
use std::borrow::Cow;
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
    url_credentials: Regex,
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
            r"(?i)\b(Bearer|Basic)\s+([A-Za-z0-9\-._~+/]+=*)",
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
        url_credentials: build_ascii_regex(
            r"(?i)(https?://)([A-Za-z0-9._%+\-]+):([A-Za-z0-9._%+\-!$&'()*+,;=]+)@",
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

#[derive(Debug, Clone, Default)]
pub struct ScrubReport {
    pub categories: Vec<&'static str>,
}

impl ScrubReport {
    fn push_unique(&mut self, cat: &'static str) {
        if !self.categories.contains(&cat) {
            self.categories.push(cat);
        }
    }
}

pub fn strip_ansi_and_bidi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            match chars.peek().copied() {
                Some('[') => {
                    chars.next();
                    for ch in chars.by_ref() {
                        if ('@'..='~').contains(&ch) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    chars.next();
                    while let Some(ch) = chars.next() {
                        if ch == '\x07' {
                            break;
                        }
                        if ch == '\x1b' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                _ => {}
            }
            continue;
        }
        if c == '\r'
            || c == '\0'
            || ('\u{202A}'..='\u{202E}').contains(&c)
            || ('\u{2066}'..='\u{2069}').contains(&c)
            || matches!(c, '\u{200E}' | '\u{200F}' | '\u{061C}')
            || (c.is_control() && c != '\n' && c != '\t')
        {
            continue;
        }
        out.push(c);
    }
    out
}

pub struct Scrubber {
    safe_keys: HashSet<String>,
    sensitive_keys: HashSet<String>,
    scrub_emails: bool,
    scrub_ips: bool,
    aggressive_key_match: bool,
}

impl Scrubber {
    pub fn from_filters(filters: &ProjectFilters) -> Self {
        Self::from_filters_with_org(filters, false)
    }

    /// Org-level `scrub_ip_addresses` overrides the project setting (matching GlitchTip).
    pub fn from_filters_with_org(filters: &ProjectFilters, org_scrub_ip: bool) -> Self {
        Self {
            safe_keys: filters.safe_keys.iter().map(|k| normalize_whole_key(k)).collect(),
            sensitive_keys: filters
                .sensitive_keys
                .iter()
                .map(|k| normalize_whole_key(k))
                .collect(),
            scrub_emails: filters.scrub_emails,
            scrub_ips: filters.scrub_ip_addresses || org_scrub_ip,
            aggressive_key_match: filters.aggressive_key_match,
        }
    }

    fn is_sensitive_key(&self, key: &str) -> bool {
        let whole = normalize_whole_key(key);
        if whole.is_empty() {
            return false;
        }
        if self.aggressive_key_match {
            if self.safe_keys.iter().any(|s| !s.is_empty() && whole.contains(s)) {
                return false;
            }
            if self.sensitive_keys.iter().any(|s| !s.is_empty() && whole.contains(s))
                || DEFAULT_WHOLE_KEYS.iter().any(|k| whole.contains(k))
                || DEFAULT_KEY_TOKENS.iter().any(|k| whole.contains(k))
            {
                return true;
            }
            return false;
        }
        if self.safe_keys.contains(&whole) {
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
        let mut report = ScrubReport::default();
        self.scrub_string_with_report(input, &mut report).into_owned()
    }

    pub fn scrub_string_with_report<'a>(
        &self,
        input: &'a str,
        report: &mut ScrubReport,
    ) -> Cow<'a, str> {
        let has_nul = input.contains('\0');
        let has_pem = input.contains("PRIVATE KEY");
        let has_auth_hdr = contains_ascii_ci(input.as_bytes(), b"bearer")
            || contains_ascii_ci(input.as_bytes(), b"basic");
        let has_jwt = input.contains("eyJ");
        let has_prefixed = has_prefixed_secret_hint(input);
        let has_url_creds = input.contains("://") && input.contains('@');
        let has_query = input.contains('=') && (input.contains('?') || input.contains('&'));
        let has_card_digits = input.bytes().filter(|b| b.is_ascii_digit()).count() >= 13;
        let has_email = self.scrub_emails && input.contains('@');

        if !(has_nul
            || has_pem
            || has_auth_hdr
            || has_jwt
            || has_prefixed
            || has_url_creds
            || has_query
            || has_card_digits
            || has_email)
        {
            return Cow::Borrowed(input);
        }

        let mut s: Cow<'a, str> = if has_nul {
            Cow::Owned(input.replace('\0', ""))
        } else {
            Cow::Borrowed(input)
        };

        let rx = regexes();
        if s.contains("PRIVATE KEY") && rx.pem_block.is_match(&s) {
            report.push_unique("pem_private_key");
            s = Cow::Owned(rx.pem_block.replace_all(&s, PLACEHOLDER).into_owned());
        }
        if contains_ascii_ci(s.as_bytes(), b"bearer") || contains_ascii_ci(s.as_bytes(), b"basic")
        {
            if rx.auth_header.is_match(&s) {
                for cap in rx.auth_header.captures_iter(&s) {
                    if let Some(tok) = cap.get(2).map(|m| m.as_str()) {
                        if tok.len() >= 12 {
                            report.push_unique("auth_header");
                            break;
                        }
                    }
                }
                s = Cow::Owned(rx.auth_header.replace_all(&s, "$1 [Filtered]").into_owned());
            }
        }
        if s.contains("eyJ") && rx.jwt.is_match(&s) {
            report.push_unique("jwt");
            s = Cow::Owned(rx.jwt.replace_all(&s, PLACEHOLDER).into_owned());
        }
        if has_prefixed_secret_hint(&s) && rx.prefixed_secret.is_match(&s) {
            for m in rx.prefixed_secret.find_iter(&s) {
                let raw = m.as_str();
                if !raw.starts_with("sk_test_") && !raw.starts_with("rk_test_") {
                    report.push_unique("live_prefixed_secret");
                    break;
                }
            }
            s = Cow::Owned(rx.prefixed_secret.replace_all(&s, PLACEHOLDER).into_owned());
        }
        if s.contains("://") && s.contains('@') && rx.url_credentials.is_match(&s) {
            report.push_unique("url_credentials");
            s = Cow::Owned(
                rx.url_credentials
                    .replace_all(&s, "$1[Filtered]:[Filtered]@")
                    .into_owned(),
            );
        }
        if s.contains('=') && (s.contains('?') || s.contains('&')) && rx.query_secret.is_match(&s)
        {
            s = Cow::Owned(rx.query_secret.replace_all(&s, "$1[Filtered]").into_owned());
        }
        if s.bytes().filter(|b| b.is_ascii_digit()).count() >= 13 {
            let has_luhn = rx
                .card_candidate
                .find_iter(&s)
                .any(|m| is_luhn_valid(m.as_str()));
            if has_luhn {
                let mut tmp = String::new();
                std::mem::swap(&mut tmp, &mut s.to_mut());
                let replaced = rx
                    .card_candidate
                    .replace_all(&tmp, |caps: &regex::Captures| {
                        let m = caps.get(0).map(|m| m.as_str()).unwrap_or("");
                        if is_luhn_valid(m) {
                            report.push_unique("luhn_card_pan");
                            PLACEHOLDER.to_string()
                        } else {
                            m.to_string()
                        }
                    })
                    .into_owned();
                s = Cow::Owned(replaced);
            }
        }
        if self.scrub_emails && s.contains('@') && rx.email.is_match(&s) {
            s = Cow::Owned(rx.email.replace_all(&s, PLACEHOLDER).into_owned());
        }
        s
    }

    fn scrub_value(&self, val: &mut Value, depth: usize, report: &mut ScrubReport) {
        if depth >= MAX_SCRUB_DEPTH {
            return;
        }
        match val {
            Value::String(s) => {
                if let Cow::Owned(clean) = self.scrub_string_with_report(s, report) {
                    *s = clean;
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.scrub_value(item, depth + 1, report);
                }
            }
            Value::Object(map) => {
                let keys: Vec<String> = map.keys().cloned().collect();
                for k in keys {
                    if self.is_sensitive_key(&k) {
                        if let Some(entry) = map.get_mut(&k) {
                            if let Some(s) = entry.as_str() {
                                if s != PLACEHOLDER && !s.is_empty() {
                                    let _ = self.scrub_string_with_report(s, report);
                                }
                            }
                            if !entry.is_null() {
                                *entry = Value::String(PLACEHOLDER.to_string());
                            }
                        }
                    } else if self.scrub_ips && (k == "ip_address" || k == "ipAddress") {
                        if let Some(Value::String(ip)) = map.get_mut(&k) {
                            *ip = anonymize_ip(ip);
                        }
                    } else if let Some(entry) = map.get_mut(&k) {
                        self.scrub_value(entry, depth + 1, report);
                    }
                }
            }
            _ => {}
        }
    }

    pub fn scrub_event_in_place(&self, event: &mut Value) {
        let _ = self.scrub_event_with_report(event);
    }

    pub fn scrub_event_with_report(&self, event: &mut Value) -> ScrubReport {
        let mut report = ScrubReport::default();
        let Some(obj) = event.as_object_mut() else {
            return report;
        };
        for section in EVENT_SECTIONS {
            if let Some(val) = obj.get_mut(*section) {
                self.scrub_value(val, 0, &mut report);
            }
        }
        if let Some(Value::String(rel)) = obj.get_mut("release") {
            if rel.contains('\0') {
                *rel = rel.replace('\0', "");
            }
        }
        if let Some(Value::String(env)) = obj.get_mut("environment") {
            if env.contains('\0') {
                *env = env.replace('\0', "");
            }
        }
        report
    }

    pub fn scrub_log_in_place(&self, body: &mut String, attrs: &mut Value) {
        let _ = self.scrub_log_with_report(body, attrs);
    }

    pub fn scrub_log_with_report(&self, body: &mut String, attrs: &mut Value) -> ScrubReport {
        let mut report = ScrubReport::default();
        if let Cow::Owned(clean) = self.scrub_string_with_report(body, &mut report) {
            *body = clean;
        }
        self.scrub_value(attrs, 0, &mut report);
        report
    }
}

fn contains_ascii_ci(hay: &[u8], needle_lower: &[u8]) -> bool {
    if hay.len() < needle_lower.len() {
        return false;
    }
    hay.windows(needle_lower.len())
        .any(|w| w.eq_ignore_ascii_case(needle_lower))
}

fn has_prefixed_secret_hint(s: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "sk_live_",
        "sk_test_",
        "rk_live_",
        "rk_test_",
        "whsec_",
        "ghp_",
        "gho_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "bf_",
    ];
    (s.contains('_') || s.contains('-')) && PREFIXES.iter().any(|p| s.contains(p))
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

    #[test]
    fn secret_leak_radar_avoids_false_positives_and_strip_ansi_works() {
        let scrubber = Scrubber::from_filters(&ProjectFilters::default());

        // Test keys, empty password, pre-filtered placeholder, short Bearer label -> 0 categories
        let mut benign = json!({
            "message": "Using sk_test_1234567890abcdef and Bearer short with password=", // gitleaks:allow
            "extra": { "password": "", "token": "[Filtered]" }
        });
        let rep0 = scrubber.scrub_event_with_report(&mut benign);
        assert!(rep0.categories.is_empty(), "Unexpected false positive: {:?}", rep0.categories);

        // Live secret in log -> triggers live_prefixed_secret
        let mut leak_body = "Leaked key sk_live_0000111122223333".to_string(); // gitleaks:allow
        let mut leak_attrs = json!({});
        let rep1 = scrubber.scrub_log_with_report(&mut leak_body, &mut leak_attrs);
        assert_eq!(rep1.categories, vec!["live_prefixed_secret"]);
        assert!(leak_body.contains(PLACEHOLDER));

        // ANSI + bidi terminal injection stripped while preserving valid text
        let raw = "\x1b[31mFAKE\x1b[0m \u{202E}txt\r\nok";
        assert_eq!(strip_ansi_and_bidi(raw), "FAKE txt\nok");

        // Zero-allocation fast-path returns Cow::Borrowed for clean telemetry text
        let mut clean_rep = ScrubReport::default();
        let clean = scrubber.scrub_string_with_report(
            "Simulated failure #12 at /app/src/mod_1.ts:52 orderId=12345678901234",
            &mut clean_rep,
        );
        assert!(matches!(clean, Cow::Borrowed(_)));
        assert!(clean_rep.categories.is_empty());
    }
}
