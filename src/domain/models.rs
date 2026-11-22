use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{Read, Write};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Owner,
    Manager,
    Admin,
    Member,
    Viewer,
}

pub const ALL_SCOPES: &[&str] = &[
    "org:read",
    "org:write",
    "org:admin",
    "member:read",
    "member:write",
    "member:admin",
    "project:read",
    "project:write",
    "project:admin",
    "project:releases",
    "event:read",
    "event:write",
    "event:admin",
    "shield:read",
    "shield:write",
];

impl UserRole {
    pub fn from_db(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "owner" => Some(Self::Owner),
            "manager" => Some(Self::Manager),
            "admin" => Some(Self::Admin),
            "member" => Some(Self::Member),
            "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Manager => "manager",
            Self::Admin => "admin",
            Self::Member => "member",
            Self::Viewer => "viewer",
        }
    }

    pub fn rank(&self) -> u8 {
        match self {
            Self::Viewer => 0,
            Self::Member => 1,
            Self::Admin => 2,
            Self::Manager => 3,
            Self::Owner => 4,
        }
    }

    pub fn min_role(self, other: Self) -> Self {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }

    pub fn default_scopes(&self) -> &'static [&'static str] {
        match self {
            Self::Viewer => &["org:read", "project:read", "event:read", "shield:read"],
            Self::Member => &[
                "org:read",
                "member:read",
                "project:read",
                "project:releases",
                "event:read",
                "event:write",
                "event:admin",
                "shield:read",
            ],
            Self::Admin => &[
                "org:read",
                "member:read",
                "project:read",
                "project:write",
                "project:admin",
                "project:releases",
                "event:read",
                "event:write",
                "event:admin",
                "shield:read",
                "shield:write",
            ],
            Self::Manager => &[
                "org:read",
                "org:write",
                "member:read",
                "member:write",
                "member:admin",
                "project:read",
                "project:write",
                "project:admin",
                "project:releases",
                "event:read",
                "event:write",
                "event:admin",
                "shield:read",
                "shield:write",
            ],
            Self::Owner => ALL_SCOPES,
        }
    }

    pub fn can_manage_org(&self) -> bool {
        matches!(self, Self::Owner | Self::Manager | Self::Admin)
    }

    pub fn can_write_project(&self) -> bool {
        matches!(self, Self::Owner | Self::Manager | Self::Admin)
    }

    pub fn can_mutate_issues(&self) -> bool {
        matches!(self, Self::Owner | Self::Manager | Self::Admin | Self::Member)
    }

    pub fn can_read(&self) -> bool {
        true
    }
}

pub fn intersect_scopes(role: UserRole, raw_scopes: &str) -> Vec<String> {
    let allowed = role.default_scopes();
    let mut out = Vec::new();
    for tok in raw_scopes.split(|c: char| c.is_ascii_whitespace() || c == ',') {
        let s = tok.trim();
        if !s.is_empty() && allowed.contains(&s) && !out.iter().any(|x| x == s) {
            out.push(s.to_string());
        }
    }
    out
}

/// Server-derived tenant & capability boundary.
/// Every tenant-scoped repository query requires `&TenantCtx`.
#[derive(Debug, Clone)]
pub struct TenantCtx {
    pub organization_id: i64,
    pub organization_slug: String,
    pub user_id: Option<i64>,
    pub role: UserRole,
    pub scopes: Vec<String>,
    pub is_session_auth: bool,
    pub reauth_at: Option<i64>,
    pub session_id: Option<i64>,
}

impl TenantCtx {
    pub fn from_session(
        organization_id: i64,
        organization_slug: String,
        user_id: i64,
        role: UserRole,
        reauth_at: Option<i64>,
        session_id: Option<i64>,
    ) -> Self {
        Self {
            organization_id,
            organization_slug,
            user_id: Some(user_id),
            role,
            scopes: role.default_scopes().iter().map(|s| (*s).to_string()).collect(),
            is_session_auth: true,
            reauth_at,
            session_id,
        }
    }

    pub fn from_token(
        organization_id: i64,
        organization_slug: String,
        user_id: i64,
        effective_role: UserRole,
        raw_scopes: &str,
    ) -> Self {
        Self {
            organization_id,
            organization_slug,
            user_id: Some(user_id),
            role: effective_role,
            scopes: intersect_scopes(effective_role, raw_scopes),
            is_session_auth: false,
            reauth_at: None,
            session_id: None,
        }
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    pub fn has_any_scope(&self, required: &[&str]) -> bool {
        required.iter().any(|s| self.has_scope(s))
    }

    pub fn has_recent_reauth(&self, now_sec: i64) -> bool {
        self.is_session_auth
            && self
                .reauth_at
                .map(|t| now_sec.saturating_sub(t) <= 600)
                .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace = 1,
    Debug = 5,
    Info = 9,
    Warn = 13,
    Error = 17,
    Fatal = 21,
}

impl LogLevel {
    pub fn try_from_str_strict(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "trace" => Some(Self::Trace),
            "debug" => Some(Self::Debug),
            "info" | "log" => Some(Self::Info),
            "warn" | "warning" => Some(Self::Warn),
            "error" | "err" => Some(Self::Error),
            "fatal" | "critical" | "crit" | "emerg" => Some(Self::Fatal),
            _ => None,
        }
    }

    pub fn from_str_loose(raw: &str) -> Self {
        Self::try_from_str_strict(raw).unwrap_or(Self::Info)
    }

    pub fn from_num(n: i32) -> Self {
        match n {
            ..=4 => Self::Trace,
            5..=8 => Self::Debug,
            9..=12 => Self::Info,
            13..=16 => Self::Warn,
            17..=20 => Self::Error,
            21.. => Self::Fatal,
        }
    }

    pub fn from_otel_severity(sev: u16) -> Self {
        match sev {
            1..=4 => Self::Trace,
            5..=8 => Self::Debug,
            9..=12 => Self::Info,
            13..=16 => Self::Warn,
            17..=20 => Self::Error,
            21..=24 => Self::Fatal,
            _ => Self::Info,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Fatal => "fatal",
        }
    }

    pub fn num(&self) -> i32 {
        *self as i32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IssueStatus {
    Unresolved,
    Resolved,
    Ignored,
}

impl IssueStatus {
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "unresolved" => Some(Self::Unresolved),
            "resolved" => Some(Self::Resolved),
            "ignored" => Some(Self::Ignored),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unresolved => "unresolved",
            Self::Resolved => "resolved",
            Self::Ignored => "ignored",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IssueType {
    Error,
    Default,
    Csp,
    Log,
}

impl IssueType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Default => "default",
            Self::Csp => "csp",
            Self::Log => "log",
        }
    }

    pub fn from_str_loose(s: &str) -> Self {
        match s {
            "error" => Self::Error,
            "csp" => Self::Csp,
            "log" => Self::Log,
            _ => Self::Default,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ShieldPolicy {
    pub enabled: bool,
    pub mode: String, // "detect" | "defend" | "lockdown"
    pub quarantine_threshold: u32,
    pub quarantine_ttl_sec: u64,
    pub enforce_origin_check: bool,
    pub secret_leak_alerts: bool,
    pub log_ids_enabled: bool,
    pub canary_globals: Vec<String>,
}

impl Default for ShieldPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: "detect".to_string(),
            quarantine_threshold: 80,
            quarantine_ttl_sec: 900,
            enforce_origin_check: false,
            secret_leak_alerts: true,
            log_ids_enabled: true,
            canary_globals: vec!["__BF_INTERNAL_SECRETS__".to_string()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProjectFilters {
    pub allowed_domains: Vec<String>,
    pub ignore_browser_extensions: bool,
    pub ignore_crawlers: bool,
    pub ignore_localhost: bool,
    pub ignore_messages: Vec<String>,
    pub storm_sample_threshold: u32,
    pub storm_sample_every: u32,
    pub event_throttle_rate: u8,
    pub auto_promote_log_level: Option<String>,
    pub scrub_ip_addresses: bool,
    pub scrub_emails: bool,
    pub aggressive_key_match: bool,
    pub safe_keys: Vec<String>,
    pub sensitive_keys: Vec<String>,
    pub shield: ShieldPolicy,
}

impl Default for ProjectFilters {
    fn default() -> Self {
        Self {
            allowed_domains: Vec::new(),
            ignore_browser_extensions: true,
            ignore_crawlers: true,
            ignore_localhost: false,
            ignore_messages: Vec::new(),
            storm_sample_threshold: 50,
            storm_sample_every: 10,
            event_throttle_rate: 0,
            auto_promote_log_level: None,
            scrub_ip_addresses: true,
            scrub_emails: false,
            aggressive_key_match: false,
            safe_keys: Vec::new(),
            sensitive_keys: Vec::new(),
            shield: ShieldPolicy::default(),
        }
    }
}

/// GlitchTip-compatible Base32 alphabet (`0-9A-V`) for short IDs like `PROJECT-1A`.
const BASE32_DIGS: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

pub fn base32_encode(mut value: u64) -> String {
    if value == 0 {
        return "0".to_string();
    }
    let mut digits = Vec::with_capacity(14);
    while value > 0 {
        digits.push(BASE32_DIGS[(value % 32) as usize] as char);
        value /= 32;
    }
    digits.reverse();
    digits.into_iter().collect()
}

pub fn format_short_id(project_slug: &str, short_num: u64) -> String {
    let prefix = project_slug
        .chars()
        .take(24)
        .collect::<String>()
        .to_ascii_uppercase();
    format!("{prefix}-{}", base32_encode(short_num))
}

pub fn parse_short_id(raw: &str) -> Option<(String, u64)> {
    let trimmed = raw.trim();
    let (slug, code) = trimmed.rsplit_once('-')?;
    if slug.is_empty() || code.is_empty() || slug.len() > 50 || code.len() > 7 {
        return None;
    }
    if !slug
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return None;
    }
    let val = u64::from_str_radix(code, 32).ok()?;
    if val > i32::MAX as u64 {
        return None;
    }
    Some((slug.to_ascii_lowercase(), val))
}

pub fn new_uuid_v7_from_ms(ms: i64) -> String {
    let secs = (ms.max(0) / 1000) as u64;
    let sub_nanos = ((ms.max(0) % 1000) as u32) * 1_000_000;
    let ts = uuid::Timestamp::from_unix(uuid::NoContext, secs, sub_nanos);
    Uuid::new_v7(ts).to_string()
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Compress JSON blobs > 2 KiB with deflate to reduce SQLite/Postgres disk footprint 5x-8x.
pub fn compress_payload_if_large(raw: &[u8]) -> (Vec<u8>, bool) {
    if raw.len() <= 2048 {
        return (raw.to_vec(), false);
    }
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::with_capacity(raw.len() / 3), flate2::Compression::fast());
    if encoder.write_all(raw).is_ok() {
        if let Ok(compressed) = encoder.finish() {
            if compressed.len() < raw.len() {
                return (compressed, true);
            }
        }
    }
    (raw.to_vec(), false)
}

pub fn decompress_payload(raw: &[u8], compressed: bool) -> Result<Vec<u8>, String> {
    if !compressed {
        return Ok(raw.to_vec());
    }
    let dec = flate2::read::DeflateDecoder::new(raw);
    let mut out = Vec::new();
    dec.take(16 * 1024 * 1024)
        .read_to_end(&mut out)
        .map_err(|e| format!("Failed decompressing stored payload: {e}"))?;
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectAuthInfo {
    pub project_id: i64,
    pub organization_id: i64,
    pub organization_slug: String,
    pub project_slug: String,
    pub first_event_at: Option<i64>,
    pub rate_limit_per_min: u32,
    pub filters: ProjectFilters,
    pub org_scrub_ip_addresses: bool,
    pub org_event_throttle_rate: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct OrgSecuritySettings {
    pub scrub_ip_addresses: bool,
    pub event_throttle_rate: u8,
    pub require_mfa_for_admins: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationDto {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub role: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectDto {
    pub id: i64,
    pub organization_id: i64,
    pub slug: String,
    pub name: String,
    pub platform: String,
    pub first_event_at: Option<i64>,
    pub filters: ProjectFilters,
    pub dsn_public_key: Option<String>,
    pub tunnel_slug: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectKeyDto {
    pub id: i64,
    pub project_id: i64,
    pub label: String,
    pub public_key: String,
    pub rate_limit_per_min: u32,
    pub is_active: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueSummaryDto {
    pub id: i64,
    #[serde(rename = "shortId")]
    pub short_id: String,
    pub project_id: i64,
    pub project_slug: String,
    pub title: String,
    pub culprit: String,
    pub level: String,
    #[serde(rename = "type")]
    pub issue_type: String,
    pub status: String,
    pub is_regression: bool,
    pub resolved_in_release: Option<String>,
    #[serde(rename = "firstSeen")]
    pub first_seen: String,
    #[serde(rename = "lastSeen")]
    pub last_seen: String,
    pub count: i64,
    #[serde(rename = "userCount")]
    pub user_count: i64,
    pub first_release: Option<String>,
    pub last_release: Option<String>,
    pub environment: String,
    pub permalink: String,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueEventDetailDto {
    pub id: String,
    pub event_id: String,
    pub issue_id: i64,
    pub project_id: i64,
    pub timestamp: String,
    pub level: String,
    pub environment: String,
    pub release: Option<String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub tags: Value,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedLog {
    pub timestamp_ms: i64,
    pub level: LogLevel,
    pub severity_number: Option<u16>,
    pub body: String,
    pub service: String,
    pub environment: String,
    pub host: String,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub attributes: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEventDto {
    pub id: String,
    pub timestamp: String,
    pub timestamp_ms: i64,
    pub level: String,
    pub severity_number: Option<u16>,
    pub body: String,
    pub service: String,
    pub environment: String,
    pub host: String,
    #[serde(rename = "traceID")]
    pub trace_id: Option<String>,
    #[serde(rename = "spanID")]
    pub span_id: Option<String>,
    pub data: Value,
    #[serde(rename = "projectId")]
    pub project_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogResourceDto {
    pub name: String,
    #[serde(rename = "type")]
    pub resource_type: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedTransaction {
    pub timestamp_ms: i64,
    pub name: String,
    pub op: String,
    pub status: String,
    pub duration_ms: f64,
    pub trace_id: String,
    pub span_id: String,
    pub environment: String,
    pub release: Option<String>,
    pub spans: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSummaryDto {
    pub name: String,
    pub op: String,
    pub count: i64,
    pub error_count: i64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub avg_ms: f64,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseHealthDto {
    pub version: String,
    pub first_seen: String,
    pub last_seen: String,
    pub issue_count: i64,
    pub healthy_sessions: i64,
    pub errored_sessions: i64,
    pub crashed_sessions: i64,
    pub abnormal_sessions: i64,
    pub crash_free_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UptimeMonitorDto {
    pub id: i64,
    pub project_id: i64,
    pub uuid: String,
    pub name: String,
    pub expected_interval_sec: i64,
    pub last_heartbeat_at: Option<String>,
    pub status: String,
    pub is_active: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRuleDto {
    pub id: i64,
    pub project_id: i64,
    pub name: String,
    pub trigger_type: String,
    pub threshold_count: i64,
    pub window_sec: i64,
    pub cooldown_sec: i64,
    pub channel_type: String,
    pub target_url: String,
    pub has_secret: bool,
    pub email_to: String,
    pub last_triggered_at: Option<i64>,
    pub is_active: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiTokenDto {
    pub id: i64,
    pub name: String,
    pub token_prefix: String,
    pub role: String,
    pub scopes: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogDto {
    pub id: i64,
    pub actor_user_id: Option<i64>,
    pub actor_email: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub ip_hmac: String,
    pub metadata: Value,
    pub entry_hash: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditVerifyDto {
    pub valid: bool,
    pub checked_entries: usize,
    pub broken_at_id: Option<i64>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSessionDto {
    pub id: i64,
    pub user_agent: String,
    pub ip_hmac_short: String,
    pub last_seen_at: String,
    pub created_at: String,
    pub is_current: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyDto {
    pub id: i64,
    pub name: String,
    pub cose_alg: i32,
    pub sign_count: u32,
    pub last_used_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaStatusDto {
    pub totp_enabled: bool,
    pub recovery_codes_remaining: i64,
    pub passkeys: Vec<PasskeyDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationDto {
    pub id: i64,
    pub email: String,
    pub role: String,
    pub invited_by_email: String,
    pub expires_at: String,
    pub accepted_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberDto {
    pub user_id: i64,
    pub email: String,
    pub name: String,
    pub role: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveStreamEvent {
    pub organization_id: i64,
    pub project_id: i64,
    pub kind: String, // "log" | "issue"
    pub level: String,
    pub title_or_body: String,
    pub service: String,
    pub environment: String,
    pub trace_id: Option<String>,
    pub timestamp_ms: i64,
    pub payload: Value,
}

#[derive(Debug, Clone)]
pub struct NewSecurityEvent {
    pub organization_id: i64,
    pub project_id: i64,
    pub project_slug: String,
    pub signal_type: String,
    pub category: String,
    pub severity: String,
    pub risk_score: u32,
    pub source_kind: String,
    pub actor_hmac: String,
    pub session_id: String,
    pub path: String,
    pub details_json: Value,
    pub action_taken: String,
    pub timestamp_ms: i64,
    pub quarantine: Option<(String, String, i64)>, // (subject_type, subject_hmac, expires_at_sec)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEventDto {
    pub id: i64,
    pub project_id: i64,
    pub signal_type: String,
    pub category: String,
    pub severity: String,
    pub risk_score: i64,
    pub source_kind: String,
    pub actor_hmac: String,
    pub session_id: String,
    pub path: String,
    pub details_json: Value,
    pub action_taken: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntryDto {
    pub id: i64,
    pub project_id: i64,
    pub subject_type: String,
    pub subject_hmac: String,
    pub reason: String,
    pub risk_score: i64,
    pub expires_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldSummaryDto {
    pub events_24h: i64,
    pub high_critical_24h: i64,
    pub secret_leaks_24h: i64,
    pub active_quarantines: i64,
}

pub fn iso_from_ms(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_id_roundtrip_matches_glitchtip() {
        assert_eq!(base32_encode(0), "0");
        assert_eq!(base32_encode(10), "A");
        assert_eq!(base32_encode(42), "1A");
        let s = format_short_id("rolelane-api", 42);
        assert_eq!(s, "ROLELANE-API-1A");
        assert_eq!(parse_short_id(&s), Some(("rolelane-api".to_string(), 42)));
    }

    #[test]
    fn payload_compression_roundtrip() {
        let big = vec![b'x'; 4096];
        let (blob, compressed) = compress_payload_if_large(&big);
        assert!(compressed);
        assert!(blob.len() < 512);
        let decoded = decompress_payload(&blob, compressed).unwrap();
        assert_eq!(decoded, big);
    }
}
