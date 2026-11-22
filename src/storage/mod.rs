pub mod batch_writer;
pub mod postgres;
pub mod sqlite;

use crate::alerts::dispatcher::AlertDispatchJob;
use crate::domain::envelope::{CheckInItem, SessionUpdate};
use crate::domain::fingerprint::ComputedIssueMetadata;
use crate::domain::models::*;
use async_trait::async_trait;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct AuthenticatedSession {
    pub session_id: i64,
    pub user_id: i64,
    pub email: String,
    pub name: String,
    pub organization_id: i64,
    pub organization_slug: String,
    pub role: UserRole,
    pub csrf_token: String,
    pub reauth_at: Option<i64>,
    pub totp_enabled: bool,
    pub passkey_count: i64,
}

#[derive(Debug, Clone)]
pub struct UserMfaRecord {
    pub user_id: i64,
    pub totp_secret_enc: String,
    pub is_enabled: bool,
    pub last_used_step: Option<i64>,
    pub failed_attempts: i64,
    pub locked_until: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct RecoveryCodeRecord {
    pub id: i64,
    pub code_hash: String,
}

#[derive(Debug, Clone)]
pub struct MfaChallengeRecord {
    pub user_id: i64,
    pub target_org_id: i64,
    pub ip_hmac: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct WebAuthnCredRecord {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub credential_id_b64: String,
    pub cose_alg: i32,
    pub public_key_b64: String,
    pub sign_count: u32,
    pub last_used_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct WebAuthnChallengeRecord {
    pub challenge_b64: String,
    pub user_id: Option<i64>,
    pub flow_kind: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct InvitationLookupInfo {
    pub organization_id: i64,
    pub organization_slug: String,
    pub organization_name: String,
    pub email: String,
    pub role: String,
    pub expires_at: i64,
    pub accepted_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewAuditLog {
    pub organization_id: i64,
    pub actor_user_id: Option<i64>,
    pub actor_email: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub ip_hmac: String,
    pub metadata: Value,
}

#[derive(Debug, Clone)]
pub struct LoginUserRecord {
    pub user_id: i64,
    pub email: String,
    pub name: String,
    pub password_hash: String,
    pub is_active: bool,
    pub organization_id: i64,
    pub organization_slug: String,
    pub role: UserRole,
}

#[derive(Debug, Clone)]
pub struct IssueQueryParams {
    pub status: Option<String>,
    pub level: Option<String>,
    pub environment: Option<String>,
    pub release: Option<String>,
    pub project_id: Option<i64>,
    pub search_query: Option<String>,
    pub sort: String,
    pub since_ms: Option<i64>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Clone)]
pub struct LogQueryParams {
    pub project_ids: Vec<i64>,
    pub min_level_num: Option<i32>,
    pub level_list: Vec<i32>,
    pub service: Option<String>,
    pub environment: Option<String>,
    pub host: Option<String>,
    pub trace_id: Option<String>,
    pub search_query: Option<String>,
    pub start_ms: Option<i64>,
    pub end_ms: Option<i64>,
    pub cursor_id: Option<String>,
    pub limit: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StorageHealthInfo {
    pub engine: String,
    pub ok: bool,
    pub detail: String,
    pub wal_or_rls_verified: bool,
}

#[derive(Debug, Clone)]
pub enum IdempotencyCheck {
    Proceed,
    Replay { status_code: u16, body: String },
    Conflict(String),
}

#[derive(Debug, Clone)]
pub enum IngestWriteItem {
    Event {
        auth: ProjectAuthInfo,
        meta: ComputedIssueMetadata,
        payload_json: Vec<u8>,
        received_ms: i64,
    },
    Logs {
        organization_id: i64,
        project_id: i64,
        project_slug: String,
        auto_promote_level: Option<LogLevel>,
        logs: Vec<NormalizedLog>,
    },
    Transaction {
        organization_id: i64,
        project_id: i64,
        tx: NormalizedTransaction,
    },
    Session {
        organization_id: i64,
        project_id: i64,
        session: SessionUpdate,
        received_ms: i64,
    },
    CheckIn {
        organization_id: i64,
        project_id: i64,
        check_in: CheckInItem,
        received_ms: i64,
    },
}

#[derive(Debug, Clone)]
pub struct NewAlertRule {
    pub project_id: i64,
    pub name: String,
    pub trigger_type: String,
    pub threshold_count: i64,
    pub window_sec: i64,
    pub cooldown_sec: i64,
    pub channel_type: String,
    pub target_url: String,
    pub webhook_secret: String,
    pub email_to: String,
}

#[derive(Debug, Clone)]
pub struct SourceMapRecord {
    pub id: i64,
    pub release_version: String,
    pub debug_id: String,
    pub filename: String,
    pub blob_sha256: String,
    pub size_bytes: i64,
}

/// Sanitize arbitrary user search string into safe FTS5 match tokens (max 256 chars),
/// preventing syntax errors or DoS from unbalanced quotes/operators (`NEAR`, `NOT`, `*`, `:`).
pub fn sanitize_fts5_query(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let tokens: Vec<String> = trimmed
        .chars()
        .take(256)
        .collect::<String>()
        .split_whitespace()
        .filter_map(|tok| {
            let cleaned: String = tok
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '.' || *c == '/')
                .collect();
            let upper = cleaned.to_ascii_uppercase();
            if cleaned.is_empty() || matches!(upper.as_str(), "AND" | "OR" | "NOT" | "NEAR") {
                None
            } else {
                Some(format!("\"{cleaned}\"*"))
            }
        })
        .take(12)
        .collect();

    if tokens.is_empty() {
        None
    } else {
        Some(tokens.join(" "))
    }
}

#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn needs_setup(&self) -> Result<bool, String>;

    async fn initial_setup(
        &self,
        org_name: &str,
        org_slug: &str,
        email: &str,
        name: &str,
        password_hash: &str,
        first_project_name: &str,
        first_project_slug: &str,
        dsn_public_key: &str,
        dsn_key_sha256: &str,
    ) -> Result<(OrganizationDto, ProjectDto), String>;

    async fn find_user_for_login(&self, email: &str) -> Result<Option<LoginUserRecord>, String>;

    async fn check_login_lockout(&self, key_hmac: &str, now_sec: i64) -> Result<Option<i64>, String>;
    async fn record_login_failure(&self, key_hmac: &str, now_sec: i64) -> Result<Option<i64>, String>;
    async fn clear_login_failures(&self, key_hmac: &str) -> Result<(), String>;

    async fn create_session(
        &self,
        token_sha256: &str,
        user_id: i64,
        org_id: i64,
        csrf_token: &str,
        user_agent: &str,
        ip_hmac: &str,
        now_sec: i64,
        expires_at: i64,
    ) -> Result<i64, String>;
    async fn resolve_session(
        &self,
        token_sha256: &str,
        now_sec: i64,
        idle_ttl_sec: i64,
    ) -> Result<Option<AuthenticatedSession>, String>;
    async fn delete_session(&self, token_sha256: &str) -> Result<(), String>;

    async fn resolve_api_token(
        &self,
        token_sha256: &str,
        org_slug: Option<&str>,
        now_sec: i64,
    ) -> Result<Option<TenantCtx>, String>;

    async fn resolve_dsn(&self, project_id: i64, key_sha256: &str) -> Result<Option<ProjectAuthInfo>, String>;
    async fn tunnel_slug_exists(&self, tunnel_slug: &str) -> Result<bool, String>;
    async fn resolve_tunnel(&self, tunnel_slug: &str, project_id: i64, key_sha256: &str) -> Result<Option<ProjectAuthInfo>, String>;

    async fn list_user_organizations(&self, user_id: i64) -> Result<Vec<OrganizationDto>, String>;
    async fn resolve_tenant_for_user(&self, user_id: i64, org_slug: &str) -> Result<Option<TenantCtx>, String>;

    // Tenant-scoped APIs (ALL require &TenantCtx!)
    async fn list_projects(&self, ctx: &TenantCtx) -> Result<Vec<ProjectDto>, String>;
    async fn create_project(
        &self,
        ctx: &TenantCtx,
        name: &str,
        slug: &str,
        platform: &str,
        dsn_public_key: &str,
        dsn_key_sha256: &str,
    ) -> Result<ProjectDto, String>;
    async fn update_project_filters(
        &self,
        ctx: &TenantCtx,
        project_slug: &str,
        filters: &ProjectFilters,
    ) -> Result<Option<ProjectDto>, String>;
    async fn list_project_keys(&self, ctx: &TenantCtx, project_slug: &str) -> Result<Vec<ProjectKeyDto>, String>;
    async fn create_project_key(
        &self,
        ctx: &TenantCtx,
        project_slug: &str,
        label: &str,
        public_key: &str,
        key_sha256: &str,
    ) -> Result<Option<ProjectKeyDto>, String>;
    async fn delete_project_key(&self, ctx: &TenantCtx, project_slug: &str, key_id: i64) -> Result<bool, String>;
    async fn update_project_key(
        &self,
        ctx: &TenantCtx,
        project_slug: &str,
        key_id: i64,
        rate_limit_per_min: u32,
        is_active: bool,
    ) -> Result<Option<ProjectKeyDto>, String>;
    async fn enable_project_tunnel(
        &self,
        ctx: &TenantCtx,
        project_slug: &str,
        tunnel_slug: &str,
    ) -> Result<Option<String>, String>;

    async fn list_issues(&self, ctx: &TenantCtx, params: &IssueQueryParams) -> Result<(Vec<IssueSummaryDto>, i64), String>;
    async fn get_issue(&self, ctx: &TenantCtx, issue_id: i64) -> Result<Option<IssueSummaryDto>, String>;
    async fn update_issue_status(
        &self,
        ctx: &TenantCtx,
        issue_id: i64,
        status: IssueStatus,
        resolved_in_release: Option<&str>,
    ) -> Result<Option<IssueSummaryDto>, String>;
    async fn list_issue_events(&self, ctx: &TenantCtx, issue_id: i64, limit: i64) -> Result<Vec<IssueEventDetailDto>, String>;
    async fn get_issue_event(&self, ctx: &TenantCtx, issue_id: i64, event_id_or_latest: &str) -> Result<Option<IssueEventDetailDto>, String>;

    async fn query_logs(&self, ctx: &TenantCtx, params: &LogQueryParams) -> Result<Vec<LogEventDto>, String>;
    async fn list_log_resources(&self, ctx: &TenantCtx) -> Result<Vec<LogResourceDto>, String>;
    async fn get_log_stats(&self, ctx: &TenantCtx, since_ms: i64, until_ms: i64) -> Result<Value, String>;
    async fn get_stats_v2(&self, ctx: &TenantCtx, category: &str, since_ms: i64, until_ms: i64) -> Result<Value, String>;

    async fn list_transactions(&self, ctx: &TenantCtx, since_ms: i64) -> Result<Vec<TransactionSummaryDto>, String>;
    async fn get_trace_context(&self, ctx: &TenantCtx, trace_id: &str) -> Result<Value, String>;
    async fn list_releases(&self, ctx: &TenantCtx) -> Result<Vec<ReleaseHealthDto>, String>;

    async fn save_source_map(
        &self,
        ctx: &TenantCtx,
        project_slug: &str,
        release_version: &str,
        debug_id: &str,
        filename: &str,
        blob_sha256: &str,
        size_bytes: i64,
    ) -> Result<SourceMapRecord, String>;
    async fn find_source_map(
        &self,
        organization_id: i64,
        project_id: i64,
        release: Option<&str>,
        debug_id: Option<&str>,
        filename: &str,
    ) -> Result<Option<SourceMapRecord>, String>;

    async fn list_monitors(&self, ctx: &TenantCtx) -> Result<Vec<UptimeMonitorDto>, String>;
    async fn create_monitor(
        &self,
        ctx: &TenantCtx,
        project_id: i64,
        name: &str,
        uuid: &str,
        expected_interval_sec: i64,
    ) -> Result<UptimeMonitorDto, String>;
    async fn delete_monitor(&self, ctx: &TenantCtx, monitor_id: i64) -> Result<bool, String>;
    async fn record_heartbeat(&self, ctx: &TenantCtx, uuid: &str, is_up: bool, message: &str) -> Result<Option<UptimeMonitorDto>, String>;
    async fn get_heartbeat(&self, ctx: &TenantCtx, uuid: &str) -> Result<Option<UptimeMonitorDto>, String>;

    async fn list_alert_rules(&self, ctx: &TenantCtx) -> Result<Vec<AlertRuleDto>, String>;
    async fn create_alert_rule(&self, ctx: &TenantCtx, rule: &NewAlertRule) -> Result<AlertRuleDto, String>;
    async fn delete_alert_rule(&self, ctx: &TenantCtx, rule_id: i64) -> Result<bool, String>;
    async fn get_alert_rule(&self, ctx: &TenantCtx, rule_id: i64) -> Result<Option<AlertRuleDto>, String>;
    async fn get_alert_rule_for_dispatch(&self, ctx: &TenantCtx, rule_id: i64) -> Result<Option<(AlertRuleDto, String)>, String>;

    async fn list_api_tokens(&self, ctx: &TenantCtx) -> Result<Vec<ApiTokenDto>, String>;
    async fn create_api_token(
        &self,
        ctx: &TenantCtx,
        name: &str,
        token_sha256: &str,
        token_prefix: &str,
        role: UserRole,
        scopes: &str,
        expires_at: Option<i64>,
    ) -> Result<ApiTokenDto, String>;
    async fn delete_api_token(&self, ctx: &TenantCtx, token_id: i64) -> Result<bool, String>;

    // MFA (TOTP, Recovery Codes, Challenges)
    async fn get_mfa_status(&self, user_id: i64) -> Result<MfaStatusDto, String>;
    async fn get_user_mfa_record(&self, user_id: i64) -> Result<Option<UserMfaRecord>, String>;
    async fn upsert_pending_totp(&self, user_id: i64, totp_secret_enc: &str, now_sec: i64) -> Result<(), String>;
    async fn enable_totp_with_recovery_codes(&self, user_id: i64, code_hashes: &[String], now_sec: i64) -> Result<(), String>;
    async fn disable_mfa(&self, user_id: i64, now_sec: i64) -> Result<(), String>;
    async fn replace_recovery_codes(&self, user_id: i64, code_hashes: &[String], now_sec: i64) -> Result<(), String>;
    async fn record_mfa_attempt(&self, user_id: i64, success_step: Option<i64>, now_sec: i64) -> Result<Option<i64>, String>;
    async fn list_unused_recovery_codes(&self, user_id: i64) -> Result<Vec<RecoveryCodeRecord>, String>;
    async fn mark_recovery_code_used(&self, user_id: i64, code_id: i64, now_sec: i64) -> Result<bool, String>;
    async fn create_mfa_challenge(&self, token_sha256: &str, user_id: i64, target_org_id: i64, ip_hmac: &str, expires_at: i64) -> Result<(), String>;
    async fn consume_mfa_challenge(&self, token_sha256: &str, now_sec: i64) -> Result<Option<MfaChallengeRecord>, String>;
    async fn get_mfa_challenge_user(&self, token_sha256: &str, now_sec: i64) -> Result<Option<MfaChallengeRecord>, String>;

    // Passkeys / WebAuthn
    async fn save_webauthn_challenge(&self, challenge_b64: &str, user_id: Option<i64>, flow_kind: &str, expires_at: i64) -> Result<(), String>;
    async fn consume_webauthn_challenge(&self, challenge_b64: &str, flow_kind: &str, now_sec: i64) -> Result<Option<WebAuthnChallengeRecord>, String>;
    async fn create_webauthn_credential(&self, user_id: i64, name: &str, credential_id_b64: &str, cose_alg: i32, public_key_b64: &str, sign_count: u32) -> Result<PasskeyDto, String>;
    async fn list_webauthn_credentials(&self, user_id: i64) -> Result<Vec<WebAuthnCredRecord>, String>;
    async fn find_webauthn_credential(&self, credential_id_b64: &str) -> Result<Option<WebAuthnCredRecord>, String>;
    async fn update_webauthn_sign_count(&self, cred_id: i64, sign_count: u32, now_sec: i64) -> Result<(), String>;
    async fn delete_webauthn_credential(&self, user_id: i64, cred_id: i64) -> Result<bool, String>;

    // Session lifecycle, step-up & password rotation
    async fn list_user_sessions(&self, user_id: i64, org_id: i64, current_token_sha256: &str, now_sec: i64) -> Result<Vec<ActiveSessionDto>, String>;
    async fn revoke_session_by_id(&self, user_id: i64, org_id: i64, session_id: i64) -> Result<bool, String>;
    async fn revoke_other_sessions(&self, user_id: i64, org_id: i64, keep_token_sha256: &str) -> Result<usize, String>;
    async fn mark_session_reauth(&self, token_sha256: &str, org_id: i64, now_sec: i64) -> Result<(), String>;
    async fn find_user_password_hash(&self, user_id: i64) -> Result<Option<(String, String, String)>, String>;
    async fn change_user_password(
        &self,
        user_id: i64,
        org_id: i64,
        new_password_hash: &str,
        old_session_sha: &str,
        new_session_sha: &str,
        new_csrf: &str,
        user_agent: &str,
        ip_hmac: &str,
        now_sec: i64,
        expires_at: i64,
    ) -> Result<(), String>;

    // Expirable member invitations (72h links)
    async fn create_invitation(&self, ctx: &TenantCtx, email: &str, role: UserRole, token_sha256: &str, expires_at: i64) -> Result<InvitationDto, String>;
    async fn list_invitations(&self, ctx: &TenantCtx) -> Result<Vec<InvitationDto>, String>;
    async fn revoke_invitation(&self, ctx: &TenantCtx, inv_id: i64) -> Result<bool, String>;
    async fn lookup_invitation(&self, token_sha256: &str) -> Result<Option<InvitationLookupInfo>, String>;
    async fn accept_invitation(&self, token_sha256: &str, name: &str, password_hash: &str, now_sec: i64) -> Result<Result<(i64, i64, String, String, UserRole), String>, String>;

    // Hash-chained Audit Logs & Org Security Settings
    async fn append_audit_log(&self, entry: &NewAuditLog) -> Result<(), String>;
    async fn list_audit_logs(&self, ctx: &TenantCtx, action_filter: Option<&str>, limit: i64, offset: i64) -> Result<Vec<AuditLogDto>, String>;
    async fn verify_audit_chain(&self, ctx: &TenantCtx) -> Result<AuditVerifyDto, String>;
    async fn get_org_security_settings(&self, ctx: &TenantCtx) -> Result<OrgSecuritySettings, String>;
    async fn update_org_security_settings(&self, ctx: &TenantCtx, settings: &OrgSecuritySettings) -> Result<OrgSecuritySettings, String>;
    async fn count_owners_without_mfa(&self, ctx: &TenantCtx) -> Result<i64, String>;

    async fn list_members(&self, ctx: &TenantCtx) -> Result<Vec<MemberDto>, String>;
    async fn invite_member(
        &self,
        ctx: &TenantCtx,
        email: &str,
        name: &str,
        password_hash: &str,
        role: UserRole,
    ) -> Result<MemberDto, String>;
    async fn update_member_role(&self, ctx: &TenantCtx, target_user_id: i64, role: UserRole) -> Result<Result<MemberDto, String>, String>;
    async fn remove_member(&self, ctx: &TenantCtx, target_user_id: i64) -> Result<Result<bool, String>, String>;

    async fn begin_idempotency(
        &self,
        ctx: &TenantCtx,
        action: &str,
        idem_key: &str,
        payload_sha256: &str,
    ) -> Result<IdempotencyCheck, String>;
    async fn finish_idempotency(
        &self,
        ctx: &TenantCtx,
        action: &str,
        idem_key: &str,
        status_code: u16,
        response_body: &str,
    ) -> Result<(), String>;

    async fn flush_ingest_batch(&self, items: Vec<IngestWriteItem>) -> Result<Vec<AlertDispatchJob>, String>;
    async fn run_maintenance(&self, retention_days: u32, max_db_mb: u64) -> Result<Vec<AlertDispatchJob>, String>;
    async fn db_size_bytes(&self) -> u64;
    async fn check_health(&self) -> Result<StorageHealthInfo, String>;

    // Anti-REA Shield & Log-IDS telemetry / quarantine
    async fn record_security_event(&self, ev: &NewSecurityEvent) -> Result<(SecurityEventDto, Vec<AlertDispatchJob>), String>;
    async fn list_security_events(
        &self,
        ctx: &TenantCtx,
        project_id: Option<i64>,
        limit: i64,
    ) -> Result<(Vec<SecurityEventDto>, ShieldSummaryDto), String>;
    async fn list_quarantine(&self, ctx: &TenantCtx, project_id: Option<i64>) -> Result<Vec<QuarantineEntryDto>, String>;
    async fn delete_quarantine(&self, ctx: &TenantCtx, entry_id: i64) -> Result<bool, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fts5_sanitizer_neutralizes_hostile_operators() {
        assert_eq!(
            sanitize_fts5_query(r#""foo" OR NOT bar* (baz:1) NEAR/5"#),
            Some("\"foo\"* \"bar\"* \"baz1\"* \"NEAR/5\"*".to_string())
        );
        assert_eq!(sanitize_fts5_query("   ***  "), None);
    }
}
