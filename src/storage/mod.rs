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
    pub user_id: i64,
    pub email: String,
    pub name: String,
    pub organization_id: i64,
    pub organization_slug: String,
    pub role: UserRole,
    pub csrf_token: String,
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
        expires_at: i64,
    ) -> Result<(), String>;
    async fn resolve_session(&self, token_sha256: &str, now_sec: i64) -> Result<Option<AuthenticatedSession>, String>;
    async fn delete_session(&self, token_sha256: &str) -> Result<(), String>;

    async fn resolve_api_token(&self, token_sha256: &str, org_slug: Option<&str>) -> Result<Option<TenantCtx>, String>;

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
    ) -> Result<ApiTokenDto, String>;
    async fn delete_api_token(&self, ctx: &TenantCtx, token_id: i64) -> Result<bool, String>;

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
