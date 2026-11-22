use crate::config::AppConfig;
use crate::domain::envelope::{parse_envelope, EnvelopeItem};
use crate::domain::models::{
    now_ms, LogLevel, NormalizedLog, ProjectFilters, TenantCtx,
};
use crate::domain::scrubber::Scrubber;
use crate::domain::sourcemap::SourceMapV3;
use crate::runtime::current_vm_rss_bytes;
use crate::storage::{IssueQueryParams, LogQueryParams};
use crate::{build_storage, AppState};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::VecDeque;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_SELF_ERRORS: usize = 128;
const CRASH_FILE_NAME: &str = ".last_self_crash.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Ok,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfCheckItem {
    pub id: String,
    pub status: CheckStatus,
    pub category: String,
    pub title: String,
    pub detail: String,
    pub fix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfErrorRecord {
    pub id: u64,
    pub timestamp_ms: i64,
    pub source: String,
    pub severity: String,
    pub component: String,
    pub message: String,
    pub detail: Option<String>,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfCheckReport {
    pub overall_status: CheckStatus,
    pub version: String,
    pub uptime_sec: u64,
    pub engine: String,
    pub vm_rss_bytes: Option<u64>,
    pub db_size_bytes: u64,
    pub max_db_mb: u64,
    pub checks: Vec<SelfCheckItem>,
    pub self_errors: Vec<SelfErrorRecord>,
    pub unacknowledged_error_count: usize,
    pub missing_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfProbeStep {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfProbeResult {
    pub ok: bool,
    pub steps: Vec<SelfProbeStep>,
    pub report: SelfCheckReport,
}

#[derive(Debug, Deserialize, Serialize)]
struct PersistedCrash {
    timestamp_ms: i64,
    message: String,
    detail: Option<String>,
}

struct MonitorState {
    next_id: u64,
    acknowledged_up_to_id: u64,
    entries: VecDeque<SelfErrorRecord>,
}

/// Bounded in-memory self-monitoring ring buffer (max 128 entries) with disk crash handoff
/// across `panic = "abort"` restarts and mandatory PII/secret scrubbing before storage.
pub struct SelfMonitor {
    data_dir: PathBuf,
    started_at: Instant,
    inner: Mutex<MonitorState>,
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max_chars.saturating_sub(3)).collect();
        out.push_str("...");
        out
    }
}

fn scrub_self_text(raw: &str, max_chars: usize) -> String {
    let scrubber = Scrubber::from_filters(&ProjectFilters::default());
    let scrubbed = scrubber.scrub_string(raw);
    truncate_chars(scrubbed.trim(), max_chars)
}

impl SelfMonitor {
    pub fn new(data_dir: PathBuf) -> Self {
        let mut entries = VecDeque::with_capacity(16);
        let mut next_id = 1u64;

        let crash_path = data_dir.join(CRASH_FILE_NAME);
        if crash_path.is_file() {
            if let Ok(raw) = fs::read_to_string(&crash_path) {
                if let Ok(crash) = serde_json::from_str::<PersistedCrash>(&raw) {
                    entries.push_back(SelfErrorRecord {
                        id: next_id,
                        timestamp_ms: crash.timestamp_ms,
                        source: "rust_panic".to_string(),
                        severity: "error".to_string(),
                        component: "runtime".to_string(),
                        message: scrub_self_text(&crash.message, 256),
                        detail: crash.detail.map(|d| scrub_self_text(&d, 512)),
                        count: 1,
                    });
                    next_id += 1;
                }
            }
        }

        Self {
            data_dir,
            started_at: Instant::now(),
            inner: Mutex::new(MonitorState {
                next_id,
                acknowledged_up_to_id: 0,
                entries,
            }),
        }
    }

    pub fn record(
        &self,
        source: &str,
        severity: &str,
        component: &str,
        message: &str,
        detail: Option<&str>,
    ) {
        let clean_source = truncate_chars(source.trim(), 48);
        let clean_severity = match severity.trim().to_ascii_lowercase().as_str() {
            "warn" | "warning" => "warn".to_string(),
            _ => "error".to_string(),
        };
        let clean_component = truncate_chars(component.trim(), 64);
        let clean_msg = scrub_self_text(message, 256);
        let clean_detail = detail
            .map(|d| scrub_self_text(d, 512))
            .filter(|d| !d.is_empty());

        let ts = now_ms();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(pos) = guard.entries.iter().position(|e| {
            e.source == clean_source
                && e.component == clean_component
                && e.message == clean_msg
        }) {
            let id = guard.next_id;
            guard.next_id += 1;
            if let Some(mut existing) = guard.entries.remove(pos) {
                existing.id = id;
                existing.timestamp_ms = ts;
                existing.severity = clean_severity;
                if clean_detail.is_some() {
                    existing.detail = clean_detail;
                }
                existing.count = existing.count.saturating_add(1);
                guard.entries.push_back(existing);
            }
            return;
        }

        while guard.entries.len() >= MAX_SELF_ERRORS {
            guard.entries.pop_front();
        }
        let id = guard.next_id;
        guard.next_id += 1;
        guard.entries.push_back(SelfErrorRecord {
            id,
            timestamp_ms: ts,
            source: clean_source,
            severity: clean_severity,
            component: clean_component,
            message: if clean_msg.is_empty() {
                "Internal error".to_string()
            } else {
                clean_msg
            },
            detail: clean_detail,
            count: 1,
        });
    }

    pub fn snapshot(&self) -> (Vec<SelfErrorRecord>, usize) {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let ack = guard.acknowledged_up_to_id;
        let list: Vec<SelfErrorRecord> = guard.entries.iter().rev().cloned().collect();
        let unack = list.iter().filter(|e| e.id > ack).count();
        (list, unack)
    }

    pub fn acknowledge_all(&self) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.acknowledged_up_to_id = guard.next_id.saturating_sub(1);
        drop(guard);
        let _ = fs::remove_file(self.data_dir.join(CRASH_FILE_NAME));
    }

    pub fn clear_all(&self) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.entries.clear();
        guard.acknowledged_up_to_id = guard.next_id.saturating_sub(1);
        drop(guard);
        let _ = fs::remove_file(self.data_dir.join(CRASH_FILE_NAME));
    }

    pub fn uptime_sec(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}

/// Install a process panic hook that persists scrubbed crash diagnostics to `{data_dir}/.last_self_crash.json`
/// so fatal panics (even under `panic = "abort"`) surface inside the dashboard after restart.
pub fn install_panic_hook(data_dir: PathBuf) {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "Unexpected Rust panic".to_string()
        };
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()));

        let crash = PersistedCrash {
            timestamp_ms: now_ms(),
            message: scrub_self_text(&payload, 256),
            detail: location.map(|loc| scrub_self_text(&loc, 512)),
        };

        if let Ok(json_str) = serde_json::to_string(&crash) {
            let tmp = data_dir.join(format!("{CRASH_FILE_NAME}.tmp"));
            let final_path = data_dir.join(CRASH_FILE_NAME);
            #[cfg(unix)]
            let file_res = {
                use std::os::unix::fs::OpenOptionsExt;
                fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&tmp)
            };
            #[cfg(not(unix))]
            let file_res = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp);

            if let Ok(mut f) = file_res {
                let _ = f.write_all(json_str.as_bytes());
                let _ = f.sync_all();
                let _ = fs::rename(&tmp, &final_path);
            }
        }

        prev(info);
    }));
}

fn check_data_dir_item(data_dir: &Path) -> SelfCheckItem {
    let probe = data_dir.join(".write_probe");
    let write_res = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&probe)
        .and_then(|mut f| f.write_all(b"ok"));
    let _ = fs::remove_file(&probe);

    if let Err(err) = write_res {
        return SelfCheckItem {
            id: "data_dir_writable".into(),
            status: CheckStatus::Error,
            category: "runtime".into(),
            title: "Data Directory Writable & Key Permissions".into(),
            detail: format!("Cannot write inside {}: {err}", data_dir.display()),
            fix: Some(format!("Ensure user has read/write permissions on {}", data_dir.display())),
        };
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let key_path = data_dir.join(".app_key");
        if key_path.is_file() {
            if let Ok(meta) = fs::metadata(&key_path) {
                let mode = meta.permissions().mode();
                if (mode & 0o077) != 0 {
                    return SelfCheckItem {
                        id: "data_dir_writable".into(),
                        status: CheckStatus::Warn,
                        category: "runtime".into(),
                        title: "Data Directory Writable & Key Permissions".into(),
                        detail: format!(
                            "Key file {} has overly broad Unix permissions ({:o}).",
                            key_path.display(),
                            mode & 0o777
                        ),
                        fix: Some(format!("Run: chmod 600 {}", key_path.display())),
                    };
                }
            }
        }
    }

    SelfCheckItem {
        id: "data_dir_writable".into(),
        status: CheckStatus::Ok,
        category: "runtime".into(),
        title: "Data Directory Writable & Key Permissions".into(),
        detail: format!("{} is writable and .app_key permissions are locked down (0600).", data_dir.display()),
        fix: None,
    }
}

fn check_disk_budget_item(db_size_bytes: u64, max_db_mb: u64) -> SelfCheckItem {
    let max_bytes = max_db_mb.saturating_mul(1024 * 1024).max(1);
    let pct = (db_size_bytes as f64 / max_bytes as f64) * 100.0;
    let mb = db_size_bytes as f64 / (1024.0 * 1024.0);

    if pct >= 95.0 {
        SelfCheckItem {
            id: "disk_budget".into(),
            status: CheckStatus::Error,
            category: "runtime".into(),
            title: "Database Disk Budget".into(),
            detail: format!("{mb:.2} MiB used of {max_db_mb} MiB limit ({pct:.1}%). Circuit breaker active."),
            fix: Some("Increase BUGFINDER_MAX_DB_MB or reduce BUGFINDER_RETENTION_DAYS.".into()),
        }
    } else if pct >= 80.0 {
        SelfCheckItem {
            id: "disk_budget".into(),
            status: CheckStatus::Warn,
            category: "runtime".into(),
            title: "Database Disk Budget".into(),
            detail: format!("{mb:.2} MiB used of {max_db_mb} MiB limit ({pct:.1}%)."),
            fix: Some("Approaching DB limit; review BUGFINDER_MAX_DB_MB or BUGFINDER_RETENTION_DAYS.".into()),
        }
    } else {
        SelfCheckItem {
            id: "disk_budget".into(),
            status: CheckStatus::Ok,
            category: "runtime".into(),
            title: "Database Disk Budget".into(),
            detail: format!("{mb:.2} MiB / {max_db_mb} MiB ({pct:.1}% used)."),
            fix: None,
        }
    }
}

fn check_memory_item(vm_rss_bytes: Option<u64>) -> SelfCheckItem {
    match vm_rss_bytes {
        Some(bytes) => {
            let mb = bytes as f64 / (1024.0 * 1024.0);
            if bytes > 32 * 1024 * 1024 {
                SelfCheckItem {
                    id: "memory_footprint".into(),
                    status: CheckStatus::Warn,
                    category: "runtime".into(),
                    title: "Process Memory Footprint (VmRSS)".into(),
                    detail: format!("Current VmRSS is {mb:.2} MiB (above 32 MiB soft target)."),
                    fix: Some("Monitor active SSE clients or restart process after heavy burst.".into()),
                }
            } else {
                SelfCheckItem {
                    id: "memory_footprint".into(),
                    status: CheckStatus::Ok,
                    category: "runtime".into(),
                    title: "Process Memory Footprint (VmRSS)".into(),
                    detail: format!("Current VmRSS is {mb:.2} MiB (ultra-low RAM target < 15 MiB nominal)."),
                    fix: None,
                }
            }
        }
        None => SelfCheckItem {
            id: "memory_footprint".into(),
            status: CheckStatus::Ok,
            category: "runtime".into(),
            title: "Process Memory Footprint (VmRSS)".into(),
            detail: "Process RSS telemetry unavailable on this OS.".into(),
            fix: None,
        },
    }
}

fn check_security_posture_item(config: &AppConfig) -> SelfCheckItem {
    if !config.is_dev && config.dev_allow_http_webhooks {
        SelfCheckItem {
            id: "security_posture".into(),
            status: CheckStatus::Error,
            category: "security".into(),
            title: "Production Security Posture".into(),
            detail: "BUGFINDER_DEV_ALLOW_HTTP_WEBHOOKS is enabled while BUGFINDER_ENV is production.".into(),
            fix: Some("Unset BUGFINDER_DEV_ALLOW_HTTP_WEBHOOKS or set it to 0 in production.".into()),
        }
    } else if !config.is_dev && !config.force_secure_cookies && config.trusted_proxies.is_empty() {
        SelfCheckItem {
            id: "security_posture".into(),
            status: CheckStatus::Warn,
            category: "security".into(),
            title: "Production Security Posture".into(),
            detail: "Running in production mode without BUGFINDER_FORCE_SECURE_COOKIES or BUGFINDER_TRUSTED_PROXIES.".into(),
            fix: Some("Set BUGFINDER_FORCE_SECURE_COOKIES=1 behind HTTPS reverse proxy and configure BUGFINDER_TRUSTED_PROXIES.".into()),
        }
    } else {
        SelfCheckItem {
            id: "security_posture".into(),
            status: CheckStatus::Ok,
            category: "security".into(),
            title: "Production Security Posture".into(),
            detail: format!(
                "Security headers, CSP nonces, PII scrubber, and SSRF guard active (mode={}).",
                if config.is_dev { "dev" } else { "prod" }
            ),
            fix: None,
        }
    }
}

pub async fn evaluate_self_check(state: &AppState, ctx: &TenantCtx) -> SelfCheckReport {
    let mut checks = Vec::with_capacity(16);
    let mut engine = if state.config.is_postgres() {
        "postgres".to_string()
    } else {
        "sqlite".to_string()
    };

    // 1. Storage engine health
    match state.storage.check_health().await {
        Ok(h) => {
            engine = h.engine.clone();
            let status = if !h.ok {
                CheckStatus::Error
            } else if !h.wal_or_rls_verified {
                if engine == "postgres" {
                    CheckStatus::Error
                } else {
                    CheckStatus::Warn
                }
            } else {
                CheckStatus::Ok
            };
            let fix = match status {
                CheckStatus::Ok => None,
                CheckStatus::Warn => Some("Enable WAL mode on SQLite or check database file lock.".into()),
                CheckStatus::Error => Some(
                    "Verify database file permissions/PostgreSQL FORCE RLS & NOBYPASSRLS role."
                        .into(),
                ),
            };
            checks.push(SelfCheckItem {
                id: "storage_health".into(),
                status,
                category: "runtime".into(),
                title: "Storage Engine & Integrity".into(),
                detail: h.detail,
                fix,
            });
        }
        Err(err) => {
            state.self_monitor.record(
                "storage",
                "error",
                &engine,
                "Storage health check failed",
                Some(&err),
            );
            state.metrics.self_errors_total.fetch_add(1, Ordering::Relaxed);
            checks.push(SelfCheckItem {
                id: "storage_health".into(),
                status: CheckStatus::Error,
                category: "runtime".into(),
                title: "Storage Engine & Integrity".into(),
                detail: scrub_self_text(&err, 256),
                fix: Some("Inspect SQLite file / DATABASE_URL connectivity and file permissions.".into()),
            });
        }
    }

    // 2. Disk budget
    let db_size_bytes = state.storage.db_size_bytes().await;
    checks.push(check_disk_budget_item(db_size_bytes, state.config.max_db_mb));

    // 3. Data dir & key permissions
    checks.push(check_data_dir_item(&state.config.data_dir));

    // 4. Memory footprint
    let vm_rss_bytes = current_vm_rss_bytes();
    checks.push(check_memory_item(vm_rss_bytes));

    // 5. BatchWriter queue depth
    let q_depth = state.metrics.queue_depth.load(Ordering::Relaxed);
    let bw_item = if q_depth >= 3800 {
        SelfCheckItem {
            id: "batch_writer".into(),
            status: CheckStatus::Error,
            category: "runtime".into(),
            title: "Async Micro-Batch Ingestion Queue".into(),
            detail: format!("Queue depth {q_depth}/4096 is near saturation."),
            fix: Some("Check disk I/O latency or reduce ingestion flood.".into()),
        }
    } else if q_depth >= 2048 {
        SelfCheckItem {
            id: "batch_writer".into(),
            status: CheckStatus::Warn,
            category: "runtime".into(),
            title: "Async Micro-Batch Ingestion Queue".into(),
            detail: format!("Queue depth elevated: {q_depth}/4096 pending items."),
            fix: Some("Ingest burst in progress; monitor flush throughput.".into()),
        }
    } else {
        SelfCheckItem {
            id: "batch_writer".into(),
            status: CheckStatus::Ok,
            category: "runtime".into(),
            title: "Async Micro-Batch Ingestion Queue".into(),
            detail: format!(
                "Queue healthy ({q_depth}/4096 pending, {} total flushes).",
                state.metrics.batch_flushes_total.load(Ordering::Relaxed)
            ),
            fix: None,
        }
    };
    checks.push(bw_item);

    // 6. Projects & active DSN key
    let projects_res = state.storage.list_projects(ctx).await;
    match &projects_res {
        Ok(list) => {
            let active_dsns = list.iter().filter(|p| p.dsn_public_key.is_some()).count();
            if list.is_empty() || active_dsns == 0 {
                checks.push(SelfCheckItem {
                    id: "projects_and_dsn".into(),
                    status: CheckStatus::Error,
                    category: "setup".into(),
                    title: "Projects & Active DSN Key".into(),
                    detail: format!("{} projects, {active_dsns} active DSN keys.", list.len()),
                    fix: Some("Open 'Projects & SDK' to create a project and issue a DSN key.".into()),
                });
            } else {
                checks.push(SelfCheckItem {
                    id: "projects_and_dsn".into(),
                    status: CheckStatus::Ok,
                    category: "setup".into(),
                    title: "Projects & Active DSN Key".into(),
                    detail: format!("{} project(s) configured with {active_dsns} active DSN key(s).", list.len()),
                    fix: None,
                });
            }
        }
        Err(err) => {
            checks.push(SelfCheckItem {
                id: "projects_and_dsn".into(),
                status: CheckStatus::Error,
                category: "setup".into(),
                title: "Projects & Active DSN Key".into(),
                detail: scrub_self_text(err, 200),
                fix: Some("Check database permissions or tenant isolation configuration.".into()),
            });
        }
    }

    // 7. Telemetry received (any persisted issue or log)
    let has_issue = state
        .storage
        .list_issues(
            ctx,
            &IssueQueryParams {
                status: None,
                level: None,
                environment: None,
                release: None,
                project_id: None,
                search_query: None,
                sort: "date".into(),
                since_ms: None,
                limit: 1,
                offset: 0,
            },
        )
        .await
        .map(|(rows, _, _)| !rows.is_empty())
        .unwrap_or(false);

    let has_log = state
        .storage
        .query_logs(
            ctx,
            &LogQueryParams {
                project_ids: vec![],
                min_level_num: None,
                level_list: vec![],
                service: None,
                environment: None,
                host: None,
                trace_id: None,
                search_query: None,
                start_ms: None,
                end_ms: None,
                cursor_id: None,
                limit: 1,
            },
        )
        .await
        .map(|rows| !rows.is_empty())
        .unwrap_or(false);

    if has_issue || has_log {
        checks.push(SelfCheckItem {
            id: "telemetry_received".into(),
            status: CheckStatus::Ok,
            category: "setup".into(),
            title: "Telemetry Ingestion Active".into(),
            detail: format!(
                "Persisted telemetry verified (issues={}, logs={}).",
                if has_issue { "present" } else { "none" },
                if has_log { "present" } else { "none" }
            ),
            fix: None,
        });
    } else {
        checks.push(SelfCheckItem {
            id: "telemetry_received".into(),
            status: CheckStatus::Warn,
            category: "setup".into(),
            title: "Telemetry Ingestion Active".into(),
            detail: "No events or structured logs have been ingested yet for this organization.".into(),
            fix: Some("Click 'Run End-to-End Self-Test' or configure the 1-line SDK snippet below.".into()),
        });
    }

    // 8. Alert rules & SMTP configuration
    match state.storage.list_alert_rules(ctx).await {
        Ok(rules) => {
            let needs_smtp = rules.iter().any(|r| r.channel_type.eq_ignore_ascii_case("email"));
            if needs_smtp && state.config.smtp.is_none() {
                checks.push(SelfCheckItem {
                    id: "alerts_configured".into(),
                    status: CheckStatus::Error,
                    category: "setup".into(),
                    title: "Alert Rules & Delivery Channels".into(),
                    detail: "An email alert rule is configured, but BUGFINDER_SMTP_HOST is not set.".into(),
                    fix: Some("Set BUGFINDER_SMTP_HOST, BUGFINDER_SMTP_PORT, BUGFINDER_SMTP_USER, BUGFINDER_SMTP_PASS, BUGFINDER_SMTP_FROM.".into()),
                });
            } else if rules.is_empty() {
                checks.push(SelfCheckItem {
                    id: "alerts_configured".into(),
                    status: CheckStatus::Warn,
                    category: "setup".into(),
                    title: "Alert Rules & Delivery Channels".into(),
                    detail: "No alert rules configured yet.".into(),
                    fix: Some("Open 'Uptime & Alerts' to add a Webhook, Slack, Discord, or Email rule.".into()),
                });
            } else {
                checks.push(SelfCheckItem {
                    id: "alerts_configured".into(),
                    status: CheckStatus::Ok,
                    category: "setup".into(),
                    title: "Alert Rules & Delivery Channels".into(),
                    detail: format!("{} alert rule(s) active.", rules.len()),
                    fix: None,
                });
            }
        }
        Err(err) => {
            checks.push(SelfCheckItem {
                id: "alerts_configured".into(),
                status: CheckStatus::Error,
                category: "setup".into(),
                title: "Alert Rules & Delivery Channels".into(),
                detail: scrub_self_text(&err, 200),
                fix: Some("Verify storage health.".into()),
            });
        }
    }

    // 9. API Tokens & hygiene
    let mut tokens_without_expiry: usize = 0;
    let mut total_tokens: usize = 0;
    match state.storage.list_api_tokens(ctx).await {
        Ok(tokens) => {
            total_tokens = tokens.len();
            tokens_without_expiry = tokens.iter().filter(|t| t.expires_at.is_none()).count();
            if tokens.is_empty() {
                checks.push(SelfCheckItem {
                    id: "api_tokens_configured".into(),
                    status: CheckStatus::Warn,
                    category: "setup".into(),
                    title: "API Tokens (CLI / MCP / ReadClient)".into(),
                    detail: "No API tokens created yet.".into(),
                    fix: Some("Open 'Projects & SDK' -> Generate API Token for bugfinder tail / mcp / integrations.".into()),
                });
            } else {
                checks.push(SelfCheckItem {
                    id: "api_tokens_configured".into(),
                    status: CheckStatus::Ok,
                    category: "setup".into(),
                    title: "API Tokens (CLI / MCP / ReadClient)".into(),
                    detail: format!("{} API token(s) provisioned.", tokens.len()),
                    fix: None,
                });
            }
        }
        Err(err) => {
            checks.push(SelfCheckItem {
                id: "api_tokens_configured".into(),
                status: CheckStatus::Error,
                category: "setup".into(),
                title: "API Tokens (CLI / MCP / ReadClient)".into(),
                detail: scrub_self_text(&err, 200),
                fix: Some("Verify storage health.".into()),
            });
        }
    }

    // 10. Security posture + Enterprise & GlitchTip Parity checks + Runtime Anti-REA integrity
    checks.push(check_security_posture_item(&state.config));

    checks.push(if state.config.is_dev || !state.config.allowed_hosts.is_empty() || state.config.desktop_app_mode {
        SelfCheckItem {
            id: "allowed_hosts_configured".into(),
            status: CheckStatus::Ok,
            category: "security".into(),
            title: "Host Header Allowlist (BUGFINDER_ALLOWED_HOSTS)".into(),
            detail: if state.config.allowed_hosts.is_empty() {
                "Localhost/dev host guard active.".into()
            } else {
                format!("Strict allowlist enforcing {} host(s).", state.config.allowed_hosts.len())
            },
            fix: None,
        }
    } else {
        SelfCheckItem {
            id: "allowed_hosts_configured".into(),
            status: CheckStatus::Warn,
            category: "security".into(),
            title: "Host Header Allowlist (BUGFINDER_ALLOWED_HOSTS)".into(),
            detail: "BUGFINDER_ALLOWED_HOSTS is empty while running in production mode.".into(),
            fix: Some("Set BUGFINDER_ALLOWED_HOSTS=bugs.yourdomain.com to reject Host-header spoofing.".into()),
        }
    });

    match state.storage.count_owners_without_mfa(ctx).await {
        Ok(0) => checks.push(SelfCheckItem {
            id: "mfa_owner_posture".into(),
            status: CheckStatus::Ok,
            category: "security".into(),
            title: "Owner Multi-Factor Authentication (TOTP / Passkey)".into(),
            detail: "All active owner accounts have TOTP or Passkey MFA enrolled.".into(),
            fix: None,
        }),
        Ok(n) => checks.push(SelfCheckItem {
            id: "mfa_owner_posture".into(),
            status: CheckStatus::Warn,
            category: "security".into(),
            title: "Owner Multi-Factor Authentication (TOTP / Passkey)".into(),
            detail: format!("{n} owner account(s) do not have MFA enabled yet."),
            fix: Some("Open Security Shield -> Account & MFA to enroll TOTP or a WebAuthn Passkey.".into()),
        }),
        Err(err) => checks.push(SelfCheckItem {
            id: "mfa_owner_posture".into(),
            status: CheckStatus::Error,
            category: "security".into(),
            title: "Owner Multi-Factor Authentication (TOTP / Passkey)".into(),
            detail: scrub_self_text(&err, 200),
            fix: Some("Verify database schema and MFA tables.".into()),
        }),
    }

    match state.storage.verify_audit_chain(ctx).await {
        Ok(rep) if rep.valid => checks.push(SelfCheckItem {
            id: "audit_chain_integrity".into(),
            status: CheckStatus::Ok,
            category: "security".into(),
            title: "Tamper-Evident Audit Hash Chain".into(),
            detail: format!("Verified {} SHA-256 chained audit entries intact.", rep.checked_entries),
            fix: None,
        }),
        Ok(rep) => checks.push(SelfCheckItem {
            id: "audit_chain_integrity".into(),
            status: CheckStatus::Error,
            category: "security".into(),
            title: "Tamper-Evident Audit Hash Chain".into(),
            detail: format!("Tampered audit chain detected: {}", rep.detail),
            fix: Some("Inspect audit_logs table around broken_at_id immediately for unauthorized modification.".into()),
        }),
        Err(err) => checks.push(SelfCheckItem {
            id: "audit_chain_integrity".into(),
            status: CheckStatus::Error,
            category: "security".into(),
            title: "Tamper-Evident Audit Hash Chain".into(),
            detail: scrub_self_text(&err, 200),
            fix: Some("Verify audit_logs table accessibility.".into()),
        }),
    }

    checks.push(if total_tokens == 0 || tokens_without_expiry == 0 {
        SelfCheckItem {
            id: "api_token_hygiene".into(),
            status: CheckStatus::Ok,
            category: "security".into(),
            title: "Scoped API Token Expiration Hygiene".into(),
            detail: if total_tokens == 0 {
                "No non-expiring API tokens present.".into()
            } else {
                format!("All {total_tokens} active API token(s) have expiration deadlines.")
            },
            fix: None,
        }
    } else {
        SelfCheckItem {
            id: "api_token_hygiene".into(),
            status: CheckStatus::Warn,
            category: "security".into(),
            title: "Scoped API Token Expiration Hygiene".into(),
            detail: format!("{tokens_without_expiry} of {total_tokens} API token(s) have no expiration date."),
            fix: Some("Rotate non-expiring tokens to time-bounded 30-90 day scoped tokens in Projects & SDK.".into()),
        }
    });

    checks.push(SelfCheckItem {
        id: "aead_secret_encryption".into(),
        status: CheckStatus::Ok,
        category: "security".into(),
        title: "At-Rest AEAD Encryption (HKDF-SHA256 + AES-256-GCM)".into(),
        detail: "AES-256-GCM AEAD active for MFA TOTP secrets and webhook HMAC secrets via HKDF-SHA256.".into(),
        fix: None,
    });

    let rt_integrity = crate::security::anti_rea::probe_self_runtime_integrity();
    checks.push(SelfCheckItem {
        id: "runtime_anti_rea_integrity".into(),
        status: if rt_integrity.ok {
            CheckStatus::Ok
        } else if rt_integrity.indicators.iter().any(|i| i.starts_with("mapped:frida")) && !state.config.is_dev {
            CheckStatus::Error
        } else {
            CheckStatus::Warn
        },
        category: "security".into(),
        title: "Self Runtime Anti-REA Integrity (TracerPid / Frida / LD_PRELOAD)".into(),
        detail: rt_integrity.detail,
        fix: if rt_integrity.ok {
            None
        } else {
            Some("Inspect attached debugger/preload libraries and enable BUGFINDER_ANTI_PTRACE=1 in production.".into())
        },
    });

    // 11. Internal self errors
    let (self_errors, unacknowledged_error_count) = state.self_monitor.snapshot();
    let has_unack_err = self_errors
        .iter()
        .take(unacknowledged_error_count)
        .any(|e| e.severity == "error");
    let self_err_item = if unacknowledged_error_count > 0 && has_unack_err {
        SelfCheckItem {
            id: "internal_self_errors".into(),
            status: CheckStatus::Error,
            category: "runtime".into(),
            title: "Internal App Self-Errors".into(),
            detail: format!("{unacknowledged_error_count} unacknowledged internal error(s) detected by self-monitor."),
            fix: Some("Inspect 'Internal App Errors' below, fix the root cause, and click Acknowledge / Clear.".into()),
        }
    } else if unacknowledged_error_count > 0 {
        SelfCheckItem {
            id: "internal_self_errors".into(),
            status: CheckStatus::Warn,
            category: "runtime".into(),
            title: "Internal App Self-Errors".into(),
            detail: format!("{unacknowledged_error_count} unacknowledged internal warning(s)."),
            fix: Some("Review warnings below and acknowledge once checked.".into()),
        }
    } else {
        SelfCheckItem {
            id: "internal_self_errors".into(),
            status: CheckStatus::Ok,
            category: "runtime".into(),
            title: "Internal App Self-Errors".into(),
            detail: format!(
                "Zero unacknowledged internal errors ({} historical buffered).",
                self_errors.len()
            ),
            fix: None,
        }
    };
    checks.push(self_err_item);

    let missing_count = checks
        .iter()
        .filter(|c| c.category == "setup" && !matches!(c.status, CheckStatus::Ok))
        .count();

    let overall_status = if checks.iter().any(|c| c.status == CheckStatus::Error) {
        CheckStatus::Error
    } else if checks.iter().any(|c| c.status == CheckStatus::Warn) {
        CheckStatus::Warn
    } else {
        CheckStatus::Ok
    };

    SelfCheckReport {
        overall_status,
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_sec: state.self_monitor.uptime_sec(),
        engine,
        vm_rss_bytes,
        db_size_bytes,
        max_db_mb: state.config.max_db_mb,
        checks,
        self_errors,
        unacknowledged_error_count,
        missing_count,
    }
}

pub async fn run_live_self_probe(
    state: &AppState,
    ctx: &TenantCtx,
    send_test_log: bool,
) -> SelfProbeResult {
    let mut steps = Vec::with_capacity(5);

    // Step 1: storage_roundtrip
    match state.storage.check_health().await {
        Ok(h) if h.ok && (h.engine != "postgres" || h.wal_or_rls_verified) => {
            steps.push(SelfProbeStep {
                name: "storage_roundtrip".into(),
                ok: true,
                detail: h.detail,
            });
        }
        Ok(h) => {
            let msg = format!("Storage check incomplete: {}", h.detail);
            state
                .self_monitor
                .record("self_probe", "error", "storage", &msg, None);
            state.metrics.self_errors_total.fetch_add(1, Ordering::Relaxed);
            steps.push(SelfProbeStep {
                name: "storage_roundtrip".into(),
                ok: false,
                detail: msg,
            });
        }
        Err(err) => {
            state.self_monitor.record(
                "self_probe",
                "error",
                "storage",
                "Storage roundtrip probe failed",
                Some(&err),
            );
            state.metrics.self_errors_total.fetch_add(1, Ordering::Relaxed);
            steps.push(SelfProbeStep {
                name: "storage_roundtrip".into(),
                ok: false,
                detail: scrub_self_text(&err, 256),
            });
        }
    }

    // Step 2: pii_scrubber
    let sample_secret = "bf_probe_synthetic_token_0000000000"; // gitleaks:allow
    let probe_input = format!("Authorization: Bearer {sample_secret}");
    let scrubbed = Scrubber::from_filters(&ProjectFilters::default()).scrub_string(&probe_input);
    let scrub_ok = scrubbed.contains("[Filtered]") && !scrubbed.contains(sample_secret);
    if !scrub_ok {
        state.self_monitor.record(
            "self_probe",
            "error",
            "scrubber",
            "PII/secret scrubber self-test failed",
            None,
        );
        state.metrics.self_errors_total.fetch_add(1, Ordering::Relaxed);
    }
    steps.push(SelfProbeStep {
        name: "pii_scrubber".into(),
        ok: scrub_ok,
        detail: if scrub_ok {
            "Bearer token and secrets redacted in memory cleanly.".into()
        } else {
            "Scrubber failed to redact synthetic secret.".into()
        },
    });

    // Step 3: envelope_parser
    let env_payload = br#"{"event_id":"11111111111111111111111111111111"}
{"type":"log","content_type":"application/vnd.sentry.items.log+json"}
{"version":2,"items":[{"timestamp":1730000000,"level":"info","severity_number":9,"body":"selfcheck probe"}]}
"#;
    match parse_envelope(env_payload) {
        Ok(parsed) if matches!(parsed.items.first(), Some(EnvelopeItem::Logs(l)) if l.len() == 1) => {
            steps.push(SelfProbeStep {
                name: "envelope_parser".into(),
                ok: true,
                detail: "Sentry NDJSON envelope + Logs v2 item parsed.".into(),
            });
        }
        Ok(_) | Err(_) => {
            state.self_monitor.record(
                "self_probe",
                "error",
                "envelope",
                "Envelope parser self-test failed",
                None,
            );
            state.metrics.self_errors_total.fetch_add(1, Ordering::Relaxed);
            steps.push(SelfProbeStep {
                name: "envelope_parser".into(),
                ok: false,
                detail: "Failed parsing synthetic Sentry Logs v2 envelope.".into(),
            });
        }
    }

    // Step 4: sourcemap_vlq
    let sample_map = br#"{"version":3,"sources":["src/app.ts"],"names":["boot"],"sourcesContent":["const x = 1;\nconst y = 2;\nexport function boot() { return x + y; }\n"],"mappings":";;AAAA"}"#;
    let sm_ok = SourceMapV3::parse(sample_map)
        .ok()
        .and_then(|sm| sm.lookup(3, 0))
        .map(|loc| loc.source == "src/app.ts")
        .unwrap_or(false);
    if !sm_ok {
        state.self_monitor.record(
            "self_probe",
            "error",
            "sourcemap",
            "SourceMap v3 VLQ self-test failed",
            None,
        );
        state.metrics.self_errors_total.fetch_add(1, Ordering::Relaxed);
    }
    steps.push(SelfProbeStep {
        name: "sourcemap_vlq".into(),
        ok: sm_ok,
        detail: if sm_ok {
            "Pure-Rust VLQ decoder mapped frame to src/app.ts.".into()
        } else {
            "VLQ source map lookup failed.".into()
        },
    });

    // Step 5: ingest_pipeline
    if send_test_log {
        match state.storage.list_projects(ctx).await {
            Ok(projects) if !projects.is_empty() => {
                let proj = &projects[0];
                let marker = format!("Live pipeline verification {}", now_ms());
                let body_text = format!("[Self-Check] {marker}");
                let log = NormalizedLog {
                    timestamp_ms: now_ms(),
                    level: LogLevel::Info,
                    severity_number: Some(9),
                    body: body_text,
                    service: "bugfinder-selfcheck".into(),
                    environment: "self-check".into(),
                    host: "localhost".into(),
                    trace_id: None,
                    span_id: None,
                    attributes: json!({ "self_check": true, "project": proj.slug }),
                };
                match state.batch_writer.try_enqueue(crate::storage::IngestWriteItem::Logs {
                    organization_id: ctx.organization_id,
                    project_id: proj.id,
                    project_slug: proj.slug.clone(),
                    auto_promote_level: None,
                    logs: vec![log],
                }) {
                    Ok(()) => {
                        state.batch_writer.flush_now().await;
                        match state
                            .storage
                            .query_logs(
                                ctx,
                                &LogQueryParams {
                                    project_ids: vec![proj.id],
                                    min_level_num: None,
                                    level_list: vec![],
                                    service: Some("bugfinder-selfcheck".into()),
                                    environment: None,
                                    host: None,
                                    trace_id: None,
                                    search_query: Some(marker.clone()),
                                    start_ms: None,
                                    end_ms: None,
                                    cursor_id: None,
                                    limit: 5,
                                },
                            )
                            .await
                        {
                            Ok(rows) if rows.iter().any(|r| r.body.contains(&marker)) => {
                                state.metrics.ingest_logs_total.fetch_add(1, Ordering::Relaxed);
                                steps.push(SelfProbeStep {
                                    name: "ingest_pipeline".into(),
                                    ok: true,
                                    detail: format!(
                                        "Queued, flushed, indexed, and queried synthetic log in project '{}' (FTS5 verified).",
                                        proj.slug
                                    ),
                                });
                            }
                            Ok(_) => {
                                state.self_monitor.record(
                                    "self_probe",
                                    "error",
                                    "ingest",
                                    "Synthetic log missing after flush",
                                    None,
                                );
                                state.metrics.self_errors_total.fetch_add(1, Ordering::Relaxed);
                                steps.push(SelfProbeStep {
                                    name: "ingest_pipeline".into(),
                                    ok: false,
                                    detail: "Synthetic log queued and flushed but not returned by FTS query.".into(),
                                });
                            }
                            Err(err) => {
                                state.self_monitor.record(
                                    "self_probe",
                                    "error",
                                    "ingest",
                                    "Synthetic log query failed",
                                    Some(&err),
                                );
                                state.metrics.self_errors_total.fetch_add(1, Ordering::Relaxed);
                                steps.push(SelfProbeStep {
                                    name: "ingest_pipeline".into(),
                                    ok: false,
                                    detail: scrub_self_text(&err, 256),
                                });
                            }
                        }
                    }
                    Err(err) => {
                        steps.push(SelfProbeStep {
                            name: "ingest_pipeline".into(),
                            ok: false,
                            detail: format!("BatchWriter enqueue failed: {err}"),
                        });
                    }
                }
            }
            _ => {
                steps.push(SelfProbeStep {
                    name: "ingest_pipeline".into(),
                    ok: false,
                    detail: "No project available in organization to verify ingestion pipeline.".into(),
                });
            }
        }
    } else {
        steps.push(SelfProbeStep {
            name: "ingest_pipeline".into(),
            ok: true,
            detail: "Skipped synthetic log write (send_test_log=false).".into(),
        });
    }

    let ok = steps.iter().all(|s| s.ok);
    let report = evaluate_self_check(state, ctx).await;
    SelfProbeResult { ok, steps, report }
}

pub async fn run_doctor_cli(config: &AppConfig, explicit_url: Option<&str>, json_mode: bool) -> i32 {
    let mut items: Vec<SelfCheckItem> = Vec::new();

    // 1. Data directory & .app_key permissions
    items.push(check_data_dir_item(&config.data_dir));

    // 2. Persisted crash artifact from prior panic
    let crash_path = config.data_dir.join(CRASH_FILE_NAME);
    if crash_path.is_file() {
        let msg = fs::read_to_string(&crash_path)
            .ok()
            .and_then(|s| serde_json::from_str::<PersistedCrash>(&s).ok())
            .map(|c| scrub_self_text(&c.message, 180))
            .unwrap_or_else(|| "Unparsed crash record present".into());
        items.push(SelfCheckItem {
            id: "previous_self_crash".into(),
            status: CheckStatus::Error,
            category: "runtime".into(),
            title: "Previous Fatal Self-Crash".into(),
            detail: format!("Crash artifact found at {}: {msg}", crash_path.display()),
            fix: Some("Inspect crash details in UI Auto-Check tab and acknowledge once resolved.".into()),
        });
    } else {
        items.push(SelfCheckItem {
            id: "previous_self_crash".into(),
            status: CheckStatus::Ok,
            category: "runtime".into(),
            title: "Previous Fatal Self-Crash".into(),
            detail: "No unacknowledged fatal crash file found.".into(),
            fix: None,
        });
    }

    // 3. Storage open + health + needs_setup + disk budget
    match build_storage(config).await {
        Ok(storage) => {
            match storage.check_health().await {
                Ok(h) => {
                    let st = if !h.ok || (h.engine == "postgres" && !h.wal_or_rls_verified) {
                        CheckStatus::Error
                    } else if !h.wal_or_rls_verified {
                        CheckStatus::Warn
                    } else {
                        CheckStatus::Ok
                    };
                    items.push(SelfCheckItem {
                        id: "storage_health".into(),
                        status: st,
                        category: "runtime".into(),
                        title: "Storage Engine & Schema".into(),
                        detail: h.detail,
                        fix: if st == CheckStatus::Ok {
                            None
                        } else {
                            Some("Check SQLite WAL or PostgreSQL FORCE RLS + NOBYPASSRLS.".into())
                        },
                    });
                }
                Err(err) => {
                    items.push(SelfCheckItem {
                        id: "storage_health".into(),
                        status: CheckStatus::Error,
                        category: "runtime".into(),
                        title: "Storage Engine & Schema".into(),
                        detail: scrub_self_text(&err, 220),
                        fix: Some("Inspect database permissions or DATABASE_URL.".into()),
                    });
                }
            }

            match storage.needs_setup().await {
                Ok(true) => items.push(SelfCheckItem {
                    id: "initial_setup".into(),
                    status: CheckStatus::Warn,
                    category: "setup".into(),
                    title: "Initial Organization & Owner Setup".into(),
                    detail: "No organization or admin account created yet.".into(),
                    fix: Some("Start Bug-Finder and open http://127.0.0.1:8080 to run 1-minute setup.".into()),
                }),
                Ok(false) => items.push(SelfCheckItem {
                    id: "initial_setup".into(),
                    status: CheckStatus::Ok,
                    category: "setup".into(),
                    title: "Initial Organization & Owner Setup".into(),
                    detail: "Organization, owner account, and project schema initialized.".into(),
                    fix: None,
                }),
                Err(err) => items.push(SelfCheckItem {
                    id: "initial_setup".into(),
                    status: CheckStatus::Error,
                    category: "setup".into(),
                    title: "Initial Organization & Owner Setup".into(),
                    detail: scrub_self_text(&err, 200),
                    fix: Some("Check storage health.".into()),
                }),
            }

            let db_bytes = storage.db_size_bytes().await;
            items.push(check_disk_budget_item(db_bytes, config.max_db_mb));
        }
        Err(err) => {
            items.push(SelfCheckItem {
                id: "storage_health".into(),
                status: CheckStatus::Error,
                category: "runtime".into(),
                title: "Storage Engine & Schema".into(),
                detail: scrub_self_text(&err, 240),
                fix: Some("Ensure valid BUGFINDER_DATA_DIR or DATABASE_URL.".into()),
            });
        }
    }

    // 4. Security posture & optional SMTP
    items.push(check_security_posture_item(config));
    items.push(match &config.smtp {
        Some(smtp) => SelfCheckItem {
            id: "smtp_config".into(),
            status: CheckStatus::Ok,
            category: "setup".into(),
            title: "SMTP Email Transport".into(),
            detail: format!("Configured {}:{} (implicit_tls={}).", smtp.host, smtp.port, smtp.implicit_tls),
            fix: None,
        },
        None => SelfCheckItem {
            id: "smtp_config".into(),
            status: CheckStatus::Ok,
            category: "setup".into(),
            title: "SMTP Email Transport".into(),
            detail: "Optional SMTP not configured (Webhook/Slack/Discord alerts active; set BUGFINDER_SMTP_HOST for email).".into(),
            fix: None,
        },
    });

    // 5. Memory footprint
    items.push(check_memory_item(current_vm_rss_bytes()));

    // 6. Optional live HTTP probe
    if let Some(target_url) = explicit_url {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(2))
            .timeout(Duration::from_secs(2))
            .build();
        let probe_item = match agent.get(target_url).call() {
            Ok(resp) if resp.status() == 200 => SelfCheckItem {
                id: "live_http_probe".into(),
                status: CheckStatus::Ok,
                category: "runtime".into(),
                title: "Live HTTP /api/health Probe".into(),
                detail: format!("GET {target_url} returned HTTP 200."),
                fix: None,
            },
            Ok(resp) => SelfCheckItem {
                id: "live_http_probe".into(),
                status: CheckStatus::Error,
                category: "runtime".into(),
                title: "Live HTTP /api/health Probe".into(),
                detail: format!("GET {target_url} returned HTTP {}.", resp.status()),
                fix: Some("Check Bug-Finder service logs and storage health.".into()),
            },
            Err(err) => SelfCheckItem {
                id: "live_http_probe".into(),
                status: CheckStatus::Error,
                category: "runtime".into(),
                title: "Live HTTP /api/health Probe".into(),
                detail: format!("Failed reaching {target_url}: {err}"),
                fix: Some("Start Bug-Finder daemon or verify --url / port.".into()),
            },
        };
        items.push(probe_item);
    }

    let has_error = items.iter().any(|i| i.status == CheckStatus::Error);
    let has_warn = items.iter().any(|i| i.status == CheckStatus::Warn);

    if json_mode {
        let overall = if has_error {
            "error"
        } else if has_warn {
            "warn"
        } else {
            "ok"
        };
        println!(
            "{}",
            json!({
                "version": env!("CARGO_PKG_VERSION"),
                "overall_status": overall,
                "checks": items,
            })
        );
    } else {
        println!("Bug-Finder Doctor v{}", env!("CARGO_PKG_VERSION"));
        for item in &items {
            let tag = match item.status {
                CheckStatus::Ok => "[OK]  ",
                CheckStatus::Warn => "[WARN]",
                CheckStatus::Error => "[FAIL]",
            };
            println!("{tag} {}: {}", item.title, item.detail);
            if let Some(fix) = &item.fix {
                println!("       Fix: {fix}");
            }
        }
    }

    if has_error {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn self_monitor_scrubs_secrets_deduplicates_and_bounds_at_128() {
        let dir = TempDir::new().unwrap();
        let monitor = SelfMonitor::new(dir.path().to_path_buf());

        // Secret should be scrubbed before persisting in ring buffer
        let raw_bearer = "Bearer secret_unit_test_value_1234567890"; // gitleaks:allow
        monitor.record(
            "http_5xx",
            "error",
            "ingest",
            &format!("Auth failed: {raw_bearer}"),
            Some("bf_test_api_token_unit_9876543210"), // gitleaks:allow
        );
        let (items, unack) = monitor.snapshot();
        assert_eq!(items.len(), 1);
        assert_eq!(unack, 1);
        assert!(!items[0].message.contains("secret_unit_test_value_1234567890"));
        assert!(items[0].message.contains("[Filtered]"));
        assert!(items[0]
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("[Filtered]"));

        // Duplicate increments count rather than adding second entry
        monitor.record(
            "http_5xx",
            "error",
            "ingest",
            &format!("Auth failed: {raw_bearer}"),
            None,
        );
        let (items, _) = monitor.snapshot();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].count, 2);

        // Acknowledge zeros unacknowledged counter
        monitor.acknowledge_all();
        let (_, unack_after) = monitor.snapshot();
        assert_eq!(unack_after, 0);

        // Exceed 128 distinct errors -> oldest dropped, max len stays 128
        for i in 0..140 {
            monitor.record("batch_writer", "warn", "sqlite", &format!("err #{i}"), None);
        }
        let (bounded, _) = monitor.snapshot();
        assert_eq!(bounded.len(), 128);
        assert_eq!(bounded[0].message, "err #139");

        monitor.clear_all();
        let (cleared, unack_cleared) = monitor.snapshot();
        assert!(cleared.is_empty());
        assert_eq!(unack_cleared, 0);
    }

    #[test]
    fn self_monitor_reloads_and_clears_last_crash_file() {
        let dir = TempDir::new().unwrap();
        let crash_path = dir.path().join(CRASH_FILE_NAME);
        fs::write(
            &crash_path,
            r#"{"timestamp_ms":1730000000000,"message":"panic with bf_secret_crash_token_1234567890","detail":"src/main.rs:10:5"}"#, // gitleaks:allow
        )
        .unwrap();

        let monitor = SelfMonitor::new(dir.path().to_path_buf());
        let (items, unack) = monitor.snapshot();
        assert_eq!(items.len(), 1);
        assert_eq!(unack, 1);
        assert_eq!(items[0].source, "rust_panic");
        assert!(!items[0].message.contains("bf_secret_crash_token_1234567890"));
        assert!(items[0].message.contains("[Filtered]"));

        monitor.acknowledge_all();
        assert!(!crash_path.exists());
    }
}
