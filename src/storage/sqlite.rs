use crate::alerts::dispatcher::AlertDispatchJob;
use crate::domain::fingerprint::{extract_issue_metadata, should_reopen_on_regression};
use crate::domain::models::*;
use crate::runtime::trim_heap;
use crate::security::auth::{compute_audit_entry_hash, compute_lockout_seconds};
use crate::security::crypto::{open_secret, seal_secret};
use crate::storage::*;
use async_trait::async_trait;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Transaction};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const SQLITE_SCHEMA: &str = include_str!("../../migrations/sqlite/001_init.sql");

fn webhook_aad(org_id: i64) -> Vec<u8> {
    format!("alert_rules:webhook_secret:{org_id}").into_bytes()
}

fn open_webhook_secret(app_key: &[u8; 32], org_id: i64, stored: &str) -> String {
    open_secret(app_key, &webhook_aad(org_id), stored, true).unwrap_or_default()
}

fn sqlite_has_column(conn: &Connection, table: &str, col: &str) -> bool {
    let Ok(mut stmt) = conn.prepare(&format!("PRAGMA table_info({table})")) else {
        return false;
    };
    let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(1)) else {
        return false;
    };
    for r in rows.flatten() {
        if r == col {
            return true;
        }
    }
    false
}

struct StormWindow {
    window_start_ms: i64,
    count: u32,
}

pub struct SqliteStorage {
    path: PathBuf,
    app_key: [u8; 32],
    writer: Arc<Mutex<Connection>>,
    readers: Arc<Vec<Mutex<Connection>>>,
    rr_idx: Arc<AtomicUsize>,
    storm_counters: Arc<Mutex<HashMap<(i64, String), StormWindow>>>,
}

impl SqliteStorage {
    pub fn open(path: &Path) -> Result<Arc<Self>, String> {
        Self::open_with_key(path, [0u8; 32])
    }

    pub fn open_with_key(path: &Path, app_key: [u8; 32]) -> Result<Arc<Self>, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed creating SQLite parent dir: {e}"))?;
        }
        let writer = Connection::open(path).map_err(|e| format!("Open SQLite writer: {e}"))?;
        writer
            .execute_batch(SQLITE_SCHEMA)
            .map_err(|e| format!("SQLite schema migration: {e}"))?;

        // Idempotent upgrades for pre-existing SQLite databases
        let upgrades = [
            ("organizations", "settings_json", "ALTER TABLE organizations ADD COLUMN settings_json TEXT NOT NULL DEFAULT '{}'"),
            ("sessions", "user_agent", "ALTER TABLE sessions ADD COLUMN user_agent TEXT NOT NULL DEFAULT ''"),
            ("sessions", "ip_hmac", "ALTER TABLE sessions ADD COLUMN ip_hmac TEXT NOT NULL DEFAULT ''"),
            ("sessions", "last_seen_at", "ALTER TABLE sessions ADD COLUMN last_seen_at INTEGER NOT NULL DEFAULT 0"),
            ("sessions", "reauth_at", "ALTER TABLE sessions ADD COLUMN reauth_at INTEGER"),
            ("api_tokens", "expires_at", "ALTER TABLE api_tokens ADD COLUMN expires_at INTEGER"),
            ("audit_logs", "actor_email", "ALTER TABLE audit_logs ADD COLUMN actor_email TEXT NOT NULL DEFAULT ''"),
            ("audit_logs", "ip_hmac", "ALTER TABLE audit_logs ADD COLUMN ip_hmac TEXT NOT NULL DEFAULT ''"),
            ("audit_logs", "metadata_json", "ALTER TABLE audit_logs ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}'"),
            ("audit_logs", "prev_hash", "ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT NOT NULL DEFAULT 'GENESIS'"),
            ("audit_logs", "entry_hash", "ALTER TABLE audit_logs ADD COLUMN entry_hash TEXT NOT NULL DEFAULT ''"),
        ];
        for (tbl, col, ddl) in upgrades {
            if !sqlite_has_column(&writer, tbl, col) {
                writer
                    .execute_batch(ddl)
                    .map_err(|e| format!("SQLite column upgrade {tbl}.{col}: {e}"))?;
            }
        }

        // Upgrade legacy organization_members / api_tokens role CHECK constraints if missing 'manager'
        if let Ok(Some(sql_def)) = writer
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='organization_members'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()
        {
            if !sql_def.contains("manager") {
                writer
                    .execute_batch(
                        "PRAGMA foreign_keys = OFF;
                         BEGIN IMMEDIATE;
                         CREATE TABLE organization_members_v2 (
                             organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                             user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                             role TEXT NOT NULL CHECK(role IN ('owner', 'manager', 'admin', 'member', 'viewer')),
                             PRIMARY KEY (organization_id, user_id)
                         );
                         INSERT INTO organization_members_v2 SELECT organization_id, user_id, role FROM organization_members;
                         DROP TABLE organization_members;
                         ALTER TABLE organization_members_v2 RENAME TO organization_members;
                         COMMIT;
                         PRAGMA foreign_keys = ON;",
                    )
                    .map_err(|e| format!("SQLite organization_members migration: {e}"))?;
            }
        }
        if let Ok(Some(sql_def)) = writer
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='api_tokens'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()
        {
            if !sql_def.contains("manager") {
                writer
                    .execute_batch(
                        "PRAGMA foreign_keys = OFF;
                         BEGIN IMMEDIATE;
                         CREATE TABLE api_tokens_v2 (
                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                             organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                             user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                             name TEXT NOT NULL,
                             token_sha256 TEXT NOT NULL UNIQUE,
                             token_prefix TEXT NOT NULL,
                             role TEXT NOT NULL CHECK(role IN ('owner', 'manager', 'admin', 'member', 'viewer')),
                             scopes TEXT NOT NULL DEFAULT 'project:read project:write event:read',
                             expires_at INTEGER,
                             last_used_at INTEGER,
                             created_at INTEGER NOT NULL
                         );
                         INSERT INTO api_tokens_v2 SELECT id, organization_id, user_id, name, token_sha256, token_prefix, role, scopes, expires_at, last_used_at, created_at FROM api_tokens;
                         DROP TABLE api_tokens;
                         ALTER TABLE api_tokens_v2 RENAME TO api_tokens;
                         COMMIT;
                         PRAGMA foreign_keys = ON;",
                    )
                    .map_err(|e| format!("SQLite api_tokens migration: {e}"))?;
            }
        }

        // Upgrade legacy alert_rules CHECK constraint in existing SQLite files if needed
        if let Ok(Some(sql_def)) = writer
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='alert_rules'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()
        {
            if !sql_def.contains("security_threat") {
                writer
                    .execute_batch(
                        "BEGIN IMMEDIATE;
                         CREATE TABLE alert_rules_v2 (
                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                             organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                             project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                             name TEXT NOT NULL,
                             trigger_type TEXT NOT NULL CHECK(trigger_type IN ('new_issue', 'regression', 'threshold', 'fatal_log', 'uptime_down', 'security_threat', 'secret_leak')),
                             threshold_count INTEGER NOT NULL DEFAULT 1,
                             window_sec INTEGER NOT NULL DEFAULT 60,
                             cooldown_sec INTEGER NOT NULL DEFAULT 300,
                             channel_type TEXT NOT NULL CHECK(channel_type IN ('webhook', 'slack', 'discord', 'email')),
                             target_url TEXT NOT NULL DEFAULT '',
                             webhook_secret TEXT NOT NULL DEFAULT '',
                             email_to TEXT NOT NULL DEFAULT '',
                             last_triggered_at INTEGER,
                             is_active INTEGER NOT NULL DEFAULT 1,
                             created_at INTEGER NOT NULL
                         );
                         INSERT INTO alert_rules_v2 SELECT id, organization_id, project_id, name, trigger_type, threshold_count, window_sec, cooldown_sec, channel_type, target_url, webhook_secret, email_to, last_triggered_at, is_active, created_at FROM alert_rules;
                         DROP TABLE alert_rules;
                         ALTER TABLE alert_rules_v2 RENAME TO alert_rules;
                         COMMIT;",
                    )
                    .map_err(|e| format!("SQLite alert_rules migration: {e}"))?;
            }
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }

        let mut readers = Vec::with_capacity(4);
        for _ in 0..4 {
            let r = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(|e| format!("Open SQLite reader: {e}"))?;
            let _ = r.execute_batch("PRAGMA busy_timeout = 5000; PRAGMA query_only = ON;");
            readers.push(Mutex::new(r));
        }

        Ok(Arc::new(Self {
            path: path.to_path_buf(),
            app_key,
            writer: Arc::new(Mutex::new(writer)),
            readers: Arc::new(readers),
            rr_idx: Arc::new(AtomicUsize::new(0)),
            storm_counters: Arc::new(Mutex::new(HashMap::new())),
        }))
    }

    async fn read<F, R>(&self, f: F) -> Result<R, String>
    where
        F: FnOnce(&Connection) -> Result<R, String> + Send + 'static,
        R: Send + 'static,
    {
        let readers = self.readers.clone();
        let rr_idx = self.rr_idx.clone();
        tokio::task::spawn_blocking(move || {
            let idx = rr_idx.fetch_add(1, Ordering::Relaxed) % readers.len();
            let guard = readers[idx].lock().unwrap_or_else(|e| e.into_inner());
            f(&guard)
        })
        .await
        .map_err(|e| format!("SQLite read task join: {e}"))?
    }

    async fn write<F, R>(&self, f: F) -> Result<R, String>
    where
        F: FnOnce(&mut Connection) -> Result<R, String> + Send + 'static,
        R: Send + 'static,
    {
        let writer = self.writer.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = writer.lock().unwrap_or_else(|e| e.into_inner());
            f(&mut guard)
        })
        .await
        .map_err(|e| format!("SQLite write task join: {e}"))?
    }

    fn should_sample_storm(
        storm_counters: &Mutex<HashMap<(i64, String), StormWindow>>,
        project_id: i64,
        fingerprint: &str,
        filters: &ProjectFilters,
        now_ms: i64,
    ) -> bool {
        if filters.storm_sample_threshold == 0 {
            return true;
        }
        let mut guard = storm_counters.lock().unwrap_or_else(|e| e.into_inner());
        if guard.len() > 8192 {
            guard.clear();
        }
        let key = (project_id, fingerprint.to_string());
        let entry = guard.entry(key).or_insert(StormWindow {
            window_start_ms: now_ms,
            count: 0,
        });
        if now_ms - entry.window_start_ms >= 60_000 {
            entry.window_start_ms = now_ms;
            entry.count = 1;
            return true;
        }
        entry.count = entry.count.saturating_add(1);
        if entry.count <= filters.storm_sample_threshold {
            return true;
        }
        let every = filters.storm_sample_every.max(2);
        entry.count % every == 0
    }
}

fn map_sqlite_err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn build_alert_jobs_for_event(
    tx: &Transaction<'_>,
    app_key: &[u8; 32],
    organization_id: i64,
    project_id: i64,
    project_slug: &str,
    short_id: &str,
    title: &str,
    level: &str,
    is_new_issue: bool,
    is_regression: bool,
    now_sec: i64,
) -> Result<Vec<AlertDispatchJob>, String> {
    let mut stmt = tx
        .prepare(
            "SELECT id, name, trigger_type, threshold_count, window_sec, cooldown_sec,
                    channel_type, target_url, webhook_secret, email_to, last_triggered_at
             FROM alert_rules
             WHERE organization_id = ?1 AND project_id = ?2 AND is_active = 1",
        )
        .map_err(map_sqlite_err)?;

    let mut rows = stmt
        .query(params![organization_id, project_id])
        .map_err(map_sqlite_err)?;
    let mut jobs = Vec::new();
    let mut triggered_ids = Vec::new();

    while let Some(r) = rows.next().map_err(map_sqlite_err)? {
        let id: i64 = r.get(0).map_err(map_sqlite_err)?;
        let name: String = r.get(1).map_err(map_sqlite_err)?;
        let trigger_type: String = r.get(2).map_err(map_sqlite_err)?;
        let threshold_count: i64 = r.get(3).map_err(map_sqlite_err)?;
        let window_sec: i64 = r.get(4).map_err(map_sqlite_err)?;
        let cooldown_sec: i64 = r.get(5).map_err(map_sqlite_err)?;
        let channel_type: String = r.get(6).map_err(map_sqlite_err)?;
        let target_url: String = r.get(7).map_err(map_sqlite_err)?;
        let webhook_secret: String = open_webhook_secret(
            app_key,
            organization_id,
            &r.get::<_, String>(8).map_err(map_sqlite_err)?,
        );
        let email_to: String = r.get(9).map_err(map_sqlite_err)?;
        let last_triggered_at: Option<i64> = r.get(10).map_err(map_sqlite_err)?;

        if let Some(last) = last_triggered_at {
            if now_sec - last < cooldown_sec {
                continue;
            }
        }

        let matched = match trigger_type.as_str() {
            "new_issue" => is_new_issue,
            "regression" => is_regression,
            "fatal_log" => level == "fatal",
            "threshold" => {
                let since_ms = (now_sec - window_sec) * 1000;
                let recent: i64 = tx
                    .query_row(
                        "SELECT COUNT(*) FROM issue_events WHERE organization_id = ?1 AND project_id = ?2 AND timestamp_ms >= ?3",
                        params![organization_id, project_id, since_ms],
                        |c| c.get(0),
                    )
                    .unwrap_or(0);
                recent >= threshold_count.max(1)
            }
            _ => false,
        };

        if matched {
            triggered_ids.push(id);
            jobs.push(AlertDispatchJob {
                rule_id: id,
                rule_name: name,
                channel_type,
                target_url,
                webhook_secret,
                email_to,
                title: title.to_string(),
                message: format!("Trigger: {trigger_type} | Issue {short_id}"),
                level: level.to_string(),
                project_slug: project_slug.to_string(),
                short_id: Some(short_id.to_string()),
            });
        }
    }
    drop(rows);
    drop(stmt);

    for id in triggered_ids {
        tx.execute(
            "UPDATE alert_rules SET last_triggered_at = ?1 WHERE id = ?2 AND organization_id = ?3",
            params![now_sec, id, organization_id],
        )
        .map_err(map_sqlite_err)?;
    }

    Ok(jobs)
}

#[allow(clippy::too_many_arguments)]
fn insert_event_in_txn(
    tx: &Transaction<'_>,
    auth: &ProjectAuthInfo,
    meta: &ComputedIssueMetadata,
    payload_json: &[u8],
    received_ms: i64,
    store_full_blob: bool,
) -> Result<(i64, String, bool, bool), String> {
    if auth.first_event_at.is_none() {
        tx.execute(
            "UPDATE projects SET first_event_at = ?1 WHERE id = ?2 AND organization_id = ?3 AND first_event_at IS NULL",
            params![received_ms, auth.project_id, auth.organization_id],
        )
        .map_err(map_sqlite_err)?;
    }

    if let Some(rel) = &meta.release {
        tx.execute(
            "INSERT INTO releases (organization_id, project_id, version, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(project_id, version) DO UPDATE SET last_seen = MAX(last_seen, excluded.last_seen)",
            params![auth.organization_id, auth.project_id, rel, received_ms],
        )
        .map_err(map_sqlite_err)?;
    }

    // Deduplicate event_id safely
    let dup: Option<String> = tx
        .query_row(
            "SELECT id FROM issue_events WHERE project_id = ?1 AND event_id = ?2",
            params![auth.project_id, meta.event_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(map_sqlite_err)?;
    if dup.is_some() {
        return Ok((0, String::new(), false, false));
    }

    let existing: Option<(i64, String, String, Option<String>)> = tx
        .query_row(
            "SELECT id, short_id, status, resolved_in_release FROM issues WHERE project_id = ?1 AND fingerprint = ?2",
            params![auth.project_id, meta.fingerprint],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .map_err(map_sqlite_err)?;

    let (issue_id, short_id, is_new, is_regression) = match existing {
        Some((id, short_id, status_str, resolved_in_release)) => {
            let status = IssueStatus::from_str_opt(&status_str).unwrap_or(IssueStatus::Unresolved);
            let reopen = should_reopen_on_regression(
                status,
                resolved_in_release.as_deref(),
                meta.release.as_deref(),
            );
            let new_status = if reopen { "unresolved" } else { status.as_str() };
            let reg_flag = if reopen { 1 } else { 0 };

            tx.execute(
                "UPDATE issues
                 SET event_count = event_count + 1,
                     last_seen = MAX(last_seen, ?1),
                     last_release = COALESCE(?2, last_release),
                     status = ?3,
                     is_regression = CASE WHEN ?4 = 1 THEN 1 ELSE is_regression END
                 WHERE id = ?5 AND organization_id = ?6",
                params![
                    received_ms,
                    meta.release,
                    new_status,
                    reg_flag,
                    id,
                    auth.organization_id
                ],
            )
            .map_err(map_sqlite_err)?;

            (id, short_id, false, reopen)
        }
        None => {
            let short_num: i64 = tx
                .query_row(
                    "UPDATE projects SET next_short_num = next_short_num + 1 WHERE id = ?1 AND organization_id = ?2 RETURNING next_short_num - 1",
                    params![auth.project_id, auth.organization_id],
                    |r| r.get(0),
                )
                .map_err(map_sqlite_err)?;
            let short_id = format_short_id(&auth.project_slug, short_num.max(1) as u64);
            let metadata_json = serde_json::to_string(&json!({
                "title": meta.title,
                "value": meta.title,
            }))
            .unwrap_or_else(|_| "{}".into());

            tx.execute(
                "INSERT INTO issues (
                    organization_id, project_id, short_id, short_num, fingerprint,
                    title, culprit, level, issue_type, status, is_regression,
                    first_seen, last_seen, event_count, user_count,
                    first_release, last_release, environment, metadata_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'unresolved', 0, ?10, ?10, 1, 0, ?11, ?11, ?12, ?13)",
                params![
                    auth.organization_id,
                    auth.project_id,
                    short_id,
                    short_num,
                    meta.fingerprint,
                    meta.title,
                    meta.culprit,
                    meta.level,
                    meta.issue_type.as_str(),
                    received_ms,
                    meta.release,
                    meta.environment,
                    metadata_json
                ],
            )
            .map_err(map_sqlite_err)?;
            let id = tx.last_insert_rowid();

            tx.execute(
                "INSERT INTO issues_fts (title, culprit, search_text, issue_id, organization_id) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    meta.title,
                    meta.culprit,
                    meta.search_text,
                    id,
                    auth.organization_id
                ],
            )
            .map_err(map_sqlite_err)?;

            (id, short_id, true, false)
        }
    };

    if let Some(uh) = &meta.user_hash {
        let changed = tx
            .execute(
                "INSERT OR IGNORE INTO issue_users (issue_id, user_hash) VALUES (?1, ?2)",
                params![issue_id, uh],
            )
            .map_err(map_sqlite_err)?;
        if changed > 0 {
            tx.execute(
                "UPDATE issues SET user_count = user_count + 1 WHERE id = ?1 AND organization_id = ?2",
                params![issue_id, auth.organization_id],
            )
            .map_err(map_sqlite_err)?;
        }
    }

    if store_full_blob {
        let row_uuid = new_uuid_v7_from_ms(received_ms);
        let tags_str = serde_json::to_string(&meta.tags).unwrap_or_else(|_| "{}".into());
        let (blob, compressed) = compress_payload_if_large(payload_json);
        tx.execute(
            "INSERT OR IGNORE INTO issue_events (
                id, organization_id, project_id, issue_id, event_id, timestamp_ms,
                level, environment, release, trace_id, span_id, user_hash, tags_json,
                payload_blob, payload_compressed
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                row_uuid,
                auth.organization_id,
                auth.project_id,
                issue_id,
                meta.event_id,
                received_ms,
                meta.level,
                meta.environment,
                meta.release,
                meta.trace_id,
                meta.span_id,
                meta.user_hash,
                tags_str,
                blob,
                if compressed { 1 } else { 0 }
            ],
        )
        .map_err(map_sqlite_err)?;
    }

    let bucket_hour = (received_ms / 3_600_000) * 3_600_000;
    tx.execute(
        "INSERT INTO hourly_stats (organization_id, project_id, bucket_hour, category, quantity)
         VALUES (?1, ?2, ?3, 'error', 1)
         ON CONFLICT(project_id, bucket_hour, category) DO UPDATE SET quantity = quantity + 1",
        params![auth.organization_id, auth.project_id, bucket_hour],
    )
    .map_err(map_sqlite_err)?;

    Ok((issue_id, short_id, is_new, is_regression))
}

#[async_trait]
impl StorageBackend for SqliteStorage {
    async fn needs_setup(&self) -> Result<bool, String> {
        self.read(|conn| {
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
                .map_err(map_sqlite_err)?;
            Ok(count == 0)
        })
        .await
    }

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
    ) -> Result<(OrganizationDto, ProjectDto), String> {
        let org_name = org_name.to_string();
        let org_slug = org_slug.to_string();
        let email = email.to_ascii_lowercase();
        let name = name.to_string();
        let password_hash = password_hash.to_string();
        let proj_name = first_project_name.to_string();
        let proj_slug = first_project_slug.to_string();
        let dsn_pub = dsn_public_key.to_string();
        let dsn_sha = dsn_key_sha256.to_string();

        self.write(move |conn| {
            let now = now_ms();
            let tx = conn.transaction().map_err(map_sqlite_err)?;
            let count: i64 = tx
                .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
                .map_err(map_sqlite_err)?;
            if count > 0 {
                return Err("Setup already completed".into());
            }

            tx.execute(
                "INSERT INTO organizations (slug, name, created_at) VALUES (?1, ?2, ?3)",
                params![org_slug, org_name, now],
            )
            .map_err(map_sqlite_err)?;
            let org_id = tx.last_insert_rowid();

            tx.execute(
                "INSERT INTO users (email, name, password_hash, is_active, created_at) VALUES (?1, ?2, ?3, 1, ?4)",
                params![email, name, password_hash, now],
            )
            .map_err(map_sqlite_err)?;
            let user_id = tx.last_insert_rowid();

            tx.execute(
                "INSERT INTO organization_members (organization_id, user_id, role) VALUES (?1, ?2, 'owner')",
                params![org_id, user_id],
            )
            .map_err(map_sqlite_err)?;

            let default_filters = serde_json::to_string(&ProjectFilters::default()).unwrap();
            tx.execute(
                "INSERT INTO projects (organization_id, slug, name, platform, filters_json, created_at)
                 VALUES (?1, ?2, ?3, 'javascript', ?4, ?5)",
                params![org_id, proj_slug, proj_name, default_filters, now],
            )
            .map_err(map_sqlite_err)?;
            let project_id = tx.last_insert_rowid();

            tx.execute(
                "INSERT INTO project_keys (organization_id, project_id, label, public_key, key_sha256, rate_limit_per_min, is_active, created_at)
                 VALUES (?1, ?2, 'Default DSN', ?3, ?4, 300, 1, ?5)",
                params![org_id, project_id, dsn_pub, dsn_sha, now],
            )
            .map_err(map_sqlite_err)?;

            tx.commit().map_err(map_sqlite_err)?;

            Ok((
                OrganizationDto {
                    id: org_id,
                    slug: org_slug,
                    name: org_name,
                    role: "owner".into(),
                    created_at: now,
                },
                ProjectDto {
                    id: project_id,
                    organization_id: org_id,
                    slug: proj_slug,
                    name: proj_name,
                    platform: "javascript".into(),
                    first_event_at: None,
                    filters: ProjectFilters::default(),
                    dsn_public_key: Some(dsn_pub),
                    tunnel_slug: None,
                    created_at: now,
                },
            ))
        })
        .await
    }

    async fn find_user_for_login(&self, email: &str) -> Result<Option<LoginUserRecord>, String> {
        let email = email.trim().to_ascii_lowercase();
        self.read(move |conn| {
            conn.query_row(
                "SELECT u.id, u.email, u.name, u.password_hash, u.is_active,
                        o.id, o.slug, m.role
                 FROM users u
                 JOIN organization_members m ON m.user_id = u.id
                 JOIN organizations o ON o.id = m.organization_id
                 WHERE u.email = ?1
                 ORDER BY o.id ASC LIMIT 1",
                params![email],
                |r| {
                    let role_s: String = r.get(7)?;
                    Ok(LoginUserRecord {
                        user_id: r.get(0)?,
                        email: r.get(1)?,
                        name: r.get(2)?,
                        password_hash: r.get(3)?,
                        is_active: r.get::<_, i64>(4)? != 0,
                        organization_id: r.get(5)?,
                        organization_slug: r.get(6)?,
                        role: UserRole::from_db(&role_s).unwrap_or(UserRole::Viewer),
                    })
                },
            )
            .optional()
            .map_err(map_sqlite_err)
        })
        .await
    }

    async fn check_login_lockout(&self, key_hmac: &str, now_sec: i64) -> Result<Option<i64>, String> {
        let key_hmac = key_hmac.to_string();
        self.read(move |conn| {
            let locked: Option<Option<i64>> = conn
                .query_row(
                    "SELECT locked_until FROM login_attempts WHERE key_hmac = ?1",
                    params![key_hmac],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_sqlite_err)?;
            if let Some(Some(until)) = locked {
                if until > now_sec {
                    return Ok(Some(until - now_sec));
                }
            }
            Ok(None)
        })
        .await
    }

    async fn record_login_failure(&self, key_hmac: &str, now_sec: i64) -> Result<Option<i64>, String> {
        let key_hmac = key_hmac.to_string();
        self.write(move |conn| {
            let tx = conn.transaction().map_err(map_sqlite_err)?;
            let prev: i64 = tx
                .query_row(
                    "SELECT failed_count FROM login_attempts WHERE key_hmac = ?1",
                    params![key_hmac],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_sqlite_err)?
                .unwrap_or(0);
            let next_count = prev + 1;
            let lock_secs = compute_lockout_seconds(next_count);
            let locked_until = lock_secs.map(|s| now_sec + s);
            tx.execute(
                "INSERT INTO login_attempts (key_hmac, failed_count, locked_until, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(key_hmac) DO UPDATE SET failed_count = ?2, locked_until = ?3, updated_at = ?4",
                params![key_hmac, next_count, locked_until, now_sec],
            )
            .map_err(map_sqlite_err)?;
            tx.commit().map_err(map_sqlite_err)?;
            Ok(lock_secs)
        })
        .await
    }

    async fn clear_login_failures(&self, key_hmac: &str) -> Result<(), String> {
        let key_hmac = key_hmac.to_string();
        self.write(move |conn| {
            conn.execute(
                "DELETE FROM login_attempts WHERE key_hmac = ?1",
                params![key_hmac],
            )
            .map_err(map_sqlite_err)?;
            Ok(())
        })
        .await
    }

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
    ) -> Result<i64, String> {
        let sha = token_sha256.to_string();
        let csrf = csrf_token.to_string();
        let ua = user_agent.chars().take(160).collect::<String>();
        let iph = ip_hmac.to_string();
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO sessions (token_sha256, user_id, organization_id, csrf_token, user_agent, ip_hmac, last_seen_at, reauth_at, expires_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8, ?9)",
                params![sha, user_id, org_id, csrf, ua, iph, now_sec, expires_at, now_ms()],
            )
            .map_err(map_sqlite_err)?;
            let rid: i64 = conn
                .query_row("SELECT rowid FROM sessions WHERE token_sha256 = ?1", params![sha], |r| r.get(0))
                .unwrap_or(0);
            Ok(rid)
        })
        .await
    }

    async fn resolve_session(
        &self,
        token_sha256: &str,
        now_sec: i64,
        idle_ttl_sec: i64,
    ) -> Result<Option<AuthenticatedSession>, String> {
        let sha = token_sha256.to_string();
        let sha_read = sha.clone();
        let found: Option<(AuthenticatedSession, i64)> = self
            .read(move |conn| {
                conn.query_row(
                    "SELECT s.rowid, u.id, u.email, u.name, s.organization_id, o.slug, m.role,
                            s.csrf_token, s.last_seen_at, s.reauth_at,
                            COALESCE((SELECT is_enabled FROM user_mfa WHERE user_id = u.id), 0),
                            (SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = u.id)
                     FROM sessions s
                     JOIN users u ON u.id = s.user_id
                     JOIN organizations o ON o.id = s.organization_id
                     JOIN organization_members m ON m.organization_id = s.organization_id AND m.user_id = u.id
                     WHERE s.token_sha256 = ?1
                       AND s.expires_at > ?2
                       AND (s.last_seen_at = 0 OR (s.last_seen_at + ?3) > ?2)
                       AND u.is_active = 1",
                    params![sha_read, now_sec, idle_ttl_sec],
                    |r| {
                        let role_s: String = r.get(6)?;
                        let last_seen: i64 = r.get(8)?;
                        Ok((
                            AuthenticatedSession {
                                session_id: r.get(0)?,
                                user_id: r.get(1)?,
                                email: r.get(2)?,
                                name: r.get(3)?,
                                organization_id: r.get(4)?,
                                organization_slug: r.get(5)?,
                                role: UserRole::from_db(&role_s).unwrap_or(UserRole::Viewer),
                                csrf_token: r.get(7)?,
                                reauth_at: r.get(9)?,
                                totp_enabled: r.get::<_, i64>(10)? != 0,
                                passkey_count: r.get(11)?,
                            },
                            last_seen,
                        ))
                    },
                )
                .optional()
                .map_err(map_sqlite_err)
            })
            .await?;

        if let Some((sess, last_seen)) = found {
            if now_sec - last_seen >= 60 {
                let _ = self
                    .write(move |conn| {
                        let _ = conn.execute(
                            "UPDATE sessions SET last_seen_at = ?1 WHERE token_sha256 = ?2",
                            params![now_sec, sha],
                        );
                        Ok(())
                    })
                    .await;
            }
            return Ok(Some(sess));
        }
        Ok(None)
    }

    async fn delete_session(&self, token_sha256: &str) -> Result<(), String> {
        let sha = token_sha256.to_string();
        self.write(move |conn| {
            conn.execute("DELETE FROM sessions WHERE token_sha256 = ?1", params![sha])
                .map_err(map_sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn resolve_api_token(
        &self,
        token_sha256: &str,
        org_slug: Option<&str>,
        now_sec: i64,
    ) -> Result<Option<TenantCtx>, String> {
        let sha = token_sha256.to_string();
        let sha_upd = sha.clone();
        let slug_filter = org_slug.map(ToString::to_string);
        let found: Option<(TenantCtx, Option<i64>)> = self
            .read(move |conn| {
                let row = conn
                    .query_row(
                        "SELECT t.organization_id, o.slug, t.user_id, t.role, m.role, t.scopes, t.last_used_at
                         FROM api_tokens t
                         JOIN organizations o ON o.id = t.organization_id
                         JOIN users u ON u.id = t.user_id
                         JOIN organization_members m ON m.organization_id = t.organization_id AND m.user_id = t.user_id
                         WHERE t.token_sha256 = ?1
                           AND u.is_active = 1
                           AND (t.expires_at IS NULL OR t.expires_at > ?2)",
                        params![sha, now_sec],
                        |r| {
                            let tok_role = UserRole::from_db(&r.get::<_, String>(3)?).unwrap_or(UserRole::Viewer);
                            let mem_role = UserRole::from_db(&r.get::<_, String>(4)?).unwrap_or(UserRole::Viewer);
                            let eff_role = mem_role.min_role(tok_role);
                            let raw_scopes: String = r.get(5)?;
                            let lu: Option<i64> = r.get(6)?;
                            Ok((
                                TenantCtx::from_token(
                                    r.get(0)?,
                                    r.get(1)?,
                                    r.get(2)?,
                                    eff_role,
                                    &raw_scopes,
                                ),
                                lu,
                            ))
                        },
                    )
                    .optional()
                    .map_err(map_sqlite_err)?;
                if let (Some((ref ctx, _)), Some(ref want_slug)) = (&row, &slug_filter) {
                    if &ctx.organization_slug != want_slug {
                        return Ok(None);
                    }
                }
                Ok(row)
            })
            .await?;

        if let Some((ctx, lu)) = found {
            let now_m = now_ms();
            if lu.map(|prev| now_m - prev >= 300_000).unwrap_or(true) {
                let _ = self
                    .write(move |conn| {
                        let _ = conn.execute(
                            "UPDATE api_tokens SET last_used_at = ?1 WHERE token_sha256 = ?2",
                            params![now_m, sha_upd],
                        );
                        Ok(())
                    })
                    .await;
            }
            return Ok(Some(ctx));
        }
        Ok(None)
    }

    async fn resolve_dsn(&self, project_id: i64, key_sha256: &str) -> Result<Option<ProjectAuthInfo>, String> {
        let sha = key_sha256.to_string();
        self.read(move |conn| {
            conn.query_row(
                "SELECT p.id, p.organization_id, o.slug, p.slug, p.first_event_at, k.rate_limit_per_min, p.filters_json, o.settings_json
                 FROM project_keys k
                 JOIN projects p ON p.id = k.project_id AND p.organization_id = k.organization_id
                 JOIN organizations o ON o.id = p.organization_id
                 WHERE k.project_id = ?1 AND k.key_sha256 = ?2 AND k.is_active = 1",
                params![project_id, sha],
                |r| {
                    let fjson: String = r.get(6)?;
                    let sjson: String = r.get(7)?;
                    let filters = serde_json::from_str(&fjson).unwrap_or_default();
                    let org_sec: OrgSecuritySettings = serde_json::from_str(&sjson).unwrap_or_default();
                    Ok(ProjectAuthInfo {
                        project_id: r.get(0)?,
                        organization_id: r.get(1)?,
                        organization_slug: r.get(2)?,
                        project_slug: r.get(3)?,
                        first_event_at: r.get(4)?,
                        rate_limit_per_min: r.get::<_, i64>(5)?.max(1) as u32,
                        filters,
                        org_scrub_ip_addresses: org_sec.scrub_ip_addresses,
                        org_event_throttle_rate: org_sec.event_throttle_rate,
                    })
                },
            )
            .optional()
            .map_err(map_sqlite_err)
        })
        .await
    }

    async fn tunnel_slug_exists(&self, tunnel_slug: &str) -> Result<bool, String> {
        let slug = tunnel_slug.to_string();
        self.read(move |conn| {
            let exists: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM tunnel_routes WHERE slug = ?1 AND is_active = 1",
                    params![slug],
                    |r| r.get(0),
                )
                .map_err(map_sqlite_err)?;
            Ok(exists > 0)
        })
        .await
    }

    async fn resolve_tunnel(&self, tunnel_slug: &str, project_id: i64, key_sha256: &str) -> Result<Option<ProjectAuthInfo>, String> {
        let tslug = tunnel_slug.to_string();
        let sha = key_sha256.to_string();
        self.read(move |conn| {
            conn.query_row(
                "SELECT p.id, p.organization_id, o.slug, p.slug, p.first_event_at, k.rate_limit_per_min, p.filters_json, o.settings_json
                 FROM tunnel_routes tr
                 JOIN project_keys k ON k.project_id = tr.project_id AND k.organization_id = tr.organization_id
                 JOIN projects p ON p.id = tr.project_id AND p.organization_id = tr.organization_id
                 JOIN organizations o ON o.id = p.organization_id
                 WHERE tr.slug = ?1 AND tr.is_active = 1 AND p.id = ?2 AND k.key_sha256 = ?3 AND k.is_active = 1",
                params![tslug, project_id, sha],
                |r| {
                    let fjson: String = r.get(6)?;
                    let sjson: String = r.get(7)?;
                    let filters = serde_json::from_str(&fjson).unwrap_or_default();
                    let org_sec: OrgSecuritySettings = serde_json::from_str(&sjson).unwrap_or_default();
                    Ok(ProjectAuthInfo {
                        project_id: r.get(0)?,
                        organization_id: r.get(1)?,
                        organization_slug: r.get(2)?,
                        project_slug: r.get(3)?,
                        first_event_at: r.get(4)?,
                        rate_limit_per_min: r.get::<_, i64>(5)?.max(1) as u32,
                        filters,
                        org_scrub_ip_addresses: org_sec.scrub_ip_addresses,
                        org_event_throttle_rate: org_sec.event_throttle_rate,
                    })
                },
            )
            .optional()
            .map_err(map_sqlite_err)
        })
        .await
    }

    async fn list_user_organizations(&self, user_id: i64) -> Result<Vec<OrganizationDto>, String> {
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT o.id, o.slug, o.name, m.role, o.created_at
                     FROM organizations o
                     JOIN organization_members m ON m.organization_id = o.id
                     JOIN users u ON u.id = m.user_id
                     WHERE m.user_id = ?1 AND u.is_active = 1
                     ORDER BY o.id ASC",
                )
                .map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map(params![user_id], |r| {
                    Ok(OrganizationDto {
                        id: r.get(0)?,
                        slug: r.get(1)?,
                        name: r.get(2)?,
                        role: r.get(3)?,
                        created_at: r.get(4)?,
                    })
                })
                .map_err(map_sqlite_err)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(map_sqlite_err)?);
            }
            Ok(out)
        })
        .await
    }

    async fn resolve_tenant_for_user(&self, user_id: i64, org_slug: &str) -> Result<Option<TenantCtx>, String> {
        let slug = org_slug.to_string();
        self.read(move |conn| {
            conn.query_row(
                "SELECT o.id, o.slug, m.role
                 FROM organizations o
                 JOIN organization_members m ON m.organization_id = o.id
                 JOIN users u ON u.id = m.user_id
                 WHERE m.user_id = ?1 AND o.slug = ?2 AND u.is_active = 1",
                params![user_id, slug],
                |r| {
                    let role_s: String = r.get(2)?;
                    let role = UserRole::from_db(&role_s).unwrap_or(UserRole::Viewer);
                    Ok(TenantCtx::from_session(
                        r.get(0)?,
                        r.get(1)?,
                        user_id,
                        role,
                        None,
                        None,
                    ))
                },
            )
            .optional()
            .map_err(map_sqlite_err)
        })
        .await
    }

    async fn list_projects(&self, ctx: &TenantCtx) -> Result<Vec<ProjectDto>, String> {
        let org_id = ctx.organization_id;
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT p.id, p.organization_id, p.slug, p.name, p.platform, p.first_event_at,
                            p.filters_json,
                            (SELECT public_key FROM project_keys pk WHERE pk.project_id = p.id AND pk.is_active = 1 ORDER BY pk.id ASC LIMIT 1),
                            (SELECT slug FROM tunnel_routes tr WHERE tr.project_id = p.id AND tr.is_active = 1 LIMIT 1),
                            p.created_at
                     FROM projects p
                     WHERE p.organization_id = ?1
                     ORDER BY p.id ASC",
                )
                .map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map(params![org_id], |r| {
                    let fjson: String = r.get(6)?;
                    Ok(ProjectDto {
                        id: r.get(0)?,
                        organization_id: r.get(1)?,
                        slug: r.get(2)?,
                        name: r.get(3)?,
                        platform: r.get(4)?,
                        first_event_at: r.get(5)?,
                        filters: serde_json::from_str(&fjson).unwrap_or_default(),
                        dsn_public_key: r.get(7)?,
                        tunnel_slug: r.get(8)?,
                        created_at: r.get(9)?,
                    })
                })
                .map_err(map_sqlite_err)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(map_sqlite_err)?);
            }
            Ok(out)
        })
        .await
    }

    async fn create_project(
        &self,
        ctx: &TenantCtx,
        name: &str,
        slug: &str,
        platform: &str,
        dsn_public_key: &str,
        dsn_key_sha256: &str,
    ) -> Result<ProjectDto, String> {
        let org_id = ctx.organization_id;
        let name = name.to_string();
        let slug = slug.to_string();
        let platform = platform.to_string();
        let dsn_pub = dsn_public_key.to_string();
        let dsn_sha = dsn_key_sha256.to_string();

        self.write(move |conn| {
            let now = now_ms();
            let tx = conn.transaction().map_err(map_sqlite_err)?;
            let filters_json = serde_json::to_string(&ProjectFilters::default()).unwrap();
            tx.execute(
                "INSERT INTO projects (organization_id, slug, name, platform, filters_json, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![org_id, slug, name, platform, filters_json, now],
            )
            .map_err(map_sqlite_err)?;
            let pid = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO project_keys (organization_id, project_id, label, public_key, key_sha256, rate_limit_per_min, is_active, created_at)
                 VALUES (?1, ?2, 'Default DSN', ?3, ?4, 300, 1, ?5)",
                params![org_id, pid, dsn_pub, dsn_sha, now],
            )
            .map_err(map_sqlite_err)?;
            tx.commit().map_err(map_sqlite_err)?;
            Ok(ProjectDto {
                id: pid,
                organization_id: org_id,
                slug,
                name,
                platform,
                first_event_at: None,
                filters: ProjectFilters::default(),
                dsn_public_key: Some(dsn_pub),
                tunnel_slug: None,
                created_at: now,
            })
        })
        .await
    }

    async fn update_project_filters(
        &self,
        ctx: &TenantCtx,
        project_slug: &str,
        filters: &ProjectFilters,
    ) -> Result<Option<ProjectDto>, String> {
        let org_id = ctx.organization_id;
        let pslug = project_slug.to_string();
        let fjson = serde_json::to_string(filters).map_err(map_sqlite_err)?;
        let filters_clone = filters.clone();
        self.write(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE projects SET filters_json = ?1 WHERE organization_id = ?2 AND slug = ?3",
                    params![fjson, org_id, pslug],
                )
                .map_err(map_sqlite_err)?;
            if changed == 0 {
                return Ok(None);
            }
            conn.query_row(
                "SELECT id, name, platform, first_event_at,
                        (SELECT public_key FROM project_keys WHERE project_id = projects.id AND is_active = 1 LIMIT 1),
                        (SELECT slug FROM tunnel_routes WHERE project_id = projects.id AND is_active = 1 LIMIT 1),
                        created_at
                 FROM projects WHERE organization_id = ?1 AND slug = ?2",
                params![org_id, pslug],
                |r| {
                    Ok(ProjectDto {
                        id: r.get(0)?,
                        organization_id: org_id,
                        slug: pslug.clone(),
                        name: r.get(1)?,
                        platform: r.get(2)?,
                        first_event_at: r.get(3)?,
                        filters: filters_clone,
                        dsn_public_key: r.get(4)?,
                        tunnel_slug: r.get(5)?,
                        created_at: r.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(map_sqlite_err)
        })
        .await
    }

    async fn list_project_keys(&self, ctx: &TenantCtx, project_slug: &str) -> Result<Vec<ProjectKeyDto>, String> {
        let org_id = ctx.organization_id;
        let pslug = project_slug.to_string();
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT k.id, k.project_id, k.label, k.public_key, k.rate_limit_per_min, k.is_active, k.created_at
                     FROM project_keys k
                     JOIN projects p ON p.id = k.project_id AND p.organization_id = k.organization_id
                     WHERE k.organization_id = ?1 AND p.slug = ?2
                     ORDER BY k.id ASC",
                )
                .map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map(params![org_id, pslug], |r| {
                    Ok(ProjectKeyDto {
                        id: r.get(0)?,
                        project_id: r.get(1)?,
                        label: r.get(2)?,
                        public_key: r.get(3)?,
                        rate_limit_per_min: r.get::<_, i64>(4)?.max(1) as u32,
                        is_active: r.get::<_, i64>(5)? != 0,
                        created_at: r.get(6)?,
                    })
                })
                .map_err(map_sqlite_err)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(map_sqlite_err)?);
            }
            Ok(out)
        })
        .await
    }

    async fn create_project_key(
        &self,
        ctx: &TenantCtx,
        project_slug: &str,
        label: &str,
        public_key: &str,
        key_sha256: &str,
    ) -> Result<Option<ProjectKeyDto>, String> {
        let org_id = ctx.organization_id;
        let pslug = project_slug.to_string();
        let label = label.to_string();
        let pubk = public_key.to_string();
        let sha = key_sha256.to_string();
        self.write(move |conn| {
            let pid: Option<i64> = conn
                .query_row(
                    "SELECT id FROM projects WHERE organization_id = ?1 AND slug = ?2",
                    params![org_id, pslug],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_sqlite_err)?;
            let Some(project_id) = pid else {
                return Ok(None);
            };
            let now = now_ms();
            conn.execute(
                "INSERT INTO project_keys (organization_id, project_id, label, public_key, key_sha256, rate_limit_per_min, is_active, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 300, 1, ?6)",
                params![org_id, project_id, label, pubk, sha, now],
            )
            .map_err(map_sqlite_err)?;
            let id = conn.last_insert_rowid();
            Ok(Some(ProjectKeyDto {
                id,
                project_id,
                label,
                public_key: pubk,
                rate_limit_per_min: 300,
                is_active: true,
                created_at: now,
            }))
        })
        .await
    }

    async fn delete_project_key(&self, ctx: &TenantCtx, project_slug: &str, key_id: i64) -> Result<bool, String> {
        let org_id = ctx.organization_id;
        let pslug = project_slug.to_string();
        self.write(move |conn| {
            let changed = conn
                .execute(
                    "DELETE FROM project_keys
                     WHERE id = ?1 AND organization_id = ?2
                       AND project_id IN (SELECT id FROM projects WHERE organization_id = ?2 AND slug = ?3)",
                    params![key_id, org_id, pslug],
                )
                .map_err(map_sqlite_err)?;
            Ok(changed > 0)
        })
        .await
    }

    async fn enable_project_tunnel(
        &self,
        ctx: &TenantCtx,
        project_slug: &str,
        tunnel_slug: &str,
    ) -> Result<Option<String>, String> {
        let org_id = ctx.organization_id;
        let pslug = project_slug.to_string();
        let tslug = tunnel_slug.to_string();
        self.write(move |conn| {
            let pid: Option<i64> = conn
                .query_row(
                    "SELECT id FROM projects WHERE organization_id = ?1 AND slug = ?2",
                    params![org_id, pslug],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_sqlite_err)?;
            let Some(project_id) = pid else {
                return Ok(None);
            };
            let existing: Option<String> = conn
                .query_row(
                    "SELECT slug FROM tunnel_routes WHERE organization_id = ?1 AND project_id = ?2 AND is_active = 1 LIMIT 1",
                    params![org_id, project_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_sqlite_err)?;
            if let Some(s) = existing {
                return Ok(Some(s));
            }
            conn.execute(
                "INSERT INTO tunnel_routes (slug, organization_id, project_id, is_active, created_at)
                 VALUES (?1, ?2, ?3, 1, ?4)",
                params![tslug, org_id, project_id, now_ms()],
            )
            .map_err(map_sqlite_err)?;
            Ok(Some(tslug))
        })
        .await
    }

    async fn list_issues(&self, ctx: &TenantCtx, params_in: &IssueQueryParams) -> Result<(Vec<IssueSummaryDto>, i64), String> {
        let org_id = ctx.organization_id;
        let org_slug = ctx.organization_slug.clone();
        let p = params_in.clone();
        self.read(move |conn| {
            let fts_query = p.search_query.as_deref().and_then(sanitize_fts5_query);
            let mut sql = String::from(
                "SELECT i.id, i.short_id, i.project_id, pr.slug, i.title, i.culprit, i.level,
                        i.issue_type, i.status, i.is_regression, i.resolved_in_release,
                        i.first_seen, i.last_seen, i.event_count, i.user_count,
                        i.first_release, i.last_release, i.environment, i.metadata_json
                 FROM issues i
                 JOIN projects pr ON pr.id = i.project_id
                 WHERE i.organization_id = ?1",
            );
            let mut count_sql = String::from("SELECT COUNT(*) FROM issues i WHERE i.organization_id = ?1");
            let mut bind_vals: Vec<rusqlite::types::Value> = vec![org_id.into()];

            if let Some(ref st) = p.status {
                bind_vals.push(st.clone().into());
                let idx = bind_vals.len();
                sql.push_str(&format!(" AND i.status = ?{idx}"));
                count_sql.push_str(&format!(" AND i.status = ?{idx}"));
            }
            if let Some(ref lvl) = p.level {
                bind_vals.push(lvl.clone().into());
                let idx = bind_vals.len();
                sql.push_str(&format!(" AND i.level = ?{idx}"));
                count_sql.push_str(&format!(" AND i.level = ?{idx}"));
            }
            if let Some(ref env) = p.environment {
                bind_vals.push(env.clone().into());
                let idx = bind_vals.len();
                sql.push_str(&format!(" AND i.environment = ?{idx}"));
                count_sql.push_str(&format!(" AND i.environment = ?{idx}"));
            }
            if let Some(ref rel) = p.release {
                bind_vals.push(rel.clone().into());
                let idx = bind_vals.len();
                sql.push_str(&format!(" AND (i.last_release = ?{idx} OR i.first_release = ?{idx})"));
                count_sql.push_str(&format!(" AND (i.last_release = ?{idx} OR i.first_release = ?{idx})"));
            }
            if let Some(pid) = p.project_id {
                bind_vals.push(pid.into());
                let idx = bind_vals.len();
                sql.push_str(&format!(" AND i.project_id = ?{idx}"));
                count_sql.push_str(&format!(" AND i.project_id = ?{idx}"));
            }
            if let Some(since) = p.since_ms {
                bind_vals.push(since.into());
                let idx = bind_vals.len();
                sql.push_str(&format!(" AND i.last_seen >= ?{idx}"));
                count_sql.push_str(&format!(" AND i.last_seen >= ?{idx}"));
            }
            if let Some(ref fts) = fts_query {
                bind_vals.push(fts.clone().into());
                let idx = bind_vals.len();
                let clause = format!(
                    " AND i.id IN (SELECT issue_id FROM issues_fts WHERE issues_fts MATCH ?{idx} AND organization_id = ?1)"
                );
                sql.push_str(&clause);
                count_sql.push_str(&clause);
            }

            let order = match p.sort.as_str() {
                "freq" => " ORDER BY i.event_count DESC, i.last_seen DESC",
                "new" => " ORDER BY i.first_seen DESC",
                _ => " ORDER BY i.last_seen DESC",
            };
            sql.push_str(order);
            let limit = p.limit.clamp(1, 200);
            let offset = p.offset.clamp(0, 100_000);
            sql.push_str(&format!(" LIMIT {limit} OFFSET {offset}"));

            let total: i64 = conn
                .query_row(&count_sql, rusqlite::params_from_iter(bind_vals.iter()), |r| r.get(0))
                .map_err(map_sqlite_err)?;

            let mut stmt = conn.prepare(&sql).map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(bind_vals.iter()), |r| {
                    let id: i64 = r.get(0)?;
                    let meta_str: String = r.get(18)?;
                    Ok(IssueSummaryDto {
                        id,
                        short_id: r.get(1)?,
                        project_id: r.get(2)?,
                        project_slug: r.get(3)?,
                        title: r.get(4)?,
                        culprit: r.get(5)?,
                        level: r.get(6)?,
                        issue_type: r.get(7)?,
                        status: r.get(8)?,
                        is_regression: r.get::<_, i64>(9)? != 0,
                        resolved_in_release: r.get(10)?,
                        first_seen: iso_from_ms(r.get(11)?),
                        last_seen: iso_from_ms(r.get(12)?),
                        count: r.get(13)?,
                        user_count: r.get(14)?,
                        first_release: r.get(15)?,
                        last_release: r.get(16)?,
                        environment: r.get(17)?,
                        permalink: format!("/{org_slug}/issues/{id}"),
                        metadata: serde_json::from_str(&meta_str).unwrap_or_else(|_| json!({})),
                    })
                })
                .map_err(map_sqlite_err)?;

            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(map_sqlite_err)?);
            }
            Ok((out, total))
        })
        .await
    }

    async fn get_issue(&self, ctx: &TenantCtx, issue_id: i64) -> Result<Option<IssueSummaryDto>, String> {
        let org_id = ctx.organization_id;
        let org_slug = ctx.organization_slug.clone();
        self.read(move |conn| {
            conn.query_row(
                "SELECT i.id, i.short_id, i.project_id, pr.slug, i.title, i.culprit, i.level,
                        i.issue_type, i.status, i.is_regression, i.resolved_in_release,
                        i.first_seen, i.last_seen, i.event_count, i.user_count,
                        i.first_release, i.last_release, i.environment, i.metadata_json
                 FROM issues i
                 JOIN projects pr ON pr.id = i.project_id
                 WHERE i.id = ?1 AND i.organization_id = ?2",
                params![issue_id, org_id],
                |r| {
                    let meta_str: String = r.get(18)?;
                    Ok(IssueSummaryDto {
                        id: r.get(0)?,
                        short_id: r.get(1)?,
                        project_id: r.get(2)?,
                        project_slug: r.get(3)?,
                        title: r.get(4)?,
                        culprit: r.get(5)?,
                        level: r.get(6)?,
                        issue_type: r.get(7)?,
                        status: r.get(8)?,
                        is_regression: r.get::<_, i64>(9)? != 0,
                        resolved_in_release: r.get(10)?,
                        first_seen: iso_from_ms(r.get(11)?),
                        last_seen: iso_from_ms(r.get(12)?),
                        count: r.get(13)?,
                        user_count: r.get(14)?,
                        first_release: r.get(15)?,
                        last_release: r.get(16)?,
                        environment: r.get(17)?,
                        permalink: format!("/{org_slug}/issues/{issue_id}"),
                        metadata: serde_json::from_str(&meta_str).unwrap_or_else(|_| json!({})),
                    })
                },
            )
            .optional()
            .map_err(map_sqlite_err)
        })
        .await
    }

    async fn update_issue_status(
        &self,
        ctx: &TenantCtx,
        issue_id: i64,
        status: IssueStatus,
        resolved_in_release: Option<&str>,
    ) -> Result<Option<IssueSummaryDto>, String> {
        let org_id = ctx.organization_id;
        let status_s = status.as_str().to_string();
        let rel = resolved_in_release.map(ToString::to_string);
        let changed = self
            .write(move |conn| {
                let c = conn
                    .execute(
                        "UPDATE issues
                         SET status = ?1,
                             resolved_in_release = CASE WHEN ?1 = 'resolved' THEN COALESCE(?2, last_release) ELSE NULL END,
                             is_regression = CASE WHEN ?1 = 'resolved' THEN 0 ELSE is_regression END
                         WHERE id = ?3 AND organization_id = ?4",
                        params![status_s, rel, issue_id, org_id],
                    )
                    .map_err(map_sqlite_err)?;
                Ok(c)
            })
            .await?;
        if changed == 0 {
            return Ok(None);
        }
        self.get_issue(ctx, issue_id).await
    }

    async fn list_issue_events(&self, ctx: &TenantCtx, issue_id: i64, limit: i64) -> Result<Vec<IssueEventDetailDto>, String> {
        let org_id = ctx.organization_id;
        let lim = limit.clamp(1, 100);
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, event_id, issue_id, project_id, timestamp_ms, level, environment,
                            release, trace_id, span_id, tags_json, payload_blob, payload_compressed
                     FROM issue_events
                     WHERE organization_id = ?1 AND issue_id = ?2
                     ORDER BY timestamp_ms DESC LIMIT ?3",
                )
                .map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map(params![org_id, issue_id, lim], |r| {
                    let tags_s: String = r.get(10)?;
                    let blob: Vec<u8> = r.get(11)?;
                    let comp: i64 = r.get(12)?;
                    let decoded = decompress_payload(&blob, comp != 0).unwrap_or(blob);
                    let payload: Value = serde_json::from_slice(&decoded).unwrap_or_else(|_| json!({}));
                    Ok(IssueEventDetailDto {
                        id: r.get(0)?,
                        event_id: r.get(1)?,
                        issue_id: r.get(2)?,
                        project_id: r.get(3)?,
                        timestamp: iso_from_ms(r.get(4)?),
                        level: r.get(5)?,
                        environment: r.get(6)?,
                        release: r.get(7)?,
                        trace_id: r.get(8)?,
                        span_id: r.get(9)?,
                        tags: serde_json::from_str(&tags_s).unwrap_or_else(|_| json!({})),
                        payload,
                    })
                })
                .map_err(map_sqlite_err)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(map_sqlite_err)?);
            }
            Ok(out)
        })
        .await
    }

    async fn get_issue_event(&self, ctx: &TenantCtx, issue_id: i64, event_id_or_latest: &str) -> Result<Option<IssueEventDetailDto>, String> {
        let org_id = ctx.organization_id;
        let target = event_id_or_latest.to_string();
        self.read(move |conn| {
            let sql = if target == "latest" {
                "SELECT id, event_id, issue_id, project_id, timestamp_ms, level, environment,
                        release, trace_id, span_id, tags_json, payload_blob, payload_compressed
                 FROM issue_events
                 WHERE organization_id = ?1 AND issue_id = ?2
                 ORDER BY timestamp_ms DESC LIMIT 1"
            } else {
                "SELECT id, event_id, issue_id, project_id, timestamp_ms, level, environment,
                        release, trace_id, span_id, tags_json, payload_blob, payload_compressed
                 FROM issue_events
                 WHERE organization_id = ?1 AND issue_id = ?2 AND (event_id = ?3 OR id = ?3)
                 LIMIT 1"
            };
            let row = if target == "latest" {
                conn.query_row(sql, params![org_id, issue_id], |r| {
                    let tags_s: String = r.get(10)?;
                    let blob: Vec<u8> = r.get(11)?;
                    let comp: i64 = r.get(12)?;
                    let decoded = decompress_payload(&blob, comp != 0).unwrap_or(blob);
                    let payload: Value = serde_json::from_slice(&decoded).unwrap_or_else(|_| json!({}));
                    Ok(IssueEventDetailDto {
                        id: r.get(0)?,
                        event_id: r.get(1)?,
                        issue_id: r.get(2)?,
                        project_id: r.get(3)?,
                        timestamp: iso_from_ms(r.get(4)?),
                        level: r.get(5)?,
                        environment: r.get(6)?,
                        release: r.get(7)?,
                        trace_id: r.get(8)?,
                        span_id: r.get(9)?,
                        tags: serde_json::from_str(&tags_s).unwrap_or_else(|_| json!({})),
                        payload,
                    })
                })
                .optional()
            } else {
                conn.query_row(sql, params![org_id, issue_id, target], |r| {
                    let tags_s: String = r.get(10)?;
                    let blob: Vec<u8> = r.get(11)?;
                    let comp: i64 = r.get(12)?;
                    let decoded = decompress_payload(&blob, comp != 0).unwrap_or(blob);
                    let payload: Value = serde_json::from_slice(&decoded).unwrap_or_else(|_| json!({}));
                    Ok(IssueEventDetailDto {
                        id: r.get(0)?,
                        event_id: r.get(1)?,
                        issue_id: r.get(2)?,
                        project_id: r.get(3)?,
                        timestamp: iso_from_ms(r.get(4)?),
                        level: r.get(5)?,
                        environment: r.get(6)?,
                        release: r.get(7)?,
                        trace_id: r.get(8)?,
                        span_id: r.get(9)?,
                        tags: serde_json::from_str(&tags_s).unwrap_or_else(|_| json!({})),
                        payload,
                    })
                })
                .optional()
            };
            row.map_err(map_sqlite_err)
        })
        .await
    }

    async fn query_logs(&self, ctx: &TenantCtx, params_in: &LogQueryParams) -> Result<Vec<LogEventDto>, String> {
        let org_id = ctx.organization_id;
        let p = params_in.clone();
        self.read(move |conn| {
            let mut sql = String::from(
                "SELECT id, timestamp_ms, level_num, severity_number, body, service, environment,
                        host, trace_id, span_id, attributes_json, project_id
                 FROM log_events
                 WHERE organization_id = ?1",
            );
            let mut binds: Vec<rusqlite::types::Value> = vec![org_id.into()];

            if !p.project_ids.is_empty() {
                let placeholders: Vec<String> = p
                    .project_ids
                    .iter()
                    .map(|pid| {
                        binds.push((*pid).into());
                        format!("?{}", binds.len())
                    })
                    .collect();
                sql.push_str(&format!(" AND project_id IN ({})", placeholders.join(",")));
            }
            if !p.level_list.is_empty() {
                let placeholders: Vec<String> = p
                    .level_list
                    .iter()
                    .map(|lvl| {
                        binds.push((*lvl).into());
                        format!("?{}", binds.len())
                    })
                    .collect();
                sql.push_str(&format!(" AND level_num IN ({})", placeholders.join(",")));
            } else if let Some(min_lvl) = p.min_level_num {
                binds.push(min_lvl.into());
                sql.push_str(&format!(" AND level_num >= ?{}", binds.len()));
            }
            if let Some(ref svc) = p.service {
                binds.push(svc.clone().into());
                sql.push_str(&format!(" AND service = ?{}", binds.len()));
            }
            if let Some(ref env) = p.environment {
                binds.push(env.clone().into());
                sql.push_str(&format!(" AND environment = ?{}", binds.len()));
            }
            if let Some(ref host) = p.host {
                binds.push(host.clone().into());
                sql.push_str(&format!(" AND host = ?{}", binds.len()));
            }
            if let Some(ref tid) = p.trace_id {
                binds.push(tid.clone().into());
                sql.push_str(&format!(" AND trace_id = ?{}", binds.len()));
            }
            if let Some(start) = p.start_ms {
                binds.push(start.into());
                sql.push_str(&format!(" AND timestamp_ms >= ?{}", binds.len()));
            }
            if let Some(end) = p.end_ms {
                binds.push(end.into());
                sql.push_str(&format!(" AND timestamp_ms <= ?{}", binds.len()));
            }
            if let Some(ref cursor) = p.cursor_id {
                binds.push(cursor.clone().into());
                sql.push_str(&format!(" AND id < ?{}", binds.len()));
            }
            if let Some(ref fts) = p.search_query.as_deref().and_then(sanitize_fts5_query) {
                binds.push(fts.clone().into());
                let idx = binds.len();
                sql.push_str(&format!(
                    " AND id IN (SELECT log_id FROM logs_fts WHERE logs_fts MATCH ?{idx} AND organization_id = ?1)"
                ));
            }
            let limit = p.limit.clamp(1, 200);
            sql.push_str(&format!(" ORDER BY id DESC LIMIT {limit}"));

            let mut stmt = conn.prepare(&sql).map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(binds.iter()), |r| {
                    let ts_ms: i64 = r.get(1)?;
                    let lvl_num: i32 = r.get(2)?;
                    let sev: Option<i64> = r.get(3)?;
                    let attr_s: String = r.get(10)?;
                    Ok(LogEventDto {
                        id: r.get(0)?,
                        timestamp: iso_from_ms(ts_ms),
                        timestamp_ms: ts_ms,
                        level: LogLevel::from_num(lvl_num).as_str().to_string(),
                        severity_number: sev.map(|n| n as u16),
                        body: r.get(4)?,
                        service: r.get(5)?,
                        environment: r.get(6)?,
                        host: r.get(7)?,
                        trace_id: r.get(8)?,
                        span_id: r.get(9)?,
                        data: serde_json::from_str(&attr_s).unwrap_or_else(|_| json!({})),
                        project_id: r.get(11)?,
                    })
                })
                .map_err(map_sqlite_err)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(map_sqlite_err)?);
            }
            Ok(out)
        })
        .await
    }

    async fn list_log_resources(&self, ctx: &TenantCtx) -> Result<Vec<LogResourceDto>, String> {
        let org_id = ctx.organization_id;
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT name, resource_type, last_seen
                     FROM log_resources WHERE organization_id = ?1
                     ORDER BY last_seen DESC LIMIT 200",
                )
                .map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map(params![org_id], |r| {
                    Ok(LogResourceDto {
                        name: r.get(0)?,
                        resource_type: r.get(1)?,
                        last_seen: iso_from_ms(r.get(2)?),
                    })
                })
                .map_err(map_sqlite_err)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(map_sqlite_err)?);
            }
            Ok(out)
        })
        .await
    }

    async fn get_log_stats(&self, ctx: &TenantCtx, since_ms: i64, until_ms: i64) -> Result<Value, String> {
        let org_id = ctx.organization_id;
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT (timestamp_ms / 3600000) * 3600000 AS b, level_num, COUNT(*)
                     FROM log_events
                     WHERE organization_id = ?1 AND timestamp_ms >= ?2 AND timestamp_ms <= ?3
                     GROUP BY b, level_num
                     ORDER BY b ASC",
                )
                .map_err(map_sqlite_err)?;
            let mut rows = stmt.query(params![org_id, since_ms, until_ms]).map_err(map_sqlite_err)?;
            let mut buckets: std::collections::BTreeMap<i64, [i64; 6]> = std::collections::BTreeMap::new();
            while let Some(r) = rows.next().map_err(map_sqlite_err)? {
                let b: i64 = r.get(0).map_err(map_sqlite_err)?;
                let lvl: i32 = r.get(1).map_err(map_sqlite_err)?;
                let cnt: i64 = r.get(2).map_err(map_sqlite_err)?;
                let slot = match LogLevel::from_num(lvl) {
                    LogLevel::Trace => 0,
                    LogLevel::Debug => 1,
                    LogLevel::Info => 2,
                    LogLevel::Warn => 3,
                    LogLevel::Error => 4,
                    LogLevel::Fatal => 5,
                };
                let entry = buckets.entry(b).or_insert([0; 6]);
                entry[slot] += cnt;
            }
            let intervals: Vec<String> = buckets.keys().map(|b| iso_from_ms(*b)).collect();
            let names = ["trace", "debug", "info", "warn", "error", "fatal"];
            let series: Vec<Value> = names
                .iter()
                .enumerate()
                .map(|(i, name)| {
                    let data: Vec<i64> = buckets.values().map(|arr| arr[i]).collect();
                    json!({ "name": name, "data": data })
                })
                .collect();
            Ok(json!({ "intervals": intervals, "series": series }))
        })
        .await
    }

    async fn get_stats_v2(&self, ctx: &TenantCtx, category: &str, since_ms: i64, until_ms: i64) -> Result<Value, String> {
        let org_id = ctx.organization_id;
        let cat = category.to_string();
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT bucket_hour, SUM(quantity)
                     FROM hourly_stats
                     WHERE organization_id = ?1 AND category = ?2 AND bucket_hour >= ?3 AND bucket_hour <= ?4
                     GROUP BY bucket_hour ORDER BY bucket_hour ASC",
                )
                .map_err(map_sqlite_err)?;
            let mut rows = stmt.query(params![org_id, cat, since_ms, until_ms]).map_err(map_sqlite_err)?;
            let mut intervals = Vec::new();
            let mut series = Vec::new();
            let mut total = 0i64;
            while let Some(r) = rows.next().map_err(map_sqlite_err)? {
                let bh: i64 = r.get(0).map_err(map_sqlite_err)?;
                let q: i64 = r.get(1).map_err(map_sqlite_err)?;
                intervals.push(iso_from_ms(bh));
                series.push(q);
                total += q;
            }
            Ok(json!({
                "start": iso_from_ms(since_ms),
                "end": iso_from_ms(until_ms),
                "intervals": intervals,
                "groups": [{
                    "by": { "category": cat },
                    "totals": { "sum(quantity)": total },
                    "series": { "sum(quantity)": series }
                }]
            }))
        })
        .await
    }

    async fn list_transactions(&self, ctx: &TenantCtx, since_ms: i64) -> Result<Vec<TransactionSummaryDto>, String> {
        let org_id = ctx.organization_id;
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT name, op, status, duration_ms, timestamp_ms
                     FROM transaction_events
                     WHERE organization_id = ?1 AND timestamp_ms >= ?2
                     ORDER BY timestamp_ms DESC LIMIT 2000",
                )
                .map_err(map_sqlite_err)?;
            let mut rows = stmt.query(params![org_id, since_ms]).map_err(map_sqlite_err)?;
            struct Acc {
                op: String,
                durations: Vec<f64>,
                err_count: i64,
                last_ms: i64,
            }
            let mut map: HashMap<String, Acc> = HashMap::new();
            while let Some(r) = rows.next().map_err(map_sqlite_err)? {
                let name: String = r.get(0).map_err(map_sqlite_err)?;
                let op: String = r.get(1).map_err(map_sqlite_err)?;
                let status: String = r.get(2).map_err(map_sqlite_err)?;
                let dur: f64 = r.get(3).map_err(map_sqlite_err)?;
                let ts: i64 = r.get(4).map_err(map_sqlite_err)?;
                let entry = map.entry(name).or_insert(Acc {
                    op,
                    durations: Vec::new(),
                    err_count: 0,
                    last_ms: ts,
                });
                entry.durations.push(dur);
                if status != "ok" && status != "unset" {
                    entry.err_count += 1;
                }
                if ts > entry.last_ms {
                    entry.last_ms = ts;
                }
            }
            let mut out: Vec<TransactionSummaryDto> = map
                .into_iter()
                .map(|(name, mut acc)| {
                    acc.durations.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                    let n = acc.durations.len();
                    let p50 = acc.durations.get(n / 2).copied().unwrap_or(0.0);
                    let p95 = acc.durations.get((n * 95) / 100).copied().unwrap_or(p50);
                    let avg = if n == 0 { 0.0 } else { acc.durations.iter().sum::<f64>() / n as f64 };
                    TransactionSummaryDto {
                        name,
                        op: acc.op,
                        count: n as i64,
                        error_count: acc.err_count,
                        p50_ms: (p50 * 100.0).round() / 100.0,
                        p95_ms: (p95 * 100.0).round() / 100.0,
                        avg_ms: (avg * 100.0).round() / 100.0,
                        last_seen: iso_from_ms(acc.last_ms),
                    }
                })
                .collect();
            out.sort_by(|a, b| b.count.cmp(&a.count));
            Ok(out)
        })
        .await
    }

    async fn get_trace_context(&self, ctx: &TenantCtx, trace_id: &str) -> Result<Value, String> {
        let org_id = ctx.organization_id;
        let tid = trace_id.to_string();
        self.read(move |conn| {
            let mut tx_stmt = conn
                .prepare(
                    "SELECT id, name, op, status, duration_ms, span_id, environment, release, spans_json, timestamp_ms
                     FROM transaction_events WHERE organization_id = ?1 AND trace_id = ?2 ORDER BY timestamp_ms ASC LIMIT 100",
                )
                .map_err(map_sqlite_err)?;
            let tx_rows = tx_stmt
                .query_map(params![org_id, tid], |r| {
                    let spans_s: String = r.get(8)?;
                    Ok(json!({
                        "id": r.get::<_, String>(0)?,
                        "name": r.get::<_, String>(1)?,
                        "op": r.get::<_, String>(2)?,
                        "status": r.get::<_, String>(3)?,
                        "duration_ms": r.get::<_, f64>(4)?,
                        "span_id": r.get::<_, String>(5)?,
                        "environment": r.get::<_, String>(6)?,
                        "release": r.get::<_, Option<String>>(7)?,
                        "spans": serde_json::from_str::<Value>(&spans_s).unwrap_or_else(|_| json!([])),
                        "timestamp": iso_from_ms(r.get(9)?),
                    }))
                })
                .map_err(map_sqlite_err)?;
            let mut transactions = Vec::new();
            for t in tx_rows {
                transactions.push(t.map_err(map_sqlite_err)?);
            }

            let mut err_stmt = conn
                .prepare(
                    "SELECT ie.issue_id, i.short_id, i.title, ie.event_id, ie.level, ie.timestamp_ms
                     FROM issue_events ie
                     JOIN issues i ON i.id = ie.issue_id
                     WHERE ie.organization_id = ?1 AND ie.trace_id = ?2
                     ORDER BY ie.timestamp_ms ASC LIMIT 50",
                )
                .map_err(map_sqlite_err)?;
            let err_rows = err_stmt
                .query_map(params![org_id, tid], |r| {
                    Ok(json!({
                        "issue_id": r.get::<_, i64>(0)?,
                        "short_id": r.get::<_, String>(1)?,
                        "title": r.get::<_, String>(2)?,
                        "event_id": r.get::<_, String>(3)?,
                        "level": r.get::<_, String>(4)?,
                        "timestamp": iso_from_ms(r.get(5)?),
                    }))
                })
                .map_err(map_sqlite_err)?;
            let mut errors = Vec::new();
            for e in err_rows {
                errors.push(e.map_err(map_sqlite_err)?);
            }

            let mut log_stmt = conn
                .prepare(
                    "SELECT id, timestamp_ms, level_num, body, service, span_id, attributes_json
                     FROM log_events WHERE organization_id = ?1 AND trace_id = ?2 ORDER BY id ASC LIMIT 200",
                )
                .map_err(map_sqlite_err)?;
            let log_rows = log_stmt
                .query_map(params![org_id, tid], |r| {
                    let lvl_num: i32 = r.get(2)?;
                    let attr_s: String = r.get(6)?;
                    Ok(json!({
                        "id": r.get::<_, String>(0)?,
                        "timestamp": iso_from_ms(r.get(1)?),
                        "level": LogLevel::from_num(lvl_num).as_str(),
                        "body": r.get::<_, String>(3)?,
                        "service": r.get::<_, String>(4)?,
                        "span_id": r.get::<_, Option<String>>(5)?,
                        "attributes": serde_json::from_str::<Value>(&attr_s).unwrap_or_else(|_| json!({})),
                    }))
                })
                .map_err(map_sqlite_err)?;
            let mut logs = Vec::new();
            for l in log_rows {
                logs.push(l.map_err(map_sqlite_err)?);
            }

            Ok(json!({
                "trace_id": tid,
                "transactions": transactions,
                "errors": errors,
                "logs": logs,
            }))
        })
        .await
    }

    async fn list_releases(&self, ctx: &TenantCtx) -> Result<Vec<ReleaseHealthDto>, String> {
        let org_id = ctx.organization_id;
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT r.version, MIN(r.first_seen), MAX(r.last_seen),
                            (SELECT COUNT(*) FROM issues i WHERE i.organization_id = ?1 AND i.first_release = r.version),
                            COALESCE((SELECT SUM(rs.healthy_count) FROM release_sessions rs WHERE rs.organization_id = ?1 AND rs.release_version = r.version), 0),
                            COALESCE((SELECT SUM(rs.errored_count) FROM release_sessions rs WHERE rs.organization_id = ?1 AND rs.release_version = r.version), 0),
                            COALESCE((SELECT SUM(rs.crashed_count) FROM release_sessions rs WHERE rs.organization_id = ?1 AND rs.release_version = r.version), 0),
                            COALESCE((SELECT SUM(rs.abnormal_count) FROM release_sessions rs WHERE rs.organization_id = ?1 AND rs.release_version = r.version), 0)
                     FROM releases r
                     WHERE r.organization_id = ?1
                     GROUP BY r.version
                     ORDER BY MAX(r.last_seen) DESC LIMIT 50",
                )
                .map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map(params![org_id], |r| {
                    let healthy: i64 = r.get(4)?;
                    let errored: i64 = r.get(5)?;
                    let crashed: i64 = r.get(6)?;
                    let abnormal: i64 = r.get(7)?;
                    let total = healthy + errored + crashed + abnormal;
                    let crash_free = if total > 0 {
                        (((total - crashed) as f64) / (total as f64)) * 100.0
                    } else {
                        100.0
                    };
                    Ok(ReleaseHealthDto {
                        version: r.get(0)?,
                        first_seen: iso_from_ms(r.get(1)?),
                        last_seen: iso_from_ms(r.get(2)?),
                        issue_count: r.get(3)?,
                        healthy_sessions: healthy,
                        errored_sessions: errored,
                        crashed_sessions: crashed,
                        abnormal_sessions: abnormal,
                        crash_free_rate: (crash_free * 100.0).round() / 100.0,
                    })
                })
                .map_err(map_sqlite_err)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(map_sqlite_err)?);
            }
            Ok(out)
        })
        .await
    }

    async fn save_source_map(
        &self,
        ctx: &TenantCtx,
        project_slug: &str,
        release_version: &str,
        debug_id: &str,
        filename: &str,
        blob_sha256: &str,
        size_bytes: i64,
    ) -> Result<SourceMapRecord, String> {
        let org_id = ctx.organization_id;
        let pslug = project_slug.to_string();
        let rel = release_version.to_string();
        let did = debug_id.to_string();
        let fname = filename.to_string();
        let bsha = blob_sha256.to_string();
        self.write(move |conn| {
            let pid: i64 = conn
                .query_row(
                    "SELECT id FROM projects WHERE organization_id = ?1 AND slug = ?2",
                    params![org_id, pslug],
                    |r| r.get(0),
                )
                .map_err(map_sqlite_err)?;
            let now = now_ms();
            conn.execute(
                "INSERT INTO source_maps (organization_id, project_id, release_version, debug_id, filename, blob_sha256, size_bytes, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![org_id, pid, rel, did, fname, bsha, size_bytes, now],
            )
            .map_err(map_sqlite_err)?;
            let id = conn.last_insert_rowid();
            Ok(SourceMapRecord {
                id,
                release_version: rel,
                debug_id: did,
                filename: fname,
                blob_sha256: bsha,
                size_bytes,
            })
        })
        .await
    }

    async fn find_source_map(
        &self,
        organization_id: i64,
        project_id: i64,
        release: Option<&str>,
        debug_id: Option<&str>,
        filename: &str,
    ) -> Result<Option<SourceMapRecord>, String> {
        let rel = release.map(ToString::to_string);
        let did = debug_id.map(ToString::to_string);
        let fname = filename.to_string();
        self.read(move |conn| {
            if let Some(d) = did {
                if let Some(rec) = conn
                    .query_row(
                        "SELECT id, release_version, debug_id, filename, blob_sha256, size_bytes
                         FROM source_maps WHERE organization_id = ?1 AND project_id = ?2 AND debug_id = ?3
                         ORDER BY id DESC LIMIT 1",
                        params![organization_id, project_id, d],
                        |r| {
                            Ok(SourceMapRecord {
                                id: r.get(0)?,
                                release_version: r.get(1)?,
                                debug_id: r.get(2)?,
                                filename: r.get(3)?,
                                blob_sha256: r.get(4)?,
                                size_bytes: r.get(5)?,
                            })
                        },
                    )
                    .optional()
                    .map_err(map_sqlite_err)?
                {
                    return Ok(Some(rec));
                }
            }
            let map_name = format!("{fname}.map");
            let rel_s = rel.unwrap_or_default();
            conn.query_row(
                "SELECT id, release_version, debug_id, filename, blob_sha256, size_bytes
                 FROM source_maps
                 WHERE organization_id = ?1 AND project_id = ?2
                   AND (filename = ?3 OR filename = ?4)
                   AND (release_version = ?5 OR release_version = '')
                 ORDER BY CASE WHEN release_version = ?5 THEN 0 ELSE 1 END, id DESC
                 LIMIT 1",
                params![organization_id, project_id, map_name, fname, rel_s],
                |r| {
                    Ok(SourceMapRecord {
                        id: r.get(0)?,
                        release_version: r.get(1)?,
                        debug_id: r.get(2)?,
                        filename: r.get(3)?,
                        blob_sha256: r.get(4)?,
                        size_bytes: r.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(map_sqlite_err)
        })
        .await
    }

    async fn list_monitors(&self, ctx: &TenantCtx) -> Result<Vec<UptimeMonitorDto>, String> {
        let org_id = ctx.organization_id;
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, project_id, uuid, name, expected_interval_sec, last_heartbeat_at, status, is_active, created_at
                     FROM uptime_monitors WHERE organization_id = ?1 ORDER BY id ASC",
                )
                .map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map(params![org_id], |r| {
                    let hb: Option<i64> = r.get(5)?;
                    Ok(UptimeMonitorDto {
                        id: r.get(0)?,
                        project_id: r.get(1)?,
                        uuid: r.get(2)?,
                        name: r.get(3)?,
                        expected_interval_sec: r.get(4)?,
                        last_heartbeat_at: hb.map(iso_from_ms),
                        status: r.get(6)?,
                        is_active: r.get::<_, i64>(7)? != 0,
                        created_at: iso_from_ms(r.get(8)?),
                    })
                })
                .map_err(map_sqlite_err)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(map_sqlite_err)?);
            }
            Ok(out)
        })
        .await
    }

    async fn create_monitor(
        &self,
        ctx: &TenantCtx,
        project_id: i64,
        name: &str,
        uuid: &str,
        expected_interval_sec: i64,
    ) -> Result<UptimeMonitorDto, String> {
        let org_id = ctx.organization_id;
        let name = name.to_string();
        let uuid = uuid.to_string();
        self.write(move |conn| {
            let owns: Option<i64> = conn
                .query_row(
                    "SELECT id FROM projects WHERE id = ?1 AND organization_id = ?2",
                    params![project_id, org_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_sqlite_err)?;
            if owns.is_none() {
                return Err("Project not found in organization".into());
            }
            let now = now_ms();
            conn.execute(
                "INSERT INTO uptime_monitors (organization_id, project_id, uuid, name, expected_interval_sec, status, is_active, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 1, ?6)",
                params![org_id, project_id, uuid, name, expected_interval_sec, now],
            )
            .map_err(map_sqlite_err)?;
            let id = conn.last_insert_rowid();
            Ok(UptimeMonitorDto {
                id,
                project_id,
                uuid,
                name,
                expected_interval_sec,
                last_heartbeat_at: None,
                status: "pending".into(),
                is_active: true,
                created_at: iso_from_ms(now),
            })
        })
        .await
    }

    async fn delete_monitor(&self, ctx: &TenantCtx, monitor_id: i64) -> Result<bool, String> {
        let org_id = ctx.organization_id;
        self.write(move |conn| {
            let c = conn
                .execute(
                    "DELETE FROM uptime_monitors WHERE id = ?1 AND organization_id = ?2",
                    params![monitor_id, org_id],
                )
                .map_err(map_sqlite_err)?;
            Ok(c > 0)
        })
        .await
    }

    async fn record_heartbeat(&self, ctx: &TenantCtx, uuid: &str, is_up: bool, message: &str) -> Result<Option<UptimeMonitorDto>, String> {
        let org_id = ctx.organization_id;
        let uuid = uuid.to_string();
        let msg = message.to_string();
        self.write(move |conn| {
            let tx = conn.transaction().map_err(map_sqlite_err)?;
            let mon: Option<(i64, i64, String, i64, i64)> = tx
                .query_row(
                    "SELECT id, project_id, name, expected_interval_sec, created_at
                     FROM uptime_monitors WHERE organization_id = ?1 AND uuid = ?2",
                    params![org_id, uuid],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()
                .map_err(map_sqlite_err)?;
            let Some((mon_id, pid, name, interval, created_at)) = mon else {
                return Ok(None);
            };
            let now = now_ms();
            let status = if is_up { "up" } else { "down" };
            tx.execute(
                "UPDATE uptime_monitors SET last_heartbeat_at = ?1, status = ?2 WHERE id = ?3 AND organization_id = ?4",
                params![now, status, mon_id, org_id],
            )
            .map_err(map_sqlite_err)?;
            tx.execute(
                "INSERT INTO uptime_checks (organization_id, monitor_id, is_up, message, checked_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![org_id, mon_id, if is_up { 1 } else { 0 }, msg, now],
            )
            .map_err(map_sqlite_err)?;
            tx.commit().map_err(map_sqlite_err)?;
            Ok(Some(UptimeMonitorDto {
                id: mon_id,
                project_id: pid,
                uuid,
                name,
                expected_interval_sec: interval,
                last_heartbeat_at: Some(iso_from_ms(now)),
                status: status.into(),
                is_active: true,
                created_at: iso_from_ms(created_at),
            }))
        })
        .await
    }

    async fn get_heartbeat(&self, ctx: &TenantCtx, uuid: &str) -> Result<Option<UptimeMonitorDto>, String> {
        let org_id = ctx.organization_id;
        let uuid = uuid.to_string();
        self.read(move |conn| {
            conn.query_row(
                "SELECT id, project_id, uuid, name, expected_interval_sec, last_heartbeat_at, status, is_active, created_at
                 FROM uptime_monitors WHERE organization_id = ?1 AND uuid = ?2",
                params![org_id, uuid],
                |r| {
                    let hb: Option<i64> = r.get(5)?;
                    Ok(UptimeMonitorDto {
                        id: r.get(0)?,
                        project_id: r.get(1)?,
                        uuid: r.get(2)?,
                        name: r.get(3)?,
                        expected_interval_sec: r.get(4)?,
                        last_heartbeat_at: hb.map(iso_from_ms),
                        status: r.get(6)?,
                        is_active: r.get::<_, i64>(7)? != 0,
                        created_at: iso_from_ms(r.get(8)?),
                    })
                },
            )
            .optional()
            .map_err(map_sqlite_err)
        })
        .await
    }

    async fn list_alert_rules(&self, ctx: &TenantCtx) -> Result<Vec<AlertRuleDto>, String> {
        let org_id = ctx.organization_id;
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, project_id, name, trigger_type, threshold_count, window_sec, cooldown_sec,
                            channel_type, target_url, webhook_secret, email_to, last_triggered_at, is_active, created_at
                     FROM alert_rules WHERE organization_id = ?1 ORDER BY id DESC",
                )
                .map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map(params![org_id], |r| {
                    let secret: String = r.get(9)?;
                    Ok(AlertRuleDto {
                        id: r.get(0)?,
                        project_id: r.get(1)?,
                        name: r.get(2)?,
                        trigger_type: r.get(3)?,
                        threshold_count: r.get(4)?,
                        window_sec: r.get(5)?,
                        cooldown_sec: r.get(6)?,
                        channel_type: r.get(7)?,
                        target_url: r.get(8)?,
                        has_secret: !secret.is_empty(),
                        email_to: r.get(10)?,
                        last_triggered_at: r.get(11)?,
                        is_active: r.get::<_, i64>(12)? != 0,
                        created_at: iso_from_ms(r.get(13)?),
                    })
                })
                .map_err(map_sqlite_err)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(map_sqlite_err)?);
            }
            Ok(out)
        })
        .await
    }

    async fn create_alert_rule(&self, ctx: &TenantCtx, rule: &NewAlertRule) -> Result<AlertRuleDto, String> {
        let org_id = ctx.organization_id;
        let r = rule.clone();
        let enc_secret = seal_secret(&self.app_key, &webhook_aad(org_id), &r.webhook_secret)?;
        self.write(move |conn| {
            let owns: Option<i64> = conn
                .query_row(
                    "SELECT id FROM projects WHERE id = ?1 AND organization_id = ?2",
                    params![r.project_id, org_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(map_sqlite_err)?;
            if owns.is_none() {
                return Err("Project not found in organization".into());
            }
            let now = now_ms();
            conn.execute(
                "INSERT INTO alert_rules (organization_id, project_id, name, trigger_type, threshold_count, window_sec, cooldown_sec, channel_type, target_url, webhook_secret, email_to, is_active, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 1, ?12)",
                params![
                    org_id, r.project_id, r.name, r.trigger_type, r.threshold_count, r.window_sec,
                    r.cooldown_sec, r.channel_type, r.target_url, enc_secret, r.email_to, now
                ],
            )
            .map_err(map_sqlite_err)?;
            let id = conn.last_insert_rowid();
            Ok(AlertRuleDto {
                id,
                project_id: r.project_id,
                name: r.name,
                trigger_type: r.trigger_type,
                threshold_count: r.threshold_count,
                window_sec: r.window_sec,
                cooldown_sec: r.cooldown_sec,
                channel_type: r.channel_type,
                target_url: r.target_url,
                has_secret: !r.webhook_secret.is_empty(),
                email_to: r.email_to,
                last_triggered_at: None,
                is_active: true,
                created_at: iso_from_ms(now),
            })
        })
        .await
    }

    async fn delete_alert_rule(&self, ctx: &TenantCtx, rule_id: i64) -> Result<bool, String> {
        let org_id = ctx.organization_id;
        self.write(move |conn| {
            let c = conn
                .execute(
                    "DELETE FROM alert_rules WHERE id = ?1 AND organization_id = ?2",
                    params![rule_id, org_id],
                )
                .map_err(map_sqlite_err)?;
            Ok(c > 0)
        })
        .await
    }

    async fn get_alert_rule(&self, ctx: &TenantCtx, rule_id: i64) -> Result<Option<AlertRuleDto>, String> {
        Ok(self.get_alert_rule_for_dispatch(ctx, rule_id).await?.map(|(dto, _)| dto))
    }

    async fn get_alert_rule_for_dispatch(&self, ctx: &TenantCtx, rule_id: i64) -> Result<Option<(AlertRuleDto, String)>, String> {
        let org_id = ctx.organization_id;
        let app_key = self.app_key;
        self.read(move |conn| {
            conn.query_row(
                "SELECT id, project_id, name, trigger_type, threshold_count, window_sec, cooldown_sec,
                        channel_type, target_url, webhook_secret, email_to, last_triggered_at, is_active, created_at
                 FROM alert_rules WHERE id = ?1 AND organization_id = ?2",
                params![rule_id, org_id],
                |r| {
                    let stored: String = r.get(9)?;
                    let secret = open_webhook_secret(&app_key, org_id, &stored);
                    let dto = AlertRuleDto {
                        id: r.get(0)?,
                        project_id: r.get(1)?,
                        name: r.get(2)?,
                        trigger_type: r.get(3)?,
                        threshold_count: r.get(4)?,
                        window_sec: r.get(5)?,
                        cooldown_sec: r.get(6)?,
                        channel_type: r.get(7)?,
                        target_url: r.get(8)?,
                        has_secret: !stored.is_empty(),
                        email_to: r.get(10)?,
                        last_triggered_at: r.get(11)?,
                        is_active: r.get::<_, i64>(12)? != 0,
                        created_at: iso_from_ms(r.get(13)?),
                    };
                    Ok((dto, secret))
                },
            )
            .optional()
            .map_err(map_sqlite_err)
        })
        .await
    }

    async fn list_api_tokens(&self, ctx: &TenantCtx) -> Result<Vec<ApiTokenDto>, String> {
        let org_id = ctx.organization_id;
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, name, token_prefix, role, scopes, last_used_at, expires_at, created_at
                     FROM api_tokens WHERE organization_id = ?1 ORDER BY id DESC",
                )
                .map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map(params![org_id], |r| {
                    let lu: Option<i64> = r.get(5)?;
                    let exp: Option<i64> = r.get(6)?;
                    Ok(ApiTokenDto {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        token_prefix: r.get(2)?,
                        role: r.get(3)?,
                        scopes: r.get(4)?,
                        last_used_at: lu.map(iso_from_ms),
                        expires_at: exp.map(|s| iso_from_ms(s * 1000)),
                        created_at: iso_from_ms(r.get(7)?),
                    })
                })
                .map_err(map_sqlite_err)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(map_sqlite_err)?);
            }
            Ok(out)
        })
        .await
    }

    async fn create_api_token(
        &self,
        ctx: &TenantCtx,
        name: &str,
        token_sha256: &str,
        token_prefix: &str,
        role: UserRole,
        scopes: &str,
        expires_at: Option<i64>,
    ) -> Result<ApiTokenDto, String> {
        let org_id = ctx.organization_id;
        let user_id = ctx.user_id.ok_or("Missing actor user_id")?;
        let name = name.to_string();
        let sha = token_sha256.to_string();
        let pref = token_prefix.to_string();
        let role_s = role.as_str().to_string();
        let scopes_s = scopes.to_string();
        self.write(move |conn| {
            let now = now_ms();
            conn.execute(
                "INSERT INTO api_tokens (organization_id, user_id, name, token_sha256, token_prefix, role, scopes, expires_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![org_id, user_id, name, sha, pref, role_s, scopes_s, expires_at, now],
            )
            .map_err(map_sqlite_err)?;
            let id = conn.last_insert_rowid();
            Ok(ApiTokenDto {
                id,
                name,
                token_prefix: pref,
                role: role_s,
                scopes: scopes_s,
                last_used_at: None,
                expires_at: expires_at.map(|s| iso_from_ms(s * 1000)),
                created_at: iso_from_ms(now),
            })
        })
        .await
    }

    async fn delete_api_token(&self, ctx: &TenantCtx, token_id: i64) -> Result<bool, String> {
        let org_id = ctx.organization_id;
        self.write(move |conn| {
            let c = conn
                .execute(
                    "DELETE FROM api_tokens WHERE id = ?1 AND organization_id = ?2",
                    params![token_id, org_id],
                )
                .map_err(map_sqlite_err)?;
            Ok(c > 0)
        })
        .await
    }

    async fn list_members(&self, ctx: &TenantCtx) -> Result<Vec<MemberDto>, String> {
        let org_id = ctx.organization_id;
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT u.id, u.email, u.name, m.role, u.is_active
                     FROM organization_members m
                     JOIN users u ON u.id = m.user_id
                     WHERE m.organization_id = ?1
                     ORDER BY u.id ASC",
                )
                .map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map(params![org_id], |r| {
                    Ok(MemberDto {
                        user_id: r.get(0)?,
                        email: r.get(1)?,
                        name: r.get(2)?,
                        role: r.get(3)?,
                        is_active: r.get::<_, i64>(4)? != 0,
                    })
                })
                .map_err(map_sqlite_err)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(map_sqlite_err)?);
            }
            Ok(out)
        })
        .await
    }

    async fn invite_member(
        &self,
        ctx: &TenantCtx,
        email: &str,
        name: &str,
        password_hash: &str,
        role: UserRole,
    ) -> Result<MemberDto, String> {
        let org_id = ctx.organization_id;
        let email = email.trim().to_ascii_lowercase();
        let name = name.to_string();
        let hash = password_hash.to_string();
        let role_s = role.as_str().to_string();
        self.write(move |conn| {
            let tx = conn.transaction().map_err(map_sqlite_err)?;
            let existing_uid: Option<i64> = tx
                .query_row("SELECT id FROM users WHERE email = ?1", params![email], |r| r.get(0))
                .optional()
                .map_err(map_sqlite_err)?;
            let uid = match existing_uid {
                Some(id) => id,
                None => {
                    tx.execute(
                        "INSERT INTO users (email, name, password_hash, is_active, created_at) VALUES (?1, ?2, ?3, 1, ?4)",
                        params![email, name, hash, now_ms()],
                    )
                    .map_err(map_sqlite_err)?;
                    tx.last_insert_rowid()
                }
            };
            tx.execute(
                "INSERT INTO organization_members (organization_id, user_id, role) VALUES (?1, ?2, ?3)
                 ON CONFLICT(organization_id, user_id) DO UPDATE SET role = ?3",
                params![org_id, uid, role_s],
            )
            .map_err(map_sqlite_err)?;
            tx.commit().map_err(map_sqlite_err)?;
            Ok(MemberDto {
                user_id: uid,
                email,
                name,
                role: role_s,
                is_active: true,
            })
        })
        .await
    }

    async fn update_member_role(&self, ctx: &TenantCtx, target_user_id: i64, role: UserRole) -> Result<Result<MemberDto, String>, String> {
        let org_id = ctx.organization_id;
        let role_s = role.as_str().to_string();
        self.write(move |conn| {
            let tx = conn.transaction().map_err(map_sqlite_err)?;
            let current_role: Option<String> = tx
                .query_row(
                    "SELECT role FROM organization_members WHERE organization_id = ?1 AND user_id = ?2",
                    params![org_id, target_user_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_sqlite_err)?;
            let Some(curr) = current_role else {
                return Ok(Err("Member not found".into()));
            };
            if curr == "owner" && role != UserRole::Owner {
                let owners: i64 = tx
                    .query_row(
                        "SELECT COUNT(*) FROM organization_members WHERE organization_id = ?1 AND role = 'owner'",
                        params![org_id],
                        |r| r.get(0),
                    )
                    .map_err(map_sqlite_err)?;
                if owners <= 1 {
                    return Ok(Err("Cannot demote the last organization owner".into()));
                }
            }
            tx.execute(
                "UPDATE organization_members SET role = ?1 WHERE organization_id = ?2 AND user_id = ?3",
                params![role_s, org_id, target_user_id],
            )
            .map_err(map_sqlite_err)?;
            // Rotate out stale sessions & revoke any API tokens exceeding the new role rank
            tx.execute(
                "DELETE FROM sessions WHERE organization_id = ?1 AND user_id = ?2",
                params![org_id, target_user_id],
            )
            .map_err(map_sqlite_err)?;
            let mut tok_stmt = tx
                .prepare("SELECT id, role FROM api_tokens WHERE organization_id = ?1 AND user_id = ?2")
                .map_err(map_sqlite_err)?;
            let tok_ids: Vec<(i64, String)> = tok_stmt
                .query_map(params![org_id, target_user_id], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(map_sqlite_err)?
                .filter_map(Result::ok)
                .collect();
            drop(tok_stmt);
            for (tid, trole) in tok_ids {
                if UserRole::from_db(&trole).map(|r| r.rank() > role.rank()).unwrap_or(true) {
                    tx.execute("DELETE FROM api_tokens WHERE id = ?1", params![tid])
                        .map_err(map_sqlite_err)?;
                }
            }
            let dto = tx
                .query_row(
                    "SELECT u.id, u.email, u.name, m.role, u.is_active
                     FROM organization_members m JOIN users u ON u.id = m.user_id
                     WHERE m.organization_id = ?1 AND m.user_id = ?2",
                    params![org_id, target_user_id],
                    |r| {
                        Ok(MemberDto {
                            user_id: r.get(0)?,
                            email: r.get(1)?,
                            name: r.get(2)?,
                            role: r.get(3)?,
                            is_active: r.get::<_, i64>(4)? != 0,
                        })
                    },
                )
                .map_err(map_sqlite_err)?;
            tx.commit().map_err(map_sqlite_err)?;
            Ok(Ok(dto))
        })
        .await
    }

    async fn remove_member(&self, ctx: &TenantCtx, target_user_id: i64) -> Result<Result<bool, String>, String> {
        let org_id = ctx.organization_id;
        self.write(move |conn| {
            let tx = conn.transaction().map_err(map_sqlite_err)?;
            let current_role: Option<String> = tx
                .query_row(
                    "SELECT role FROM organization_members WHERE organization_id = ?1 AND user_id = ?2",
                    params![org_id, target_user_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_sqlite_err)?;
            let Some(curr) = current_role else {
                return Ok(Ok(false));
            };
            if curr == "owner" {
                let owners: i64 = tx
                    .query_row(
                        "SELECT COUNT(*) FROM organization_members WHERE organization_id = ?1 AND role = 'owner'",
                        params![org_id],
                        |r| r.get(0),
                    )
                    .map_err(map_sqlite_err)?;
                if owners <= 1 {
                    return Ok(Err("Cannot remove the last organization owner".into()));
                }
            }
            tx.execute(
                "DELETE FROM organization_members WHERE organization_id = ?1 AND user_id = ?2",
                params![org_id, target_user_id],
            )
            .map_err(map_sqlite_err)?;
            tx.execute(
                "DELETE FROM sessions WHERE organization_id = ?1 AND user_id = ?2",
                params![org_id, target_user_id],
            )
            .map_err(map_sqlite_err)?;
            tx.execute(
                "DELETE FROM api_tokens WHERE organization_id = ?1 AND user_id = ?2",
                params![org_id, target_user_id],
            )
            .map_err(map_sqlite_err)?;
            tx.commit().map_err(map_sqlite_err)?;
            Ok(Ok(true))
        })
        .await
    }

    async fn begin_idempotency(
        &self,
        ctx: &TenantCtx,
        action: &str,
        idem_key: &str,
        payload_sha256: &str,
    ) -> Result<IdempotencyCheck, String> {
        let org_id = ctx.organization_id;
        let uid = ctx.user_id.unwrap_or(0);
        let action = action.to_string();
        let key = idem_key.to_string();
        let psha = payload_sha256.to_string();
        self.write(move |conn| {
            let tx = conn.transaction().map_err(map_sqlite_err)?;
            let existing: Option<(String, i64, String, i64)> = tx
                .query_row(
                    "SELECT payload_sha256, status_code, response_body, in_flight
                     FROM idempotency_keys
                     WHERE organization_id = ?1 AND user_id = ?2 AND action = ?3 AND idem_key = ?4",
                    params![org_id, uid, action, key],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()
                .map_err(map_sqlite_err)?;
            match existing {
                Some((old_sha, status, body, in_flight)) => {
                    if in_flight != 0 {
                        return Ok(IdempotencyCheck::Conflict("Request with this Idempotency-Key is currently in-flight".into()));
                    }
                    if old_sha != psha {
                        return Ok(IdempotencyCheck::Conflict("Idempotency-Key reused with different payload".into()));
                    }
                    Ok(IdempotencyCheck::Replay {
                        status_code: status as u16,
                        body,
                    })
                }
                None => {
                    tx.execute(
                        "INSERT INTO idempotency_keys (organization_id, user_id, action, idem_key, payload_sha256, status_code, response_body, in_flight, created_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, 0, '', 1, ?6)",
                        params![org_id, uid, action, key, psha, now_ms()],
                    )
                    .map_err(map_sqlite_err)?;
                    tx.commit().map_err(map_sqlite_err)?;
                    Ok(IdempotencyCheck::Proceed)
                }
            }
        })
        .await
    }

    async fn finish_idempotency(
        &self,
        ctx: &TenantCtx,
        action: &str,
        idem_key: &str,
        status_code: u16,
        response_body: &str,
    ) -> Result<(), String> {
        let org_id = ctx.organization_id;
        let uid = ctx.user_id.unwrap_or(0);
        let action = action.to_string();
        let key = idem_key.to_string();
        let body = response_body.to_string();
        self.write(move |conn| {
            conn.execute(
                "UPDATE idempotency_keys SET status_code = ?1, response_body = ?2, in_flight = 0
                 WHERE organization_id = ?3 AND user_id = ?4 AND action = ?5 AND idem_key = ?6",
                params![status_code as i64, body, org_id, uid, action, key],
            )
            .map_err(map_sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn flush_ingest_batch(&self, items: Vec<IngestWriteItem>) -> Result<Vec<AlertDispatchJob>, String> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let writer = self.writer.clone();
        let storm_counters = self.storm_counters.clone();
        let app_key = self.app_key;
        tokio::task::spawn_blocking(move || {
            let mut guard = writer.lock().unwrap_or_else(|e| e.into_inner());
            let tx = guard.transaction().map_err(map_sqlite_err)?;
            let now_sec = chrono::Utc::now().timestamp();
            let mut alert_jobs = Vec::new();

            for item in items {
                match item {
                    IngestWriteItem::Event { auth, meta, payload_json, received_ms } => {
                        let store_blob = Self::should_sample_storm(
                            &storm_counters,
                            auth.project_id,
                            &meta.fingerprint,
                            &auth.filters,
                            received_ms,
                        );
                        let (issue_id, short_id, is_new, is_reg) = insert_event_in_txn(
                            &tx,
                            &auth,
                            &meta,
                            &payload_json,
                            received_ms,
                            store_blob,
                        )?;
                        if issue_id > 0 {
                            let jobs = build_alert_jobs_for_event(
                                &tx,
                                &app_key,
                                auth.organization_id,
                                auth.project_id,
                                &auth.project_slug,
                                &short_id,
                                &meta.title,
                                &meta.level,
                                is_new,
                                is_reg,
                                now_sec,
                            )?;
                            alert_jobs.extend(jobs);
                        }
                    }
                    IngestWriteItem::Logs { organization_id, project_id, project_slug, auto_promote_level, logs } => {
                        for l in logs {
                            let row_id = new_uuid_v7_from_ms(l.timestamp_ms);
                            let attr_str = serde_json::to_string(&l.attributes).unwrap_or_else(|_| "{}".into());
                            tx.execute(
                                "INSERT INTO log_events (
                                    id, organization_id, project_id, timestamp_ms, level_num, severity_number,
                                    body, service, environment, host, trace_id, span_id, attributes_json
                                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                                params![
                                    row_id,
                                    organization_id,
                                    project_id,
                                    l.timestamp_ms,
                                    l.level.num(),
                                    l.severity_number.map(|n| n as i64),
                                    l.body,
                                    l.service,
                                    l.environment,
                                    l.host,
                                    l.trace_id,
                                    l.span_id,
                                    attr_str,
                                ],
                            )
                            .map_err(map_sqlite_err)?;

                            tx.execute(
                                "INSERT INTO logs_fts (body, service, host, log_id, organization_id) VALUES (?1, ?2, ?3, ?4, ?5)",
                                params![l.body, l.service, l.host, row_id, organization_id],
                            )
                            .map_err(map_sqlite_err)?;

                            for (rtype, val) in [("service", &l.service), ("environment", &l.environment), ("host", &l.host)] {
                                if !val.is_empty() {
                                    tx.execute(
                                        "INSERT INTO log_resources (organization_id, resource_type, name, last_seen)
                                         VALUES (?1, ?2, ?3, ?4)
                                         ON CONFLICT(organization_id, resource_type, name) DO UPDATE SET last_seen = MAX(last_seen, excluded.last_seen)",
                                        params![organization_id, rtype, val, l.timestamp_ms],
                                    )
                                    .map_err(map_sqlite_err)?;
                                }
                            }

                            let bucket_hour = (l.timestamp_ms / 3_600_000) * 3_600_000;
                            tx.execute(
                                "INSERT INTO hourly_stats (organization_id, project_id, bucket_hour, category, quantity)
                                 VALUES (?1, ?2, ?3, 'log', 1)
                                 ON CONFLICT(project_id, bucket_hour, category) DO UPDATE SET quantity = quantity + 1",
                                params![organization_id, project_id, bucket_hour],
                            )
                            .map_err(map_sqlite_err)?;

                            // Auto-promote fatal/error logs into trackable Issues if enabled on project
                            let mut fatal_alert_checked = false;
                            if let Some(min_lvl) = auto_promote_level {
                                if l.level.num() >= min_lvl.num() {
                                    let ev = json!({
                                        "type": "log",
                                        "level": l.level.as_str(),
                                        "message": l.body,
                                        "environment": if l.environment.is_empty() { "production" } else { &l.environment },
                                        "culprit": if l.service.is_empty() { "log" } else { &l.service },
                                        "contexts": { "trace": { "trace_id": l.trace_id, "span_id": l.span_id } },
                                        "extra": l.attributes,
                                    });
                                    let meta = extract_issue_metadata(&ev);
                                    let bytes = serde_json::to_vec(&ev).unwrap_or_default();
                                    let synth_auth = ProjectAuthInfo {
                                        project_id,
                                        organization_id,
                                        organization_slug: String::new(),
                                        project_slug: project_slug.clone(),
                                        first_event_at: Some(l.timestamp_ms),
                                        rate_limit_per_min: 300,
                                        filters: ProjectFilters::default(),
                                        org_scrub_ip_addresses: false,
                                        org_event_throttle_rate: 0,
                                    };
                                    let (issue_id, short_id, is_new, is_reg) = insert_event_in_txn(
                                        &tx,
                                        &synth_auth,
                                        &meta,
                                        &bytes,
                                        l.timestamp_ms,
                                        true,
                                    )?;
                                    if issue_id > 0 {
                                        let jobs = build_alert_jobs_for_event(
                                            &tx,
                                            &app_key,
                                            organization_id,
                                            project_id,
                                            &project_slug,
                                            &short_id,
                                            &meta.title,
                                            l.level.as_str(),
                                            is_new,
                                            is_reg,
                                            now_sec,
                                        )?;
                                        alert_jobs.extend(jobs);
                                        fatal_alert_checked = true;
                                    }
                                }
                            }
                            if !fatal_alert_checked && l.level == LogLevel::Fatal {
                                let jobs = build_alert_jobs_for_event(
                                    &tx,
                                    &app_key,
                                    organization_id,
                                    project_id,
                                    &project_slug,
                                    "LOG",
                                    &l.body,
                                    "fatal",
                                    false,
                                    false,
                                    now_sec,
                                )?;
                                alert_jobs.extend(jobs);
                            }
                        }
                    }
                    IngestWriteItem::Transaction { organization_id, project_id, tx: tr } => {
                        let id = new_uuid_v7_from_ms(tr.timestamp_ms);
                        let spans_s = serde_json::to_string(&tr.spans).unwrap_or_else(|_| "[]".into());
                        tx.execute(
                            "INSERT INTO transaction_events (
                                id, organization_id, project_id, name, op, status, duration_ms,
                                trace_id, span_id, environment, release, spans_json, timestamp_ms
                            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                            params![
                                id, organization_id, project_id, tr.name, tr.op, tr.status, tr.duration_ms,
                                tr.trace_id, tr.span_id, tr.environment, tr.release, spans_s, tr.timestamp_ms
                            ],
                        )
                        .map_err(map_sqlite_err)?;
                        let bucket_hour = (tr.timestamp_ms / 3_600_000) * 3_600_000;
                        tx.execute(
                            "INSERT INTO hourly_stats (organization_id, project_id, bucket_hour, category, quantity)
                             VALUES (?1, ?2, ?3, 'transaction', 1)
                             ON CONFLICT(project_id, bucket_hour, category) DO UPDATE SET quantity = quantity + 1",
                            params![organization_id, project_id, bucket_hour],
                        )
                        .map_err(map_sqlite_err)?;
                    }
                    IngestWriteItem::Session { organization_id, project_id, session, received_ms } => {
                        let bucket_hour = (received_ms / 3_600_000) * 3_600_000;
                        tx.execute(
                            "INSERT INTO releases (organization_id, project_id, version, first_seen, last_seen)
                             VALUES (?1, ?2, ?3, ?4, ?4)
                             ON CONFLICT(project_id, version) DO UPDATE SET last_seen = MAX(last_seen, excluded.last_seen)",
                            params![organization_id, project_id, session.release, received_ms],
                        )
                        .map_err(map_sqlite_err)?;

                        let (h, e, c, a) = match session.status.as_str() {
                            "crashed" => (0, 0, 1, 0),
                            "abnormal" => (0, 0, 0, 1),
                            _ if session.errors > 0 || session.status == "errored" => (0, 1, 0, 0),
                            _ if session.init || session.status == "exited" || session.status == "ok" => (1, 0, 0, 0),
                            _ => (0, 0, 0, 0),
                        };
                        tx.execute(
                            "INSERT INTO release_sessions (organization_id, project_id, release_version, environment, bucket_hour, healthy_count, errored_count, crashed_count, abnormal_count)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                             ON CONFLICT(project_id, release_version, environment, bucket_hour)
                             DO UPDATE SET healthy_count = healthy_count + ?6,
                                           errored_count = errored_count + ?7,
                                           crashed_count = crashed_count + ?8,
                                           abnormal_count = abnormal_count + ?9",
                            params![organization_id, project_id, session.release, session.environment, bucket_hour, h, e, c, a],
                        )
                        .map_err(map_sqlite_err)?;
                    }
                    IngestWriteItem::CheckIn { organization_id, project_id, check_in, received_ms } => {
                        let is_up = check_in.status != "error";
                        let status = if is_up { "up" } else { "down" };
                        if let Some(mon_id) = tx
                            .query_row(
                                "SELECT id FROM uptime_monitors WHERE organization_id = ?1 AND project_id = ?2 AND (uuid = ?3 OR name = ?3)",
                                params![organization_id, project_id, check_in.monitor_slug],
                                |r| r.get::<_, i64>(0),
                            )
                            .optional()
                            .map_err(map_sqlite_err)?
                        {
                            tx.execute(
                                "UPDATE uptime_monitors SET last_heartbeat_at = ?1, status = ?2 WHERE id = ?3",
                                params![received_ms, status, mon_id],
                            )
                            .map_err(map_sqlite_err)?;
                            tx.execute(
                                "INSERT INTO uptime_checks (organization_id, monitor_id, is_up, duration_ms, checked_at)
                                 VALUES (?1, ?2, ?3, ?4, ?5)",
                                params![organization_id, mon_id, if is_up { 1 } else { 0 }, check_in.duration_ms, received_ms],
                            )
                            .map_err(map_sqlite_err)?;
                        }
                    }
                }
            }

            tx.commit().map_err(map_sqlite_err)?;
            Ok(alert_jobs)
        })
        .await
        .map_err(|e| format!("Batch flush join: {e}"))?
    }

    async fn run_maintenance(&self, retention_days: u32, max_db_mb: u64) -> Result<Vec<AlertDispatchJob>, String> {
        let size_bytes = self.db_size_bytes().await;
        let app_key = self.app_key;
        self.write(move |conn| {
            let now = now_ms();
            let cutoff_ms = now - (retention_days as i64) * 86_400_000;
            let now_sec = now / 1000;
            let mut alerts = Vec::new();

            let tx = conn.transaction().map_err(map_sqlite_err)?;
            tx.execute("DELETE FROM sessions WHERE expires_at <= ?1", params![now_sec])
                .map_err(map_sqlite_err)?;
            let _ = tx.execute("DELETE FROM mfa_challenges WHERE expires_at <= ?1", params![now_sec]);
            let _ = tx.execute("DELETE FROM webauthn_challenges WHERE expires_at <= ?1", params![now_sec]);
            let _ = tx.execute("DELETE FROM org_invitations WHERE accepted_at IS NULL AND expires_at <= ?1", params![now_sec]);
            let _ = tx.execute("DELETE FROM api_tokens WHERE expires_at IS NOT NULL AND expires_at <= ?1", params![now_sec]);
            tx.execute(
                "DELETE FROM idempotency_keys WHERE created_at < ?1",
                params![now - 86_400_000],
            )
            .map_err(map_sqlite_err)?;
            let mut purged_rows = 0usize;
            purged_rows += tx
                .execute(
                    "DELETE FROM issue_events WHERE timestamp_ms < ?1",
                    params![cutoff_ms],
                )
                .map_err(map_sqlite_err)?;
            purged_rows += tx
                .execute(
                    "DELETE FROM log_events WHERE timestamp_ms < ?1",
                    params![cutoff_ms],
                )
                .map_err(map_sqlite_err)?;
            purged_rows += tx
                .execute(
                    "DELETE FROM transaction_events WHERE timestamp_ms < ?1",
                    params![cutoff_ms],
                )
                .map_err(map_sqlite_err)?;
            let _ = tx.execute(
                "DELETE FROM security_events WHERE timestamp_ms < ?1",
                params![cutoff_ms],
            );
            let _ = tx.execute(
                "DELETE FROM shield_quarantine WHERE expires_at <= ?1",
                params![now_sec],
            );

            // Circuit breaker: if DB exceeds max_db_mb, shed oldest 10% of logs & events
            let max_bytes = max_db_mb * 1024 * 1024;
            let over_budget = size_bytes > max_bytes;
            if over_budget {
                purged_rows += tx
                    .execute(
                        "DELETE FROM log_events WHERE id IN (SELECT id FROM log_events ORDER BY id ASC LIMIT 5000)",
                        [],
                    )
                    .map_err(map_sqlite_err)?;
                purged_rows += tx
                    .execute(
                        "DELETE FROM issue_events WHERE id IN (SELECT id FROM issue_events ORDER BY timestamp_ms ASC LIMIT 2000)",
                        [],
                    )
                    .map_err(map_sqlite_err)?;
            }
            if purged_rows > 0 {
                let _ = tx.execute(
                    "DELETE FROM logs_fts WHERE log_id NOT IN (SELECT id FROM log_events)",
                    [],
                );
            }

            // Detect missed uptime heartbeats
            let mut stmt = tx
                .prepare(
                    "SELECT m.id, m.organization_id, m.project_id, p.slug, m.name, m.uuid
                     FROM uptime_monitors m
                     JOIN projects p ON p.id = m.project_id
                     WHERE m.is_active = 1 AND m.status = 'up'
                       AND m.last_heartbeat_at IS NOT NULL
                       AND (?1 - m.last_heartbeat_at) > (m.expected_interval_sec * 1500)",
                )
                .map_err(map_sqlite_err)?;
            let mut down_list = Vec::new();
            let mut rows = stmt.query(params![now]).map_err(map_sqlite_err)?;
            while let Some(r) = rows.next().map_err(map_sqlite_err)? {
                down_list.push((
                    r.get::<_, i64>(0).map_err(map_sqlite_err)?,
                    r.get::<_, i64>(1).map_err(map_sqlite_err)?,
                    r.get::<_, i64>(2).map_err(map_sqlite_err)?,
                    r.get::<_, String>(3).map_err(map_sqlite_err)?,
                    r.get::<_, String>(4).map_err(map_sqlite_err)?,
                    r.get::<_, String>(5).map_err(map_sqlite_err)?,
                ));
            }
            drop(rows);
            drop(stmt);

            for (mon_id, org_id, proj_id, pslug, mname, muuid) in down_list {
                tx.execute(
                    "UPDATE uptime_monitors SET status = 'down' WHERE id = ?1",
                    params![mon_id],
                )
                .map_err(map_sqlite_err)?;
                tx.execute(
                    "INSERT INTO uptime_checks (organization_id, monitor_id, is_up, message, checked_at)
                     VALUES (?1, ?2, 0, 'Heartbeat missed', ?3)",
                    params![org_id, mon_id, now],
                )
                .map_err(map_sqlite_err)?;
                let mut rstmt = tx
                    .prepare(
                        "SELECT id, name, channel_type, target_url, webhook_secret, email_to, cooldown_sec, last_triggered_at
                         FROM alert_rules WHERE organization_id = ?1 AND project_id = ?2 AND trigger_type = 'uptime_down' AND is_active = 1",
                    )
                    .map_err(map_sqlite_err)?;
                let mut rrows = rstmt.query(params![org_id, proj_id]).map_err(map_sqlite_err)?;
                let mut fired = Vec::new();
                while let Some(rr) = rrows.next().map_err(map_sqlite_err)? {
                    let rid: i64 = rr.get(0).map_err(map_sqlite_err)?;
                    let cd: i64 = rr.get(6).map_err(map_sqlite_err)?;
                    let lt: Option<i64> = rr.get(7).map_err(map_sqlite_err)?;
                    if lt.map(|t| now_sec - t >= cd).unwrap_or(true) {
                        fired.push(rid);
                        alerts.push(AlertDispatchJob {
                            rule_id: rid,
                            rule_name: rr.get(1).map_err(map_sqlite_err)?,
                            channel_type: rr.get(2).map_err(map_sqlite_err)?,
                            target_url: rr.get(3).map_err(map_sqlite_err)?,
                            webhook_secret: open_webhook_secret(&app_key, org_id, &rr.get::<_, String>(4).map_err(map_sqlite_err)?),
                            email_to: rr.get(5).map_err(map_sqlite_err)?,
                            title: format!("Uptime monitor down: {mname}"),
                            message: format!("Heartbeat missed for monitor {muuid}"),
                            level: "fatal".into(),
                            project_slug: pslug.clone(),
                            short_id: None,
                        });
                    }
                }
                drop(rrows);
                drop(rstmt);
                for rid in fired {
                    tx.execute(
                        "UPDATE alert_rules SET last_triggered_at = ?1 WHERE id = ?2",
                        params![now_sec, rid],
                    )
                    .map_err(map_sqlite_err)?;
                }
            }

            tx.commit().map_err(map_sqlite_err)?;
            if purged_rows > 0 || over_budget {
                let _ = conn.execute_batch(
                    "PRAGMA incremental_vacuum(256); PRAGMA wal_checkpoint(TRUNCATE);",
                );
            }
            let _ = conn.execute_batch("PRAGMA optimize;");
            trim_heap();
            Ok(alerts)
        })
        .await
    }

    async fn db_size_bytes(&self) -> u64 {
        let main = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        let mut wal_os = self.path.as_os_str().to_os_string();
        wal_os.push("-wal");
        let wal = std::fs::metadata(PathBuf::from(wal_os))
            .map(|m| m.len())
            .unwrap_or(0);
        main + wal
    }

    async fn check_health(&self) -> Result<StorageHealthInfo, String> {
        let (journal_mode, fts_ok) = self
            .read(|conn| {
                let _: i64 = conn
                    .query_row("SELECT 1", [], |r| r.get(0))
                    .map_err(map_sqlite_err)?;
                let mode: String = conn
                    .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
                    .map_err(map_sqlite_err)?;
                let fts_ok = conn
                    .query_row("SELECT count(*) FROM issues_fts LIMIT 1", [], |r| {
                        r.get::<_, i64>(0)
                    })
                    .is_ok();
                Ok((mode, fts_ok))
            })
            .await?;

        self.write(|conn| {
            let _: i64 = conn
                .query_row("SELECT 1", [], |r| r.get(0))
                .map_err(map_sqlite_err)?;
            Ok(())
        })
        .await?;

        let is_wal = journal_mode.eq_ignore_ascii_case("wal");
        let ok = fts_ok;
        let detail = format!(
            "SQLite engine reachable (journal_mode={journal_mode}, fts5={})",
            if fts_ok { "ready" } else { "missing" }
        );
        Ok(StorageHealthInfo {
            engine: "sqlite".to_string(),
            ok,
            detail,
            wal_or_rls_verified: is_wal,
        })
    }

    async fn record_security_event(
        &self,
        ev: &NewSecurityEvent,
    ) -> Result<(SecurityEventDto, Vec<AlertDispatchJob>), String> {
        let ev = ev.clone();
        let app_key = self.app_key;
        self.write(move |conn| {
            let now_sec = ev.timestamp_ms / 1000;
            let details_str = ev.details_json.to_string();
            let tx = conn.transaction().map_err(map_sqlite_err)?;

            tx.execute(
                "INSERT INTO security_events
                 (organization_id, project_id, signal_type, category, severity, risk_score, source_kind, actor_hmac, session_id, path, details_json, action_taken, timestamp_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    ev.organization_id,
                    ev.project_id,
                    ev.signal_type,
                    ev.category,
                    ev.severity,
                    ev.risk_score as i64,
                    ev.source_kind,
                    ev.actor_hmac,
                    ev.session_id,
                    ev.path,
                    details_str,
                    ev.action_taken,
                    ev.timestamp_ms,
                ],
            )
            .map_err(map_sqlite_err)?;
            let row_id = tx.last_insert_rowid();

            if let Some((ref stype, ref shmac, exp_sec)) = ev.quarantine {
                tx.execute(
                    "INSERT INTO shield_quarantine
                     (organization_id, project_id, subject_type, subject_hmac, reason, risk_score, expires_at, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT(organization_id, project_id, subject_type, subject_hmac) DO UPDATE SET
                       reason = excluded.reason,
                       risk_score = MAX(shield_quarantine.risk_score, excluded.risk_score),
                       expires_at = MAX(shield_quarantine.expires_at, excluded.expires_at)",
                    params![
                        ev.organization_id,
                        ev.project_id,
                        stype,
                        shmac,
                        ev.signal_type,
                        ev.risk_score as i64,
                        exp_sec,
                        now_sec,
                    ],
                )
                .map_err(map_sqlite_err)?;
            }

            let mut alerts = Vec::new();
            let mut stmt = tx
                .prepare(
                    "SELECT id, name, trigger_type, cooldown_sec, channel_type, target_url, webhook_secret, email_to, last_triggered_at
                     FROM alert_rules
                     WHERE organization_id = ?1 AND project_id = ?2 AND is_active = 1
                       AND (trigger_type = 'security_threat' OR (?3 = 'secret_leak' AND trigger_type = 'secret_leak'))",
                )
                .map_err(map_sqlite_err)?;
            let mut fired = Vec::new();
            let mut rows = stmt
                .query(params![ev.organization_id, ev.project_id, ev.category])
                .map_err(map_sqlite_err)?;
            while let Some(r) = rows.next().map_err(map_sqlite_err)? {
                let rid: i64 = r.get(0).map_err(map_sqlite_err)?;
                let cd: i64 = r.get(3).map_err(map_sqlite_err)?;
                let last: Option<i64> = r.get(8).map_err(map_sqlite_err)?;
                if last.map(|t| now_sec - t >= cd).unwrap_or(true) {
                    let trig: String = r.get(2).map_err(map_sqlite_err)?;
                    fired.push(rid);
                    alerts.push(AlertDispatchJob {
                        rule_id: rid,
                        rule_name: r.get(1).map_err(map_sqlite_err)?,
                        channel_type: r.get(4).map_err(map_sqlite_err)?,
                        target_url: r.get(5).map_err(map_sqlite_err)?,
                        webhook_secret: open_webhook_secret(&app_key, ev.organization_id, &r.get::<_, String>(6).map_err(map_sqlite_err)?),
                        email_to: r.get(7).map_err(map_sqlite_err)?,
                        title: format!("[{}:{}] {} (score {})", ev.category, ev.severity, ev.signal_type, ev.risk_score),
                        message: format!(
                            "Trigger={trig} | Source={} | Action={} | Path={}",
                            ev.source_kind, ev.action_taken, ev.path
                        ),
                        level: if ev.severity == "critical" || ev.severity == "high" {
                            "fatal".into()
                        } else {
                            "warning".into()
                        },
                        project_slug: ev.project_slug.clone(),
                        short_id: None,
                    });
                }
            }
            drop(rows);
            drop(stmt);
            for rid in fired {
                tx.execute(
                    "UPDATE alert_rules SET last_triggered_at = ?1 WHERE id = ?2",
                    params![now_sec, rid],
                )
                .map_err(map_sqlite_err)?;
            }

            tx.commit().map_err(map_sqlite_err)?;
            Ok((
                SecurityEventDto {
                    id: row_id,
                    project_id: ev.project_id,
                    signal_type: ev.signal_type,
                    category: ev.category,
                    severity: ev.severity,
                    risk_score: ev.risk_score as i64,
                    source_kind: ev.source_kind,
                    actor_hmac: ev.actor_hmac,
                    session_id: ev.session_id,
                    path: ev.path,
                    details_json: ev.details_json,
                    action_taken: ev.action_taken,
                    timestamp: iso_from_ms(ev.timestamp_ms),
                },
                alerts,
            ))
        })
        .await
    }

    async fn list_security_events(
        &self,
        ctx: &TenantCtx,
        project_id: Option<i64>,
        limit: i64,
    ) -> Result<(Vec<SecurityEventDto>, ShieldSummaryDto), String> {
        let org_id = ctx.organization_id;
        let lim = limit.clamp(1, 200);
        self.read(move |conn| {
            let now = now_ms();
            let since_24h = now - 86_400_000;
            let now_sec = now / 1000;

            let (events_24h, high_critical_24h, secret_leaks_24h): (i64, i64, i64) = conn
                .query_row(
                    "SELECT
                       COUNT(*),
                       COALESCE(SUM(CASE WHEN severity IN ('high', 'critical') THEN 1 ELSE 0 END), 0),
                       COALESCE(SUM(CASE WHEN category = 'secret_leak' THEN 1 ELSE 0 END), 0)
                     FROM security_events
                     WHERE organization_id = ?1 AND timestamp_ms >= ?2
                       AND (?3 IS NULL OR project_id = ?3)",
                    params![org_id, since_24h, project_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .map_err(map_sqlite_err)?;

            let active_quarantines: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM shield_quarantine
                     WHERE organization_id = ?1 AND expires_at > ?2
                       AND (?3 IS NULL OR project_id = ?3)",
                    params![org_id, now_sec, project_id],
                    |r| r.get(0),
                )
                .map_err(map_sqlite_err)?;

            let mut stmt = conn
                .prepare(
                    "SELECT id, project_id, signal_type, category, severity, risk_score, source_kind,
                            actor_hmac, session_id, path, details_json, action_taken, timestamp_ms
                     FROM security_events
                     WHERE organization_id = ?1 AND (?2 IS NULL OR project_id = ?2)
                     ORDER BY timestamp_ms DESC, id DESC
                     LIMIT ?3",
                )
                .map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map(params![org_id, project_id, lim], |r| {
                    let dj: String = r.get(10)?;
                    let ts: i64 = r.get(12)?;
                    Ok(SecurityEventDto {
                        id: r.get(0)?,
                        project_id: r.get(1)?,
                        signal_type: r.get(2)?,
                        category: r.get(3)?,
                        severity: r.get(4)?,
                        risk_score: r.get(5)?,
                        source_kind: r.get(6)?,
                        actor_hmac: r.get(7)?,
                        session_id: r.get(8)?,
                        path: r.get(9)?,
                        details_json: serde_json::from_str(&dj).unwrap_or_else(|_| json!({})),
                        action_taken: r.get(11)?,
                        timestamp: iso_from_ms(ts),
                    })
                })
                .map_err(map_sqlite_err)?;
            let mut items = Vec::new();
            for row in rows {
                items.push(row.map_err(map_sqlite_err)?);
            }

            Ok((
                items,
                ShieldSummaryDto {
                    events_24h,
                    high_critical_24h,
                    secret_leaks_24h,
                    active_quarantines,
                },
            ))
        })
        .await
    }

    async fn list_quarantine(
        &self,
        ctx: &TenantCtx,
        project_id: Option<i64>,
    ) -> Result<Vec<QuarantineEntryDto>, String> {
        let org_id = ctx.organization_id;
        self.read(move |conn| {
            let now_sec = now_ms() / 1000;
            let mut stmt = conn
                .prepare(
                    "SELECT id, project_id, subject_type, subject_hmac, reason, risk_score, expires_at, created_at
                     FROM shield_quarantine
                     WHERE organization_id = ?1 AND expires_at > ?2
                       AND (?3 IS NULL OR project_id = ?3)
                     ORDER BY expires_at DESC, id DESC
                     LIMIT 250",
                )
                .map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map(params![org_id, now_sec, project_id], |r| {
                    let exp: i64 = r.get(6)?;
                    let crt: i64 = r.get(7)?;
                    Ok(QuarantineEntryDto {
                        id: r.get(0)?,
                        project_id: r.get(1)?,
                        subject_type: r.get(2)?,
                        subject_hmac: r.get(3)?,
                        reason: r.get(4)?,
                        risk_score: r.get(5)?,
                        expires_at: iso_from_ms(exp * 1000),
                        created_at: iso_from_ms(crt * 1000),
                    })
                })
                .map_err(map_sqlite_err)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(map_sqlite_err)?);
            }
            Ok(out)
        })
        .await
    }

    async fn delete_quarantine(&self, ctx: &TenantCtx, entry_id: i64) -> Result<bool, String> {
        let org_id = ctx.organization_id;
        self.write(move |conn| {
            let changed = conn
                .execute(
                    "DELETE FROM shield_quarantine WHERE id = ?1 AND organization_id = ?2",
                    params![entry_id, org_id],
                )
                .map_err(map_sqlite_err)?;
            Ok(changed > 0)
        })
        .await
    }

    async fn update_project_key(
        &self,
        ctx: &TenantCtx,
        project_slug: &str,
        key_id: i64,
        rate_limit_per_min: u32,
        is_active: bool,
    ) -> Result<Option<ProjectKeyDto>, String> {
        let org_id = ctx.organization_id;
        let pslug = project_slug.to_string();
        let rpm = rate_limit_per_min.clamp(10, 100_000) as i64;
        let act = if is_active { 1i64 } else { 0i64 };
        self.write(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE project_keys SET rate_limit_per_min = ?1, is_active = ?2
                     WHERE id = ?3 AND organization_id = ?4
                       AND project_id = (SELECT id FROM projects WHERE organization_id = ?4 AND slug = ?5)",
                    params![rpm, act, key_id, org_id, pslug],
                )
                .map_err(map_sqlite_err)?;
            if changed == 0 {
                return Ok(None);
            }
            conn.query_row(
                "SELECT id, project_id, label, public_key, rate_limit_per_min, is_active, created_at
                 FROM project_keys WHERE id = ?1 AND organization_id = ?2",
                params![key_id, org_id],
                |r| {
                    Ok(ProjectKeyDto {
                        id: r.get(0)?,
                        project_id: r.get(1)?,
                        label: r.get(2)?,
                        public_key: r.get(3)?,
                        rate_limit_per_min: r.get::<_, i64>(4)?.max(1) as u32,
                        is_active: r.get::<_, i64>(5)? != 0,
                        created_at: r.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(map_sqlite_err)
        })
        .await
    }

    async fn get_mfa_status(&self, user_id: i64) -> Result<MfaStatusDto, String> {
        self.read(move |conn| {
            let totp_enabled: bool = conn
                .query_row(
                    "SELECT is_enabled FROM user_mfa WHERE user_id = ?1",
                    params![user_id],
                    |r| Ok(r.get::<_, i64>(0)? != 0),
                )
                .optional()
                .map_err(map_sqlite_err)?
                .unwrap_or(false);
            let recovery_codes_remaining: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM user_mfa_recovery_codes WHERE user_id = ?1 AND used_at IS NULL",
                    params![user_id],
                    |r| r.get(0),
                )
                .map_err(map_sqlite_err)?;
            let mut stmt = conn
                .prepare(
                    "SELECT id, name, cose_alg, sign_count, last_used_at, created_at
                     FROM webauthn_credentials WHERE user_id = ?1 ORDER BY id DESC",
                )
                .map_err(map_sqlite_err)?;
            let passkeys: Vec<PasskeyDto> = stmt
                .query_map(params![user_id], |r| {
                    let lu: Option<i64> = r.get(4)?;
                    Ok(PasskeyDto {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        cose_alg: r.get(2)?,
                        sign_count: r.get::<_, i64>(3)?.max(0) as u32,
                        last_used_at: lu.map(|s| iso_from_ms(s * 1000)),
                        created_at: iso_from_ms(r.get(5)?),
                    })
                })
                .map_err(map_sqlite_err)?
                .filter_map(Result::ok)
                .collect();
            Ok(MfaStatusDto {
                totp_enabled,
                recovery_codes_remaining,
                passkeys,
            })
        })
        .await
    }

    async fn get_user_mfa_record(&self, user_id: i64) -> Result<Option<UserMfaRecord>, String> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT user_id, totp_secret_enc, is_enabled, last_used_step, failed_attempts, locked_until
                 FROM user_mfa WHERE user_id = ?1",
                params![user_id],
                |r| {
                    Ok(UserMfaRecord {
                        user_id: r.get(0)?,
                        totp_secret_enc: r.get(1)?,
                        is_enabled: r.get::<_, i64>(2)? != 0,
                        last_used_step: r.get(3)?,
                        failed_attempts: r.get(4)?,
                        locked_until: r.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(map_sqlite_err)
        })
        .await
    }

    async fn upsert_pending_totp(&self, user_id: i64, totp_secret_enc: &str, now_sec: i64) -> Result<(), String> {
        let enc = totp_secret_enc.to_string();
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO user_mfa (user_id, totp_secret_enc, is_enabled, failed_attempts, updated_at)
                 VALUES (?1, ?2, 0, 0, ?3)
                 ON CONFLICT(user_id) DO UPDATE SET totp_secret_enc = ?2, is_enabled = 0, last_used_step = NULL, failed_attempts = 0, locked_until = NULL, updated_at = ?3",
                params![user_id, enc, now_sec],
            )
            .map_err(map_sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn enable_totp_with_recovery_codes(&self, user_id: i64, code_hashes: &[String], now_sec: i64) -> Result<(), String> {
        let hashes = code_hashes.to_vec();
        self.write(move |conn| {
            let tx = conn.transaction().map_err(map_sqlite_err)?;
            tx.execute(
                "UPDATE user_mfa SET is_enabled = 1, enabled_at = ?1, failed_attempts = 0, locked_until = NULL, updated_at = ?1
                 WHERE user_id = ?2",
                params![now_sec, user_id],
            )
            .map_err(map_sqlite_err)?;
            tx.execute("DELETE FROM user_mfa_recovery_codes WHERE user_id = ?1", params![user_id])
                .map_err(map_sqlite_err)?;
            let now_m = now_ms();
            for h in hashes {
                tx.execute(
                    "INSERT INTO user_mfa_recovery_codes (user_id, code_hash, created_at) VALUES (?1, ?2, ?3)",
                    params![user_id, h, now_m],
                )
                .map_err(map_sqlite_err)?;
            }
            tx.commit().map_err(map_sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn disable_mfa(&self, user_id: i64, now_sec: i64) -> Result<(), String> {
        self.write(move |conn| {
            let tx = conn.transaction().map_err(map_sqlite_err)?;
            tx.execute(
                "UPDATE user_mfa SET is_enabled = 0, totp_secret_enc = '', last_used_step = NULL, failed_attempts = 0, locked_until = NULL, updated_at = ?1 WHERE user_id = ?2",
                params![now_sec, user_id],
            )
            .map_err(map_sqlite_err)?;
            tx.execute("DELETE FROM user_mfa_recovery_codes WHERE user_id = ?1", params![user_id])
                .map_err(map_sqlite_err)?;
            tx.commit().map_err(map_sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn replace_recovery_codes(&self, user_id: i64, code_hashes: &[String], _now_sec: i64) -> Result<(), String> {
        let hashes = code_hashes.to_vec();
        self.write(move |conn| {
            let tx = conn.transaction().map_err(map_sqlite_err)?;
            tx.execute("DELETE FROM user_mfa_recovery_codes WHERE user_id = ?1", params![user_id])
                .map_err(map_sqlite_err)?;
            let now_m = now_ms();
            for h in hashes {
                tx.execute(
                    "INSERT INTO user_mfa_recovery_codes (user_id, code_hash, created_at) VALUES (?1, ?2, ?3)",
                    params![user_id, h, now_m],
                )
                .map_err(map_sqlite_err)?;
            }
            tx.commit().map_err(map_sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn record_mfa_attempt(&self, user_id: i64, success_step: Option<i64>, now_sec: i64) -> Result<Option<i64>, String> {
        self.write(move |conn| {
            let tx = conn.transaction().map_err(map_sqlite_err)?;
            if let Some(step) = success_step {
                tx.execute(
                    "UPDATE user_mfa SET last_used_step = ?1, failed_attempts = 0, locked_until = NULL, updated_at = ?2 WHERE user_id = ?3",
                    params![step, now_sec, user_id],
                )
                .map_err(map_sqlite_err)?;
                tx.commit().map_err(map_sqlite_err)?;
                return Ok(None);
            }
            let prev: i64 = tx
                .query_row(
                    "SELECT failed_attempts FROM user_mfa WHERE user_id = ?1",
                    params![user_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_sqlite_err)?
                .unwrap_or(0);
            let next = prev + 1;
            let lock_secs = compute_lockout_seconds(next);
            let locked_until = lock_secs.map(|s| now_sec + s);
            tx.execute(
                "INSERT INTO user_mfa (user_id, totp_secret_enc, is_enabled, failed_attempts, locked_until, updated_at)
                 VALUES (?1, '', 0, ?2, ?3, ?4)
                 ON CONFLICT(user_id) DO UPDATE SET failed_attempts = ?2, locked_until = ?3, updated_at = ?4",
                params![user_id, next, locked_until, now_sec],
            )
            .map_err(map_sqlite_err)?;
            tx.commit().map_err(map_sqlite_err)?;
            Ok(lock_secs)
        })
        .await
    }

    async fn list_unused_recovery_codes(&self, user_id: i64) -> Result<Vec<RecoveryCodeRecord>, String> {
        self.read(move |conn| {
            let mut stmt = conn
                .prepare("SELECT id, code_hash FROM user_mfa_recovery_codes WHERE user_id = ?1 AND used_at IS NULL")
                .map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map(params![user_id], |r| {
                    Ok(RecoveryCodeRecord { id: r.get(0)?, code_hash: r.get(1)? })
                })
                .map_err(map_sqlite_err)?;
            Ok(rows.filter_map(Result::ok).collect())
        })
        .await
    }

    async fn mark_recovery_code_used(&self, user_id: i64, code_id: i64, now_sec: i64) -> Result<bool, String> {
        self.write(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE user_mfa_recovery_codes SET used_at = ?1 WHERE id = ?2 AND user_id = ?3 AND used_at IS NULL",
                    params![now_sec, code_id, user_id],
                )
                .map_err(map_sqlite_err)?;
            Ok(changed > 0)
        })
        .await
    }

    async fn create_mfa_challenge(&self, token_sha256: &str, user_id: i64, target_org_id: i64, ip_hmac: &str, expires_at: i64) -> Result<(), String> {
        let sha = token_sha256.to_string();
        let iph = ip_hmac.to_string();
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO mfa_challenges (token_sha256, user_id, target_org_id, ip_hmac, expires_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![sha, user_id, target_org_id, iph, expires_at, now_ms()],
            )
            .map_err(map_sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn consume_mfa_challenge(&self, token_sha256: &str, now_sec: i64) -> Result<Option<MfaChallengeRecord>, String> {
        let sha = token_sha256.to_string();
        self.write(move |conn| {
            let tx = conn.transaction().map_err(map_sqlite_err)?;
            let row = tx
                .query_row(
                    "SELECT user_id, target_org_id, ip_hmac, expires_at FROM mfa_challenges WHERE token_sha256 = ?1",
                    params![sha],
                    |r| {
                        Ok(MfaChallengeRecord {
                            user_id: r.get(0)?,
                            target_org_id: r.get(1)?,
                            ip_hmac: r.get(2)?,
                            expires_at: r.get(3)?,
                        })
                    },
                )
                .optional()
                .map_err(map_sqlite_err)?;
            if let Some(ref rec) = row {
                tx.execute("DELETE FROM mfa_challenges WHERE token_sha256 = ?1", params![sha])
                    .map_err(map_sqlite_err)?;
                tx.commit().map_err(map_sqlite_err)?;
                if rec.expires_at > now_sec {
                    return Ok(Some(rec.clone()));
                }
            }
            Ok(None)
        })
        .await
    }

    async fn get_mfa_challenge_user(&self, token_sha256: &str, now_sec: i64) -> Result<Option<MfaChallengeRecord>, String> {
        let sha = token_sha256.to_string();
        self.read(move |conn| {
            conn.query_row(
                "SELECT user_id, target_org_id, ip_hmac, expires_at FROM mfa_challenges WHERE token_sha256 = ?1 AND expires_at > ?2",
                params![sha, now_sec],
                |r| {
                    Ok(MfaChallengeRecord {
                        user_id: r.get(0)?,
                        target_org_id: r.get(1)?,
                        ip_hmac: r.get(2)?,
                        expires_at: r.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(map_sqlite_err)
        })
        .await
    }

    async fn save_webauthn_challenge(&self, challenge_b64: &str, user_id: Option<i64>, flow_kind: &str, expires_at: i64) -> Result<(), String> {
        let cb = challenge_b64.to_string();
        let fk = flow_kind.to_string();
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO webauthn_challenges (challenge_b64, user_id, flow_kind, expires_at, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![cb, user_id, fk, expires_at, now_ms()],
            )
            .map_err(map_sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn consume_webauthn_challenge(&self, challenge_b64: &str, flow_kind: &str, now_sec: i64) -> Result<Option<WebAuthnChallengeRecord>, String> {
        let cb = challenge_b64.to_string();
        let fk = flow_kind.to_string();
        self.write(move |conn| {
            let tx = conn.transaction().map_err(map_sqlite_err)?;
            let row = tx
                .query_row(
                    "SELECT challenge_b64, user_id, flow_kind, expires_at FROM webauthn_challenges WHERE challenge_b64 = ?1 AND flow_kind = ?2",
                    params![cb, fk],
                    |r| {
                        Ok(WebAuthnChallengeRecord {
                            challenge_b64: r.get(0)?,
                            user_id: r.get(1)?,
                            flow_kind: r.get(2)?,
                            expires_at: r.get(3)?,
                        })
                    },
                )
                .optional()
                .map_err(map_sqlite_err)?;
            if let Some(ref rec) = row {
                tx.execute("DELETE FROM webauthn_challenges WHERE challenge_b64 = ?1", params![cb])
                    .map_err(map_sqlite_err)?;
                tx.commit().map_err(map_sqlite_err)?;
                if rec.expires_at > now_sec {
                    return Ok(Some(rec.clone()));
                }
            }
            Ok(None)
        })
        .await
    }

    async fn create_webauthn_credential(&self, user_id: i64, name: &str, credential_id_b64: &str, cose_alg: i32, public_key_b64: &str, sign_count: u32) -> Result<PasskeyDto, String> {
        let nm = name.to_string();
        let cid = credential_id_b64.to_string();
        let pk = public_key_b64.to_string();
        let now = now_ms();
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO webauthn_credentials (user_id, name, credential_id_b64, cose_alg, public_key_b64, sign_count, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![user_id, nm, cid, cose_alg, pk, sign_count as i64, now],
            )
            .map_err(map_sqlite_err)?;
            let id = conn.last_insert_rowid();
            Ok(PasskeyDto {
                id,
                name: nm,
                cose_alg,
                sign_count,
                last_used_at: None,
                created_at: iso_from_ms(now),
            })
        })
        .await
    }

    async fn list_webauthn_credentials(&self, user_id: i64) -> Result<Vec<WebAuthnCredRecord>, String> {
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, user_id, name, credential_id_b64, cose_alg, public_key_b64, sign_count, last_used_at, created_at
                     FROM webauthn_credentials WHERE user_id = ?1 ORDER BY id DESC",
                )
                .map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map(params![user_id], |r| {
                    Ok(WebAuthnCredRecord {
                        id: r.get(0)?,
                        user_id: r.get(1)?,
                        name: r.get(2)?,
                        credential_id_b64: r.get(3)?,
                        cose_alg: r.get(4)?,
                        public_key_b64: r.get(5)?,
                        sign_count: r.get::<_, i64>(6)?.max(0) as u32,
                        last_used_at: r.get(7)?,
                        created_at: r.get(8)?,
                    })
                })
                .map_err(map_sqlite_err)?;
            Ok(rows.filter_map(Result::ok).collect())
        })
        .await
    }

    async fn find_webauthn_credential(&self, credential_id_b64: &str) -> Result<Option<WebAuthnCredRecord>, String> {
        let cid = credential_id_b64.to_string();
        self.read(move |conn| {
            conn.query_row(
                "SELECT id, user_id, name, credential_id_b64, cose_alg, public_key_b64, sign_count, last_used_at, created_at
                 FROM webauthn_credentials WHERE credential_id_b64 = ?1",
                params![cid],
                |r| {
                    Ok(WebAuthnCredRecord {
                        id: r.get(0)?,
                        user_id: r.get(1)?,
                        name: r.get(2)?,
                        credential_id_b64: r.get(3)?,
                        cose_alg: r.get(4)?,
                        public_key_b64: r.get(5)?,
                        sign_count: r.get::<_, i64>(6)?.max(0) as u32,
                        last_used_at: r.get(7)?,
                        created_at: r.get(8)?,
                    })
                },
            )
            .optional()
            .map_err(map_sqlite_err)
        })
        .await
    }

    async fn update_webauthn_sign_count(&self, cred_id: i64, sign_count: u32, now_sec: i64) -> Result<(), String> {
        self.write(move |conn| {
            conn.execute(
                "UPDATE webauthn_credentials SET sign_count = ?1, last_used_at = ?2 WHERE id = ?3",
                params![sign_count as i64, now_sec, cred_id],
            )
            .map_err(map_sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn delete_webauthn_credential(&self, user_id: i64, cred_id: i64) -> Result<bool, String> {
        self.write(move |conn| {
            let changed = conn
                .execute(
                    "DELETE FROM webauthn_credentials WHERE id = ?1 AND user_id = ?2",
                    params![cred_id, user_id],
                )
                .map_err(map_sqlite_err)?;
            Ok(changed > 0)
        })
        .await
    }

    async fn list_user_sessions(&self, user_id: i64, org_id: i64, current_token_sha256: &str, now_sec: i64) -> Result<Vec<ActiveSessionDto>, String> {
        let cur = current_token_sha256.to_string();
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT rowid, token_sha256, user_agent, ip_hmac, last_seen_at, created_at
                     FROM sessions
                     WHERE user_id = ?1 AND organization_id = ?2 AND expires_at > ?3
                     ORDER BY rowid DESC",
                )
                .map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map(params![user_id, org_id, now_sec], |r| {
                    let sha: String = r.get(1)?;
                    let iph: String = r.get(3)?;
                    let lseen: i64 = r.get(4)?;
                    let crt: i64 = r.get(5)?;
                    Ok(ActiveSessionDto {
                        id: r.get(0)?,
                        user_agent: r.get(2)?,
                        ip_hmac_short: iph.chars().take(12).collect(),
                        last_seen_at: iso_from_ms(if lseen > 0 { lseen * 1000 } else { crt }),
                        created_at: iso_from_ms(crt),
                        is_current: sha == cur,
                    })
                })
                .map_err(map_sqlite_err)?;
            Ok(rows.filter_map(Result::ok).collect())
        })
        .await
    }

    async fn revoke_session_by_id(&self, user_id: i64, org_id: i64, session_id: i64) -> Result<bool, String> {
        self.write(move |conn| {
            let changed = conn
                .execute(
                    "DELETE FROM sessions WHERE rowid = ?1 AND user_id = ?2 AND organization_id = ?3",
                    params![session_id, user_id, org_id],
                )
                .map_err(map_sqlite_err)?;
            Ok(changed > 0)
        })
        .await
    }

    async fn revoke_other_sessions(&self, user_id: i64, org_id: i64, keep_token_sha256: &str) -> Result<usize, String> {
        let keep = keep_token_sha256.to_string();
        self.write(move |conn| {
            conn.execute(
                "DELETE FROM sessions WHERE user_id = ?1 AND organization_id = ?2 AND token_sha256 != ?3",
                params![user_id, org_id, keep],
            )
            .map_err(map_sqlite_err)
        })
        .await
    }

    async fn mark_session_reauth(&self, token_sha256: &str, org_id: i64, now_sec: i64) -> Result<(), String> {
        let sha = token_sha256.to_string();
        self.write(move |conn| {
            conn.execute(
                "UPDATE sessions SET reauth_at = ?1, last_seen_at = ?1 WHERE token_sha256 = ?2 AND organization_id = ?3",
                params![now_sec, sha, org_id],
            )
            .map_err(map_sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn find_user_password_hash(&self, user_id: i64) -> Result<Option<(String, String, String)>, String> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT email, name, password_hash FROM users WHERE id = ?1 AND is_active = 1",
                params![user_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(map_sqlite_err)
        })
        .await
    }

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
    ) -> Result<(), String> {
        let npw = new_password_hash.to_string();
        let old_s = old_session_sha.to_string();
        let new_s = new_session_sha.to_string();
        let csrf = new_csrf.to_string();
        let ua = user_agent.chars().take(160).collect::<String>();
        let iph = ip_hmac.to_string();
        self.write(move |conn| {
            let tx = conn.transaction().map_err(map_sqlite_err)?;
            tx.execute(
                "UPDATE users SET password_hash = ?1 WHERE id = ?2",
                params![npw, user_id],
            )
            .map_err(map_sqlite_err)?;
            tx.execute("DELETE FROM sessions WHERE user_id = ?1", params![user_id])
                .map_err(map_sqlite_err)?;
            let _ = old_s;
            tx.execute(
                "INSERT INTO sessions (token_sha256, user_id, organization_id, csrf_token, user_agent, ip_hmac, last_seen_at, reauth_at, expires_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8, ?9)",
                params![new_s, user_id, org_id, csrf, ua, iph, now_sec, expires_at, now_ms()],
            )
            .map_err(map_sqlite_err)?;
            tx.commit().map_err(map_sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn create_invitation(&self, ctx: &TenantCtx, email: &str, role: UserRole, token_sha256: &str, expires_at: i64) -> Result<InvitationDto, String> {
        let org_id = ctx.organization_id;
        let uid = ctx.user_id;
        let email_norm = email.trim().to_ascii_lowercase();
        let role_s = role.as_str().to_string();
        let sha = token_sha256.to_string();
        let now = now_ms();
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO org_invitations (organization_id, email, role, token_sha256, invited_by, expires_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![org_id, email_norm, role_s, sha, uid, expires_at, now],
            )
            .map_err(map_sqlite_err)?;
            let id = conn.last_insert_rowid();
            let inv_email: String = uid
                .and_then(|u| conn.query_row("SELECT email FROM users WHERE id = ?1", params![u], |r| r.get(0)).ok())
                .unwrap_or_default();
            Ok(InvitationDto {
                id,
                email: email_norm,
                role: role_s,
                invited_by_email: inv_email,
                expires_at: iso_from_ms(expires_at * 1000),
                accepted_at: None,
                created_at: iso_from_ms(now),
            })
        })
        .await
    }

    async fn list_invitations(&self, ctx: &TenantCtx) -> Result<Vec<InvitationDto>, String> {
        let org_id = ctx.organization_id;
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT i.id, i.email, i.role, COALESCE(u.email, ''), i.expires_at, i.accepted_at, i.created_at
                     FROM org_invitations i
                     LEFT JOIN users u ON u.id = i.invited_by
                     WHERE i.organization_id = ?1
                     ORDER BY i.id DESC LIMIT 100",
                )
                .map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map(params![org_id], |r| {
                    let acc: Option<i64> = r.get(5)?;
                    Ok(InvitationDto {
                        id: r.get(0)?,
                        email: r.get(1)?,
                        role: r.get(2)?,
                        invited_by_email: r.get(3)?,
                        expires_at: iso_from_ms(r.get::<_, i64>(4)? * 1000),
                        accepted_at: acc.map(|s| iso_from_ms(s * 1000)),
                        created_at: iso_from_ms(r.get(6)?),
                    })
                })
                .map_err(map_sqlite_err)?;
            Ok(rows.filter_map(Result::ok).collect())
        })
        .await
    }

    async fn revoke_invitation(&self, ctx: &TenantCtx, inv_id: i64) -> Result<bool, String> {
        let org_id = ctx.organization_id;
        self.write(move |conn| {
            let changed = conn
                .execute(
                    "DELETE FROM org_invitations WHERE id = ?1 AND organization_id = ?2",
                    params![inv_id, org_id],
                )
                .map_err(map_sqlite_err)?;
            Ok(changed > 0)
        })
        .await
    }

    async fn lookup_invitation(&self, token_sha256: &str) -> Result<Option<InvitationLookupInfo>, String> {
        let sha = token_sha256.to_string();
        self.read(move |conn| {
            conn.query_row(
                "SELECT i.organization_id, o.slug, o.name, i.email, i.role, i.expires_at, i.accepted_at
                 FROM org_invitations i
                 JOIN organizations o ON o.id = i.organization_id
                 WHERE i.token_sha256 = ?1",
                params![sha],
                |r| {
                    Ok(InvitationLookupInfo {
                        organization_id: r.get(0)?,
                        organization_slug: r.get(1)?,
                        organization_name: r.get(2)?,
                        email: r.get(3)?,
                        role: r.get(4)?,
                        expires_at: r.get(5)?,
                        accepted_at: r.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(map_sqlite_err)
        })
        .await
    }

    async fn accept_invitation(
        &self,
        token_sha256: &str,
        name: &str,
        password_hash: &str,
        now_sec: i64,
    ) -> Result<Result<(i64, i64, String, String, UserRole), String>, String> {
        let sha = token_sha256.to_string();
        let nm = name.to_string();
        let pwh = password_hash.to_string();
        self.write(move |conn| {
            let tx = conn.transaction().map_err(map_sqlite_err)?;
            let inv: Option<(i64, i64, String, String, String, i64, Option<i64>)> = tx
                .query_row(
                    "SELECT i.id, i.organization_id, o.slug, i.email, i.role, i.expires_at, i.accepted_at
                     FROM org_invitations i
                     JOIN organizations o ON o.id = i.organization_id
                     WHERE i.token_sha256 = ?1",
                    params![sha],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
                )
                .optional()
                .map_err(map_sqlite_err)?;
            let Some((inv_id, org_id, org_slug, email, role_s, exp, acc)) = inv else {
                return Ok(Err("Invitation not found".into()));
            };
            if acc.is_some() {
                return Ok(Err("Invitation has already been used".into()));
            }
            if exp <= now_sec {
                return Ok(Err("Invitation has expired".into()));
            }
            let updated = tx
                .execute(
                    "UPDATE org_invitations SET accepted_at = ?1 WHERE id = ?2 AND accepted_at IS NULL",
                    params![now_sec, inv_id],
                )
                .map_err(map_sqlite_err)?;
            if updated == 0 {
                return Ok(Err("Invitation already claimed".into()));
            }
            let existing_uid: Option<i64> = tx
                .query_row("SELECT id FROM users WHERE email = ?1", params![email], |r| r.get(0))
                .optional()
                .map_err(map_sqlite_err)?;
            let uid = match existing_uid {
                Some(id) => id,
                None => {
                    tx.execute(
                        "INSERT INTO users (email, name, password_hash, is_active, created_at) VALUES (?1, ?2, ?3, 1, ?4)",
                        params![email, nm, pwh, now_ms()],
                    )
                    .map_err(map_sqlite_err)?;
                    tx.last_insert_rowid()
                }
            };
            let role = UserRole::from_db(&role_s).unwrap_or(UserRole::Member);
            tx.execute(
                "INSERT INTO organization_members (organization_id, user_id, role) VALUES (?1, ?2, ?3)
                 ON CONFLICT(organization_id, user_id) DO UPDATE SET role = ?3",
                params![org_id, uid, role.as_str()],
            )
            .map_err(map_sqlite_err)?;
            tx.commit().map_err(map_sqlite_err)?;
            Ok(Ok((uid, org_id, org_slug, email, role)))
        })
        .await
    }

    async fn append_audit_log(&self, entry: &NewAuditLog) -> Result<(), String> {
        let e = entry.clone();
        self.write(move |conn| {
            let tx = conn.transaction().map_err(map_sqlite_err)?;
            let prev_hash: String = tx
                .query_row(
                    "SELECT entry_hash FROM audit_logs WHERE organization_id = ?1 ORDER BY id DESC LIMIT 1",
                    params![e.organization_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_sqlite_err)?
                .filter(|s: &String| !s.is_empty())
                .unwrap_or_else(|| "GENESIS".to_string());
            let created_at = now_ms();
            let meta_str = serde_json::to_string(&e.metadata).unwrap_or_else(|_| "{}".into());
            let entry_hash = compute_audit_entry_hash(
                &prev_hash,
                e.organization_id,
                e.actor_user_id,
                &e.action,
                &e.target_type,
                &e.target_id,
                &e.metadata,
                created_at,
            );
            tx.execute(
                "INSERT INTO audit_logs (organization_id, actor_user_id, actor_email, action, target_type, target_id, ip_hmac, metadata_json, prev_hash, entry_hash, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    e.organization_id, e.actor_user_id, e.actor_email, e.action, e.target_type,
                    e.target_id, e.ip_hmac, meta_str, prev_hash, entry_hash, created_at
                ],
            )
            .map_err(map_sqlite_err)?;
            tx.commit().map_err(map_sqlite_err)?;
            Ok(())
        })
        .await
    }

    async fn list_audit_logs(&self, ctx: &TenantCtx, action_filter: Option<&str>, limit: i64, offset: i64) -> Result<Vec<AuditLogDto>, String> {
        let org_id = ctx.organization_id;
        let act = action_filter.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let lim = limit.clamp(1, 200);
        let off = offset.max(0);
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, actor_user_id, actor_email, action, target_type, target_id, ip_hmac, metadata_json, entry_hash, created_at
                     FROM audit_logs
                     WHERE organization_id = ?1 AND (?2 IS NULL OR action = ?2)
                     ORDER BY id DESC LIMIT ?3 OFFSET ?4",
                )
                .map_err(map_sqlite_err)?;
            let rows = stmt
                .query_map(params![org_id, act, lim, off], |r| {
                    let meta_s: String = r.get(7)?;
                    Ok(AuditLogDto {
                        id: r.get(0)?,
                        actor_user_id: r.get(1)?,
                        actor_email: r.get(2)?,
                        action: r.get(3)?,
                        target_type: r.get(4)?,
                        target_id: r.get(5)?,
                        ip_hmac: r.get(6)?,
                        metadata: serde_json::from_str(&meta_s).unwrap_or_else(|_| json!({})),
                        entry_hash: r.get(8)?,
                        created_at: iso_from_ms(r.get(9)?),
                    })
                })
                .map_err(map_sqlite_err)?;
            Ok(rows.filter_map(Result::ok).collect())
        })
        .await
    }

    async fn verify_audit_chain(&self, ctx: &TenantCtx) -> Result<AuditVerifyDto, String> {
        let org_id = ctx.organization_id;
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, actor_user_id, action, target_type, target_id, metadata_json, prev_hash, entry_hash, created_at
                     FROM audit_logs WHERE organization_id = ?1 ORDER BY id ASC",
                )
                .map_err(map_sqlite_err)?;
            let mut rows = stmt.query(params![org_id]).map_err(map_sqlite_err)?;
            let mut expected_prev = "GENESIS".to_string();
            let mut count = 0usize;
            while let Some(r) = rows.next().map_err(map_sqlite_err)? {
                let id: i64 = r.get(0).map_err(map_sqlite_err)?;
                let actor_uid: Option<i64> = r.get(1).map_err(map_sqlite_err)?;
                let action: String = r.get(2).map_err(map_sqlite_err)?;
                let target_type: String = r.get(3).map_err(map_sqlite_err)?;
                let target_id: String = r.get(4).map_err(map_sqlite_err)?;
                let metadata_json: String = r.get(5).map_err(map_sqlite_err)?;
                let prev_hash: String = r.get(6).map_err(map_sqlite_err)?;
                let entry_hash: String = r.get(7).map_err(map_sqlite_err)?;
                let created_at: i64 = r.get(8).map_err(map_sqlite_err)?;
                count += 1;
                if prev_hash != expected_prev {
                    return Ok(AuditVerifyDto {
                        valid: false,
                        checked_entries: count,
                        broken_at_id: Some(id),
                        detail: format!("Previous hash link mismatch at audit_logs.id={id}"),
                    });
                }
                let meta_val: Value = serde_json::from_str(&metadata_json).unwrap_or_else(|_| json!({}));
                let recomputed = compute_audit_entry_hash(
                    &prev_hash,
                    org_id,
                    actor_uid,
                    &action,
                    &target_type,
                    &target_id,
                    &meta_val,
                    created_at,
                );
                if recomputed != entry_hash {
                    return Ok(AuditVerifyDto {
                        valid: false,
                        checked_entries: count,
                        broken_at_id: Some(id),
                        detail: format!("SHA-256 tamper detected at audit_logs.id={id}"),
                    });
                }
                expected_prev = entry_hash;
            }
            Ok(AuditVerifyDto {
                valid: true,
                checked_entries: count,
                broken_at_id: None,
                detail: if count == 0 {
                    "No audit entries yet".into()
                } else {
                    format!("Verified {count} immutable hash-chained entries")
                },
            })
        })
        .await
    }

    async fn get_org_security_settings(&self, ctx: &TenantCtx) -> Result<OrgSecuritySettings, String> {
        let org_id = ctx.organization_id;
        self.read(move |conn| {
            let s: String = conn
                .query_row(
                    "SELECT settings_json FROM organizations WHERE id = ?1",
                    params![org_id],
                    |r| r.get(0),
                )
                .map_err(map_sqlite_err)?;
            Ok(serde_json::from_str(&s).unwrap_or_default())
        })
        .await
    }

    async fn update_org_security_settings(&self, ctx: &TenantCtx, settings: &OrgSecuritySettings) -> Result<OrgSecuritySettings, String> {
        let org_id = ctx.organization_id;
        let mut clean = settings.clone();
        clean.event_throttle_rate = clean.event_throttle_rate.min(100);
        let sjson = serde_json::to_string(&clean).map_err(map_sqlite_err)?;
        self.write(move |conn| {
            conn.execute(
                "UPDATE organizations SET settings_json = ?1 WHERE id = ?2",
                params![sjson, org_id],
            )
            .map_err(map_sqlite_err)?;
            Ok(clean)
        })
        .await
    }

    async fn count_owners_without_mfa(&self, ctx: &TenantCtx) -> Result<i64, String> {
        let org_id = ctx.organization_id;
        self.read(move |conn| {
            conn.query_row(
                "SELECT COUNT(*)
                 FROM organization_members m
                 JOIN users u ON u.id = m.user_id
                 WHERE m.organization_id = ?1
                   AND m.role = 'owner'
                   AND u.is_active = 1
                   AND NOT EXISTS (SELECT 1 FROM user_mfa f WHERE f.user_id = u.id AND f.is_enabled = 1)
                   AND NOT EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = u.id)",
                params![org_id],
                |r| r.get(0),
            )
            .map_err(map_sqlite_err)
        })
        .await
    }
}
