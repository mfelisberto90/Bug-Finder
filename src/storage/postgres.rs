use crate::alerts::dispatcher::AlertDispatchJob;
use crate::domain::fingerprint::{extract_issue_metadata, should_reopen_on_regression};
use crate::domain::models::*;
use crate::security::auth::{compute_audit_entry_hash, compute_lockout_seconds};
use crate::security::crypto::{open_secret, seal_secret};
use crate::storage::*;
use async_trait::async_trait;
use serde_json::{json, Value};
use sqlx::postgres::{PgPoolOptions, PgRow};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const PG_SCHEMA: &str = include_str!("../../migrations/postgres/001_init_rls.sql");

fn webhook_aad(org_id: i64) -> Vec<u8> {
    format!("alert_rules:webhook_secret:{org_id}").into_bytes()
}

fn open_webhook_secret(app_key: &[u8; 32], org_id: i64, stored: &str) -> String {
    open_secret(app_key, &webhook_aad(org_id), stored, true).unwrap_or_default()
}

struct PgStormWindow {
    window_start_ms: i64,
    count: u32,
}

pub struct PostgresStorage {
    pool: PgPool,
    app_key: [u8; 32],
    storm_counters: Mutex<HashMap<(i64, String), PgStormWindow>>,
}

impl PostgresStorage {
    pub async fn connect(database_url: &str, run_migrations: bool) -> Result<Arc<Self>, String> {
        Self::connect_with_key(database_url, run_migrations, [0u8; 32]).await
    }

    pub async fn connect_with_key(
        database_url: &str,
        run_migrations: bool,
        app_key: [u8; 32],
    ) -> Result<Arc<Self>, String> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .min_connections(1)
            .connect(database_url)
            .await
            .map_err(|e| format!("Postgres connect error: {e}"))?;

        if run_migrations {
            for stmt in split_pg_statements(PG_SCHEMA) {
                let trimmed = stmt.trim();
                if trimmed.is_empty() {
                    continue;
                }
                sqlx::query(trimmed)
                    .execute(&pool)
                    .await
                    .map_err(|e| format!("PG migration stmt failed ({trimmed}): {e}"))?;
            }
        }

        Ok(Arc::new(Self {
            pool,
            app_key,
            storm_counters: Mutex::new(HashMap::new()),
        }))
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    async fn begin_tenant(&self, organization_id: i64) -> Result<Transaction<'_, Postgres>, String> {
        let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(organization_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
        Ok(tx)
    }

    fn should_sample_storm(
        &self,
        project_id: i64,
        fingerprint: &str,
        filters: &ProjectFilters,
        now_ms: i64,
    ) -> bool {
        if filters.storm_sample_threshold == 0 {
            return true;
        }
        let mut guard = self.storm_counters.lock().unwrap_or_else(|e| e.into_inner());
        if guard.len() > 8192 {
            guard.clear();
        }
        let key = (project_id, fingerprint.to_string());
        let entry = guard.entry(key).or_insert(PgStormWindow {
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

fn split_pg_statements(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_dollar = false;
    let chars: Vec<char> = sql.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if i + 1 < chars.len() && chars[i] == '$' && chars[i + 1] == '$' {
            in_dollar = !in_dollar;
            cur.push('$');
            cur.push('$');
            i += 2;
            continue;
        }
        if !in_dollar && chars[i] == '-' && i + 1 < chars.len() && chars[i + 1] == '-' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if !in_dollar && chars[i] == ';' {
            out.push(std::mem::take(&mut cur));
            i += 1;
            continue;
        }
        cur.push(chars[i]);
        i += 1;
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

fn map_pg_err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn row_to_issue(r: &PgRow, org_slug: &str) -> IssueSummaryDto {
    let id: i64 = r.get("id");
    IssueSummaryDto {
        id,
        short_id: r.get("short_id"),
        project_id: r.get("project_id"),
        project_slug: r.get("project_slug"),
        title: r.get("title"),
        culprit: r.get("culprit"),
        level: r.get("level"),
        issue_type: r.get("issue_type"),
        status: r.get("status"),
        is_regression: r.get("is_regression"),
        resolved_in_release: r.get("resolved_in_release"),
        first_seen: iso_from_ms(r.get("first_seen")),
        last_seen: iso_from_ms(r.get("last_seen")),
        count: r.get("event_count"),
        user_count: r.get("user_count"),
        first_release: r.get("first_release"),
        last_release: r.get("last_release"),
        environment: r.get("environment"),
        permalink: format!("/{org_slug}/issues/{id}"),
        metadata: r.get("metadata_json"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn pg_build_alert_jobs_for_event(
    tx: &mut Transaction<'_, Postgres>,
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
    let rows = sqlx::query(
        "SELECT id, name, trigger_type, threshold_count, window_sec, cooldown_sec,
                channel_type, target_url, webhook_secret, email_to, last_triggered_at
         FROM alert_rules
         WHERE organization_id = $1 AND project_id = $2 AND is_active = TRUE",
    )
    .bind(organization_id)
    .bind(project_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(map_pg_err)?;

    let mut jobs = Vec::new();
    let mut triggered_ids = Vec::new();

    for r in rows {
        let id: i64 = r.get("id");
        let name: String = r.get("name");
        let trigger_type: String = r.get("trigger_type");
        let threshold_count: i64 = r.get("threshold_count");
        let window_sec: i64 = r.get("window_sec");
        let cooldown_sec: i64 = r.get("cooldown_sec");
        let channel_type: String = r.get("channel_type");
        let target_url: String = r.get("target_url");
        let stored_secret: String = r.get("webhook_secret");
        let webhook_secret = open_webhook_secret(app_key, organization_id, &stored_secret);
        let email_to: String = r.get("email_to");
        let last_triggered_at: Option<i64> = r.get("last_triggered_at");

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
                let recent: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM issue_events WHERE project_id = $1 AND timestamp_ms >= $2",
                )
                .bind(project_id)
                .bind(since_ms)
                .fetch_one(&mut **tx)
                .await
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

    for id in triggered_ids {
        sqlx::query("UPDATE alert_rules SET last_triggered_at = $1 WHERE id = $2")
            .bind(now_sec)
            .bind(id)
            .execute(&mut **tx)
            .await
            .map_err(map_pg_err)?;
    }

    Ok(jobs)
}

#[allow(clippy::too_many_arguments)]
async fn pg_insert_event_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    auth: &ProjectAuthInfo,
    meta: &ComputedIssueMetadata,
    payload_json: &[u8],
    received_ms: i64,
    store_full_blob: bool,
) -> Result<(i64, String, bool, bool), String> {
    if auth.first_event_at.is_none() {
        sqlx::query("UPDATE projects SET first_event_at = $1 WHERE id = $2 AND first_event_at IS NULL")
            .bind(received_ms)
            .bind(auth.project_id)
            .execute(&mut **tx)
            .await
            .map_err(map_pg_err)?;
    }

    if let Some(rel) = &meta.release {
        sqlx::query(
            "INSERT INTO releases (organization_id, project_id, version, first_seen, last_seen)
             VALUES ($1, $2, $3, $4, $4)
             ON CONFLICT (project_id, version) DO UPDATE SET last_seen = GREATEST(releases.last_seen, EXCLUDED.last_seen)",
        )
        .bind(auth.organization_id)
        .bind(auth.project_id)
        .bind(rel)
        .bind(received_ms)
        .execute(&mut **tx)
        .await
        .map_err(map_pg_err)?;
    }

    let dup: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM issue_events WHERE project_id = $1 AND event_id = $2",
    )
    .bind(auth.project_id)
    .bind(&meta.event_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_pg_err)?;
    if dup.is_some() {
        return Ok((0, String::new(), false, false));
    }

    let existing: Option<(i64, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, short_id, status, resolved_in_release FROM issues WHERE project_id = $1 AND fingerprint = $2",
    )
    .bind(auth.project_id)
    .bind(&meta.fingerprint)
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_pg_err)?;

    let (issue_id, short_id, is_new, is_regression) = match existing {
        Some((id, short_id, status_str, resolved_in_release)) => {
            let status = IssueStatus::from_str_opt(&status_str).unwrap_or(IssueStatus::Unresolved);
            let reopen = should_reopen_on_regression(
                status,
                resolved_in_release.as_deref(),
                meta.release.as_deref(),
            );
            let new_status = if reopen { "unresolved" } else { status.as_str() };
            sqlx::query(
                "UPDATE issues
                 SET event_count = event_count + 1,
                     last_seen = GREATEST(last_seen, $1),
                     last_release = COALESCE($2, last_release),
                     status = $3,
                     is_regression = CASE WHEN $4 THEN TRUE ELSE is_regression END
                 WHERE id = $5",
            )
            .bind(received_ms)
            .bind(&meta.release)
            .bind(new_status)
            .bind(reopen)
            .bind(id)
            .execute(&mut **tx)
            .await
            .map_err(map_pg_err)?;
            (id, short_id, false, reopen)
        }
        None => {
            let short_num: i64 = sqlx::query_scalar(
                "UPDATE projects SET next_short_num = next_short_num + 1 WHERE id = $1 RETURNING next_short_num - 1",
            )
            .bind(auth.project_id)
            .fetch_one(&mut **tx)
            .await
            .map_err(map_pg_err)?;
            let short_id = format_short_id(&auth.project_slug, short_num.max(1) as u64);
            let metadata_json = json!({ "title": meta.title, "value": meta.title });

            let id: i64 = sqlx::query_scalar(
                "INSERT INTO issues (
                    organization_id, project_id, short_id, short_num, fingerprint,
                    title, culprit, level, issue_type, status, is_regression,
                    first_seen, last_seen, event_count, user_count,
                    first_release, last_release, environment, metadata_json, search_vec
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'unresolved',FALSE,$10,$10,1,0,$11,$11,$12,$13,to_tsvector('english',$14))
                RETURNING id",
            )
            .bind(auth.organization_id)
            .bind(auth.project_id)
            .bind(&short_id)
            .bind(short_num)
            .bind(&meta.fingerprint)
            .bind(&meta.title)
            .bind(&meta.culprit)
            .bind(&meta.level)
            .bind(meta.issue_type.as_str())
            .bind(received_ms)
            .bind(&meta.release)
            .bind(&meta.environment)
            .bind(metadata_json)
            .bind(&meta.search_text)
            .fetch_one(&mut **tx)
            .await
            .map_err(map_pg_err)?;

            (id, short_id, true, false)
        }
    };

    if let Some(uh) = &meta.user_hash {
        let res = sqlx::query(
            "INSERT INTO issue_users (organization_id, issue_id, user_hash) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(auth.organization_id)
        .bind(issue_id)
        .bind(uh)
        .execute(&mut **tx)
        .await
        .map_err(map_pg_err)?;
        if res.rows_affected() > 0 {
            sqlx::query("UPDATE issues SET user_count = user_count + 1 WHERE id = $1")
                .bind(issue_id)
                .execute(&mut **tx)
                .await
                .map_err(map_pg_err)?;
        }
    }

    if store_full_blob {
        let row_uuid = Uuid::parse_str(&new_uuid_v7_from_ms(received_ms)).unwrap_or_else(|_| Uuid::now_v7());
        let (blob, compressed) = compress_payload_if_large(payload_json);
        sqlx::query(
            "INSERT INTO issue_events (
                id, organization_id, project_id, issue_id, event_id, timestamp_ms,
                level, environment, release, trace_id, span_id, user_hash, tags_json,
                payload_blob, payload_compressed
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
            ON CONFLICT (project_id, event_id) DO NOTHING",
        )
        .bind(row_uuid)
        .bind(auth.organization_id)
        .bind(auth.project_id)
        .bind(issue_id)
        .bind(&meta.event_id)
        .bind(received_ms)
        .bind(&meta.level)
        .bind(&meta.environment)
        .bind(&meta.release)
        .bind(&meta.trace_id)
        .bind(&meta.span_id)
        .bind(&meta.user_hash)
        .bind(&meta.tags)
        .bind(blob)
        .bind(compressed)
        .execute(&mut **tx)
        .await
        .map_err(map_pg_err)?;
    }

    let bucket_hour = (received_ms / 3_600_000) * 3_600_000;
    sqlx::query(
        "INSERT INTO hourly_stats (organization_id, project_id, bucket_hour, category, quantity)
         VALUES ($1, $2, $3, 'error', 1)
         ON CONFLICT (project_id, bucket_hour, category) DO UPDATE SET quantity = hourly_stats.quantity + 1",
    )
    .bind(auth.organization_id)
    .bind(auth.project_id)
    .bind(bucket_hour)
    .execute(&mut **tx)
    .await
    .map_err(map_pg_err)?;

    Ok((issue_id, short_id, is_new, is_regression))
}

#[async_trait]
impl StorageBackend for PostgresStorage {
    async fn needs_setup(&self) -> Result<bool, String> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await
            .map_err(map_pg_err)?;
        Ok(count == 0)
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
        let now = now_ms();
        let mut tx = self.pool.begin().await.map_err(map_pg_err)?;
        sqlx::query("SELECT set_config('app.setup_bootstrap', '1', true)")
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        if count > 0 {
            return Err("Setup already completed".into());
        }

        let org_id: i64 = sqlx::query_scalar(
            "INSERT INTO organizations (slug, name, created_at) VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(org_slug)
        .bind(org_name)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(org_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;

        let user_id: i64 = sqlx::query_scalar(
            "INSERT INTO users (email, name, password_hash, is_active, created_at) VALUES ($1, $2, $3, TRUE, $4) RETURNING id",
        )
        .bind(email.to_ascii_lowercase())
        .bind(name)
        .bind(password_hash)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        sqlx::query(
            "INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1, $2, 'owner')",
        )
        .bind(org_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        let filters_val = serde_json::to_value(ProjectFilters::default()).unwrap();
        let project_id: i64 = sqlx::query_scalar(
            "INSERT INTO projects (organization_id, slug, name, platform, filters_json, created_at)
             VALUES ($1, $2, $3, 'javascript', $4, $5) RETURNING id",
        )
        .bind(org_id)
        .bind(first_project_slug)
        .bind(first_project_name)
        .bind(&filters_val)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        sqlx::query(
            "INSERT INTO project_keys (organization_id, project_id, label, public_key, key_sha256, rate_limit_per_min, is_active, created_at)
             VALUES ($1, $2, 'Default DSN', $3, $4, 300, TRUE, $5)",
        )
        .bind(org_id)
        .bind(project_id)
        .bind(dsn_public_key)
        .bind(dsn_key_sha256)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        sqlx::query(
            "INSERT INTO dsn_key_lookup (key_sha256, organization_id, project_id, organization_slug, project_slug, rate_limit_per_min, filters_json, is_active)
             VALUES ($1, $2, $3, $4, $5, 300, $6, TRUE)",
        )
        .bind(dsn_key_sha256)
        .bind(org_id)
        .bind(project_id)
        .bind(org_slug)
        .bind(first_project_slug)
        .bind(&filters_val)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        tx.commit().await.map_err(map_pg_err)?;
        Ok((
            OrganizationDto {
                id: org_id,
                slug: org_slug.to_string(),
                name: org_name.to_string(),
                role: "owner".into(),
                created_at: now,
            },
            ProjectDto {
                id: project_id,
                organization_id: org_id,
                slug: first_project_slug.to_string(),
                name: first_project_name.to_string(),
                platform: "javascript".into(),
                first_event_at: None,
                filters: ProjectFilters::default(),
                dsn_public_key: Some(dsn_public_key.to_string()),
                tunnel_slug: None,
                created_at: now,
            },
        ))
    }

    async fn find_user_for_login(&self, email: &str) -> Result<Option<LoginUserRecord>, String> {
        let mut tx = self.pool.begin().await.map_err(map_pg_err)?;
        let user_row: Option<(i64, String, String, String, bool)> = sqlx::query_as(
            "SELECT id, email, name, password_hash, is_active FROM users WHERE email = $1",
        )
        .bind(email.trim().to_ascii_lowercase())
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        let Some((uid, uemail, uname, uhash, active)) = user_row else {
            return Ok(None);
        };
        sqlx::query("SELECT set_config('app.current_user_id', $1, true)")
            .bind(uid.to_string())
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let org_row: Option<(i64, String, String)> = sqlx::query_as(
            "SELECT o.id, o.slug, m.role
             FROM organization_members m
             JOIN organizations o ON o.id = m.organization_id
             WHERE m.user_id = $1
             ORDER BY o.id ASC LIMIT 1",
        )
        .bind(uid)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;

        Ok(org_row.map(|(oid, oslug, role_s)| LoginUserRecord {
            user_id: uid,
            email: uemail,
            name: uname,
            password_hash: uhash,
            is_active: active,
            organization_id: oid,
            organization_slug: oslug,
            role: UserRole::from_db(&role_s).unwrap_or(UserRole::Viewer),
        }))
    }

    async fn check_login_lockout(&self, key_hmac: &str, now_sec: i64) -> Result<Option<i64>, String> {
        let locked: Option<Option<i64>> =
            sqlx::query_scalar("SELECT locked_until FROM login_attempts WHERE key_hmac = $1")
                .bind(key_hmac)
                .fetch_optional(&self.pool)
                .await
                .map_err(map_pg_err)?;
        if let Some(Some(until)) = locked {
            if until > now_sec {
                return Ok(Some(until - now_sec));
            }
        }
        Ok(None)
    }

    async fn record_login_failure(&self, key_hmac: &str, now_sec: i64) -> Result<Option<i64>, String> {
        let mut tx = self.pool.begin().await.map_err(map_pg_err)?;
        let prev: i64 = sqlx::query_scalar(
            "SELECT failed_count FROM login_attempts WHERE key_hmac = $1",
        )
        .bind(key_hmac)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?
        .unwrap_or(0);
        let next = prev + 1;
        let lock_secs = compute_lockout_seconds(next);
        let locked_until = lock_secs.map(|s| now_sec + s);
        sqlx::query(
            "INSERT INTO login_attempts (key_hmac, failed_count, locked_until, updated_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (key_hmac) DO UPDATE SET failed_count = $2, locked_until = $3, updated_at = $4",
        )
        .bind(key_hmac)
        .bind(next)
        .bind(locked_until)
        .bind(now_sec)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(lock_secs)
    }

    async fn clear_login_failures(&self, key_hmac: &str) -> Result<(), String> {
        sqlx::query("DELETE FROM login_attempts WHERE key_hmac = $1")
            .bind(key_hmac)
            .execute(&self.pool)
            .await
            .map_err(map_pg_err)?;
        Ok(())
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
        let mut tx = self.begin_tenant(org_id).await?;
        sqlx::query("SELECT set_config('app.current_user_id', $1, true)")
            .bind(user_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let (org_slug, role): (String, String) = sqlx::query_as(
            "SELECT o.slug, m.role FROM organizations o
             JOIN organization_members m ON m.organization_id = o.id
             WHERE o.id = $1 AND m.user_id = $2",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        let ua: String = user_agent.chars().take(160).collect();
        let sess_id: i64 = sqlx::query_scalar(
            "INSERT INTO sessions (token_sha256, user_id, organization_id, csrf_token, user_agent, ip_hmac, last_seen_at, reauth_at, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $9) RETURNING id",
        )
        .bind(token_sha256)
        .bind(user_id)
        .bind(org_id)
        .bind(csrf_token)
        .bind(&ua)
        .bind(ip_hmac)
        .bind(now_sec)
        .bind(expires_at)
        .bind(now_ms())
        .fetch_one(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        sqlx::query(
            "INSERT INTO session_lookup (token_sha256, session_id, organization_id, organization_slug, user_id, role, csrf_token, last_seen_at, reauth_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9)",
        )
        .bind(token_sha256)
        .bind(sess_id)
        .bind(org_id)
        .bind(org_slug)
        .bind(user_id)
        .bind(role)
        .bind(csrf_token)
        .bind(now_sec)
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        tx.commit().await.map_err(map_pg_err)?;
        Ok(sess_id)
    }

    async fn resolve_session(
        &self,
        token_sha256: &str,
        now_sec: i64,
        idle_ttl_sec: i64,
    ) -> Result<Option<AuthenticatedSession>, String> {
        let mut tx = self.pool.begin().await.map_err(map_pg_err)?;
        // Stage 1: Capability-GUC lookup under FORCE RLS (zero BYPASSRLS)
        sqlx::query("SELECT set_config('app.session_sha256', $1, true)")
            .bind(token_sha256)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let cap: Option<(i64, i64, String, i64, String, i64, Option<i64>, i64)> = sqlx::query_as(
            "SELECT session_id, organization_id, organization_slug, user_id, csrf_token, last_seen_at, reauth_at, expires_at
             FROM session_lookup WHERE token_sha256 = $1",
        )
        .bind(token_sha256)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        let Some((sess_id, org_id, org_slug, uid, csrf, last_seen, reauth_at, exp)) = cap else {
            return Ok(None);
        };
        if exp <= now_sec || (last_seen > 0 && last_seen + idle_ttl_sec <= now_sec) {
            return Ok(None);
        }
        // Stage 2: Set transaction-local tenant context & verify active user + LIVE org membership
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(org_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let live_row: Option<(String, String, bool, String, i64, bool, i64)> = sqlx::query_as(
            "SELECT u.email, u.name, u.is_active, m.role, s.id,
                    COALESCE((SELECT is_enabled FROM user_mfa WHERE user_id = u.id), FALSE),
                    (SELECT COUNT(*)::bigint FROM webauthn_credentials WHERE user_id = u.id)
             FROM sessions s
             JOIN users u ON u.id = s.user_id
             JOIN organization_members m ON m.organization_id = s.organization_id AND m.user_id = u.id
             WHERE s.token_sha256 = $1 AND s.expires_at > $2",
        )
        .bind(token_sha256)
        .bind(now_sec)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        let Some((email, name, active, live_role, real_sess_id, totp_en, pk_cnt)) = live_row else {
            tx.commit().await.map_err(map_pg_err)?;
            return Ok(None);
        };
        if !active {
            tx.commit().await.map_err(map_pg_err)?;
            return Ok(None);
        }
        if now_sec - last_seen >= 60 {
            sqlx::query("UPDATE sessions SET last_seen_at = $1 WHERE token_sha256 = $2")
                .bind(now_sec)
                .bind(token_sha256)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
            sqlx::query("UPDATE session_lookup SET last_seen_at = $1 WHERE token_sha256 = $2")
                .bind(now_sec)
                .bind(token_sha256)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
        }
        tx.commit().await.map_err(map_pg_err)?;

        Ok(Some(AuthenticatedSession {
            session_id: if real_sess_id > 0 { real_sess_id } else { sess_id },
            user_id: uid,
            email,
            name,
            organization_id: org_id,
            organization_slug: org_slug,
            role: UserRole::from_db(&live_role).unwrap_or(UserRole::Viewer),
            csrf_token: csrf,
            reauth_at,
            totp_enabled: totp_en,
            passkey_count: pk_cnt,
        }))
    }

    async fn delete_session(&self, token_sha256: &str) -> Result<(), String> {
        let mut tx = self.pool.begin().await.map_err(map_pg_err)?;
        sqlx::query("SELECT set_config('app.session_sha256', $1, true)")
            .bind(token_sha256)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let org_id: Option<i64> =
            sqlx::query_scalar("SELECT organization_id FROM session_lookup WHERE token_sha256 = $1")
                .bind(token_sha256)
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_pg_err)?;
        if let Some(oid) = org_id {
            sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
                .bind(oid.to_string())
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
            sqlx::query("DELETE FROM sessions WHERE token_sha256 = $1")
                .bind(token_sha256)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
            sqlx::query("DELETE FROM session_lookup WHERE token_sha256 = $1")
                .bind(token_sha256)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
        }
        tx.commit().await.map_err(map_pg_err)?;
        Ok(())
    }

    async fn resolve_api_token(
        &self,
        token_sha256: &str,
        org_slug: Option<&str>,
        now_sec: i64,
    ) -> Result<Option<TenantCtx>, String> {
        let mut tx = self.pool.begin().await.map_err(map_pg_err)?;
        sqlx::query("SELECT set_config('app.api_token_sha256', $1, true)")
            .bind(token_sha256)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let row: Option<(i64, String, i64, String, String, Option<i64>)> = sqlx::query_as(
            "SELECT organization_id, organization_slug, user_id, role, scopes, expires_at
             FROM api_token_lookup WHERE token_sha256 = $1",
        )
        .bind(token_sha256)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        let Some((org_id, found_slug, uid, tok_role_s, raw_scopes, exp)) = row else {
            tx.commit().await.map_err(map_pg_err)?;
            return Ok(None);
        };
        if let Some(want) = org_slug {
            if found_slug != want {
                tx.commit().await.map_err(map_pg_err)?;
                return Ok(None);
            }
        }
        if exp.map(|e| e <= now_sec).unwrap_or(false) {
            tx.commit().await.map_err(map_pg_err)?;
            return Ok(None);
        }

        // Stage 2: Verify live api_tokens row + active user + LIVE membership under FORCE RLS
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(org_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let live: Option<(String, bool, Option<i64>)> = sqlx::query_as(
            "SELECT m.role, u.is_active, t.last_used_at
             FROM api_tokens t
             JOIN users u ON u.id = t.user_id
             JOIN organization_members m ON m.organization_id = t.organization_id AND m.user_id = t.user_id
             WHERE t.token_sha256 = $1
               AND (t.expires_at IS NULL OR t.expires_at > $2)",
        )
        .bind(token_sha256)
        .bind(now_sec)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        let Some((mem_role_s, active, lu)) = live else {
            tx.commit().await.map_err(map_pg_err)?;
            return Ok(None);
        };
        if !active {
            tx.commit().await.map_err(map_pg_err)?;
            return Ok(None);
        }
        let now_m = now_ms();
        if lu.map(|p| now_m - p >= 300_000).unwrap_or(true) {
            sqlx::query("UPDATE api_tokens SET last_used_at = $1 WHERE token_sha256 = $2")
                .bind(now_m)
                .bind(token_sha256)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
        }
        tx.commit().await.map_err(map_pg_err)?;

        let tok_role = UserRole::from_db(&tok_role_s).unwrap_or(UserRole::Viewer);
        let mem_role = UserRole::from_db(&mem_role_s).unwrap_or(UserRole::Viewer);
        let eff_role = mem_role.min_role(tok_role);
        Ok(Some(TenantCtx::from_token(
            org_id,
            found_slug,
            uid,
            eff_role,
            &raw_scopes,
        )))
    }

    async fn resolve_dsn(&self, project_id: i64, key_sha256: &str) -> Result<Option<ProjectAuthInfo>, String> {
        let mut tx = self.pool.begin().await.map_err(map_pg_err)?;
        sqlx::query("SELECT set_config('app.ingest_dsn_key_sha256', $1, true)")
            .bind(key_sha256)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let row: Option<(i64, i64, String, String, Option<i64>, i32, Value, Value, bool)> = sqlx::query_as(
            "SELECT project_id, organization_id, organization_slug, project_slug, first_event_at, rate_limit_per_min, filters_json, org_settings_json, is_active
             FROM dsn_key_lookup WHERE key_sha256 = $1 AND project_id = $2",
        )
        .bind(key_sha256)
        .bind(project_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;

        let Some((pid, oid, oslug, pslug, first_ev, rpm, fval, sval, active)) = row else {
            return Ok(None);
        };
        if !active {
            return Ok(None);
        }
        let org_sec: OrgSecuritySettings = serde_json::from_value(sval).unwrap_or_default();
        Ok(Some(ProjectAuthInfo {
            project_id: pid,
            organization_id: oid,
            organization_slug: oslug,
            project_slug: pslug,
            first_event_at: first_ev,
            rate_limit_per_min: rpm.max(1) as u32,
            filters: serde_json::from_value(fval).unwrap_or_default(),
            org_scrub_ip_addresses: org_sec.scrub_ip_addresses,
            org_event_throttle_rate: org_sec.event_throttle_rate,
        }))
    }

    async fn tunnel_slug_exists(&self, tunnel_slug: &str) -> Result<bool, String> {
        let mut tx = self.pool.begin().await.map_err(map_pg_err)?;
        sqlx::query("SELECT set_config('app.tunnel_slug', $1, true)")
            .bind(tunnel_slug)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let active: Option<bool> = sqlx::query_scalar(
            "SELECT is_active FROM tunnel_lookup WHERE slug = $1",
        )
        .bind(tunnel_slug)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(active == Some(true))
    }

    async fn resolve_tunnel(&self, tunnel_slug: &str, project_id: i64, key_sha256: &str) -> Result<Option<ProjectAuthInfo>, String> {
        let mut tx = self.pool.begin().await.map_err(map_pg_err)?;
        sqlx::query("SELECT set_config('app.tunnel_slug', $1, true)")
            .bind(tunnel_slug)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let t_row: Option<(i64, i64, bool)> = sqlx::query_as(
            "SELECT organization_id, project_id, is_active FROM tunnel_lookup WHERE slug = $1",
        )
        .bind(tunnel_slug)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        let Some((t_org, t_proj, t_active)) = t_row else {
            return Ok(None);
        };
        if !t_active || t_proj != project_id {
            return Ok(None);
        }
        tx.commit().await.map_err(map_pg_err)?;
        let auth = self.resolve_dsn(project_id, key_sha256).await?;
        Ok(auth.filter(|a| a.organization_id == t_org))
    }

    async fn list_user_organizations(&self, user_id: i64) -> Result<Vec<OrganizationDto>, String> {
        let mut tx = self.pool.begin().await.map_err(map_pg_err)?;
        sqlx::query("SELECT set_config('app.current_user_id', $1, true)")
            .bind(user_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let rows: Vec<(i64, String, String, String, i64)> = sqlx::query_as(
            "SELECT o.id, o.slug, o.name, m.role, o.created_at
             FROM organizations o
             JOIN organization_members m ON m.organization_id = o.id
             JOIN users u ON u.id = m.user_id
             WHERE m.user_id = $1 AND u.is_active = TRUE ORDER BY o.id ASC",
        )
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(rows
            .into_iter()
            .map(|(id, slug, name, role, created_at)| OrganizationDto {
                id,
                slug,
                name,
                role,
                created_at,
            })
            .collect())
    }

    async fn resolve_tenant_for_user(&self, user_id: i64, org_slug: &str) -> Result<Option<TenantCtx>, String> {
        let mut tx = self.pool.begin().await.map_err(map_pg_err)?;
        sqlx::query("SELECT set_config('app.current_user_id', $1, true)")
            .bind(user_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let row: Option<(i64, String, String)> = sqlx::query_as(
            "SELECT o.id, o.slug, m.role
             FROM organizations o
             JOIN organization_members m ON m.organization_id = o.id
             JOIN users u ON u.id = m.user_id
             WHERE m.user_id = $1 AND o.slug = $2 AND u.is_active = TRUE",
        )
        .bind(user_id)
        .bind(org_slug)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(row.map(|(oid, slug, role_s)| {
            let role = UserRole::from_db(&role_s).unwrap_or(UserRole::Viewer);
            TenantCtx::from_session(oid, slug, user_id, role, None, None)
        }))
    }

    async fn list_projects(&self, ctx: &TenantCtx) -> Result<Vec<ProjectDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let rows = sqlx::query(
            "SELECT p.id, p.organization_id, p.slug, p.name, p.platform, p.first_event_at, p.filters_json,
                    (SELECT public_key FROM project_keys pk WHERE pk.project_id = p.id AND pk.is_active = TRUE ORDER BY pk.id ASC LIMIT 1) AS dsn_key,
                    (SELECT slug FROM tunnel_routes tr WHERE tr.project_id = p.id AND tr.is_active = TRUE LIMIT 1) AS tunnel_slug,
                    p.created_at
             FROM projects p ORDER BY p.id ASC",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let fval: Value = r.get("filters_json");
                ProjectDto {
                    id: r.get("id"),
                    organization_id: r.get("organization_id"),
                    slug: r.get("slug"),
                    name: r.get("name"),
                    platform: r.get("platform"),
                    first_event_at: r.get("first_event_at"),
                    filters: serde_json::from_value(fval).unwrap_or_default(),
                    dsn_public_key: r.get("dsn_key"),
                    tunnel_slug: r.get("tunnel_slug"),
                    created_at: r.get("created_at"),
                }
            })
            .collect())
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
        let now = now_ms();
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let filters_val = serde_json::to_value(ProjectFilters::default()).unwrap();
        let pid: i64 = sqlx::query_scalar(
            "INSERT INTO projects (organization_id, slug, name, platform, filters_json, created_at)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
        )
        .bind(ctx.organization_id)
        .bind(slug)
        .bind(name)
        .bind(platform)
        .bind(&filters_val)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        sqlx::query(
            "INSERT INTO project_keys (organization_id, project_id, label, public_key, key_sha256, rate_limit_per_min, is_active, created_at)
             VALUES ($1, $2, 'Default DSN', $3, $4, 300, TRUE, $5)",
        )
        .bind(ctx.organization_id)
        .bind(pid)
        .bind(dsn_public_key)
        .bind(dsn_key_sha256)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        let org_settings: Value = sqlx::query_scalar(
            "SELECT settings_json FROM organizations WHERE id = $1",
        )
        .bind(ctx.organization_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?
        .unwrap_or_else(|| json!({}));

        sqlx::query(
            "INSERT INTO dsn_key_lookup (key_sha256, organization_id, project_id, organization_slug, project_slug, rate_limit_per_min, filters_json, org_settings_json, is_active)
             VALUES ($1, $2, $3, $4, $5, 300, $6, $7, TRUE)",
        )
        .bind(dsn_key_sha256)
        .bind(ctx.organization_id)
        .bind(pid)
        .bind(&ctx.organization_slug)
        .bind(slug)
        .bind(&filters_val)
        .bind(&org_settings)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        tx.commit().await.map_err(map_pg_err)?;
        Ok(ProjectDto {
            id: pid,
            organization_id: ctx.organization_id,
            slug: slug.to_string(),
            name: name.to_string(),
            platform: platform.to_string(),
            first_event_at: None,
            filters: ProjectFilters::default(),
            dsn_public_key: Some(dsn_public_key.to_string()),
            tunnel_slug: None,
            created_at: now,
        })
    }

    async fn update_project_filters(
        &self,
        ctx: &TenantCtx,
        project_slug: &str,
        filters: &ProjectFilters,
    ) -> Result<Option<ProjectDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let fval = serde_json::to_value(filters).map_err(map_pg_err)?;
        let row = sqlx::query(
            "UPDATE projects SET filters_json = $1 WHERE slug = $2
             RETURNING id, name, platform, first_event_at, created_at",
        )
        .bind(&fval)
        .bind(project_slug)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        let Some(r) = row else {
            return Ok(None);
        };
        let pid: i64 = r.get("id");
        sqlx::query("UPDATE dsn_key_lookup SET filters_json = $1 WHERE project_id = $2")
            .bind(&fval)
            .bind(pid)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(Some(ProjectDto {
            id: pid,
            organization_id: ctx.organization_id,
            slug: project_slug.to_string(),
            name: r.get("name"),
            platform: r.get("platform"),
            first_event_at: r.get("first_event_at"),
            filters: filters.clone(),
            dsn_public_key: None,
            tunnel_slug: None,
            created_at: r.get("created_at"),
        }))
    }

    async fn list_project_keys(&self, ctx: &TenantCtx, project_slug: &str) -> Result<Vec<ProjectKeyDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let rows = sqlx::query(
            "SELECT k.id, k.project_id, k.label, k.public_key, k.rate_limit_per_min, k.is_active, k.created_at
             FROM project_keys k JOIN projects p ON p.id = k.project_id
             WHERE p.slug = $1 ORDER BY k.id ASC",
        )
        .bind(project_slug)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(rows
            .into_iter()
            .map(|r| ProjectKeyDto {
                id: r.get("id"),
                project_id: r.get("project_id"),
                label: r.get("label"),
                public_key: r.get("public_key"),
                rate_limit_per_min: r.get::<i32, _>("rate_limit_per_min").max(1) as u32,
                is_active: r.get("is_active"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    async fn create_project_key(
        &self,
        ctx: &TenantCtx,
        project_slug: &str,
        label: &str,
        public_key: &str,
        key_sha256: &str,
    ) -> Result<Option<ProjectKeyDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let proj: Option<(i64, Value, Option<i64>)> = sqlx::query_as(
            "SELECT id, filters_json, first_event_at FROM projects WHERE slug = $1",
        )
        .bind(project_slug)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        let Some((pid, fval, first_ev)) = proj else {
            return Ok(None);
        };
        let now = now_ms();
        let kid: i64 = sqlx::query_scalar(
            "INSERT INTO project_keys (organization_id, project_id, label, public_key, key_sha256, rate_limit_per_min, is_active, created_at)
             VALUES ($1, $2, $3, $4, $5, 300, TRUE, $6) RETURNING id",
        )
        .bind(ctx.organization_id)
        .bind(pid)
        .bind(label)
        .bind(public_key)
        .bind(key_sha256)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        let org_settings: Value = sqlx::query_scalar(
            "SELECT settings_json FROM organizations WHERE id = $1",
        )
        .bind(ctx.organization_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?
        .unwrap_or_else(|| json!({}));

        sqlx::query(
            "INSERT INTO dsn_key_lookup (key_sha256, organization_id, project_id, organization_slug, project_slug, rate_limit_per_min, filters_json, org_settings_json, first_event_at, is_active)
             VALUES ($1, $2, $3, $4, $5, 300, $6, $7, $8, TRUE)",
        )
        .bind(key_sha256)
        .bind(ctx.organization_id)
        .bind(pid)
        .bind(&ctx.organization_slug)
        .bind(project_slug)
        .bind(fval)
        .bind(org_settings)
        .bind(first_ev)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(Some(ProjectKeyDto {
            id: kid,
            project_id: pid,
            label: label.to_string(),
            public_key: public_key.to_string(),
            rate_limit_per_min: 300,
            is_active: true,
            created_at: now,
        }))
    }

    async fn delete_project_key(&self, ctx: &TenantCtx, project_slug: &str, key_id: i64) -> Result<bool, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let sha: Option<String> = sqlx::query_scalar(
            "DELETE FROM project_keys k USING projects p
             WHERE k.project_id = p.id AND p.slug = $1 AND k.id = $2
             RETURNING k.key_sha256",
        )
        .bind(project_slug)
        .bind(key_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        if let Some(s) = &sha {
            sqlx::query("DELETE FROM dsn_key_lookup WHERE key_sha256 = $1")
                .bind(s)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
        }
        tx.commit().await.map_err(map_pg_err)?;
        Ok(sha.is_some())
    }

    async fn enable_project_tunnel(&self, ctx: &TenantCtx, project_slug: &str, tunnel_slug: &str) -> Result<Option<String>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let pid: Option<i64> = sqlx::query_scalar("SELECT id FROM projects WHERE slug = $1")
            .bind(project_slug)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let Some(pid) = pid else {
            return Ok(None);
        };
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT slug FROM tunnel_routes WHERE project_id = $1 AND is_active = TRUE LIMIT 1",
        )
        .bind(pid)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        if let Some(s) = existing {
            return Ok(Some(s));
        }
        sqlx::query(
            "INSERT INTO tunnel_routes (slug, organization_id, project_id, is_active, created_at) VALUES ($1, $2, $3, TRUE, $4)",
        )
        .bind(tunnel_slug)
        .bind(ctx.organization_id)
        .bind(pid)
        .bind(now_ms())
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        sqlx::query(
            "INSERT INTO tunnel_lookup (slug, organization_id, project_id, is_active) VALUES ($1, $2, $3, TRUE)",
        )
        .bind(tunnel_slug)
        .bind(ctx.organization_id)
        .bind(pid)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(Some(tunnel_slug.to_string()))
    }

    async fn list_issues(&self, ctx: &TenantCtx, p: &IssueQueryParams) -> Result<(Vec<IssueSummaryDto>, i64), String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let order = match p.sort.as_str() {
            "freq" => "i.event_count DESC, i.last_seen DESC",
            "new" => "i.first_seen DESC",
            _ => "i.last_seen DESC",
        };
        let limit = p.limit.clamp(1, 200);
        let offset = p.offset.clamp(0, 100_000);
        let q_text = p.search_query.as_deref().map(str::trim).filter(|s| !s.is_empty());

        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM issues i
             WHERE ($1::text IS NULL OR i.status = $1)
               AND ($2::text IS NULL OR i.level = $2)
               AND ($3::text IS NULL OR i.environment = $3)
               AND ($4::text IS NULL OR i.last_release = $4 OR i.first_release = $4)
               AND ($5::bigint IS NULL OR i.project_id = $5)
               AND ($6::bigint IS NULL OR i.last_seen >= $6)
               AND ($7::text IS NULL OR i.search_vec @@ plainto_tsquery('english', $7))",
        )
        .bind(&p.status)
        .bind(&p.level)
        .bind(&p.environment)
        .bind(&p.release)
        .bind(p.project_id)
        .bind(p.since_ms)
        .bind(q_text)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        let sql = format!(
            "SELECT i.id, i.short_id, i.project_id, pr.slug AS project_slug, i.title, i.culprit, i.level,
                    i.issue_type, i.status, i.is_regression, i.resolved_in_release,
                    i.first_seen, i.last_seen, i.event_count, i.user_count,
                    i.first_release, i.last_release, i.environment, i.metadata_json
             FROM issues i
             JOIN projects pr ON pr.id = i.project_id
             WHERE ($1::text IS NULL OR i.status = $1)
               AND ($2::text IS NULL OR i.level = $2)
               AND ($3::text IS NULL OR i.environment = $3)
               AND ($4::text IS NULL OR i.last_release = $4 OR i.first_release = $4)
               AND ($5::bigint IS NULL OR i.project_id = $5)
               AND ($6::bigint IS NULL OR i.last_seen >= $6)
               AND ($7::text IS NULL OR i.search_vec @@ plainto_tsquery('english', $7))
             ORDER BY {order} LIMIT $8 OFFSET $9"
        );

        let rows = sqlx::query(&sql)
            .bind(&p.status)
            .bind(&p.level)
            .bind(&p.environment)
            .bind(&p.release)
            .bind(p.project_id)
            .bind(p.since_ms)
            .bind(q_text)
            .bind(limit)
            .bind(offset)
            .fetch_all(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;

        Ok((
            rows.iter()
                .map(|r| row_to_issue(r, &ctx.organization_slug))
                .collect(),
            total,
        ))
    }

    async fn get_issue(&self, ctx: &TenantCtx, issue_id: i64) -> Result<Option<IssueSummaryDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let row = sqlx::query(
            "SELECT i.id, i.short_id, i.project_id, pr.slug AS project_slug, i.title, i.culprit, i.level,
                    i.issue_type, i.status, i.is_regression, i.resolved_in_release,
                    i.first_seen, i.last_seen, i.event_count, i.user_count,
                    i.first_release, i.last_release, i.environment, i.metadata_json
             FROM issues i JOIN projects pr ON pr.id = i.project_id WHERE i.id = $1",
        )
        .bind(issue_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(row.map(|r| row_to_issue(&r, &ctx.organization_slug)))
    }

    async fn update_issue_status(
        &self,
        ctx: &TenantCtx,
        issue_id: i64,
        status: IssueStatus,
        resolved_in_release: Option<&str>,
    ) -> Result<Option<IssueSummaryDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let res = sqlx::query(
            "UPDATE issues
             SET status = $1,
                 resolved_in_release = CASE WHEN $1 = 'resolved' THEN COALESCE($2, last_release) ELSE NULL END,
                 is_regression = CASE WHEN $1 = 'resolved' THEN FALSE ELSE is_regression END
             WHERE id = $3",
        )
        .bind(status.as_str())
        .bind(resolved_in_release)
        .bind(issue_id)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        if res.rows_affected() == 0 {
            return Ok(None);
        }
        self.get_issue(ctx, issue_id).await
    }

    async fn list_issue_events(&self, ctx: &TenantCtx, issue_id: i64, limit: i64) -> Result<Vec<IssueEventDetailDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let rows = sqlx::query(
            "SELECT id, event_id, issue_id, project_id, timestamp_ms, level, environment,
                    release, trace_id, span_id, tags_json, payload_blob, payload_compressed
             FROM issue_events WHERE issue_id = $1 ORDER BY timestamp_ms DESC LIMIT $2",
        )
        .bind(issue_id)
        .bind(limit.clamp(1, 100))
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let blob: Vec<u8> = r.get("payload_blob");
                let comp: bool = r.get("payload_compressed");
                let decoded = decompress_payload(&blob, comp).unwrap_or(blob);
                let payload: Value = serde_json::from_slice(&decoded).unwrap_or_else(|_| json!({}));
                let uid: Uuid = r.get("id");
                IssueEventDetailDto {
                    id: uid.to_string(),
                    event_id: r.get("event_id"),
                    issue_id: r.get("issue_id"),
                    project_id: r.get("project_id"),
                    timestamp: iso_from_ms(r.get("timestamp_ms")),
                    level: r.get("level"),
                    environment: r.get("environment"),
                    release: r.get("release"),
                    trace_id: r.get("trace_id"),
                    span_id: r.get("span_id"),
                    tags: r.get("tags_json"),
                    payload,
                }
            })
            .collect())
    }

    async fn get_issue_event(&self, ctx: &TenantCtx, issue_id: i64, event_id_or_latest: &str) -> Result<Option<IssueEventDetailDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let row = if event_id_or_latest == "latest" {
            sqlx::query(
                "SELECT id, event_id, issue_id, project_id, timestamp_ms, level, environment,
                        release, trace_id, span_id, tags_json, payload_blob, payload_compressed
                 FROM issue_events WHERE issue_id = $1 ORDER BY timestamp_ms DESC LIMIT 1",
            )
            .bind(issue_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_pg_err)?
        } else {
            sqlx::query(
                "SELECT id, event_id, issue_id, project_id, timestamp_ms, level, environment,
                        release, trace_id, span_id, tags_json, payload_blob, payload_compressed
                 FROM issue_events WHERE issue_id = $1 AND (event_id = $2 OR id::text = $2) LIMIT 1",
            )
            .bind(issue_id)
            .bind(event_id_or_latest)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_pg_err)?
        };
        tx.commit().await.map_err(map_pg_err)?;
        Ok(row.map(|r| {
            let blob: Vec<u8> = r.get("payload_blob");
            let comp: bool = r.get("payload_compressed");
            let decoded = decompress_payload(&blob, comp).unwrap_or(blob);
            let payload: Value = serde_json::from_slice(&decoded).unwrap_or_else(|_| json!({}));
            let uid: Uuid = r.get("id");
            IssueEventDetailDto {
                id: uid.to_string(),
                event_id: r.get("event_id"),
                issue_id: r.get("issue_id"),
                project_id: r.get("project_id"),
                timestamp: iso_from_ms(r.get("timestamp_ms")),
                level: r.get("level"),
                environment: r.get("environment"),
                release: r.get("release"),
                trace_id: r.get("trace_id"),
                span_id: r.get("span_id"),
                tags: r.get("tags_json"),
                payload,
            }
        }))
    }

    async fn query_logs(&self, ctx: &TenantCtx, p: &LogQueryParams) -> Result<Vec<LogEventDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let cursor_uuid = p
            .cursor_id
            .as_deref()
            .and_then(|s| Uuid::parse_str(s).ok());
        let proj_filter: Option<&[i64]> = if p.project_ids.is_empty() {
            None
        } else {
            Some(&p.project_ids)
        };
        let lvl_filter: Option<&[i32]> = if p.level_list.is_empty() {
            None
        } else {
            Some(&p.level_list)
        };
        let q_text = p.search_query.as_deref().map(str::trim).filter(|s| !s.is_empty());

        let rows = sqlx::query(
            "SELECT id, timestamp_ms, level_num, severity_number, body, service, environment,
                    host, trace_id, span_id, attributes_json, project_id
             FROM log_events
             WHERE ($1::bigint[] IS NULL OR project_id = ANY($1))
               AND ($2::int[] IS NULL OR level_num = ANY($2))
               AND ($3::int IS NULL OR level_num >= $3)
               AND ($4::text IS NULL OR service = $4)
               AND ($5::text IS NULL OR environment = $5)
               AND ($6::text IS NULL OR host = $6)
               AND ($7::text IS NULL OR trace_id = $7)
               AND ($8::bigint IS NULL OR timestamp_ms >= $8)
               AND ($9::bigint IS NULL OR timestamp_ms <= $9)
               AND ($10::uuid IS NULL OR id < $10)
               AND ($11::text IS NULL OR body_tsv @@ plainto_tsquery('english', $11))
             ORDER BY id DESC LIMIT $12",
        )
        .bind(proj_filter)
        .bind(lvl_filter)
        .bind(p.min_level_num)
        .bind(&p.service)
        .bind(&p.environment)
        .bind(&p.host)
        .bind(&p.trace_id)
        .bind(p.start_ms)
        .bind(p.end_ms)
        .bind(cursor_uuid)
        .bind(q_text)
        .bind(p.limit.clamp(1, 200))
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let id: Uuid = r.get("id");
                let ts_ms: i64 = r.get("timestamp_ms");
                let lvl_num: i32 = r.get("level_num");
                let sev: Option<i32> = r.get("severity_number");
                LogEventDto {
                    id: id.to_string(),
                    timestamp: iso_from_ms(ts_ms),
                    timestamp_ms: ts_ms,
                    level: LogLevel::from_num(lvl_num).as_str().to_string(),
                    severity_number: sev.map(|n| n as u16),
                    body: r.get("body"),
                    service: r.get("service"),
                    environment: r.get("environment"),
                    host: r.get("host"),
                    trace_id: r.get("trace_id"),
                    span_id: r.get("span_id"),
                    data: r.get("attributes_json"),
                    project_id: r.get("project_id"),
                }
            })
            .collect())
    }

    async fn list_log_resources(&self, ctx: &TenantCtx) -> Result<Vec<LogResourceDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let rows = sqlx::query(
            "SELECT name, resource_type, last_seen FROM log_resources ORDER BY last_seen DESC LIMIT 200",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(rows
            .into_iter()
            .map(|r| LogResourceDto {
                name: r.get("name"),
                resource_type: r.get("resource_type"),
                last_seen: iso_from_ms(r.get("last_seen")),
            })
            .collect())
    }

    async fn get_log_stats(&self, ctx: &TenantCtx, since_ms: i64, until_ms: i64) -> Result<Value, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let rows: Vec<(i64, i32, i64)> = sqlx::query_as(
            "SELECT (timestamp_ms / 3600000) * 3600000 AS b, level_num, COUNT(*)
             FROM log_events WHERE timestamp_ms >= $1 AND timestamp_ms <= $2
             GROUP BY b, level_num ORDER BY b ASC",
        )
        .bind(since_ms)
        .bind(until_ms)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        let mut buckets: std::collections::BTreeMap<i64, [i64; 6]> = std::collections::BTreeMap::new();
        for (b, lvl, cnt) in rows {
            let slot = match LogLevel::from_num(lvl) {
                LogLevel::Trace => 0,
                LogLevel::Debug => 1,
                LogLevel::Info => 2,
                LogLevel::Warn => 3,
                LogLevel::Error => 4,
                LogLevel::Fatal => 5,
            };
            buckets.entry(b).or_insert([0; 6])[slot] += cnt;
        }
        let intervals: Vec<String> = buckets.keys().map(|b| iso_from_ms(*b)).collect();
        let names = ["trace", "debug", "info", "warn", "error", "fatal"];
        let series: Vec<Value> = names
            .iter()
            .enumerate()
            .map(|(i, n)| json!({ "name": n, "data": buckets.values().map(|a| a[i]).collect::<Vec<_>>() }))
            .collect();
        Ok(json!({ "intervals": intervals, "series": series }))
    }

    async fn get_stats_v2(&self, ctx: &TenantCtx, category: &str, since_ms: i64, until_ms: i64) -> Result<Value, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let rows: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT bucket_hour, CAST(SUM(quantity) AS BIGINT)
             FROM hourly_stats WHERE category = $1 AND bucket_hour >= $2 AND bucket_hour <= $3
             GROUP BY bucket_hour ORDER BY bucket_hour ASC",
        )
        .bind(category)
        .bind(since_ms)
        .bind(until_ms)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        let mut intervals = Vec::new();
        let mut series = Vec::new();
        let mut total = 0i64;
        for (b, q) in rows {
            intervals.push(iso_from_ms(b));
            series.push(q);
            total += q;
        }
        Ok(json!({
            "start": iso_from_ms(since_ms),
            "end": iso_from_ms(until_ms),
            "intervals": intervals,
            "groups": [{
                "by": { "category": category },
                "totals": { "sum(quantity)": total },
                "series": { "sum(quantity)": series }
            }]
        }))
    }

    async fn list_transactions(&self, ctx: &TenantCtx, since_ms: i64) -> Result<Vec<TransactionSummaryDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let rows: Vec<(String, String, String, f64, i64)> = sqlx::query_as(
            "SELECT name, op, status, duration_ms, timestamp_ms
             FROM transaction_events WHERE timestamp_ms >= $1 ORDER BY timestamp_ms DESC LIMIT 2000",
        )
        .bind(since_ms)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        struct Acc { op: String, durations: Vec<f64>, err: i64, last: i64 }
        let mut map: HashMap<String, Acc> = HashMap::new();
        for (name, op, status, dur, ts) in rows {
            let e = map.entry(name).or_insert(Acc { op, durations: Vec::new(), err: 0, last: ts });
            e.durations.push(dur);
            if status != "ok" && status != "unset" { e.err += 1; }
            if ts > e.last { e.last = ts; }
        }
        let mut out: Vec<TransactionSummaryDto> = map
            .into_iter()
            .map(|(name, mut a)| {
                a.durations.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
                let n = a.durations.len();
                let p50 = a.durations.get(n / 2).copied().unwrap_or(0.0);
                let p95 = a.durations.get((n * 95) / 100).copied().unwrap_or(p50);
                let avg = if n == 0 { 0.0 } else { a.durations.iter().sum::<f64>() / n as f64 };
                TransactionSummaryDto {
                    name,
                    op: a.op,
                    count: n as i64,
                    error_count: a.err,
                    p50_ms: (p50 * 100.0).round() / 100.0,
                    p95_ms: (p95 * 100.0).round() / 100.0,
                    avg_ms: (avg * 100.0).round() / 100.0,
                    last_seen: iso_from_ms(a.last),
                }
            })
            .collect();
        out.sort_by(|a, b| b.count.cmp(&a.count));
        Ok(out)
    }

    async fn get_trace_context(&self, ctx: &TenantCtx, trace_id: &str) -> Result<Value, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let tx_rows = sqlx::query(
            "SELECT id, name, op, status, duration_ms, span_id, environment, release, spans_json, timestamp_ms
             FROM transaction_events WHERE trace_id = $1 ORDER BY timestamp_ms ASC LIMIT 100",
        )
        .bind(trace_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        let transactions: Vec<Value> = tx_rows
            .into_iter()
            .map(|r| {
                let id: Uuid = r.get("id");
                json!({
                    "id": id.to_string(),
                    "name": r.get::<String, _>("name"),
                    "op": r.get::<String, _>("op"),
                    "status": r.get::<String, _>("status"),
                    "duration_ms": r.get::<f64, _>("duration_ms"),
                    "span_id": r.get::<String, _>("span_id"),
                    "environment": r.get::<String, _>("environment"),
                    "release": r.get::<Option<String>, _>("release"),
                    "spans": r.get::<Value, _>("spans_json"),
                    "timestamp": iso_from_ms(r.get("timestamp_ms")),
                })
            })
            .collect();

        let err_rows = sqlx::query(
            "SELECT ie.issue_id, i.short_id, i.title, ie.event_id, ie.level, ie.timestamp_ms
             FROM issue_events ie JOIN issues i ON i.id = ie.issue_id
             WHERE ie.trace_id = $1 ORDER BY ie.timestamp_ms ASC LIMIT 50",
        )
        .bind(trace_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        let errors: Vec<Value> = err_rows
            .into_iter()
            .map(|r| {
                json!({
                    "issue_id": r.get::<i64, _>("issue_id"),
                    "short_id": r.get::<String, _>("short_id"),
                    "title": r.get::<String, _>("title"),
                    "event_id": r.get::<String, _>("event_id"),
                    "level": r.get::<String, _>("level"),
                    "timestamp": iso_from_ms(r.get("timestamp_ms")),
                })
            })
            .collect();

        let log_rows = sqlx::query(
            "SELECT id, timestamp_ms, level_num, body, service, span_id, attributes_json
             FROM log_events WHERE trace_id = $1 ORDER BY id ASC LIMIT 200",
        )
        .bind(trace_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        let logs: Vec<Value> = log_rows
            .into_iter()
            .map(|r| {
                let id: Uuid = r.get("id");
                json!({
                    "id": id.to_string(),
                    "timestamp": iso_from_ms(r.get("timestamp_ms")),
                    "level": LogLevel::from_num(r.get("level_num")).as_str(),
                    "body": r.get::<String, _>("body"),
                    "service": r.get::<String, _>("service"),
                    "span_id": r.get::<Option<String>, _>("span_id"),
                    "attributes": r.get::<Value, _>("attributes_json"),
                })
            })
            .collect();
        tx.commit().await.map_err(map_pg_err)?;
        Ok(json!({
            "trace_id": trace_id,
            "transactions": transactions,
            "errors": errors,
            "logs": logs,
        }))
    }

    async fn list_releases(&self, ctx: &TenantCtx) -> Result<Vec<ReleaseHealthDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let rows = sqlx::query(
            "SELECT r.version, MIN(r.first_seen) AS fs, MAX(r.last_seen) AS ls,
                    (SELECT COUNT(*) FROM issues i WHERE i.first_release = r.version) AS ic,
                    COALESCE((SELECT CAST(SUM(rs.healthy_count) AS BIGINT) FROM release_sessions rs WHERE rs.release_version = r.version), 0) AS hc,
                    COALESCE((SELECT CAST(SUM(rs.errored_count) AS BIGINT) FROM release_sessions rs WHERE rs.release_version = r.version), 0) AS ec,
                    COALESCE((SELECT CAST(SUM(rs.crashed_count) AS BIGINT) FROM release_sessions rs WHERE rs.release_version = r.version), 0) AS cc,
                    COALESCE((SELECT CAST(SUM(rs.abnormal_count) AS BIGINT) FROM release_sessions rs WHERE rs.release_version = r.version), 0) AS ac
             FROM releases r GROUP BY r.version ORDER BY MAX(r.last_seen) DESC LIMIT 50",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let healthy: i64 = r.get("hc");
                let errored: i64 = r.get("ec");
                let crashed: i64 = r.get("cc");
                let abnormal: i64 = r.get("ac");
                let total = healthy + errored + crashed + abnormal;
                let cf = if total > 0 {
                    (((total - crashed) as f64) / (total as f64)) * 100.0
                } else {
                    100.0
                };
                ReleaseHealthDto {
                    version: r.get("version"),
                    first_seen: iso_from_ms(r.get("fs")),
                    last_seen: iso_from_ms(r.get("ls")),
                    issue_count: r.get("ic"),
                    healthy_sessions: healthy,
                    errored_sessions: errored,
                    crashed_sessions: crashed,
                    abnormal_sessions: abnormal,
                    crash_free_rate: (cf * 100.0).round() / 100.0,
                }
            })
            .collect())
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
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let pid: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE slug = $1")
            .bind(project_slug)
            .fetch_one(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO source_maps (organization_id, project_id, release_version, debug_id, filename, blob_sha256, size_bytes, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
        )
        .bind(ctx.organization_id)
        .bind(pid)
        .bind(release_version)
        .bind(debug_id)
        .bind(filename)
        .bind(blob_sha256)
        .bind(size_bytes)
        .bind(now_ms())
        .fetch_one(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(SourceMapRecord {
            id,
            release_version: release_version.to_string(),
            debug_id: debug_id.to_string(),
            filename: filename.to_string(),
            blob_sha256: blob_sha256.to_string(),
            size_bytes,
        })
    }

    async fn find_source_map(
        &self,
        organization_id: i64,
        project_id: i64,
        release: Option<&str>,
        debug_id: Option<&str>,
        filename: &str,
    ) -> Result<Option<SourceMapRecord>, String> {
        let mut tx = self.begin_tenant(organization_id).await?;
        if let Some(did) = debug_id {
            if let Some(r) = sqlx::query(
                "SELECT id, release_version, debug_id, filename, blob_sha256, size_bytes
                 FROM source_maps WHERE project_id = $1 AND debug_id = $2 ORDER BY id DESC LIMIT 1",
            )
            .bind(project_id)
            .bind(did)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_pg_err)?
            {
                tx.commit().await.map_err(map_pg_err)?;
                return Ok(Some(SourceMapRecord {
                    id: r.get("id"),
                    release_version: r.get("release_version"),
                    debug_id: r.get("debug_id"),
                    filename: r.get("filename"),
                    blob_sha256: r.get("blob_sha256"),
                    size_bytes: r.get("size_bytes"),
                }));
            }
        }
        let map_name = format!("{filename}.map");
        let rel_s = release.unwrap_or("");
        let row = sqlx::query(
            "SELECT id, release_version, debug_id, filename, blob_sha256, size_bytes
             FROM source_maps
             WHERE project_id = $1 AND (filename = $2 OR filename = $3)
               AND (release_version = $4 OR release_version = '')
             ORDER BY CASE WHEN release_version = $4 THEN 0 ELSE 1 END, id DESC LIMIT 1",
        )
        .bind(project_id)
        .bind(&map_name)
        .bind(filename)
        .bind(rel_s)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(row.map(|r| SourceMapRecord {
            id: r.get("id"),
            release_version: r.get("release_version"),
            debug_id: r.get("debug_id"),
            filename: r.get("filename"),
            blob_sha256: r.get("blob_sha256"),
            size_bytes: r.get("size_bytes"),
        }))
    }

    async fn list_monitors(&self, ctx: &TenantCtx) -> Result<Vec<UptimeMonitorDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let rows = sqlx::query(
            "SELECT id, project_id, uuid, name, expected_interval_sec, last_heartbeat_at, status, is_active, created_at
             FROM uptime_monitors ORDER BY id ASC",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let hb: Option<i64> = r.get("last_heartbeat_at");
                UptimeMonitorDto {
                    id: r.get("id"),
                    project_id: r.get("project_id"),
                    uuid: r.get("uuid"),
                    name: r.get("name"),
                    expected_interval_sec: r.get("expected_interval_sec"),
                    last_heartbeat_at: hb.map(iso_from_ms),
                    status: r.get("status"),
                    is_active: r.get("is_active"),
                    created_at: iso_from_ms(r.get("created_at")),
                }
            })
            .collect())
    }

    async fn create_monitor(
        &self,
        ctx: &TenantCtx,
        project_id: i64,
        name: &str,
        uuid: &str,
        expected_interval_sec: i64,
    ) -> Result<UptimeMonitorDto, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM projects WHERE id = $1")
            .bind(project_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        if exists.is_none() {
            return Err("Project not found in organization".into());
        }
        let now = now_ms();
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO uptime_monitors (organization_id, project_id, uuid, name, expected_interval_sec, status, is_active, created_at)
             VALUES ($1, $2, $3, $4, $5, 'pending', TRUE, $6) RETURNING id",
        )
        .bind(ctx.organization_id)
        .bind(project_id)
        .bind(uuid)
        .bind(name)
        .bind(expected_interval_sec)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(UptimeMonitorDto {
            id,
            project_id,
            uuid: uuid.to_string(),
            name: name.to_string(),
            expected_interval_sec,
            last_heartbeat_at: None,
            status: "pending".into(),
            is_active: true,
            created_at: iso_from_ms(now),
        })
    }

    async fn delete_monitor(&self, ctx: &TenantCtx, monitor_id: i64) -> Result<bool, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let res = sqlx::query("DELETE FROM uptime_monitors WHERE id = $1")
            .bind(monitor_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(res.rows_affected() > 0)
    }

    async fn record_heartbeat(&self, ctx: &TenantCtx, uuid: &str, is_up: bool, message: &str) -> Result<Option<UptimeMonitorDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let now = now_ms();
        let status = if is_up { "up" } else { "down" };
        let row = sqlx::query(
            "UPDATE uptime_monitors SET last_heartbeat_at = $1, status = $2
             WHERE uuid = $3
             RETURNING id, project_id, name, expected_interval_sec, created_at",
        )
        .bind(now)
        .bind(status)
        .bind(uuid)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        let Some(r) = row else {
            return Ok(None);
        };
        let mon_id: i64 = r.get("id");
        sqlx::query(
            "INSERT INTO uptime_checks (organization_id, monitor_id, is_up, message, checked_at) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(ctx.organization_id)
        .bind(mon_id)
        .bind(is_up)
        .bind(message)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(Some(UptimeMonitorDto {
            id: mon_id,
            project_id: r.get("project_id"),
            uuid: uuid.to_string(),
            name: r.get("name"),
            expected_interval_sec: r.get("expected_interval_sec"),
            last_heartbeat_at: Some(iso_from_ms(now)),
            status: status.into(),
            is_active: true,
            created_at: iso_from_ms(r.get("created_at")),
        }))
    }

    async fn get_heartbeat(&self, ctx: &TenantCtx, uuid: &str) -> Result<Option<UptimeMonitorDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let row = sqlx::query(
            "SELECT id, project_id, uuid, name, expected_interval_sec, last_heartbeat_at, status, is_active, created_at
             FROM uptime_monitors WHERE uuid = $1",
        )
        .bind(uuid)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(row.map(|r| {
            let hb: Option<i64> = r.get("last_heartbeat_at");
            UptimeMonitorDto {
                id: r.get("id"),
                project_id: r.get("project_id"),
                uuid: r.get("uuid"),
                name: r.get("name"),
                expected_interval_sec: r.get("expected_interval_sec"),
                last_heartbeat_at: hb.map(iso_from_ms),
                status: r.get("status"),
                is_active: r.get("is_active"),
                created_at: iso_from_ms(r.get("created_at")),
            }
        }))
    }

    async fn list_alert_rules(&self, ctx: &TenantCtx) -> Result<Vec<AlertRuleDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let rows = sqlx::query(
            "SELECT id, project_id, name, trigger_type, threshold_count, window_sec, cooldown_sec,
                    channel_type, target_url, webhook_secret, email_to, last_triggered_at, is_active, created_at
             FROM alert_rules ORDER BY id DESC",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let sec: String = r.get("webhook_secret");
                AlertRuleDto {
                    id: r.get("id"),
                    project_id: r.get("project_id"),
                    name: r.get("name"),
                    trigger_type: r.get("trigger_type"),
                    threshold_count: r.get("threshold_count"),
                    window_sec: r.get("window_sec"),
                    cooldown_sec: r.get("cooldown_sec"),
                    channel_type: r.get("channel_type"),
                    target_url: r.get("target_url"),
                    has_secret: !sec.is_empty(),
                    email_to: r.get("email_to"),
                    last_triggered_at: r.get("last_triggered_at"),
                    is_active: r.get("is_active"),
                    created_at: iso_from_ms(r.get("created_at")),
                }
            })
            .collect())
    }

    async fn create_alert_rule(&self, ctx: &TenantCtx, rule: &NewAlertRule) -> Result<AlertRuleDto, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let owns: Option<i64> = sqlx::query_scalar("SELECT id FROM projects WHERE id = $1")
            .bind(rule.project_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        if owns.is_none() {
            return Err("Project not found in organization".into());
        }
        let enc_secret = seal_secret(&self.app_key, &webhook_aad(ctx.organization_id), &rule.webhook_secret)?;
        let now = now_ms();
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO alert_rules (organization_id, project_id, name, trigger_type, threshold_count, window_sec, cooldown_sec, channel_type, target_url, webhook_secret, email_to, is_active, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,TRUE,$12) RETURNING id",
        )
        .bind(ctx.organization_id)
        .bind(rule.project_id)
        .bind(&rule.name)
        .bind(&rule.trigger_type)
        .bind(rule.threshold_count)
        .bind(rule.window_sec)
        .bind(rule.cooldown_sec)
        .bind(&rule.channel_type)
        .bind(&rule.target_url)
        .bind(&enc_secret)
        .bind(&rule.email_to)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(AlertRuleDto {
            id,
            project_id: rule.project_id,
            name: rule.name.clone(),
            trigger_type: rule.trigger_type.clone(),
            threshold_count: rule.threshold_count,
            window_sec: rule.window_sec,
            cooldown_sec: rule.cooldown_sec,
            channel_type: rule.channel_type.clone(),
            target_url: rule.target_url.clone(),
            has_secret: !rule.webhook_secret.is_empty(),
            email_to: rule.email_to.clone(),
            last_triggered_at: None,
            is_active: true,
            created_at: iso_from_ms(now),
        })
    }

    async fn delete_alert_rule(&self, ctx: &TenantCtx, rule_id: i64) -> Result<bool, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let res = sqlx::query("DELETE FROM alert_rules WHERE id = $1")
            .bind(rule_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(res.rows_affected() > 0)
    }

    async fn get_alert_rule(&self, ctx: &TenantCtx, rule_id: i64) -> Result<Option<AlertRuleDto>, String> {
        Ok(self.get_alert_rule_for_dispatch(ctx, rule_id).await?.map(|(dto, _)| dto))
    }

    async fn get_alert_rule_for_dispatch(&self, ctx: &TenantCtx, rule_id: i64) -> Result<Option<(AlertRuleDto, String)>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let row = sqlx::query(
            "SELECT id, project_id, name, trigger_type, threshold_count, window_sec, cooldown_sec,
                    channel_type, target_url, webhook_secret, email_to, last_triggered_at, is_active, created_at
             FROM alert_rules WHERE id = $1",
        )
        .bind(rule_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(row.map(|r| {
            let stored: String = r.get("webhook_secret");
            let sec = open_webhook_secret(&self.app_key, ctx.organization_id, &stored);
            let dto = AlertRuleDto {
                id: r.get("id"),
                project_id: r.get("project_id"),
                name: r.get("name"),
                trigger_type: r.get("trigger_type"),
                threshold_count: r.get("threshold_count"),
                window_sec: r.get("window_sec"),
                cooldown_sec: r.get("cooldown_sec"),
                channel_type: r.get("channel_type"),
                target_url: r.get("target_url"),
                has_secret: !stored.is_empty(),
                email_to: r.get("email_to"),
                last_triggered_at: r.get("last_triggered_at"),
                is_active: r.get("is_active"),
                created_at: iso_from_ms(r.get("created_at")),
            };
            (dto, sec)
        }))
    }

    async fn list_api_tokens(&self, ctx: &TenantCtx) -> Result<Vec<ApiTokenDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let rows = sqlx::query(
            "SELECT id, name, token_prefix, role, scopes, last_used_at, expires_at, created_at FROM api_tokens ORDER BY id DESC",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let lu: Option<i64> = r.get("last_used_at");
                let exp: Option<i64> = r.get("expires_at");
                ApiTokenDto {
                    id: r.get("id"),
                    name: r.get("name"),
                    token_prefix: r.get("token_prefix"),
                    role: r.get("role"),
                    scopes: r.get("scopes"),
                    last_used_at: lu.map(iso_from_ms),
                    expires_at: exp.map(|s| iso_from_ms(s * 1000)),
                    created_at: iso_from_ms(r.get("created_at")),
                }
            })
            .collect())
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
        let uid = ctx.user_id.ok_or("Missing actor user_id")?;
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let now = now_ms();
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO api_tokens (organization_id, user_id, name, token_sha256, token_prefix, role, scopes, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
        )
        .bind(ctx.organization_id)
        .bind(uid)
        .bind(name)
        .bind(token_sha256)
        .bind(token_prefix)
        .bind(role.as_str())
        .bind(scopes)
        .bind(expires_at)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        sqlx::query(
            "INSERT INTO api_token_lookup (token_sha256, organization_id, organization_slug, user_id, role, scopes, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(token_sha256)
        .bind(ctx.organization_id)
        .bind(&ctx.organization_slug)
        .bind(uid)
        .bind(role.as_str())
        .bind(scopes)
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        tx.commit().await.map_err(map_pg_err)?;
        Ok(ApiTokenDto {
            id,
            name: name.to_string(),
            token_prefix: token_prefix.to_string(),
            role: role.as_str().to_string(),
            scopes: scopes.to_string(),
            last_used_at: None,
            expires_at: expires_at.map(|s| iso_from_ms(s * 1000)),
            created_at: iso_from_ms(now),
        })
    }

    async fn delete_api_token(&self, ctx: &TenantCtx, token_id: i64) -> Result<bool, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let sha: Option<String> = sqlx::query_scalar(
            "DELETE FROM api_tokens WHERE id = $1 RETURNING token_sha256",
        )
        .bind(token_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        if let Some(s) = &sha {
            sqlx::query("DELETE FROM api_token_lookup WHERE token_sha256 = $1")
                .bind(s)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
        }
        tx.commit().await.map_err(map_pg_err)?;
        Ok(sha.is_some())
    }

    async fn list_members(&self, ctx: &TenantCtx) -> Result<Vec<MemberDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let rows = sqlx::query(
            "SELECT u.id, u.email, u.name, m.role, u.is_active
             FROM organization_members m JOIN users u ON u.id = m.user_id ORDER BY u.id ASC",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(rows
            .into_iter()
            .map(|r| MemberDto {
                user_id: r.get("id"),
                email: r.get("email"),
                name: r.get("name"),
                role: r.get("role"),
                is_active: r.get("is_active"),
            })
            .collect())
    }

    async fn invite_member(
        &self,
        ctx: &TenantCtx,
        email: &str,
        name: &str,
        password_hash: &str,
        role: UserRole,
    ) -> Result<MemberDto, String> {
        let email_norm = email.trim().to_ascii_lowercase();
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let existing_uid: Option<i64> =
            sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
                .bind(&email_norm)
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_pg_err)?;
        let uid = match existing_uid {
            Some(id) => id,
            None => sqlx::query_scalar(
                "INSERT INTO users (email, name, password_hash, is_active, created_at) VALUES ($1, $2, $3, TRUE, $4) RETURNING id",
            )
            .bind(&email_norm)
            .bind(name)
            .bind(password_hash)
            .bind(now_ms())
            .fetch_one(&mut *tx)
            .await
            .map_err(map_pg_err)?,
        };
        sqlx::query(
            "INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1, $2, $3)
             ON CONFLICT (organization_id, user_id) DO UPDATE SET role = $3",
        )
        .bind(ctx.organization_id)
        .bind(uid)
        .bind(role.as_str())
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(MemberDto {
            user_id: uid,
            email: email_norm,
            name: name.to_string(),
            role: role.as_str().to_string(),
            is_active: true,
        })
    }

    async fn update_member_role(&self, ctx: &TenantCtx, target_user_id: i64, role: UserRole) -> Result<Result<MemberDto, String>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(ctx.organization_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let current: Option<String> = sqlx::query_scalar(
            "SELECT role FROM organization_members WHERE user_id = $1 FOR UPDATE",
        )
        .bind(target_user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        let Some(curr) = current else {
            return Ok(Err("Member not found".into()));
        };
        if curr == "owner" && role != UserRole::Owner {
            let owners: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM organization_members WHERE role = 'owner'",
            )
            .fetch_one(&mut *tx)
            .await
            .map_err(map_pg_err)?;
            if owners <= 1 {
                return Ok(Err("Cannot demote the last organization owner".into()));
            }
        }
        sqlx::query("UPDATE organization_members SET role = $1 WHERE user_id = $2")
            .bind(role.as_str())
            .bind(target_user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        // Invalidate existing sessions & lookup rows + revoke any API tokens above the new role
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(target_user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        sqlx::query("DELETE FROM session_lookup WHERE user_id = $1")
            .bind(target_user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let tok_rows: Vec<(i64, String, String)> = sqlx::query_as(
            "SELECT id, token_sha256, role FROM api_tokens WHERE user_id = $1",
        )
        .bind(target_user_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        for (tid, tsha, trole) in tok_rows {
            if UserRole::from_db(&trole).map(|r| r.rank() > role.rank()).unwrap_or(true) {
                sqlx::query("DELETE FROM api_tokens WHERE id = $1")
                    .bind(tid)
                    .execute(&mut *tx)
                    .await
                    .map_err(map_pg_err)?;
                sqlx::query("DELETE FROM api_token_lookup WHERE token_sha256 = $1")
                    .bind(&tsha)
                    .execute(&mut *tx)
                    .await
                    .map_err(map_pg_err)?;
            }
        }
        let r = sqlx::query(
            "SELECT u.id, u.email, u.name, m.role, u.is_active
             FROM organization_members m JOIN users u ON u.id = m.user_id WHERE m.user_id = $1",
        )
        .bind(target_user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(Ok(MemberDto {
            user_id: r.get("id"),
            email: r.get("email"),
            name: r.get("name"),
            role: r.get("role"),
            is_active: r.get("is_active"),
        }))
    }

    async fn remove_member(&self, ctx: &TenantCtx, target_user_id: i64) -> Result<Result<bool, String>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(ctx.organization_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let current: Option<String> = sqlx::query_scalar(
            "SELECT role FROM organization_members WHERE user_id = $1 FOR UPDATE",
        )
        .bind(target_user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        let Some(curr) = current else {
            return Ok(Ok(false));
        };
        if curr == "owner" {
            let owners: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM organization_members WHERE role = 'owner'",
            )
            .fetch_one(&mut *tx)
            .await
            .map_err(map_pg_err)?;
            if owners <= 1 {
                return Ok(Err("Cannot remove the last organization owner".into()));
            }
        }
        sqlx::query("DELETE FROM organization_members WHERE user_id = $1")
            .bind(target_user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(target_user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        sqlx::query("DELETE FROM session_lookup WHERE user_id = $1")
            .bind(target_user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        sqlx::query("DELETE FROM api_tokens WHERE user_id = $1")
            .bind(target_user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        sqlx::query("DELETE FROM api_token_lookup WHERE user_id = $1")
            .bind(target_user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(Ok(true))
    }

    async fn begin_idempotency(
        &self,
        ctx: &TenantCtx,
        action: &str,
        idem_key: &str,
        payload_sha256: &str,
    ) -> Result<IdempotencyCheck, String> {
        let uid = ctx.user_id.unwrap_or(0);
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let existing: Option<(String, i32, String, bool)> = sqlx::query_as(
            "SELECT payload_sha256, status_code, response_body, in_flight
             FROM idempotency_keys WHERE user_id = $1 AND action = $2 AND idem_key = $3 FOR UPDATE",
        )
        .bind(uid)
        .bind(action)
        .bind(idem_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        match existing {
            Some((old_sha, status, body, in_flight)) => {
                if in_flight {
                    return Ok(IdempotencyCheck::Conflict("Request in-flight".into()));
                }
                if old_sha != payload_sha256 {
                    return Ok(IdempotencyCheck::Conflict("Idempotency-Key payload mismatch".into()));
                }
                Ok(IdempotencyCheck::Replay {
                    status_code: status as u16,
                    body,
                })
            }
            None => {
                sqlx::query(
                    "INSERT INTO idempotency_keys (organization_id, user_id, action, idem_key, payload_sha256, status_code, response_body, in_flight, created_at)
                     VALUES ($1, $2, $3, $4, $5, 0, '', TRUE, $6)",
                )
                .bind(ctx.organization_id)
                .bind(uid)
                .bind(action)
                .bind(idem_key)
                .bind(payload_sha256)
                .bind(now_ms())
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
                tx.commit().await.map_err(map_pg_err)?;
                Ok(IdempotencyCheck::Proceed)
            }
        }
    }

    async fn finish_idempotency(
        &self,
        ctx: &TenantCtx,
        action: &str,
        idem_key: &str,
        status_code: u16,
        response_body: &str,
    ) -> Result<(), String> {
        let uid = ctx.user_id.unwrap_or(0);
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        sqlx::query(
            "UPDATE idempotency_keys SET status_code = $1, response_body = $2, in_flight = FALSE
             WHERE user_id = $3 AND action = $4 AND idem_key = $5",
        )
        .bind(status_code as i32)
        .bind(response_body)
        .bind(uid)
        .bind(action)
        .bind(idem_key)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(())
    }

    async fn flush_ingest_batch(&self, items: Vec<IngestWriteItem>) -> Result<Vec<AlertDispatchJob>, String> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let mut by_org: HashMap<i64, Vec<IngestWriteItem>> = HashMap::new();
        for it in items {
            let oid = match &it {
                IngestWriteItem::Event { auth, .. } => auth.organization_id,
                IngestWriteItem::Logs { organization_id, .. } => *organization_id,
                IngestWriteItem::Transaction { organization_id, .. } => *organization_id,
                IngestWriteItem::Session { organization_id, .. } => *organization_id,
                IngestWriteItem::CheckIn { organization_id, .. } => *organization_id,
            };
            by_org.entry(oid).or_default().push(it);
        }

        let mut alerts = Vec::new();
        let now_sec = chrono::Utc::now().timestamp();
        for (org_id, org_items) in by_org {
            let mut tx = self.begin_tenant(org_id).await?;
            for item in org_items {
                match item {
                    IngestWriteItem::Event { auth, meta, payload_json, received_ms } => {
                        let store_blob = self.should_sample_storm(
                            auth.project_id,
                            &meta.fingerprint,
                            &auth.filters,
                            received_ms,
                        );
                        let (issue_id, short_id, is_new, is_reg) =
                            pg_insert_event_in_tx(&mut tx, &auth, &meta, &payload_json, received_ms, store_blob).await?;
                        if issue_id > 0 {
                            let jobs = pg_build_alert_jobs_for_event(
                                &mut tx,
                                &self.app_key,
                                auth.organization_id,
                                auth.project_id,
                                &auth.project_slug,
                                &short_id,
                                &meta.title,
                                &meta.level,
                                is_new,
                                is_reg,
                                now_sec,
                            )
                            .await?;
                            alerts.extend(jobs);
                        }
                    }
                    IngestWriteItem::Logs { organization_id, project_id, project_slug, auto_promote_level, logs } => {
                        for l in logs {
                            let uid = Uuid::parse_str(&new_uuid_v7_from_ms(l.timestamp_ms)).unwrap_or_else(|_| Uuid::now_v7());
                            sqlx::query(
                                "INSERT INTO log_events (id, organization_id, project_id, timestamp_ms, level_num, severity_number, body, service, environment, host, trace_id, span_id, attributes_json)
                                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
                            )
                            .bind(uid)
                            .bind(organization_id)
                            .bind(project_id)
                            .bind(l.timestamp_ms)
                            .bind(l.level.num())
                            .bind(l.severity_number.map(|n| n as i32))
                            .bind(&l.body)
                            .bind(&l.service)
                            .bind(&l.environment)
                            .bind(&l.host)
                            .bind(&l.trace_id)
                            .bind(&l.span_id)
                            .bind(&l.attributes)
                            .execute(&mut *tx)
                            .await
                            .map_err(map_pg_err)?;

                            for (rt, val) in [("service", &l.service), ("environment", &l.environment), ("host", &l.host)] {
                                if !val.is_empty() {
                                    sqlx::query(
                                        "INSERT INTO log_resources (organization_id, resource_type, name, last_seen)
                                         VALUES ($1,$2,$3,$4)
                                         ON CONFLICT (organization_id, resource_type, name) DO UPDATE SET last_seen = GREATEST(log_resources.last_seen, EXCLUDED.last_seen)",
                                    )
                                    .bind(organization_id)
                                    .bind(rt)
                                    .bind(val)
                                    .bind(l.timestamp_ms)
                                    .execute(&mut *tx)
                                    .await
                                    .map_err(map_pg_err)?;
                                }
                            }

                            let bh = (l.timestamp_ms / 3_600_000) * 3_600_000;
                            sqlx::query(
                                "INSERT INTO hourly_stats (organization_id, project_id, bucket_hour, category, quantity)
                                 VALUES ($1,$2,$3,'log',1)
                                 ON CONFLICT (project_id, bucket_hour, category) DO UPDATE SET quantity = hourly_stats.quantity + 1",
                            )
                            .bind(organization_id)
                            .bind(project_id)
                            .bind(bh)
                            .execute(&mut *tx)
                            .await
                            .map_err(map_pg_err)?;

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
                                    let (issue_id, short_id, is_new, is_reg) =
                                        pg_insert_event_in_tx(&mut tx, &synth_auth, &meta, &bytes, l.timestamp_ms, true).await?;
                                    if issue_id > 0 {
                                        let jobs = pg_build_alert_jobs_for_event(
                                            &mut tx,
                                            &self.app_key,
                                            organization_id,
                                            project_id,
                                            &project_slug,
                                            &short_id,
                                            &meta.title,
                                            l.level.as_str(),
                                            is_new,
                                            is_reg,
                                            now_sec,
                                        )
                                        .await?;
                                        alerts.extend(jobs);
                                        fatal_alert_checked = true;
                                    }
                                }
                            }
                            if !fatal_alert_checked && l.level == LogLevel::Fatal {
                                let jobs = pg_build_alert_jobs_for_event(
                                    &mut tx,
                                    &self.app_key,
                                    organization_id,
                                    project_id,
                                    &project_slug,
                                    "LOG",
                                    &l.body,
                                    "fatal",
                                    false,
                                    false,
                                    now_sec,
                                )
                                .await?;
                                alerts.extend(jobs);
                            }
                        }
                    }
                    IngestWriteItem::Transaction { organization_id, project_id, tx: tr } => {
                        let uid = Uuid::parse_str(&new_uuid_v7_from_ms(tr.timestamp_ms)).unwrap_or_else(|_| Uuid::now_v7());
                        sqlx::query(
                            "INSERT INTO transaction_events (id, organization_id, project_id, name, op, status, duration_ms, trace_id, span_id, environment, release, spans_json, timestamp_ms)
                             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
                        )
                        .bind(uid)
                        .bind(organization_id)
                        .bind(project_id)
                        .bind(&tr.name)
                        .bind(&tr.op)
                        .bind(&tr.status)
                        .bind(tr.duration_ms)
                        .bind(&tr.trace_id)
                        .bind(&tr.span_id)
                        .bind(&tr.environment)
                        .bind(&tr.release)
                        .bind(&tr.spans)
                        .bind(tr.timestamp_ms)
                        .execute(&mut *tx)
                        .await
                        .map_err(map_pg_err)?;

                        let bh = (tr.timestamp_ms / 3_600_000) * 3_600_000;
                        sqlx::query(
                            "INSERT INTO hourly_stats (organization_id, project_id, bucket_hour, category, quantity)
                             VALUES ($1,$2,$3,'transaction',1)
                             ON CONFLICT (project_id, bucket_hour, category) DO UPDATE SET quantity = hourly_stats.quantity + 1",
                        )
                        .bind(organization_id)
                        .bind(project_id)
                        .bind(bh)
                        .execute(&mut *tx)
                        .await
                        .map_err(map_pg_err)?;
                    }
                    IngestWriteItem::Session { organization_id, project_id, session, received_ms } => {
                        let bh = (received_ms / 3_600_000) * 3_600_000;
                        sqlx::query(
                            "INSERT INTO releases (organization_id, project_id, version, first_seen, last_seen)
                             VALUES ($1,$2,$3,$4,$4)
                             ON CONFLICT (project_id, version) DO UPDATE SET last_seen = GREATEST(releases.last_seen, EXCLUDED.last_seen)",
                        )
                        .bind(organization_id)
                        .bind(project_id)
                        .bind(&session.release)
                        .bind(received_ms)
                        .execute(&mut *tx)
                        .await
                        .map_err(map_pg_err)?;
                        let (h, e, c, a) = match session.status.as_str() {
                            "crashed" => (0i64, 0, 1, 0),
                            "abnormal" => (0, 0, 0, 1),
                            _ if session.errors > 0 || session.status == "errored" => (0, 1, 0, 0),
                            _ if session.init || session.status == "exited" || session.status == "ok" => (1, 0, 0, 0),
                            _ => (0, 0, 0, 0),
                        };
                        sqlx::query(
                            "INSERT INTO release_sessions (organization_id, project_id, release_version, environment, bucket_hour, healthy_count, errored_count, crashed_count, abnormal_count)
                             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                             ON CONFLICT (project_id, release_version, environment, bucket_hour)
                             DO UPDATE SET healthy_count = release_sessions.healthy_count + $6,
                                           errored_count = release_sessions.errored_count + $7,
                                           crashed_count = release_sessions.crashed_count + $8,
                                           abnormal_count = release_sessions.abnormal_count + $9",
                        )
                        .bind(organization_id)
                        .bind(project_id)
                        .bind(&session.release)
                        .bind(&session.environment)
                        .bind(bh)
                        .bind(h)
                        .bind(e)
                        .bind(c)
                        .bind(a)
                        .execute(&mut *tx)
                        .await
                        .map_err(map_pg_err)?;
                    }
                    IngestWriteItem::CheckIn { organization_id, project_id, check_in, received_ms } => {
                        let is_up = check_in.status != "error";
                        let status = if is_up { "up" } else { "down" };
                        let mon_id: Option<i64> = sqlx::query_scalar(
                            "UPDATE uptime_monitors SET last_heartbeat_at = $1, status = $2
                             WHERE project_id = $3 AND (uuid = $4 OR name = $4) RETURNING id",
                        )
                        .bind(received_ms)
                        .bind(status)
                        .bind(project_id)
                        .bind(&check_in.monitor_slug)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(map_pg_err)?;
                        if let Some(mid) = mon_id {
                            sqlx::query(
                                "INSERT INTO uptime_checks (organization_id, monitor_id, is_up, duration_ms, checked_at)
                                 VALUES ($1,$2,$3,$4,$5)",
                            )
                            .bind(organization_id)
                            .bind(mid)
                            .bind(is_up)
                            .bind(check_in.duration_ms)
                            .bind(received_ms)
                            .execute(&mut *tx)
                            .await
                            .map_err(map_pg_err)?;
                        }
                    }
                }
            }
            tx.commit().await.map_err(map_pg_err)?;
        }
        Ok(alerts)
    }

    async fn run_maintenance(&self, retention_days: u32, max_db_mb: u64) -> Result<Vec<AlertDispatchJob>, String> {
        let now = now_ms();
        let cutoff_ms = now - (retention_days as i64) * 86_400_000;
        let now_sec = now / 1000;
        let size_bytes = self.db_size_bytes().await;
        let max_bytes = max_db_mb * 1024 * 1024;
        let over_budget = size_bytes > max_bytes;

        let mut scan_tx = self.pool.begin().await.map_err(map_pg_err)?;
        sqlx::query("SELECT set_config('app.maintenance_scan', '1', true)")
            .execute(&mut *scan_tx)
            .await
            .map_err(map_pg_err)?;
        sqlx::query("DELETE FROM session_lookup WHERE expires_at <= EXTRACT(EPOCH FROM NOW())::bigint")
            .execute(&mut *scan_tx)
            .await
            .map_err(map_pg_err)?;
        let _ = sqlx::query("DELETE FROM invitation_lookup WHERE expires_at <= EXTRACT(EPOCH FROM NOW())::bigint")
            .execute(&mut *scan_tx)
            .await;
        let _ = sqlx::query("DELETE FROM mfa_challenges WHERE expires_at <= $1")
            .bind(now_sec)
            .execute(&mut *scan_tx)
            .await;
        let _ = sqlx::query("DELETE FROM webauthn_challenges WHERE expires_at <= $1")
            .bind(now_sec)
            .execute(&mut *scan_tx)
            .await;
        let org_ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM organizations ORDER BY id ASC")
            .fetch_all(&mut *scan_tx)
            .await
            .map_err(map_pg_err)?;
        scan_tx.commit().await.map_err(map_pg_err)?;

        let mut alerts = Vec::new();
        for org_id in org_ids {
            let mut tx = self.begin_tenant(org_id).await?;
            sqlx::query("DELETE FROM sessions WHERE expires_at <= $1")
                .bind(now_sec)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
            sqlx::query("DELETE FROM org_invitations WHERE accepted_at IS NULL AND expires_at <= $1")
                .bind(now_sec)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
            sqlx::query("DELETE FROM invitation_lookup WHERE accepted_at IS NULL AND expires_at <= $1")
                .bind(now_sec)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
            sqlx::query("DELETE FROM api_tokens WHERE expires_at IS NOT NULL AND expires_at <= $1")
                .bind(now_sec)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
            sqlx::query("DELETE FROM api_token_lookup WHERE expires_at IS NOT NULL AND expires_at <= $1")
                .bind(now_sec)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
            sqlx::query("DELETE FROM idempotency_keys WHERE created_at < $1")
                .bind(now - 86_400_000)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
            sqlx::query("DELETE FROM issue_events WHERE timestamp_ms < $1")
                .bind(cutoff_ms)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
            sqlx::query("DELETE FROM log_events WHERE timestamp_ms < $1")
                .bind(cutoff_ms)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
            sqlx::query("DELETE FROM transaction_events WHERE timestamp_ms < $1")
                .bind(cutoff_ms)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
            sqlx::query("DELETE FROM security_events WHERE timestamp_ms < $1")
                .bind(cutoff_ms)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
            sqlx::query("DELETE FROM shield_quarantine WHERE expires_at <= $1")
                .bind(now_sec)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;

            if over_budget {
                sqlx::query(
                    "DELETE FROM log_events WHERE id IN (SELECT id FROM log_events ORDER BY id ASC LIMIT 2000)",
                )
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
                sqlx::query(
                    "DELETE FROM issue_events WHERE id IN (SELECT id FROM issue_events ORDER BY timestamp_ms ASC LIMIT 1000)",
                )
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
            }

            let down_rows: Vec<(i64, i64, String, String, String)> = sqlx::query_as(
                "SELECT m.id, m.project_id, p.slug, m.name, m.uuid
                 FROM uptime_monitors m
                 JOIN projects p ON p.id = m.project_id
                 WHERE m.is_active = TRUE AND m.status = 'up'
                   AND m.last_heartbeat_at IS NOT NULL
                   AND ($1 - m.last_heartbeat_at) > (m.expected_interval_sec * 1500)",
            )
            .bind(now)
            .fetch_all(&mut *tx)
            .await
            .map_err(map_pg_err)?;

            for (mon_id, proj_id, pslug, mname, muuid) in down_rows {
                sqlx::query("UPDATE uptime_monitors SET status = 'down' WHERE id = $1")
                    .bind(mon_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(map_pg_err)?;
                sqlx::query(
                    "INSERT INTO uptime_checks (organization_id, monitor_id, is_up, message, checked_at)
                     VALUES ($1, $2, FALSE, 'Heartbeat missed', $3)",
                )
                .bind(org_id)
                .bind(mon_id)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;

                let rules = sqlx::query(
                    "SELECT id, name, channel_type, target_url, webhook_secret, email_to, cooldown_sec, last_triggered_at
                     FROM alert_rules WHERE project_id = $1 AND trigger_type = 'uptime_down' AND is_active = TRUE",
                )
                .bind(proj_id)
                .fetch_all(&mut *tx)
                .await
                .map_err(map_pg_err)?;

                let mut fired = Vec::new();
                for rr in rules {
                    let rid: i64 = rr.get("id");
                    let cd: i64 = rr.get("cooldown_sec");
                    let lt: Option<i64> = rr.get("last_triggered_at");
                    if lt.map(|t| now_sec - t >= cd).unwrap_or(true) {
                        fired.push(rid);
                        alerts.push(AlertDispatchJob {
                            rule_id: rid,
                            rule_name: rr.get("name"),
                            channel_type: rr.get("channel_type"),
                            target_url: rr.get("target_url"),
                            webhook_secret: open_webhook_secret(&self.app_key, org_id, &rr.get::<String, _>("webhook_secret")),
                            email_to: rr.get("email_to"),
                            title: format!("Uptime monitor down: {mname}"),
                            message: format!("Heartbeat missed for monitor {muuid}"),
                            level: "fatal".into(),
                            project_slug: pslug.clone(),
                            short_id: None,
                        });
                    }
                }
                for rid in fired {
                    sqlx::query("UPDATE alert_rules SET last_triggered_at = $1 WHERE id = $2")
                        .bind(now_sec)
                        .bind(rid)
                        .execute(&mut *tx)
                        .await
                        .map_err(map_pg_err)?;
                }
            }

            tx.commit().await.map_err(map_pg_err)?;
        }

        Ok(alerts)
    }

    async fn db_size_bytes(&self) -> u64 {
        sqlx::query_scalar::<_, i64>("SELECT COALESCE(pg_database_size(current_database()), 0)::bigint")
            .fetch_one(&self.pool)
            .await
            .map(|v| v.max(0) as u64)
            .unwrap_or(0)
    }

    async fn check_health(&self) -> Result<StorageHealthInfo, String> {
        let _: i32 = sqlx::query_scalar("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map_err(map_pg_err)?;

        let rolbypassrls: bool = sqlx::query_scalar(
            "SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_pg_err)?
        .unwrap_or(true);

        let rls_row = sqlx::query(
            "SELECT relrowsecurity, relforcerowsecurity
             FROM pg_class
             WHERE relname = 'issues' AND relnamespace = current_schema()::regnamespace",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_pg_err)?;

        let (rel_rls, rel_force_rls) = match rls_row {
            Some(row) => (
                row.try_get::<bool, _>("relrowsecurity").unwrap_or(false),
                row.try_get::<bool, _>("relforcerowsecurity").unwrap_or(false),
            ),
            None => (false, false),
        };

        let rls_verified = !rolbypassrls && rel_rls && rel_force_rls;
        let detail = format!(
            "PostgreSQL reachable (nobypassrls={}, issues_rls={}, issues_force_rls={})",
            !rolbypassrls, rel_rls, rel_force_rls
        );
        Ok(StorageHealthInfo {
            engine: "postgres".to_string(),
            ok: true,
            detail,
            wal_or_rls_verified: rls_verified,
        })
    }

    async fn record_security_event(
        &self,
        ev: &NewSecurityEvent,
    ) -> Result<(SecurityEventDto, Vec<AlertDispatchJob>), String> {
        let mut tx = self.begin_tenant(ev.organization_id).await?;
        let now_sec = ev.timestamp_ms / 1000;

        let row_id: i64 = sqlx::query_scalar(
            "INSERT INTO security_events
             (organization_id, project_id, signal_type, category, severity, risk_score, source_kind, actor_hmac, session_id, path, details_json, action_taken, timestamp_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             RETURNING id",
        )
        .bind(ev.organization_id)
        .bind(ev.project_id)
        .bind(&ev.signal_type)
        .bind(&ev.category)
        .bind(&ev.severity)
        .bind(ev.risk_score as i32)
        .bind(&ev.source_kind)
        .bind(&ev.actor_hmac)
        .bind(&ev.session_id)
        .bind(&ev.path)
        .bind(&ev.details_json)
        .bind(&ev.action_taken)
        .bind(ev.timestamp_ms)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        if let Some((ref stype, ref shmac, exp_sec)) = ev.quarantine {
            sqlx::query(
                "INSERT INTO shield_quarantine
                 (organization_id, project_id, subject_type, subject_hmac, reason, risk_score, expires_at, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT(organization_id, project_id, subject_type, subject_hmac) DO UPDATE SET
                   reason = EXCLUDED.reason,
                   risk_score = GREATEST(shield_quarantine.risk_score, EXCLUDED.risk_score),
                   expires_at = GREATEST(shield_quarantine.expires_at, EXCLUDED.expires_at)",
            )
            .bind(ev.organization_id)
            .bind(ev.project_id)
            .bind(stype)
            .bind(shmac)
            .bind(&ev.signal_type)
            .bind(ev.risk_score as i32)
            .bind(exp_sec)
            .bind(now_sec)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        }

        let rule_rows = sqlx::query(
            "SELECT id, name, trigger_type, cooldown_sec, channel_type, target_url, webhook_secret, email_to, last_triggered_at
             FROM alert_rules
             WHERE project_id = $1 AND is_active = TRUE
               AND (trigger_type = 'security_threat' OR ($2 = 'secret_leak' AND trigger_type = 'secret_leak'))",
        )
        .bind(ev.project_id)
        .bind(&ev.category)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        let mut alerts = Vec::new();
        let mut fired = Vec::new();
        for r in rule_rows {
            let rid: i64 = r.get("id");
            let cd: i64 = r.get("cooldown_sec");
            let last: Option<i64> = r.get("last_triggered_at");
            if last.map(|t| now_sec - t >= cd).unwrap_or(true) {
                let trig: String = r.get("trigger_type");
                fired.push(rid);
                alerts.push(AlertDispatchJob {
                    rule_id: rid,
                    rule_name: r.get("name"),
                    channel_type: r.get("channel_type"),
                    target_url: r.get("target_url"),
                    webhook_secret: open_webhook_secret(&self.app_key, ev.organization_id, &r.get::<String, _>("webhook_secret")),
                    email_to: r.get("email_to"),
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
        for rid in fired {
            sqlx::query("UPDATE alert_rules SET last_triggered_at = $1 WHERE id = $2")
                .bind(now_sec)
                .bind(rid)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
        }

        tx.commit().await.map_err(map_pg_err)?;
        Ok((
            SecurityEventDto {
                id: row_id,
                project_id: ev.project_id,
                signal_type: ev.signal_type.clone(),
                category: ev.category.clone(),
                severity: ev.severity.clone(),
                risk_score: ev.risk_score as i64,
                source_kind: ev.source_kind.clone(),
                actor_hmac: ev.actor_hmac.clone(),
                session_id: ev.session_id.clone(),
                path: ev.path.clone(),
                details_json: ev.details_json.clone(),
                action_taken: ev.action_taken.clone(),
                timestamp: iso_from_ms(ev.timestamp_ms),
            },
            alerts,
        ))
    }

    async fn list_security_events(
        &self,
        ctx: &TenantCtx,
        project_id: Option<i64>,
        limit: i64,
    ) -> Result<(Vec<SecurityEventDto>, ShieldSummaryDto), String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let now = now_ms();
        let since_24h = now - 86_400_000;
        let now_sec = now / 1000;
        let lim = limit.clamp(1, 200);

        let stats_row = sqlx::query(
            "SELECT
               COUNT(*)::bigint AS total,
               COALESCE(SUM(CASE WHEN severity IN ('high', 'critical') THEN 1 ELSE 0 END), 0)::bigint AS hc,
               COALESCE(SUM(CASE WHEN category = 'secret_leak' THEN 1 ELSE 0 END), 0)::bigint AS leaks
             FROM security_events
             WHERE timestamp_ms >= $1 AND ($2::bigint IS NULL OR project_id = $2)",
        )
        .bind(since_24h)
        .bind(project_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        let active_q: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM shield_quarantine WHERE expires_at > $1 AND ($2::bigint IS NULL OR project_id = $2)",
        )
        .bind(now_sec)
        .bind(project_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        let rows = sqlx::query(
            "SELECT id, project_id, signal_type, category, severity, risk_score, source_kind,
                    actor_hmac, session_id, path, details_json, action_taken, timestamp_ms
             FROM security_events
             WHERE ($1::bigint IS NULL OR project_id = $1)
             ORDER BY timestamp_ms DESC, id DESC
             LIMIT $2",
        )
        .bind(project_id)
        .bind(lim)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        let items = rows
            .into_iter()
            .map(|r| SecurityEventDto {
                id: r.get("id"),
                project_id: r.get("project_id"),
                signal_type: r.get("signal_type"),
                category: r.get("category"),
                severity: r.get("severity"),
                risk_score: r.get::<i32, _>("risk_score") as i64,
                source_kind: r.get("source_kind"),
                actor_hmac: r.get("actor_hmac"),
                session_id: r.get("session_id"),
                path: r.get("path"),
                details_json: r.get::<Value, _>("details_json"),
                action_taken: r.get("action_taken"),
                timestamp: iso_from_ms(r.get("timestamp_ms")),
            })
            .collect();

        tx.commit().await.map_err(map_pg_err)?;
        Ok((
            items,
            ShieldSummaryDto {
                events_24h: stats_row.get("total"),
                high_critical_24h: stats_row.get("hc"),
                secret_leaks_24h: stats_row.get("leaks"),
                active_quarantines: active_q,
            },
        ))
    }

    async fn list_quarantine(
        &self,
        ctx: &TenantCtx,
        project_id: Option<i64>,
    ) -> Result<Vec<QuarantineEntryDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let now_sec = now_ms() / 1000;
        let rows = sqlx::query(
            "SELECT id, project_id, subject_type, subject_hmac, reason, risk_score, expires_at, created_at
             FROM shield_quarantine
             WHERE expires_at > $1 AND ($2::bigint IS NULL OR project_id = $2)
             ORDER BY expires_at DESC, id DESC
             LIMIT 250",
        )
        .bind(now_sec)
        .bind(project_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        let out = rows
            .into_iter()
            .map(|r| QuarantineEntryDto {
                id: r.get("id"),
                project_id: r.get("project_id"),
                subject_type: r.get("subject_type"),
                subject_hmac: r.get("subject_hmac"),
                reason: r.get("reason"),
                risk_score: r.get::<i32, _>("risk_score") as i64,
                expires_at: iso_from_ms(r.get::<i64, _>("expires_at") * 1000),
                created_at: iso_from_ms(r.get::<i64, _>("created_at") * 1000),
            })
            .collect();
        tx.commit().await.map_err(map_pg_err)?;
        Ok(out)
    }

    async fn delete_quarantine(&self, ctx: &TenantCtx, entry_id: i64) -> Result<bool, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let res = sqlx::query("DELETE FROM shield_quarantine WHERE id = $1")
            .bind(entry_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(res.rows_affected() > 0)
    }

    async fn update_project_key(
        &self,
        ctx: &TenantCtx,
        project_slug: &str,
        key_id: i64,
        rate_limit_per_min: u32,
        is_active: bool,
    ) -> Result<Option<ProjectKeyDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let rpm = rate_limit_per_min.clamp(10, 100_000) as i32;
        let row = sqlx::query(
            "UPDATE project_keys k SET rate_limit_per_min = $1, is_active = $2
             FROM projects p
             WHERE k.project_id = p.id AND p.slug = $3 AND k.id = $4
             RETURNING k.id, k.project_id, k.label, k.public_key, k.key_sha256, k.rate_limit_per_min, k.is_active, k.created_at",
        )
        .bind(rpm)
        .bind(is_active)
        .bind(project_slug)
        .bind(key_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        let Some(r) = row else {
            return Ok(None);
        };
        let key_sha: String = r.get("key_sha256");
        sqlx::query("UPDATE dsn_key_lookup SET rate_limit_per_min = $1, is_active = $2 WHERE key_sha256 = $3")
            .bind(rpm)
            .bind(is_active)
            .bind(&key_sha)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(Some(ProjectKeyDto {
            id: r.get("id"),
            project_id: r.get("project_id"),
            label: r.get("label"),
            public_key: r.get("public_key"),
            rate_limit_per_min: r.get::<i32, _>("rate_limit_per_min").max(1) as u32,
            is_active: r.get("is_active"),
            created_at: r.get("created_at"),
        }))
    }

    async fn get_mfa_status(&self, user_id: i64) -> Result<MfaStatusDto, String> {
        let totp_enabled: bool = sqlx::query_scalar(
            "SELECT is_enabled FROM user_mfa WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_pg_err)?
        .unwrap_or(false);
        let recovery_codes_remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM user_mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .map_err(map_pg_err)?;
        let rows = sqlx::query(
            "SELECT id, name, cose_alg, sign_count, last_used_at, created_at
             FROM webauthn_credentials WHERE user_id = $1 ORDER BY id DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_pg_err)?;
        let passkeys = rows
            .into_iter()
            .map(|r| {
                let lu: Option<i64> = r.get("last_used_at");
                PasskeyDto {
                    id: r.get("id"),
                    name: r.get("name"),
                    cose_alg: r.get("cose_alg"),
                    sign_count: r.get::<i64, _>("sign_count").max(0) as u32,
                    last_used_at: lu.map(|s| iso_from_ms(s * 1000)),
                    created_at: iso_from_ms(r.get("created_at")),
                }
            })
            .collect();
        Ok(MfaStatusDto {
            totp_enabled,
            recovery_codes_remaining,
            passkeys,
        })
    }

    async fn get_user_mfa_record(&self, user_id: i64) -> Result<Option<UserMfaRecord>, String> {
        let row = sqlx::query(
            "SELECT user_id, totp_secret_enc, is_enabled, last_used_step, failed_attempts, locked_until
             FROM user_mfa WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_pg_err)?;
        Ok(row.map(|r| UserMfaRecord {
            user_id: r.get("user_id"),
            totp_secret_enc: r.get("totp_secret_enc"),
            is_enabled: r.get("is_enabled"),
            last_used_step: r.get("last_used_step"),
            failed_attempts: r.get("failed_attempts"),
            locked_until: r.get("locked_until"),
        }))
    }

    async fn upsert_pending_totp(&self, user_id: i64, totp_secret_enc: &str, now_sec: i64) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO user_mfa (user_id, totp_secret_enc, is_enabled, failed_attempts, updated_at)
             VALUES ($1, $2, FALSE, 0, $3)
             ON CONFLICT (user_id) DO UPDATE SET totp_secret_enc = $2, is_enabled = FALSE, last_used_step = NULL, failed_attempts = 0, locked_until = NULL, updated_at = $3",
        )
        .bind(user_id)
        .bind(totp_secret_enc)
        .bind(now_sec)
        .execute(&self.pool)
        .await
        .map_err(map_pg_err)?;
        Ok(())
    }

    async fn enable_totp_with_recovery_codes(&self, user_id: i64, code_hashes: &[String], now_sec: i64) -> Result<(), String> {
        let mut tx = self.pool.begin().await.map_err(map_pg_err)?;
        sqlx::query(
            "UPDATE user_mfa SET is_enabled = TRUE, enabled_at = $1, failed_attempts = 0, locked_until = NULL, updated_at = $1
             WHERE user_id = $2",
        )
        .bind(now_sec)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        sqlx::query("DELETE FROM user_mfa_recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let now_m = now_ms();
        for h in code_hashes {
            sqlx::query("INSERT INTO user_mfa_recovery_codes (user_id, code_hash, created_at) VALUES ($1, $2, $3)")
                .bind(user_id)
                .bind(h)
                .bind(now_m)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
        }
        tx.commit().await.map_err(map_pg_err)?;
        Ok(())
    }

    async fn disable_mfa(&self, user_id: i64, now_sec: i64) -> Result<(), String> {
        let mut tx = self.pool.begin().await.map_err(map_pg_err)?;
        sqlx::query(
            "UPDATE user_mfa SET is_enabled = FALSE, totp_secret_enc = '', last_used_step = NULL, failed_attempts = 0, locked_until = NULL, updated_at = $1 WHERE user_id = $2",
        )
        .bind(now_sec)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        sqlx::query("DELETE FROM user_mfa_recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(())
    }

    async fn replace_recovery_codes(&self, user_id: i64, code_hashes: &[String], _now_sec: i64) -> Result<(), String> {
        let mut tx = self.pool.begin().await.map_err(map_pg_err)?;
        sqlx::query("DELETE FROM user_mfa_recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let now_m = now_ms();
        for h in code_hashes {
            sqlx::query("INSERT INTO user_mfa_recovery_codes (user_id, code_hash, created_at) VALUES ($1, $2, $3)")
                .bind(user_id)
                .bind(h)
                .bind(now_m)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
        }
        tx.commit().await.map_err(map_pg_err)?;
        Ok(())
    }

    async fn record_mfa_attempt(&self, user_id: i64, success_step: Option<i64>, now_sec: i64) -> Result<Option<i64>, String> {
        let mut tx = self.pool.begin().await.map_err(map_pg_err)?;
        if let Some(step) = success_step {
            sqlx::query(
                "UPDATE user_mfa SET last_used_step = $1, failed_attempts = 0, locked_until = NULL, updated_at = $2 WHERE user_id = $3",
            )
            .bind(step)
            .bind(now_sec)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
            tx.commit().await.map_err(map_pg_err)?;
            return Ok(None);
        }
        let prev: i64 = sqlx::query_scalar(
            "SELECT failed_attempts FROM user_mfa WHERE user_id = $1 FOR UPDATE",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?
        .unwrap_or(0);
        let next = prev + 1;
        let lock_secs = compute_lockout_seconds(next);
        let locked_until = lock_secs.map(|s| now_sec + s);
        sqlx::query(
            "INSERT INTO user_mfa (user_id, totp_secret_enc, is_enabled, failed_attempts, locked_until, updated_at)
             VALUES ($1, '', FALSE, $2, $3, $4)
             ON CONFLICT (user_id) DO UPDATE SET failed_attempts = $2, locked_until = $3, updated_at = $4",
        )
        .bind(user_id)
        .bind(next)
        .bind(locked_until)
        .bind(now_sec)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(lock_secs)
    }

    async fn list_unused_recovery_codes(&self, user_id: i64) -> Result<Vec<RecoveryCodeRecord>, String> {
        let rows: Vec<(i64, String)> = sqlx::query_as(
            "SELECT id, code_hash FROM user_mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_pg_err)?;
        Ok(rows
            .into_iter()
            .map(|(id, code_hash)| RecoveryCodeRecord { id, code_hash })
            .collect())
    }

    async fn mark_recovery_code_used(&self, user_id: i64, code_id: i64, now_sec: i64) -> Result<bool, String> {
        let res = sqlx::query(
            "UPDATE user_mfa_recovery_codes SET used_at = $1 WHERE id = $2 AND user_id = $3 AND used_at IS NULL",
        )
        .bind(now_sec)
        .bind(code_id)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(map_pg_err)?;
        Ok(res.rows_affected() > 0)
    }

    async fn create_mfa_challenge(&self, token_sha256: &str, user_id: i64, target_org_id: i64, ip_hmac: &str, expires_at: i64) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO mfa_challenges (token_sha256, user_id, target_org_id, ip_hmac, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(token_sha256)
        .bind(user_id)
        .bind(target_org_id)
        .bind(ip_hmac)
        .bind(expires_at)
        .bind(now_ms())
        .execute(&self.pool)
        .await
        .map_err(map_pg_err)?;
        Ok(())
    }

    async fn consume_mfa_challenge(&self, token_sha256: &str, now_sec: i64) -> Result<Option<MfaChallengeRecord>, String> {
        let row: Option<(i64, i64, String, i64)> = sqlx::query_as(
            "DELETE FROM mfa_challenges WHERE token_sha256 = $1
             RETURNING user_id, target_org_id, ip_hmac, expires_at",
        )
        .bind(token_sha256)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_pg_err)?;
        Ok(row.and_then(|(user_id, target_org_id, ip_hmac, expires_at)| {
            if expires_at > now_sec {
                Some(MfaChallengeRecord {
                    user_id,
                    target_org_id,
                    ip_hmac,
                    expires_at,
                })
            } else {
                None
            }
        }))
    }

    async fn get_mfa_challenge_user(&self, token_sha256: &str, now_sec: i64) -> Result<Option<MfaChallengeRecord>, String> {
        let row: Option<(i64, i64, String, i64)> = sqlx::query_as(
            "SELECT user_id, target_org_id, ip_hmac, expires_at
             FROM mfa_challenges WHERE token_sha256 = $1 AND expires_at > $2",
        )
        .bind(token_sha256)
        .bind(now_sec)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_pg_err)?;
        Ok(row.map(|(user_id, target_org_id, ip_hmac, expires_at)| MfaChallengeRecord {
            user_id,
            target_org_id,
            ip_hmac,
            expires_at,
        }))
    }

    async fn save_webauthn_challenge(&self, challenge_b64: &str, user_id: Option<i64>, flow_kind: &str, expires_at: i64) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO webauthn_challenges (challenge_b64, user_id, flow_kind, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(challenge_b64)
        .bind(user_id)
        .bind(flow_kind)
        .bind(expires_at)
        .bind(now_ms())
        .execute(&self.pool)
        .await
        .map_err(map_pg_err)?;
        Ok(())
    }

    async fn consume_webauthn_challenge(&self, challenge_b64: &str, flow_kind: &str, now_sec: i64) -> Result<Option<WebAuthnChallengeRecord>, String> {
        let row: Option<(String, Option<i64>, String, i64)> = sqlx::query_as(
            "DELETE FROM webauthn_challenges WHERE challenge_b64 = $1 AND flow_kind = $2
             RETURNING challenge_b64, user_id, flow_kind, expires_at",
        )
        .bind(challenge_b64)
        .bind(flow_kind)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_pg_err)?;
        Ok(row.and_then(|(challenge_b64, user_id, flow_kind, expires_at)| {
            if expires_at > now_sec {
                Some(WebAuthnChallengeRecord {
                    challenge_b64,
                    user_id,
                    flow_kind,
                    expires_at,
                })
            } else {
                None
            }
        }))
    }

    async fn create_webauthn_credential(&self, user_id: i64, name: &str, credential_id_b64: &str, cose_alg: i32, public_key_b64: &str, sign_count: u32) -> Result<PasskeyDto, String> {
        let now = now_ms();
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO webauthn_credentials (user_id, name, credential_id_b64, cose_alg, public_key_b64, sign_count, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
        )
        .bind(user_id)
        .bind(name)
        .bind(credential_id_b64)
        .bind(cose_alg)
        .bind(public_key_b64)
        .bind(sign_count as i64)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(map_pg_err)?;
        Ok(PasskeyDto {
            id,
            name: name.to_string(),
            cose_alg,
            sign_count,
            last_used_at: None,
            created_at: iso_from_ms(now),
        })
    }

    async fn list_webauthn_credentials(&self, user_id: i64) -> Result<Vec<WebAuthnCredRecord>, String> {
        let rows = sqlx::query(
            "SELECT id, user_id, name, credential_id_b64, cose_alg, public_key_b64, sign_count, last_used_at, created_at
             FROM webauthn_credentials WHERE user_id = $1 ORDER BY id DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_pg_err)?;
        Ok(rows
            .into_iter()
            .map(|r| WebAuthnCredRecord {
                id: r.get("id"),
                user_id: r.get("user_id"),
                name: r.get("name"),
                credential_id_b64: r.get("credential_id_b64"),
                cose_alg: r.get("cose_alg"),
                public_key_b64: r.get("public_key_b64"),
                sign_count: r.get::<i64, _>("sign_count").max(0) as u32,
                last_used_at: r.get("last_used_at"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    async fn find_webauthn_credential(&self, credential_id_b64: &str) -> Result<Option<WebAuthnCredRecord>, String> {
        let r = sqlx::query(
            "SELECT id, user_id, name, credential_id_b64, cose_alg, public_key_b64, sign_count, last_used_at, created_at
             FROM webauthn_credentials WHERE credential_id_b64 = $1",
        )
        .bind(credential_id_b64)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_pg_err)?;
        Ok(r.map(|r| WebAuthnCredRecord {
            id: r.get("id"),
            user_id: r.get("user_id"),
            name: r.get("name"),
            credential_id_b64: r.get("credential_id_b64"),
            cose_alg: r.get("cose_alg"),
            public_key_b64: r.get("public_key_b64"),
            sign_count: r.get::<i64, _>("sign_count").max(0) as u32,
            last_used_at: r.get("last_used_at"),
            created_at: r.get("created_at"),
        }))
    }

    async fn update_webauthn_sign_count(&self, cred_id: i64, sign_count: u32, now_sec: i64) -> Result<(), String> {
        sqlx::query("UPDATE webauthn_credentials SET sign_count = $1, last_used_at = $2 WHERE id = $3")
            .bind(sign_count as i64)
            .bind(now_sec)
            .bind(cred_id)
            .execute(&self.pool)
            .await
            .map_err(map_pg_err)?;
        Ok(())
    }

    async fn delete_webauthn_credential(&self, user_id: i64, cred_id: i64) -> Result<bool, String> {
        let res = sqlx::query("DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2")
            .bind(cred_id)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(map_pg_err)?;
        Ok(res.rows_affected() > 0)
    }

    async fn list_user_sessions(&self, user_id: i64, org_id: i64, current_token_sha256: &str, now_sec: i64) -> Result<Vec<ActiveSessionDto>, String> {
        let mut tx = self.begin_tenant(org_id).await?;
        let rows = sqlx::query(
            "SELECT id, token_sha256, user_agent, ip_hmac, last_seen_at, created_at
             FROM sessions WHERE user_id = $1 AND expires_at > $2 ORDER BY id DESC",
        )
        .bind(user_id)
        .bind(now_sec)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let sha: String = r.get("token_sha256");
                let iph: String = r.get("ip_hmac");
                let lseen: i64 = r.get("last_seen_at");
                let crt: i64 = r.get("created_at");
                ActiveSessionDto {
                    id: r.get("id"),
                    user_agent: r.get("user_agent"),
                    ip_hmac_short: iph.chars().take(12).collect(),
                    last_seen_at: iso_from_ms(if lseen > 0 { lseen * 1000 } else { crt }),
                    created_at: iso_from_ms(crt),
                    is_current: sha == current_token_sha256,
                }
            })
            .collect())
    }

    async fn revoke_session_by_id(&self, user_id: i64, org_id: i64, session_id: i64) -> Result<bool, String> {
        let mut tx = self.begin_tenant(org_id).await?;
        let sha: Option<String> = sqlx::query_scalar(
            "DELETE FROM sessions WHERE id = $1 AND user_id = $2 RETURNING token_sha256",
        )
        .bind(session_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        if let Some(ref s) = sha {
            sqlx::query("DELETE FROM session_lookup WHERE token_sha256 = $1")
                .bind(s)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
        }
        tx.commit().await.map_err(map_pg_err)?;
        Ok(sha.is_some())
    }

    async fn revoke_other_sessions(&self, user_id: i64, org_id: i64, keep_token_sha256: &str) -> Result<usize, String> {
        let mut tx = self.begin_tenant(org_id).await?;
        let res = sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND token_sha256 != $2")
            .bind(user_id)
            .bind(keep_token_sha256)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        sqlx::query("DELETE FROM session_lookup WHERE user_id = $1 AND token_sha256 != $2")
            .bind(user_id)
            .bind(keep_token_sha256)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(res.rows_affected() as usize)
    }

    async fn mark_session_reauth(&self, token_sha256: &str, org_id: i64, now_sec: i64) -> Result<(), String> {
        let mut tx = self.begin_tenant(org_id).await?;
        sqlx::query("UPDATE sessions SET reauth_at = $1, last_seen_at = $1 WHERE token_sha256 = $2")
            .bind(now_sec)
            .bind(token_sha256)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        sqlx::query("UPDATE session_lookup SET reauth_at = $1, last_seen_at = $1 WHERE token_sha256 = $2")
            .bind(now_sec)
            .bind(token_sha256)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(())
    }

    async fn find_user_password_hash(&self, user_id: i64) -> Result<Option<(String, String, String)>, String> {
        let row: Option<(String, String, String)> = sqlx::query_as(
            "SELECT email, name, password_hash FROM users WHERE id = $1 AND is_active = TRUE",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_pg_err)?;
        Ok(row)
    }

    async fn change_user_password(
        &self,
        user_id: i64,
        org_id: i64,
        new_password_hash: &str,
        _old_session_sha: &str,
        new_session_sha: &str,
        new_csrf: &str,
        user_agent: &str,
        ip_hmac: &str,
        now_sec: i64,
        expires_at: i64,
    ) -> Result<(), String> {
        let mut tx = self.pool.begin().await.map_err(map_pg_err)?;
        sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
            .bind(new_password_hash)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;

        sqlx::query("SELECT set_config('app.current_user_id', $1, true)")
            .bind(user_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let org_ids: Vec<i64> = sqlx::query_scalar(
            "SELECT organization_id FROM organization_members WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        for oid in org_ids {
            sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
                .bind(oid.to_string())
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
            sqlx::query("DELETE FROM sessions WHERE user_id = $1")
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
            sqlx::query("DELETE FROM session_lookup WHERE user_id = $1")
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
        }

        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(org_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let (org_slug, role): (String, String) = sqlx::query_as(
            "SELECT o.slug, m.role FROM organizations o
             JOIN organization_members m ON m.organization_id = o.id
             WHERE o.id = $1 AND m.user_id = $2",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        let ua: String = user_agent.chars().take(160).collect();
        let sess_id: i64 = sqlx::query_scalar(
            "INSERT INTO sessions (token_sha256, user_id, organization_id, csrf_token, user_agent, ip_hmac, last_seen_at, reauth_at, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $9) RETURNING id",
        )
        .bind(new_session_sha)
        .bind(user_id)
        .bind(org_id)
        .bind(new_csrf)
        .bind(&ua)
        .bind(ip_hmac)
        .bind(now_sec)
        .bind(expires_at)
        .bind(now_ms())
        .fetch_one(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        sqlx::query(
            "INSERT INTO session_lookup (token_sha256, session_id, organization_id, organization_slug, user_id, role, csrf_token, last_seen_at, reauth_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9)",
        )
        .bind(new_session_sha)
        .bind(sess_id)
        .bind(org_id)
        .bind(org_slug)
        .bind(user_id)
        .bind(role)
        .bind(new_csrf)
        .bind(now_sec)
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(())
    }

    async fn create_invitation(&self, ctx: &TenantCtx, email: &str, role: UserRole, token_sha256: &str, expires_at: i64) -> Result<InvitationDto, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let email_norm = email.trim().to_ascii_lowercase();
        let now = now_ms();
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO org_invitations (organization_id, email, role, token_sha256, invited_by, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
        )
        .bind(ctx.organization_id)
        .bind(&email_norm)
        .bind(role.as_str())
        .bind(token_sha256)
        .bind(ctx.user_id)
        .bind(expires_at)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_pg_err)?;

        let org_name: String = sqlx::query_scalar("SELECT name FROM organizations WHERE id = $1")
            .bind(ctx.organization_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let inv_email: String = match ctx.user_id {
            Some(uid) => sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
                .bind(uid)
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_pg_err)?
                .unwrap_or_default(),
            None => String::new(),
        };

        sqlx::query(
            "INSERT INTO invitation_lookup (token_sha256, organization_id, organization_slug, organization_name, email, role, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(token_sha256)
        .bind(ctx.organization_id)
        .bind(&ctx.organization_slug)
        .bind(org_name)
        .bind(&email_norm)
        .bind(role.as_str())
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;

        Ok(InvitationDto {
            id,
            email: email_norm,
            role: role.as_str().to_string(),
            invited_by_email: inv_email,
            expires_at: iso_from_ms(expires_at * 1000),
            accepted_at: None,
            created_at: iso_from_ms(now),
        })
    }

    async fn list_invitations(&self, ctx: &TenantCtx) -> Result<Vec<InvitationDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let rows = sqlx::query(
            "SELECT i.id, i.email, i.role, COALESCE(u.email, '') AS inv_email, i.expires_at, i.accepted_at, i.created_at
             FROM org_invitations i
             LEFT JOIN users u ON u.id = i.invited_by
             ORDER BY i.id DESC LIMIT 100",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let acc: Option<i64> = r.get("accepted_at");
                InvitationDto {
                    id: r.get("id"),
                    email: r.get("email"),
                    role: r.get("role"),
                    invited_by_email: r.get("inv_email"),
                    expires_at: iso_from_ms(r.get::<i64, _>("expires_at") * 1000),
                    accepted_at: acc.map(|s| iso_from_ms(s * 1000)),
                    created_at: iso_from_ms(r.get("created_at")),
                }
            })
            .collect())
    }

    async fn revoke_invitation(&self, ctx: &TenantCtx, inv_id: i64) -> Result<bool, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let sha: Option<String> = sqlx::query_scalar(
            "DELETE FROM org_invitations WHERE id = $1 RETURNING token_sha256",
        )
        .bind(inv_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        if let Some(ref s) = sha {
            sqlx::query("DELETE FROM invitation_lookup WHERE token_sha256 = $1")
                .bind(s)
                .execute(&mut *tx)
                .await
                .map_err(map_pg_err)?;
        }
        tx.commit().await.map_err(map_pg_err)?;
        Ok(sha.is_some())
    }

    async fn lookup_invitation(&self, token_sha256: &str) -> Result<Option<InvitationLookupInfo>, String> {
        let mut tx = self.pool.begin().await.map_err(map_pg_err)?;
        sqlx::query("SELECT set_config('app.invite_token_sha256', $1, true)")
            .bind(token_sha256)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let row: Option<(i64, String, String, String, String, i64, Option<i64>)> = sqlx::query_as(
            "SELECT organization_id, organization_slug, organization_name, email, role, expires_at, accepted_at
             FROM invitation_lookup WHERE token_sha256 = $1",
        )
        .bind(token_sha256)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(row.map(|(oid, oslug, oname, email, role, exp, acc)| InvitationLookupInfo {
            organization_id: oid,
            organization_slug: oslug,
            organization_name: oname,
            email,
            role,
            expires_at: exp,
            accepted_at: acc,
        }))
    }

    async fn accept_invitation(
        &self,
        token_sha256: &str,
        name: &str,
        password_hash: &str,
        now_sec: i64,
    ) -> Result<Result<(i64, i64, String, String, UserRole), String>, String> {
        let mut tx = self.pool.begin().await.map_err(map_pg_err)?;
        sqlx::query("SELECT set_config('app.invite_token_sha256', $1, true)")
            .bind(token_sha256)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let inv: Option<(i64, String, String, String, i64, Option<i64>)> = sqlx::query_as(
            "SELECT organization_id, organization_slug, email, role, expires_at, accepted_at
             FROM invitation_lookup WHERE token_sha256 = $1",
        )
        .bind(token_sha256)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        let Some((org_id, org_slug, email, role_s, exp, acc)) = inv else {
            return Ok(Err("Invitation not found".into()));
        };
        if acc.is_some() {
            return Ok(Err("Invitation has already been used".into()));
        }
        if exp <= now_sec {
            return Ok(Err("Invitation has expired".into()));
        }

        // Stage 2: Set transaction-local tenant context & atomically claim invitation
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(org_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let claimed: Option<i64> = sqlx::query_scalar(
            "UPDATE org_invitations SET accepted_at = $1 WHERE token_sha256 = $2 AND accepted_at IS NULL RETURNING id",
        )
        .bind(now_sec)
        .bind(token_sha256)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        if claimed.is_none() {
            return Ok(Err("Invitation already claimed".into()));
        }
        sqlx::query("UPDATE invitation_lookup SET accepted_at = $1 WHERE token_sha256 = $2")
            .bind(now_sec)
            .bind(token_sha256)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;

        let existing_uid: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
            .bind(&email)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let uid = match existing_uid {
            Some(id) => id,
            None => sqlx::query_scalar(
                "INSERT INTO users (email, name, password_hash, is_active, created_at) VALUES ($1, $2, $3, TRUE, $4) RETURNING id",
            )
            .bind(&email)
            .bind(name)
            .bind(password_hash)
            .bind(now_ms())
            .fetch_one(&mut *tx)
            .await
            .map_err(map_pg_err)?,
        };
        let role = UserRole::from_db(&role_s).unwrap_or(UserRole::Member);
        sqlx::query(
            "INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1, $2, $3)
             ON CONFLICT (organization_id, user_id) DO UPDATE SET role = $3",
        )
        .bind(org_id)
        .bind(uid)
        .bind(role.as_str())
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(Ok((uid, org_id, org_slug, email, role)))
    }

    async fn append_audit_log(&self, entry: &NewAuditLog) -> Result<(), String> {
        let mut tx = self.begin_tenant(entry.organization_id).await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(entry.organization_id + 1_000_000_000i64)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        let prev_hash: String = sqlx::query_scalar(
            "SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_pg_err)?
        .filter(|s: &String| !s.is_empty())
        .unwrap_or_else(|| "GENESIS".to_string());

        let created_at = now_ms();
        let entry_hash = compute_audit_entry_hash(
            &prev_hash,
            entry.organization_id,
            entry.actor_user_id,
            &entry.action,
            &entry.target_type,
            &entry.target_id,
            &entry.metadata,
            created_at,
        );
        sqlx::query(
            "INSERT INTO audit_logs (organization_id, actor_user_id, actor_email, action, target_type, target_id, ip_hmac, metadata_json, prev_hash, entry_hash, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(entry.organization_id)
        .bind(entry.actor_user_id)
        .bind(&entry.actor_email)
        .bind(&entry.action)
        .bind(&entry.target_type)
        .bind(&entry.target_id)
        .bind(&entry.ip_hmac)
        .bind(&entry.metadata)
        .bind(prev_hash)
        .bind(entry_hash)
        .bind(created_at)
        .execute(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(())
    }

    async fn list_audit_logs(&self, ctx: &TenantCtx, action_filter: Option<&str>, limit: i64, offset: i64) -> Result<Vec<AuditLogDto>, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let act = action_filter.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let rows = sqlx::query(
            "SELECT id, actor_user_id, actor_email, action, target_type, target_id, ip_hmac, metadata_json, entry_hash, created_at
             FROM audit_logs
             WHERE ($1::text IS NULL OR action = $1)
             ORDER BY id DESC LIMIT $2 OFFSET $3",
        )
        .bind(act)
        .bind(limit.clamp(1, 200))
        .bind(offset.max(0))
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(rows
            .into_iter()
            .map(|r| AuditLogDto {
                id: r.get("id"),
                actor_user_id: r.get("actor_user_id"),
                actor_email: r.get("actor_email"),
                action: r.get("action"),
                target_type: r.get("target_type"),
                target_id: r.get("target_id"),
                ip_hmac: r.get("ip_hmac"),
                metadata: r.get("metadata_json"),
                entry_hash: r.get("entry_hash"),
                created_at: iso_from_ms(r.get("created_at")),
            })
            .collect())
    }

    async fn verify_audit_chain(&self, ctx: &TenantCtx) -> Result<AuditVerifyDto, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let rows = sqlx::query(
            "SELECT id, actor_user_id, action, target_type, target_id, metadata_json, prev_hash, entry_hash, created_at
             FROM audit_logs ORDER BY id ASC",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        let mut expected_prev = "GENESIS".to_string();
        let mut count = 0usize;
        for r in rows {
            let id: i64 = r.get("id");
            let actor_uid: Option<i64> = r.get("actor_user_id");
            let action: String = r.get("action");
            let target_type: String = r.get("target_type");
            let target_id: String = r.get("target_id");
            let meta_val: Value = r.get("metadata_json");
            let prev_hash: String = r.get("prev_hash");
            let entry_hash: String = r.get("entry_hash");
            let created_at: i64 = r.get("created_at");
            count += 1;
            if prev_hash != expected_prev {
                return Ok(AuditVerifyDto {
                    valid: false,
                    checked_entries: count,
                    broken_at_id: Some(id),
                    detail: format!("Previous hash link mismatch at audit_logs.id={id}"),
                });
            }
            let recomputed = compute_audit_entry_hash(
                &prev_hash,
                ctx.organization_id,
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
    }

    async fn get_org_security_settings(&self, ctx: &TenantCtx) -> Result<OrgSecuritySettings, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let val: Value = sqlx::query_scalar("SELECT settings_json FROM organizations WHERE id = $1")
            .bind(ctx.organization_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(serde_json::from_value(val).unwrap_or_default())
    }

    async fn update_org_security_settings(&self, ctx: &TenantCtx, settings: &OrgSecuritySettings) -> Result<OrgSecuritySettings, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let mut clean = settings.clone();
        clean.event_throttle_rate = clean.event_throttle_rate.min(100);
        let sval = serde_json::to_value(&clean).map_err(map_pg_err)?;
        sqlx::query("UPDATE organizations SET settings_json = $1 WHERE id = $2")
            .bind(&sval)
            .bind(ctx.organization_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        sqlx::query("UPDATE dsn_key_lookup SET org_settings_json = $1 WHERE organization_id = $2")
            .bind(&sval)
            .bind(ctx.organization_id)
            .execute(&mut *tx)
            .await
            .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(clean)
    }

    async fn count_owners_without_mfa(&self, ctx: &TenantCtx) -> Result<i64, String> {
        let mut tx = self.begin_tenant(ctx.organization_id).await?;
        let cnt: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint
             FROM organization_members m
             JOIN users u ON u.id = m.user_id
             WHERE m.role = 'owner'
               AND u.is_active = TRUE
               AND NOT EXISTS (SELECT 1 FROM user_mfa f WHERE f.user_id = u.id AND f.is_enabled = TRUE)
               AND NOT EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = u.id)",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(map_pg_err)?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok(cnt)
    }
}
