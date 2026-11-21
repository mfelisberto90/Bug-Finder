PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS organization_members (
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK(role IN ('owner', 'admin', 'member', 'viewer')),
    PRIMARY KEY (organization_id, user_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    token_sha256 TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_sha256 TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('owner', 'admin', 'member', 'viewer')),
    scopes TEXT NOT NULL DEFAULT 'project:read project:write event:read',
    last_used_at INTEGER,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
    key_hmac TEXT PRIMARY KEY,
    failed_count INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    organization_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    idem_key TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    response_body TEXT NOT NULL,
    in_flight INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (organization_id, user_id, action, idem_key)
);

CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    platform TEXT NOT NULL DEFAULT 'other',
    filters_json TEXT NOT NULL DEFAULT '{}',
    first_event_at INTEGER,
    next_short_num INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    UNIQUE (organization_id, slug)
);

CREATE TABLE IF NOT EXISTS project_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    label TEXT NOT NULL DEFAULT 'Default',
    public_key TEXT NOT NULL UNIQUE,
    key_sha256 TEXT NOT NULL UNIQUE,
    rate_limit_per_min INTEGER NOT NULL DEFAULT 300,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tunnel_routes (
    slug TEXT PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS releases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    UNIQUE (project_id, version)
);

CREATE TABLE IF NOT EXISTS release_sessions (
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    release_version TEXT NOT NULL,
    environment TEXT NOT NULL,
    bucket_hour INTEGER NOT NULL,
    healthy_count INTEGER NOT NULL DEFAULT 0,
    errored_count INTEGER NOT NULL DEFAULT 0,
    crashed_count INTEGER NOT NULL DEFAULT 0,
    abnormal_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, release_version, environment, bucket_hour)
);

CREATE TABLE IF NOT EXISTS source_maps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    release_version TEXT NOT NULL DEFAULT '',
    debug_id TEXT NOT NULL DEFAULT '',
    filename TEXT NOT NULL,
    blob_sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sourcemaps_lookup ON source_maps(project_id, release_version, filename);
CREATE INDEX IF NOT EXISTS idx_sourcemaps_debug_id ON source_maps(project_id, debug_id);

CREATE TABLE IF NOT EXISTS issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    short_id TEXT NOT NULL,
    short_num INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    title TEXT NOT NULL,
    culprit TEXT NOT NULL DEFAULT '',
    level TEXT NOT NULL DEFAULT 'error',
    issue_type TEXT NOT NULL DEFAULT 'error',
    status TEXT NOT NULL DEFAULT 'unresolved' CHECK(status IN ('unresolved', 'resolved', 'ignored')),
    is_regression INTEGER NOT NULL DEFAULT 0,
    resolved_in_release TEXT,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 1,
    user_count INTEGER NOT NULL DEFAULT 0,
    first_release TEXT,
    last_release TEXT,
    environment TEXT NOT NULL DEFAULT 'production',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (project_id, fingerprint),
    UNIQUE (project_id, short_num)
);
CREATE INDEX IF NOT EXISTS idx_issues_org_last_seen ON issues(organization_id, status, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_issues_proj_last_seen ON issues(project_id, last_seen DESC);

CREATE TABLE IF NOT EXISTS issue_users (
    issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    user_hash TEXT NOT NULL,
    PRIMARY KEY (issue_id, user_hash)
);

CREATE TABLE IF NOT EXISTS issue_events (
    id TEXT PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL,
    timestamp_ms INTEGER NOT NULL,
    level TEXT NOT NULL,
    environment TEXT NOT NULL,
    release TEXT,
    trace_id TEXT,
    span_id TEXT,
    user_hash TEXT,
    tags_json TEXT NOT NULL DEFAULT '{}',
    payload_blob BLOB NOT NULL,
    payload_compressed INTEGER NOT NULL DEFAULT 0,
    UNIQUE (project_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_issue_events_issue_ts ON issue_events(issue_id, timestamp_ms DESC);
CREATE INDEX IF NOT EXISTS idx_issue_events_trace ON issue_events(organization_id, trace_id);

CREATE TABLE IF NOT EXISTS log_events (
    id TEXT PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    timestamp_ms INTEGER NOT NULL,
    level_num INTEGER NOT NULL,
    severity_number INTEGER,
    body TEXT NOT NULL,
    service TEXT NOT NULL DEFAULT '',
    environment TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '',
    trace_id TEXT,
    span_id TEXT,
    attributes_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_logs_org_id ON log_events(organization_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_logs_org_lvl ON log_events(organization_id, level_num, id DESC);
CREATE INDEX IF NOT EXISTS idx_logs_proj_id ON log_events(project_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_logs_trace ON log_events(organization_id, trace_id);

CREATE TABLE IF NOT EXISTS log_resources (
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    resource_type TEXT NOT NULL,
    name TEXT NOT NULL,
    last_seen INTEGER NOT NULL,
    PRIMARY KEY (organization_id, resource_type, name)
);

CREATE TABLE IF NOT EXISTS transaction_events (
    id TEXT PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    op TEXT NOT NULL,
    status TEXT NOT NULL,
    duration_ms REAL NOT NULL,
    trace_id TEXT NOT NULL,
    span_id TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT 'production',
    release TEXT,
    spans_json TEXT NOT NULL DEFAULT '[]',
    timestamp_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tx_org_ts ON transaction_events(organization_id, timestamp_ms DESC);
CREATE INDEX IF NOT EXISTS idx_tx_trace ON transaction_events(organization_id, trace_id);

CREATE TABLE IF NOT EXISTS hourly_stats (
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    bucket_hour INTEGER NOT NULL,
    category TEXT NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, bucket_hour, category)
);
CREATE INDEX IF NOT EXISTS idx_hourly_stats_org ON hourly_stats(organization_id, category, bucket_hour);

CREATE TABLE IF NOT EXISTS uptime_monitors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    uuid TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    expected_interval_sec INTEGER NOT NULL DEFAULT 60,
    last_heartbeat_at INTEGER,
    status TEXT NOT NULL DEFAULT 'pending',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS uptime_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    monitor_id INTEGER NOT NULL REFERENCES uptime_monitors(id) ON DELETE CASCADE,
    is_up INTEGER NOT NULL,
    duration_ms INTEGER,
    message TEXT NOT NULL DEFAULT '',
    checked_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_uptime_checks_mon ON uptime_checks(monitor_id, checked_at DESC);

CREATE TABLE IF NOT EXISTS alert_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    trigger_type TEXT NOT NULL CHECK(trigger_type IN ('new_issue', 'regression', 'threshold', 'fatal_log', 'uptime_down')),
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

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_user_id INTEGER,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS issues_fts USING fts5(
    title,
    culprit,
    search_text,
    issue_id UNINDEXED,
    organization_id UNINDEXED
);

CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5(
    body,
    service,
    host,
    log_id UNINDEXED,
    organization_id UNINDEXED
);
