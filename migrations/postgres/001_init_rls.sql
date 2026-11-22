-- PostgreSQL 17 Enterprise Multi-Tenant Schema with Fail-Closed ENABLE + FORCE RLS
-- Run DDL migrations as migrator role; runtime connections use NOBYPASSRLS role `bugfinder_app`.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bugfinder_app') THEN
        CREATE ROLE bugfinder_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS organizations (
    id BIGSERIAL PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS organization_members (
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    PRIMARY KEY (organization_id, user_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    token_sha256 TEXT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id BIGSERIAL PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_sha256 TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    scopes TEXT NOT NULL DEFAULT 'project:read project:write event:read',
    last_used_at BIGINT,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
    key_hmac TEXT PRIMARY KEY,
    failed_count BIGINT NOT NULL DEFAULT 0,
    locked_until BIGINT,
    updated_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL,
    action TEXT NOT NULL,
    idem_key TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    response_body TEXT NOT NULL,
    in_flight BOOLEAN NOT NULL DEFAULT FALSE,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (organization_id, user_id, action, idem_key)
);

CREATE TABLE IF NOT EXISTS projects (
    id BIGSERIAL PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    platform TEXT NOT NULL DEFAULT 'other',
    filters_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_event_at BIGINT,
    next_short_num BIGINT NOT NULL DEFAULT 1,
    created_at BIGINT NOT NULL,
    UNIQUE (organization_id, slug)
);

CREATE TABLE IF NOT EXISTS project_keys (
    id BIGSERIAL PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    label TEXT NOT NULL DEFAULT 'Default',
    public_key TEXT NOT NULL UNIQUE,
    key_sha256 TEXT NOT NULL UNIQUE,
    rate_limit_per_min INTEGER NOT NULL DEFAULT 300,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS tunnel_routes (
    slug TEXT PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS releases (
    id BIGSERIAL PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    first_seen BIGINT NOT NULL,
    last_seen BIGINT NOT NULL,
    UNIQUE (project_id, version)
);

CREATE TABLE IF NOT EXISTS release_sessions (
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    release_version TEXT NOT NULL,
    environment TEXT NOT NULL,
    bucket_hour BIGINT NOT NULL,
    healthy_count BIGINT NOT NULL DEFAULT 0,
    errored_count BIGINT NOT NULL DEFAULT 0,
    crashed_count BIGINT NOT NULL DEFAULT 0,
    abnormal_count BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, release_version, environment, bucket_hour)
);

CREATE TABLE IF NOT EXISTS source_maps (
    id BIGSERIAL PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    release_version TEXT NOT NULL DEFAULT '',
    debug_id TEXT NOT NULL DEFAULT '',
    filename TEXT NOT NULL,
    blob_sha256 TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS issues (
    id BIGSERIAL PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    short_id TEXT NOT NULL,
    short_num BIGINT NOT NULL,
    fingerprint TEXT NOT NULL,
    title TEXT NOT NULL,
    culprit TEXT NOT NULL DEFAULT '',
    level TEXT NOT NULL DEFAULT 'error',
    issue_type TEXT NOT NULL DEFAULT 'error',
    status TEXT NOT NULL DEFAULT 'unresolved' CHECK (status IN ('unresolved', 'resolved', 'ignored')),
    is_regression BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_in_release TEXT,
    first_seen BIGINT NOT NULL,
    last_seen BIGINT NOT NULL,
    event_count BIGINT NOT NULL DEFAULT 1,
    user_count BIGINT NOT NULL DEFAULT 0,
    first_release TEXT,
    last_release TEXT,
    environment TEXT NOT NULL DEFAULT 'production',
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    search_vec TSVECTOR,
    UNIQUE (project_id, fingerprint),
    UNIQUE (project_id, short_num)
);
CREATE INDEX IF NOT EXISTS pg_idx_issues_fts ON issues USING GIN (search_vec);
CREATE INDEX IF NOT EXISTS pg_idx_issues_org_last ON issues (organization_id, status, last_seen DESC);

CREATE TABLE IF NOT EXISTS issue_users (
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    issue_id BIGINT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    user_hash TEXT NOT NULL,
    PRIMARY KEY (issue_id, user_hash)
);

CREATE TABLE IF NOT EXISTS issue_events (
    id UUID PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    issue_id BIGINT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL,
    timestamp_ms BIGINT NOT NULL,
    level TEXT NOT NULL,
    environment TEXT NOT NULL,
    release TEXT,
    trace_id TEXT,
    span_id TEXT,
    user_hash TEXT,
    tags_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    payload_blob BYTEA NOT NULL,
    payload_compressed BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (project_id, event_id)
);
CREATE INDEX IF NOT EXISTS pg_idx_issue_events_trace ON issue_events (organization_id, trace_id);

CREATE TABLE IF NOT EXISTS log_events (
    id UUID PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    timestamp_ms BIGINT NOT NULL,
    level_num INTEGER NOT NULL,
    severity_number INTEGER,
    body TEXT NOT NULL,
    service TEXT NOT NULL DEFAULT '',
    environment TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '',
    trace_id TEXT,
    span_id TEXT,
    attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    body_tsv TSVECTOR GENERATED ALWAYS AS (to_tsvector('english', body)) STORED
);
CREATE INDEX IF NOT EXISTS pg_idx_logs_org_id ON log_events (organization_id, id DESC);
CREATE INDEX IF NOT EXISTS pg_idx_logs_fts ON log_events USING GIN (body_tsv);
CREATE INDEX IF NOT EXISTS pg_idx_logs_trace ON log_events (organization_id, trace_id);

CREATE TABLE IF NOT EXISTS log_resources (
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    resource_type TEXT NOT NULL,
    name TEXT NOT NULL,
    last_seen BIGINT NOT NULL,
    PRIMARY KEY (organization_id, resource_type, name)
);

CREATE TABLE IF NOT EXISTS transaction_events (
    id UUID PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    op TEXT NOT NULL,
    status TEXT NOT NULL,
    duration_ms DOUBLE PRECISION NOT NULL,
    trace_id TEXT NOT NULL,
    span_id TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT 'production',
    release TEXT,
    spans_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    timestamp_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS hourly_stats (
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    bucket_hour BIGINT NOT NULL,
    category TEXT NOT NULL,
    quantity BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, bucket_hour, category)
);

CREATE TABLE IF NOT EXISTS uptime_monitors (
    id BIGSERIAL PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    uuid TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    expected_interval_sec BIGINT NOT NULL DEFAULT 60,
    last_heartbeat_at BIGINT,
    status TEXT NOT NULL DEFAULT 'pending',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS uptime_checks (
    id BIGSERIAL PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    monitor_id BIGINT NOT NULL REFERENCES uptime_monitors(id) ON DELETE CASCADE,
    is_up BOOLEAN NOT NULL,
    duration_ms BIGINT,
    message TEXT NOT NULL DEFAULT '',
    checked_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_rules (
    id BIGSERIAL PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    trigger_type TEXT NOT NULL CHECK (trigger_type IN ('new_issue', 'regression', 'threshold', 'fatal_log', 'uptime_down', 'security_threat', 'secret_leak')),
    threshold_count BIGINT NOT NULL DEFAULT 1,
    window_sec BIGINT NOT NULL DEFAULT 60,
    cooldown_sec BIGINT NOT NULL DEFAULT 300,
    channel_type TEXT NOT NULL CHECK (channel_type IN ('webhook', 'slack', 'discord', 'email')),
    target_url TEXT NOT NULL DEFAULT '',
    webhook_secret TEXT NOT NULL DEFAULT '',
    email_to TEXT NOT NULL DEFAULT '',
    last_triggered_at BIGINT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at BIGINT NOT NULL
);

ALTER TABLE alert_rules DROP CONSTRAINT IF EXISTS alert_rules_trigger_type_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_trigger_type_check
    CHECK (trigger_type IN ('new_issue', 'regression', 'threshold', 'fatal_log', 'uptime_down', 'security_threat', 'secret_leak'));

CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    signal_type TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    source_kind TEXT NOT NULL,
    actor_hmac TEXT NOT NULL DEFAULT '',
    session_id TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    action_taken TEXT NOT NULL DEFAULT 'logged',
    timestamp_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pg_security_events_proj_time ON security_events(organization_id, project_id, timestamp_ms DESC);

CREATE TABLE IF NOT EXISTS shield_quarantine (
    id BIGSERIAL PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('session', 'ip')),
    subject_hmac TEXT NOT NULL,
    reason TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    UNIQUE(organization_id, project_id, subject_type, subject_hmac)
);
CREATE INDEX IF NOT EXISTS idx_pg_shield_quarantine_exp ON shield_quarantine(organization_id, project_id, expires_at);

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_user_id BIGINT,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    created_at BIGINT NOT NULL
);

-- Capability-GUC Lookup Tables (unauthenticated pre-tenant resolution under NOBYPASSRLS)
CREATE TABLE IF NOT EXISTS dsn_key_lookup (
    key_sha256 TEXT PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    organization_slug TEXT NOT NULL,
    project_slug TEXT NOT NULL,
    rate_limit_per_min INTEGER NOT NULL,
    filters_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_event_at BIGINT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS api_token_lookup (
    token_sha256 TEXT PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    organization_slug TEXT NOT NULL,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS session_lookup (
    token_sha256 TEXT PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    organization_slug TEXT NOT NULL,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS tunnel_lookup (
    slug TEXT PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

-- Enable + FORCE RLS on EVERY tenant table (fail-closed)
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS org_tenant_isolation ON organizations;
CREATE POLICY org_tenant_isolation ON organizations
    USING (
        id = NULLIF(current_setting('app.current_tenant_id', true), '')::bigint
        OR (
            NULLIF(current_setting('app.current_user_id', true), '')::bigint IS NOT NULL
            AND EXISTS (
                SELECT 1 FROM organization_members om
                WHERE om.organization_id = organizations.id
                  AND om.user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
            )
        )
        OR NULLIF(current_setting('app.setup_bootstrap', true), '') = '1'
        OR NULLIF(current_setting('app.maintenance_scan', true), '') = '1'
    )
    WITH CHECK (
        id = NULLIF(current_setting('app.current_tenant_id', true), '')::bigint
        OR NULLIF(current_setting('app.setup_bootstrap', true), '') = '1'
    );

DO $$
DECLARE
    tbl TEXT;
    tenant_tables TEXT[] := ARRAY[
        'sessions',
        'api_tokens',
        'idempotency_keys',
        'projects',
        'project_keys',
        'tunnel_routes',
        'releases',
        'release_sessions',
        'source_maps',
        'issues',
        'issue_users',
        'issue_events',
        'log_events',
        'log_resources',
        'transaction_events',
        'hourly_stats',
        'uptime_monitors',
        'uptime_checks',
        'alert_rules',
        'audit_logs',
        'security_events',
        'shield_quarantine'
    ];
BEGIN
    FOREACH tbl IN ARRAY tenant_tables LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY;', tbl);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY;', tbl);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I;', tbl);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING (organization_id = NULLIF(current_setting(''app.current_tenant_id'', true), '''')::bigint) WITH CHECK (organization_id = NULLIF(current_setting(''app.current_tenant_id'', true), '''')::bigint);',
            tbl
        );
    END LOOP;
END
$$;

ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_members FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON organization_members;
CREATE POLICY tenant_isolation ON organization_members
    USING (
        organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::bigint
        OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
    )
    WITH CHECK (
        organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::bigint
    );

-- Capability-GUC RLS policies for pre-tenant lookup tables
ALTER TABLE dsn_key_lookup ENABLE ROW LEVEL SECURITY;
ALTER TABLE dsn_key_lookup FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cap_dsn ON dsn_key_lookup;
CREATE POLICY cap_dsn ON dsn_key_lookup
    USING (key_sha256 = NULLIF(current_setting('app.ingest_dsn_key_sha256', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::bigint);

ALTER TABLE api_token_lookup ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_token_lookup FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cap_token ON api_token_lookup;
CREATE POLICY cap_token ON api_token_lookup
    USING (token_sha256 = NULLIF(current_setting('app.api_token_sha256', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::bigint);

ALTER TABLE session_lookup ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_lookup FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cap_session ON session_lookup;
CREATE POLICY cap_session ON session_lookup
    USING (
        token_sha256 = NULLIF(current_setting('app.session_sha256', true), '')
        OR (
            NULLIF(current_setting('app.maintenance_scan', true), '') = '1'
            AND expires_at <= EXTRACT(EPOCH FROM NOW())::bigint
        )
    )
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::bigint);

ALTER TABLE tunnel_lookup ENABLE ROW LEVEL SECURITY;
ALTER TABLE tunnel_lookup FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cap_tunnel ON tunnel_lookup;
CREATE POLICY cap_tunnel ON tunnel_lookup
    USING (slug = NULLIF(current_setting('app.tunnel_slug', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::bigint);

GRANT USAGE ON SCHEMA public TO bugfinder_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO bugfinder_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO bugfinder_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO bugfinder_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO bugfinder_app;
