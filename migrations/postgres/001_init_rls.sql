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
    settings_json JSONB NOT NULL DEFAULT '{}'::jsonb,
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
    role TEXT NOT NULL CHECK (role IN ('owner', 'manager', 'admin', 'member', 'viewer')),
    PRIMARY KEY (organization_id, user_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    id BIGSERIAL UNIQUE,
    token_sha256 TEXT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    user_agent TEXT NOT NULL DEFAULT '',
    ip_hmac TEXT NOT NULL DEFAULT '',
    last_seen_at BIGINT NOT NULL DEFAULT 0,
    reauth_at BIGINT,
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
    role TEXT NOT NULL CHECK (role IN ('owner', 'manager', 'admin', 'member', 'viewer')),
    scopes TEXT NOT NULL DEFAULT 'project:read project:write event:read',
    expires_at BIGINT,
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
    channel_type TEXT NOT NULL CHECK (channel_type IN ('webhook', 'slack', 'discord', 'telegram', 'email')),
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
ALTER TABLE alert_rules DROP CONSTRAINT IF EXISTS alert_rules_channel_type_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_channel_type_check
    CHECK (channel_type IN ('webhook', 'slack', 'discord', 'telegram', 'email'));

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
    actor_email TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    ip_hmac TEXT NOT NULL DEFAULT '',
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash TEXT NOT NULL DEFAULT 'GENESIS',
    entry_hash TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pg_audit_logs_org_id ON audit_logs(organization_id, id DESC);

CREATE TABLE IF NOT EXISTS user_mfa (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    totp_secret_enc TEXT NOT NULL DEFAULT '',
    is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    last_used_step BIGINT,
    failed_attempts BIGINT NOT NULL DEFAULT 0,
    locked_until BIGINT,
    enabled_at BIGINT,
    updated_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_mfa_recovery_codes (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at BIGINT,
    created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pg_mfa_recovery_user ON user_mfa_recovery_codes(user_id);

CREATE TABLE IF NOT EXISTS mfa_challenges (
    token_sha256 TEXT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_org_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    ip_hmac TEXT NOT NULL DEFAULT '',
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    credential_id_b64 TEXT NOT NULL UNIQUE,
    cose_alg INTEGER NOT NULL,
    public_key_b64 TEXT NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    last_used_at BIGINT,
    created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pg_webauthn_creds_user ON webauthn_credentials(user_id);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    challenge_b64 TEXT PRIMARY KEY,
    user_id BIGINT,
    flow_kind TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS org_invitations (
    id BIGSERIAL PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'manager', 'admin', 'member', 'viewer')),
    token_sha256 TEXT NOT NULL UNIQUE,
    invited_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    expires_at BIGINT NOT NULL,
    accepted_at BIGINT,
    created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pg_org_invitations_org ON org_invitations(organization_id, created_at DESC);

-- Capability-GUC Lookup Tables (unauthenticated pre-tenant resolution under NOBYPASSRLS)
CREATE TABLE IF NOT EXISTS dsn_key_lookup (
    key_sha256 TEXT PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    organization_slug TEXT NOT NULL,
    project_slug TEXT NOT NULL,
    rate_limit_per_min INTEGER NOT NULL,
    filters_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    org_settings_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_event_at BIGINT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS api_token_lookup (
    token_sha256 TEXT PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    organization_slug TEXT NOT NULL,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT 'project:read project:write event:read',
    expires_at BIGINT
);

CREATE TABLE IF NOT EXISTS session_lookup (
    token_sha256 TEXT PRIMARY KEY,
    session_id BIGINT NOT NULL DEFAULT 0,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    organization_slug TEXT NOT NULL,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    last_seen_at BIGINT NOT NULL DEFAULT 0,
    reauth_at BIGINT,
    expires_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS tunnel_lookup (
    slug TEXT PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS invitation_lookup (
    token_sha256 TEXT PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    organization_slug TEXT NOT NULL,
    organization_name TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    accepted_at BIGINT
);

-- Idempotent column & constraint upgrades for existing PostgreSQL deployments
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS settings_json JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS id BIGSERIAL UNIQUE;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_agent TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip_hmac TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_seen_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS reauth_at BIGINT;
ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS expires_at BIGINT;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS actor_email TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS ip_hmac TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT 'GENESIS';
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS entry_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE dsn_key_lookup ADD COLUMN IF NOT EXISTS org_settings_json JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE api_token_lookup ADD COLUMN IF NOT EXISTS scopes TEXT NOT NULL DEFAULT 'project:read project:write event:read';
ALTER TABLE api_token_lookup ADD COLUMN IF NOT EXISTS expires_at BIGINT;
ALTER TABLE session_lookup ADD COLUMN IF NOT EXISTS session_id BIGINT NOT NULL DEFAULT 0;
ALTER TABLE session_lookup ADD COLUMN IF NOT EXISTS last_seen_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE session_lookup ADD COLUMN IF NOT EXISTS reauth_at BIGINT;
ALTER TABLE organization_members DROP CONSTRAINT IF EXISTS organization_members_role_check;
ALTER TABLE organization_members ADD CONSTRAINT organization_members_role_check
    CHECK (role IN ('owner', 'manager', 'admin', 'member', 'viewer'));
ALTER TABLE api_tokens DROP CONSTRAINT IF EXISTS api_tokens_role_check;
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_role_check
    CHECK (role IN ('owner', 'manager', 'admin', 'member', 'viewer'));

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
        'shield_quarantine',
        'org_invitations'
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
    USING (
        key_sha256 = NULLIF(current_setting('app.ingest_dsn_key_sha256', true), '')
        OR organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::bigint
    )
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::bigint);

ALTER TABLE api_token_lookup ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_token_lookup FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cap_token ON api_token_lookup;
CREATE POLICY cap_token ON api_token_lookup
    USING (
        token_sha256 = NULLIF(current_setting('app.api_token_sha256', true), '')
        OR organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::bigint
    )
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::bigint);

ALTER TABLE session_lookup ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_lookup FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cap_session ON session_lookup;
CREATE POLICY cap_session ON session_lookup
    USING (
        token_sha256 = NULLIF(current_setting('app.session_sha256', true), '')
        OR organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::bigint
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
    USING (
        slug = NULLIF(current_setting('app.tunnel_slug', true), '')
        OR organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::bigint
    )
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::bigint);

ALTER TABLE invitation_lookup ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitation_lookup FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cap_invite ON invitation_lookup;
CREATE POLICY cap_invite ON invitation_lookup
    USING (
        token_sha256 = NULLIF(current_setting('app.invite_token_sha256', true), '')
        OR organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::bigint
        OR (
            NULLIF(current_setting('app.maintenance_scan', true), '') = '1'
            AND expires_at <= EXTRACT(EPOCH FROM NOW())::bigint
        )
    )
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::bigint);

ALTER TABLE mfa_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_challenges FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cap_mfa_challenge ON mfa_challenges;
CREATE POLICY cap_mfa_challenge ON mfa_challenges
    USING (
        token_sha256 = NULLIF(current_setting('app.mfa_challenge_sha256', true), '')
        OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
        OR target_org_id = NULLIF(current_setting('app.current_tenant_id', true), '')::bigint
        OR (
            NULLIF(current_setting('app.maintenance_scan', true), '') = '1'
            AND expires_at <= EXTRACT(EPOCH FROM NOW())::bigint
        )
    )
    WITH CHECK (
        token_sha256 = NULLIF(current_setting('app.mfa_challenge_sha256', true), '')
        OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
    );

ALTER TABLE user_mfa ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_mfa FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS user_mfa_isolation ON user_mfa;
CREATE POLICY user_mfa_isolation ON user_mfa
    USING (
        user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
        OR EXISTS (
            SELECT 1 FROM organization_members om
            WHERE om.user_id = user_mfa.user_id
              AND om.organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::bigint
        )
    )
    WITH CHECK (
        user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
    );

ALTER TABLE user_mfa_recovery_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_mfa_recovery_codes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS user_mfa_recovery_isolation ON user_mfa_recovery_codes;
CREATE POLICY user_mfa_recovery_isolation ON user_mfa_recovery_codes
    USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint)
    WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint);

ALTER TABLE webauthn_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_credentials FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS user_webauthn_cred_isolation ON webauthn_credentials;
CREATE POLICY user_webauthn_cred_isolation ON webauthn_credentials
    USING (
        user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
        OR credential_id_b64 = NULLIF(current_setting('app.webauthn_cred_id', true), '')
        OR id = NULLIF(current_setting('app.webauthn_cred_pk', true), '')::bigint
        OR EXISTS (
            SELECT 1 FROM organization_members om
            WHERE om.user_id = webauthn_credentials.user_id
              AND om.organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::bigint
        )
    )
    WITH CHECK (
        user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
        OR id = NULLIF(current_setting('app.webauthn_cred_pk', true), '')::bigint
    );

ALTER TABLE webauthn_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_challenges FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cap_webauthn_challenge ON webauthn_challenges;
CREATE POLICY cap_webauthn_challenge ON webauthn_challenges
    USING (
        challenge_b64 = NULLIF(current_setting('app.webauthn_challenge_b64', true), '')
        OR (
            NULLIF(current_setting('app.current_user_id', true), '')::bigint IS NOT NULL
            AND user_id = NULLIF(current_setting('app.current_user_id', true), '')::bigint
        )
        OR (
            NULLIF(current_setting('app.maintenance_scan', true), '') = '1'
            AND expires_at <= EXTRACT(EPOCH FROM NOW())::bigint
        )
    )
    WITH CHECK (
        challenge_b64 = NULLIF(current_setting('app.webauthn_challenge_b64', true), '')
    );

CREATE TABLE IF NOT EXISTS bugfinder_schema_meta (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    schema_sha256 TEXT NOT NULL,
    applied_at BIGINT NOT NULL
);

GRANT USAGE ON SCHEMA public TO bugfinder_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO bugfinder_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO bugfinder_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO bugfinder_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO bugfinder_app;
REVOKE INSERT, UPDATE, DELETE ON bugfinder_schema_meta FROM bugfinder_app;
GRANT SELECT ON bugfinder_schema_meta TO bugfinder_app;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM bugfinder_app;

CREATE INDEX IF NOT EXISTS idx_pg_logs_org_ts ON log_events(organization_id, timestamp_ms DESC);

CREATE OR REPLACE FUNCTION prevent_audit_logs_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only and cannot be modified or deleted';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_logs_immutable_update ON audit_logs;
CREATE TRIGGER trg_audit_logs_immutable_update
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_logs_mutation();

DROP TRIGGER IF EXISTS trg_audit_logs_immutable_delete ON audit_logs;
CREATE TRIGGER trg_audit_logs_immutable_delete
    BEFORE DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_logs_mutation();
