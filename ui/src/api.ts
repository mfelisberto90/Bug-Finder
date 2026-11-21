export interface UserInfo {
  id: number;
  email: string;
  name: string;
  role: string;
}

export interface Organization {
  id: number;
  slug: string;
  name: string;
  role: string;
}

export interface ProjectFilters {
  allowed_domains: string[];
  ignore_browser_extensions: boolean;
  ignore_crawlers: boolean;
  ignore_localhost: boolean;
  ignore_messages: string[];
  storm_sample_threshold: number;
  storm_sample_every: number;
  auto_promote_log_level: string | null;
  scrub_ip_addresses: boolean;
  scrub_emails: boolean;
}

export interface Project {
  id: number;
  organization_id: number;
  slug: string;
  name: string;
  platform: string;
  filters: ProjectFilters;
  dsn_public_key: string | null;
  tunnel_slug: string | null;
}

export interface IssueSummary {
  id: number;
  shortId: string;
  project_id: number;
  project_slug: string;
  title: string;
  culprit: string;
  level: string;
  type: string;
  status: string;
  is_regression: boolean;
  resolved_in_release: string | null;
  firstSeen: string;
  lastSeen: string;
  count: number;
  userCount: number;
  first_release: string | null;
  last_release: string | null;
  environment: string;
}

export interface IssueEventDetail {
  id: string;
  event_id: string;
  issue_id: number;
  project_id: number;
  timestamp: string;
  level: string;
  environment: string;
  release: string | null;
  trace_id: string | null;
  span_id: string | null;
  tags: Record<string, unknown>;
  payload: Record<string, any>;
}

export interface LogEventItem {
  id: string;
  timestamp: string;
  level: string;
  body: string;
  service: string;
  environment: string;
  host: string;
  traceID: string | null;
  spanID: string | null;
  data: Record<string, unknown>;
  projectId: number;
}

export interface TransactionSummary {
  name: string;
  op: string;
  count: number;
  error_count: number;
  p50_ms: number;
  p95_ms: number;
  avg_ms: number;
  last_seen: string;
}

export interface ReleaseHealth {
  version: string;
  first_seen: string;
  last_seen: string;
  issue_count: number;
  healthy_sessions: number;
  errored_sessions: number;
  crashed_sessions: number;
  crash_free_rate: number;
}

export interface UptimeMonitor {
  id: number;
  project_id: number;
  uuid: string;
  name: string;
  expected_interval_sec: number;
  last_heartbeat_at: string | null;
  status: string;
}

export interface AlertRule {
  id: number;
  project_id: number;
  name: string;
  trigger_type: string;
  channel_type: string;
  target_url: string;
  email_to: string;
}

export interface ApiTokenItem {
  id: number;
  name: string;
  token_prefix: string;
  role: string;
  created_at: string;
}

let csrfToken = "";

export function setCsrfToken(tok: string): void {
  csrfToken = tok;
}

export async function apiFetch<T>(
  path: string,
  options: { method?: string; body?: unknown } = {}
): Promise<{ ok: boolean; status: number; data: T | null; error?: string; hits?: number }> {
  const headers: Record<string, string> = {};
  const method = options.method || "GET";
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (method !== "GET" && method !== "HEAD" && csrfToken) {
    headers["X-CSRF-Token"] = csrfToken;
  }
  const resp = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined
  });

  // Always consume the body stream before returning so Playwright networkidle never hangs
  const text = await resp.text().catch(() => "");
  let parsed: any = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }
  const hitsRaw = resp.headers.get("x-hits");
  const hits = hitsRaw ? Number(hitsRaw) : undefined;

  if (!resp.ok) {
    return {
      ok: false,
      status: resp.status,
      data: null,
      error: (parsed && parsed.error) || `HTTP ${resp.status}`,
      hits
    };
  }
  return { ok: true, status: resp.status, data: parsed as T, hits };
}
