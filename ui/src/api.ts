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
  safe_keys: string[];
  sensitive_keys: string[];
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
  threshold_count: number;
  window_sec: number;
  cooldown_sec: number;
  channel_type: string;
  target_url: string;
  has_secret: boolean;
  email_to: string;
}

export interface ProjectKeyItem {
  id: number;
  project_id: number;
  label: string;
  public_key: string;
  rate_limit_per_min: number;
  is_active: boolean;
  created_at: number;
}

export interface MemberItem {
  user_id: number;
  email: string;
  name: string;
  role: string;
  is_active: boolean;
}

export interface ApiTokenItem {
  id: number;
  name: string;
  token_prefix: string;
  role: string;
  created_at: string;
}

export interface SelfCheckItem {
  id: string;
  status: "ok" | "warn" | "error";
  category: string;
  title: string;
  detail: string;
  fix: string | null;
}

export interface SelfErrorRecord {
  id: number;
  timestamp_ms: number;
  source: string;
  severity: string;
  component: string;
  message: string;
  detail: string | null;
  count: number;
}

export interface SelfCheckReport {
  overall_status: "ok" | "warn" | "error";
  version: string;
  uptime_sec: number;
  engine: string;
  vm_rss_bytes: number | null;
  db_size_bytes: number;
  max_db_mb: number;
  checks: SelfCheckItem[];
  self_errors: SelfErrorRecord[];
  unacknowledged_error_count: number;
  missing_count: number;
}

export interface SelfProbeStep {
  name: string;
  ok: boolean;
  detail: string;
}

export interface SelfProbeResult {
  ok: boolean;
  steps: SelfProbeStep[];
  report: SelfCheckReport;
}

export interface LocalSelfError {
  id: number;
  timestamp: string;
  source: string;
  severity: string;
  component: string;
  message: string;
  detail?: string;
}

type TransportErrorHook = (info: { path: string; status: number; message: string }) => void;

let csrfToken = "";
let transportErrorHook: TransportErrorHook | null = null;

export function setCsrfToken(tok: string): void {
  csrfToken = tok;
}

export function setTransportErrorHook(fn: TransportErrorHook): void {
  transportErrorHook = fn;
}

function notifyTransportError(path: string, status: number, message: string): void {
  if (!transportErrorHook || path.includes("/self-check/client-error/")) {
    return;
  }
  try {
    transportErrorHook({ path, status, message });
  } catch {}
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

  let resp: Response;
  try {
    resp = await fetch(path, {
      method,
      headers,
      credentials: "same-origin",
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined
    });
  } catch (err: any) {
    const msg = err?.message ? String(err.message) : "Network error contacting Bug-Finder server";
    notifyTransportError(path, 0, msg);
    return {
      ok: false,
      status: 0,
      data: null,
      error: msg
    };
  }

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
    const errMsg = (parsed && parsed.error) || `HTTP ${resp.status}`;
    if (resp.status >= 500) {
      notifyTransportError(path, resp.status, `${method} ${path} -> ${errMsg}`);
    }
    return {
      ok: false,
      status: resp.status,
      data: null,
      error: errMsg,
      hits
    };
  }
  return { ok: true, status: resp.status, data: parsed as T, hits };
}
