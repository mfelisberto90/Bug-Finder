import {
  apiFetch,
  setCsrfToken,
  setTransportErrorHook,
  type AlertRule,
  type ApiTokenItem,
  type IssueEventDetail,
  type IssueSummary,
  type LocalSelfError,
  type LogEventItem,
  type Organization,
  type Project,
  type ReleaseHealth,
  type SelfCheckReport,
  type SelfProbeResult,
  type TransactionSummary,
  type UptimeMonitor,
  type UserInfo
} from "./api";

type TabId = "issues" | "logs" | "perf" | "uptime" | "projects" | "selfcheck";

interface AppStateModel {
  loading: boolean;
  needsSetup: boolean;
  user: UserInfo | null;
  orgSlug: string;
  orgs: Organization[];
  tab: TabId;
  projects: Project[];
  issues: IssueSummary[];
  issueFilterStatus: string;
  issueSearch: string;
  selectedIssue: IssueSummary | null;
  selectedIssueEvent: IssueEventDetail | null;
  logs: LogEventItem[];
  logSearch: string;
  logLevelFilter: string;
  liveTailOn: boolean;
  liveEntries: LogEventItem[];
  transactions: TransactionSummary[];
  releases: ReleaseHealth[];
  monitors: UptimeMonitor[];
  alerts: AlertRule[];
  tokens: ApiTokenItem[];
  lastCreatedToken: string | null;
  toast: string | null;
  traceView: Record<string, any> | null;
  themePref: "system" | "light" | "dark";
  selfCheck: SelfCheckReport | null;
  lastProbe: SelfProbeResult | null;
  localSelfErrors: LocalSelfError[];
  probeRunning: boolean;
}

const state: AppStateModel = {
  loading: true,
  needsSetup: false,
  user: null,
  orgSlug: "",
  orgs: [],
  tab: "issues",
  projects: [],
  issues: [],
  issueFilterStatus: "unresolved",
  issueSearch: "",
  selectedIssue: null,
  selectedIssueEvent: null,
  logs: [],
  logSearch: "",
  logLevelFilter: "",
  liveTailOn: false,
  liveEntries: [],
  transactions: [],
  releases: [],
  monitors: [],
  alerts: [],
  tokens: [],
  lastCreatedToken: null,
  toast: null,
  traceView: null,
  themePref: readSavedTheme(),
  selfCheck: null,
  lastProbe: null,
  localSelfErrors: [],
  probeRunning: false
};

let sseSource: EventSource | null = null;
let openDialogCount = 0;
let inRender = false;
let localErrSeq = 1;
let sendingClientError = false;
let lastClientErrSentAt = 0;
let lastClientErrSig = "";

function readSavedTheme(): "system" | "light" | "dark" {
  try {
    const v = localStorage.getItem("bf-color-scheme");
    if (v === "light" || v === "dark") return v;
  } catch {}
  return "system";
}

function applyTheme(pref: "system" | "light" | "dark"): void {
  state.themePref = pref;
  const meta = document.querySelector('meta[name="color-scheme"]');
  if (meta) {
    meta.setAttribute("content", pref === "system" ? "light dark" : pref);
  }
  try {
    if (pref === "system") localStorage.removeItem("bf-color-scheme");
    else localStorage.setItem("bf-color-scheme", pref);
  } catch {}
}

window.addEventListener("storage", (e) => {
  if (e.key === "bf-color-scheme") {
    applyTheme(readSavedTheme());
    render();
  }
});

function showToast(msg: string): void {
  state.toast = msg;
  render();
  setTimeout(() => {
    if (state.toast === msg) {
      state.toast = null;
      render();
    }
  }, 3200);
}

function esc(val: unknown): string {
  return String(val ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function openDialog(dlg: HTMLDialogElement): void {
  const chrome = document.getElementById("app-chrome");
  openDialogCount += 1;
  if (chrome) (chrome as any).inert = openDialogCount > 0;

  // Mandatory Safari light-dismiss fallback alongside closedby="any"
  if (!("closedBy" in HTMLDialogElement.prototype)) {
    dlg.addEventListener("click", (event) => {
      if (event.target !== dlg) return;
      const rect = dlg.getBoundingClientRect();
      const inside =
        rect.top <= event.clientY &&
        event.clientY <= rect.top + rect.height &&
        rect.left <= event.clientX &&
        event.clientX <= rect.left + rect.width;
      if (!inside) dlg.close();
    });
  }

  dlg.addEventListener(
    "close",
    () => {
      openDialogCount = Math.max(0, openDialogCount - 1);
      if (chrome) (chrome as any).inert = openDialogCount > 0;
    },
    { once: true }
  );
  dlg.showModal();
}

function scheduleRender(): void {
  if (inRender) {
    queueMicrotask(() => render());
  } else {
    render();
  }
}

async function refreshSelfCheck(): Promise<void> {
  if (!state.orgSlug || !state.user) return;
  const res = await apiFetch<SelfCheckReport>(
    `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/self-check/`
  );
  if (res.ok && res.data) {
    state.selfCheck = res.data;
  }
}

function recordClientSelfError(
  source: string,
  message: string,
  detail?: string,
  severity: "error" | "warn" = "error"
): void {
  const cleanMsg = (message || "Unexpected UI error").slice(0, 240);
  const cleanDetail = detail ? detail.slice(0, 480) : undefined;
  const sig = `${source}|${cleanMsg}`;

  let insertedEntryId: number | null = null;
  if (state.localSelfErrors[0]?.message !== cleanMsg || state.localSelfErrors[0]?.source !== source) {
    insertedEntryId = localErrSeq++;
    state.localSelfErrors.unshift({
      id: insertedEntryId,
      timestamp: new Date().toISOString(),
      source,
      severity,
      component: "spa",
      message: cleanMsg,
      detail: cleanDetail
    });
    if (state.localSelfErrors.length > 32) {
      state.localSelfErrors.length = 32;
    }
    scheduleRender();
  }

  const now = Date.now();
  if (
    state.user &&
    state.orgSlug &&
    !sendingClientError &&
    (sig !== lastClientErrSig || now - lastClientErrSentAt >= 5000)
  ) {
    sendingClientError = true;
    lastClientErrSig = sig;
    lastClientErrSentAt = now;
    void apiFetch(
      `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/self-check/client-error/`,
      {
        method: "POST",
        body: {
          message: cleanMsg,
          component: "spa",
          severity,
          detail: cleanDetail
        }
      }
    )
      .then(async (res) => {
        if (res.ok) {
          await refreshSelfCheck();
          if (state.selfCheck && insertedEntryId !== null) {
            state.localSelfErrors = state.localSelfErrors.filter((e) => e.id !== insertedEntryId);
          }
          scheduleRender();
        }
      })
      .finally(() => {
        sendingClientError = false;
      });
  }
}

window.addEventListener("error", (ev) => {
  const loc = ev.filename ? `${ev.filename}:${ev.lineno}:${ev.colno}` : undefined;
  recordClientSelfError("window.error", ev.message || "Unhandled JS error", loc);
});

window.addEventListener("unhandledrejection", (ev) => {
  const reason: any = ev.reason;
  const msg = reason?.message ? String(reason.message) : String(reason || "Unhandled Promise rejection");
  const stack = reason?.stack ? String(reason.stack) : undefined;
  recordClientSelfError("unhandledrejection", msg, stack);
});

setTransportErrorHook((info) => {
  recordClientSelfError(
    info.status === 0 ? "network_error" : "api_5xx",
    info.message,
    `endpoint=${info.path} status=${info.status}`
  );
});

async function boot(): Promise<void> {
  const me = await apiFetch<any>("/api/auth/me");
  if (me.ok && me.data) {
    state.user = me.data.user;
    state.orgSlug = me.data.organization_slug;
    state.orgs = me.data.organizations || [];
    setCsrfToken(me.data.csrf_token || "");
    state.loading = false;
    await Promise.all([loadCurrentTabData(), refreshSelfCheck()]);
    render();
    return;
  }
  const st = await apiFetch<{ needs_setup: boolean }>("/api/auth/status");
  state.needsSetup = Boolean(st.data?.needs_setup);
  state.loading = false;
  render();
}

async function loadCurrentTabData(): Promise<void> {
  if (!state.orgSlug) return;
  const projRes = await apiFetch<Project[]>(`/api/0/organizations/${encodeURIComponent(state.orgSlug)}/projects/`);
  if (projRes.ok && projRes.data) state.projects = projRes.data;

  if (state.tab === "issues") {
    const qParts: string[] = [];
    if (state.issueFilterStatus) qParts.push(`is:${state.issueFilterStatus}`);
    if (state.issueSearch.trim()) qParts.push(state.issueSearch.trim());
    const q = encodeURIComponent(qParts.join(" "));
    const res = await apiFetch<IssueSummary[]>(
      `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/issues/?query=${q}&limit=50`
    );
    if (res.ok && res.data) state.issues = res.data;
  } else if (state.tab === "logs") {
    const params = new URLSearchParams();
    if (state.logLevelFilter) params.set("level", state.logLevelFilter);
    if (state.logSearch.trim()) params.set("query", state.logSearch.trim());
    params.set("limit", "100");
    const res = await apiFetch<LogEventItem[]>(
      `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/logs/?${params.toString()}`
    );
    if (res.ok && res.data) state.logs = res.data;
  } else if (state.tab === "perf") {
    const [txRes, relRes] = await Promise.all([
      apiFetch<TransactionSummary[]>(`/api/0/organizations/${encodeURIComponent(state.orgSlug)}/transactions/`),
      apiFetch<ReleaseHealth[]>(`/api/0/organizations/${encodeURIComponent(state.orgSlug)}/releases/`)
    ]);
    if (txRes.ok && txRes.data) state.transactions = txRes.data;
    if (relRes.ok && relRes.data) state.releases = relRes.data;
  } else if (state.tab === "uptime") {
    const [monRes, alRes] = await Promise.all([
      apiFetch<UptimeMonitor[]>(`/api/0/organizations/${encodeURIComponent(state.orgSlug)}/monitors/`),
      apiFetch<AlertRule[]>(`/api/0/organizations/${encodeURIComponent(state.orgSlug)}/alerts/`)
    ]);
    if (monRes.ok && monRes.data) state.monitors = monRes.data;
    if (alRes.ok && alRes.data) state.alerts = alRes.data;
  } else if (state.tab === "projects") {
    const tokRes = await apiFetch<ApiTokenItem[]>(`/api/0/api-tokens/`);
    if (tokRes.ok && tokRes.data) state.tokens = tokRes.data;
  } else if (state.tab === "selfcheck") {
    await refreshSelfCheck();
  }
}

function stopLiveTail(): void {
  if (sseSource) {
    sseSource.close();
    sseSource = null;
  }
  state.liveTailOn = false;
}

function toggleLiveTail(): void {
  if (state.liveTailOn) {
    stopLiveTail();
    render();
    return;
  }
  state.liveTailOn = true;
  const params = new URLSearchParams();
  if (state.logLevelFilter) params.set("level", state.logLevelFilter);
  if (state.logSearch.trim()) params.set("query", state.logSearch.trim());
  const url = `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/logs/stream?${params.toString()}`;
  sseSource = new EventSource(url);
  const onMsg = (ev: MessageEvent) => {
    try {
      const parsed = JSON.parse(ev.data);
      state.liveEntries.unshift({
        id: String(parsed.timestamp_ms),
        timestamp: new Date(parsed.timestamp_ms).toISOString(),
        level: parsed.level || "info",
        body: parsed.title_or_body || "",
        service: parsed.service || "",
        environment: parsed.environment || "",
        host: "",
        traceID: parsed.trace_id || null,
        spanID: null,
        data: parsed.payload || {},
        projectId: parsed.project_id || 0
      });
      if (state.liveEntries.length > 80) state.liveEntries.length = 80;
      render();
    } catch {}
  };
  sseSource.addEventListener("log", onMsg);
  sseSource.addEventListener("issue", onMsg);
  render();
}

function renderAuthScreen(): string {
  if (state.needsSetup) {
    return `
      <main class="auth-wrap">
        <section class="card auth-card">
          <div class="brand-row">
            <div class="brand-title"><span class="brand-mark">BF</span> Bug-Finder Setup</div>
          </div>
          <p>Create your first organization, owner account, and default project DSN.</p>
          <form id="setup-form" class="stack-col">
            <div class="hp-field" aria-hidden="true">
              <label for="setup-website">Website</label>
              <input id="setup-website" name="website" tabindex="-1" autocomplete="off">
            </div>
            <label>Organization Name <input name="org_name" required value="Acme Engineering"></label>
            <label>Organization Slug <input name="org_slug" required pattern="[a-z0-9_\\-]{2,40}" value="acme"></label>
            <label>Your Name <input name="name" required value="Owner"></label>
            <label>Email <input name="email" type="email" required placeholder="you@company.com"></label>
            <label>Password (min 8 chars) <input name="password" type="password" required minlength="8"></label>
            <label>First Project Name <input name="project_name" required value="Main App"></label>
            <div class="cta-dock">
              <button type="submit" data-primary-cta="true">Complete Setup</button>
            </div>
          </form>
        </section>
      </main>`;
  }

  return `
    <main class="auth-wrap">
      <section class="card auth-card">
        <div class="brand-row">
          <div class="brand-title"><span class="brand-mark">BF</span> Bug-Finder</div>
        </div>
        <p>Sign in to monitor errors, structured logs, traces, and heartbeats.</p>
        <form id="login-form" class="stack-col">
          <div class="hp-field" aria-hidden="true">
            <label for="login-website">Website</label>
            <input id="login-website" name="website" tabindex="-1" autocomplete="off">
          </div>
          <label>Email <input name="email" type="email" required autocomplete="username"></label>
          <label>Password <input name="password" type="password" required autocomplete="current-password"></label>
          <div class="cta-dock">
            <button type="submit" data-primary-cta="true">Sign In</button>
          </div>
        </form>
      </section>
    </main>`;
}

function renderIssuesTab(): string {
  const unresolvedCount = state.issues.filter((i) => i.status === "unresolved").length;
  const totalEvents = state.issues.reduce((acc, i) => acc + i.count, 0);
  const regressions = state.issues.filter((i) => i.is_regression).length;

  const rowsHtml = state.issues.length
    ? state.issues
        .map(
          (it) => `
          <tr>
            <th scope="row">
              <button class="row-trigger" data-open-issue="${it.id}">
                <span class="mono">${esc(it.shortId)}</span> &mdash; ${esc(it.title)}
              </button>
              <div class="mono">${esc(it.culprit || "-")} &middot; ${esc(it.environment)}</div>
            </th>
            <td data-label="Level"><span class="badge badge-${esc(it.level)}">${esc(it.level)}</span></td>
            <td data-label="Status">
              <span class="badge badge-${esc(it.status)}">${esc(it.status)}</span>
              ${it.is_regression ? '<span class="badge badge-error">regression</span>' : ""}
            </td>
            <td data-label="Events" class="tabular">${it.count}</td>
            <td data-label="Users" class="tabular">${it.userCount}</td>
            <td data-label="Last Seen" class="tabular">${esc(it.lastSeen.slice(0, 19).replace("T", " "))}</td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="6">No issues matching filter. Send a test event from the Projects tab or CLI.</td></tr>`;

  return `
    <div class="page-header">
      <h1 class="page-title">Issues Inbox</h1>
      <div class="row-gap">
        <a class="nav-link" href="/api/0/organizations/${encodeURIComponent(state.orgSlug)}/issues/export.csv" download="issues.csv">Export CSV</a>
        <div class="cta-dock">
          <button id="btn-refresh-issues" data-primary-cta="true">Refresh Issues</button>
        </div>
      </div>
    </div>

    <div class="kpi-grid">
      <div class="card"><div class="kpi-label">Visible Issues</div><div class="kpi-value tabular">${state.issues.length}</div></div>
      <div class="card"><div class="kpi-label">Unresolved</div><div class="kpi-value tabular">${unresolvedCount}</div></div>
      <div class="card"><div class="kpi-label">Regressions</div><div class="kpi-value tabular">${regressions}</div></div>
      <div class="card"><div class="kpi-label">Events Counted</div><div class="kpi-value tabular">${totalEvents}</div></div>
    </div>

    <div class="toolbar">
      <input id="issue-search-input" class="search-box" type="search" placeholder="Search issues (FTS)..." value="${esc(state.issueSearch)}">
      <button id="btn-open-issue-filters">Filters (${esc(state.issueFilterStatus || "all")})</button>
    </div>

    <div tabindex="0" role="region" aria-labelledby="issues-cap" class="table-wrapper">
      <table class="data-table">
        <caption id="issues-cap" class="hp-field">Issues table</caption>
        <thead>
          <tr>
            <th>Issue</th><th>Level</th><th>Status</th><th>Events</th><th>Users</th><th>Last Seen</th>
          </tr>
        </thead>
        <tbody>${rowsHtml}</tbody>
      </table>
    </div>`;
}

function renderLogsTab(): string {
  const items = state.liveTailOn ? state.liveEntries : state.logs;
  const rowsHtml = items.length
    ? items
        .map(
          (l) => `
          <tr>
            <th scope="row" class="mono tabular">${esc(l.timestamp.slice(11, 23))}</th>
            <td data-label="Level"><span class="badge badge-${esc(l.level)}">${esc(l.level)}</span></td>
            <td data-label="Service" class="mono">${esc(l.service || "-")}</td>
            <td data-label="Body" class="mono">${esc(l.body)}</td>
            <td data-label="Trace" class="mono">
              ${
                l.traceID
                  ? `<button class="row-trigger" data-open-trace="${esc(l.traceID)}">${esc(l.traceID.slice(0, 12))}...</button>`
                  : "-"
              }
            </td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="5">No structured logs yet. Post to Sentry Envelope (type=log) or OTLP /v1/logs.</td></tr>`;

  return `
    <div class="page-header">
      <h1 class="page-title">Structured Logs &amp; Live Tail</h1>
      <div class="cta-dock">
        <button id="btn-toggle-live" data-primary-cta="true">${state.liveTailOn ? "Pause Live Tail" : "Start Live Tail (SSE)"}</button>
      </div>
    </div>

    <div class="toolbar">
      <input id="log-search-input" class="search-box" type="search" placeholder="Full-text search log bodies..." value="${esc(state.logSearch)}">
      <select id="log-level-select" aria-label="Log level filter">
        <option value="" ${state.logLevelFilter === "" ? "selected" : ""}>All levels</option>
        <option value="trace" ${state.logLevelFilter === "trace" ? "selected" : ""}>trace</option>
        <option value="debug" ${state.logLevelFilter === "debug" ? "selected" : ""}>debug</option>
        <option value="info" ${state.logLevelFilter === "info" ? "selected" : ""}>info</option>
        <option value="warn" ${state.logLevelFilter === "warn" ? "selected" : ""}>warn</option>
        <option value="error" ${state.logLevelFilter === "error" ? "selected" : ""}>error</option>
        <option value="fatal" ${state.logLevelFilter === "fatal" ? "selected" : ""}>fatal</option>
      </select>
      <button id="btn-search-logs">Search</button>
    </div>

    <div tabindex="0" role="region" aria-labelledby="logs-cap" class="table-wrapper">
      <table class="data-table">
        <caption id="logs-cap" class="hp-field">Structured logs stream</caption>
        <thead>
          <tr><th>Time</th><th>Level</th><th>Service</th><th>Message Body</th><th>Trace ID</th></tr>
        </thead>
        <tbody>${rowsHtml}</tbody>
      </table>
    </div>`;
}

function renderPerfTab(): string {
  const txRows = state.transactions.length
    ? state.transactions
        .map(
          (t) => `
          <tr>
            <th scope="row">${esc(t.name)} <div class="mono">${esc(t.op)}</div></th>
            <td data-label="Count" class="tabular">${t.count}</td>
            <td data-label="Errors" class="tabular">${t.error_count}</td>
            <td data-label="p50 (ms)" class="tabular">${t.p50_ms} ms</td>
            <td data-label="p95 (ms)" class="tabular">${t.p95_ms} ms</td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="5">No transactions ingested yet.</td></tr>`;

  const relRows = state.releases.length
    ? state.releases
        .map(
          (r) => `
          <tr>
            <th scope="row" class="mono">${esc(r.version)}</th>
            <td data-label="Crash-Free" class="tabular">${r.crash_free_rate}%</td>
            <td data-label="Healthy" class="tabular">${r.healthy_sessions}</td>
            <td data-label="Crashed" class="tabular">${r.crashed_sessions}</td>
            <td data-label="New Issues" class="tabular">${r.issue_count}</td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="5">No release sessions recorded yet.</td></tr>`;

  return `
    <div class="page-header">
      <h1 class="page-title">Performance &amp; Release Health</h1>
      <div class="cta-dock">
        <button id="btn-refresh-perf" data-primary-cta="true">Refresh Metrics</button>
      </div>
    </div>

    <div class="stack-col">
      <section class="card">
        <h2>Transactions (p50 / p95)</h2>
        <div tabindex="0" role="region" aria-labelledby="tx-cap" class="table-wrapper">
          <table class="data-table">
            <caption id="tx-cap" class="hp-field">Transactions</caption>
            <thead><tr><th>Transaction</th><th>Count</th><th>Errors</th><th>p50</th><th>p95</th></tr></thead>
            <tbody>${txRows}</tbody>
          </table>
        </div>
      </section>

      <section class="card">
        <h2>Release Health (Crash-Free Sessions)</h2>
        <div tabindex="0" role="region" aria-labelledby="rel-cap" class="table-wrapper">
          <table class="data-table">
            <caption id="rel-cap" class="hp-field">Releases</caption>
            <thead><tr><th>Release</th><th>Crash-Free %</th><th>Healthy</th><th>Crashed</th><th>New Issues</th></tr></thead>
            <tbody>${relRows}</tbody>
          </table>
        </div>
      </section>
    </div>`;
}

function renderUptimeTab(): string {
  const monRows = state.monitors.length
    ? state.monitors
        .map(
          (m) => `
          <tr>
            <th scope="row">${esc(m.name)}</th>
            <td data-label="Status"><span class="badge badge-${esc(m.status)}">${esc(m.status)}</span></td>
            <td data-label="Interval" class="tabular">${m.expected_interval_sec}s</td>
            <td data-label="Heartbeat Endpoint" class="mono">/api/0/organizations/${esc(state.orgSlug)}/heartbeat_check/${esc(m.uuid)}/</td>
            <td data-label="Action"><button data-ping-monitor="${esc(m.uuid)}">Ping Now</button></td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="5">No uptime heartbeat monitors configured.</td></tr>`;

  const alertRows = state.alerts.length
    ? state.alerts
        .map(
          (a) => `
          <tr>
            <th scope="row">${esc(a.name)}</th>
            <td data-label="Trigger">${esc(a.trigger_type)}</td>
            <td data-label="Channel">${esc(a.channel_type)}</td>
            <td data-label="Target" class="mono">${esc(a.target_url || a.email_to)}</td>
            <td data-label="Test"><button data-test-alert="${a.id}">Test</button></td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="5">No alert rules yet.</td></tr>`;

  return `
    <div class="page-header">
      <h1 class="page-title">Uptime Heartbeats &amp; Alerts</h1>
      <div class="row-gap">
        <button id="btn-new-alert">New Alert Rule</button>
        <div class="cta-dock">
          <button id="btn-new-monitor" data-primary-cta="true">New Heartbeat Monitor</button>
        </div>
      </div>
    </div>

    <div class="stack-col">
      <section class="card">
        <h2>Heartbeat Monitors</h2>
        <div tabindex="0" role="region" aria-labelledby="mon-cap" class="table-wrapper">
          <table class="data-table">
            <caption id="mon-cap" class="hp-field">Monitors</caption>
            <thead><tr><th>Name</th><th>Status</th><th>Interval</th><th>Check-in Endpoint</th><th>Ping</th></tr></thead>
            <tbody>${monRows}</tbody>
          </table>
        </div>
      </section>

      <section class="card">
        <h2>Alert Rules (Webhook / Slack / Discord / SMTP)</h2>
        <div tabindex="0" role="region" aria-labelledby="al-cap" class="table-wrapper">
          <table class="data-table">
            <caption id="al-cap" class="hp-field">Alerts</caption>
            <thead><tr><th>Name</th><th>Trigger</th><th>Channel</th><th>Target</th><th>Verify</th></tr></thead>
            <tbody>${alertRows}</tbody>
          </table>
        </div>
      </section>
    </div>`;
}

function renderProjectsTab(): string {
  const origin = location.origin;
  const firstProj = state.projects[0];
  const sampleDsn = firstProj?.dsn_public_key
    ? `${origin.replace("://", `://${firstProj.dsn_public_key}@`)}/${firstProj.id}`
    : `${origin.replace("://", "://<KEY>@")}/1`;

  const projCards = state.projects
    .map((p) => {
      const dsn = p.dsn_public_key
        ? `${origin.replace("://", `://${p.dsn_public_key}@`)}/${p.id}`
        : "(no active key)";
      return `
        <article class="card stack-col">
          <div class="row-gap">
            <strong>${esc(p.name)}</strong>
            <span class="badge badge-muted">${esc(p.platform)}</span>
            <span class="mono">ID: ${p.id}</span>
          </div>
          <div class="mono">DSN: ${esc(dsn)}</div>
          <div class="row-gap">
            <button data-copy-text="${esc(dsn)}">Copy DSN</button>
            ${
              p.tunnel_slug
                ? `<span class="mono">Tunnel: /t/${esc(p.tunnel_slug)}</span>`
                : `<button data-enable-tunnel="${esc(p.slug)}">Enable Anti-AdBlock Tunnel</button>`
            }
          </div>
        </article>`;
    })
    .join("");

  const tokRows = state.tokens
    .map(
      (t) => `
      <tr>
        <th scope="row">${esc(t.name)}</th>
        <td data-label="Prefix" class="mono">${esc(t.token_prefix)}...</td>
        <td data-label="Role">${esc(t.role)}</td>
        <td data-label="Revoke"><button class="btn-danger" data-del-token="${t.id}">Revoke</button></td>
      </tr>`
    )
    .join("");

  return `
    <div class="page-header">
      <h1 class="page-title">Projects, DSNs &amp; SDK Integrations</h1>
      <div class="cta-dock">
        <button id="btn-new-project" data-primary-cta="true">Create Project</button>
      </div>
    </div>

    <div class="grid-2">${projCards}</div>

    <section class="card">
      <h2>Drop-in SDK Quickstart (Errors + Structured Logs + RoleLane)</h2>
      <p>1. Browser Mini-SDK (&lt;3 KB zero-dep):</p>
      <pre class="snippet-box">&lt;script src="${esc(origin)}/sdk/bugfinder-mini.js"&gt;&lt;/script&gt;
&lt;script&gt;
  BugFinder.init({ dsn: "${esc(sampleDsn)}", environment: "production", release: "1.0.0" });
  BugFinder.logger.info("Checkout loaded", { cart_items: 2 });
&lt;/script&gt;</pre>
      <p>2. Official Sentry SDK (@sentry/browser / @sentry/node / sentry-sdk) &amp; RoleLane .env:</p>
      <pre class="snippet-box">GLITCHTIP_ENABLED=true
GLITCHTIP_DSN=${esc(sampleDsn)}
GLITCHTIP_API_URL=${esc(origin)}
GLITCHTIP_ORGANIZATION=${esc(state.orgSlug)}</pre>
      <p>3. OpenTelemetry OTLP/HTTP Logs + Terminal Tail + MCP Agent:</p>
      <pre class="snippet-box">POST ${esc(origin)}/api/${firstProj ? firstProj.id : 1}/otlp/v1/logs  (Authorization: Bearer ${esc(firstProj?.dsn_public_key || "<KEY>")})
bugfinder tail --url ${esc(origin)} --org ${esc(state.orgSlug)} --token &lt;API_TOKEN&gt;
bugfinder mcp --org ${esc(state.orgSlug)} --token &lt;API_TOKEN&gt;</pre>
    </section>

    <section class="card stack-col">
      <div class="row-gap">
        <h2>API Tokens (RoleLane ReadClient / CLI / MCP)</h2>
        <button id="btn-create-token">Generate API Token</button>
      </div>
      ${
        state.lastCreatedToken
          ? `<div class="badge badge-ok">Copy token now (shown once): <span class="mono">${esc(state.lastCreatedToken)}</span></div>`
          : ""
      }
      <div tabindex="0" role="region" aria-labelledby="tok-cap" class="table-wrapper">
        <table class="data-table">
          <caption id="tok-cap" class="hp-field">API Tokens</caption>
          <thead><tr><th>Name</th><th>Prefix</th><th>Role</th><th>Action</th></tr></thead>
          <tbody>${tokRows || '<tr><td colspan="4">No API tokens yet.</td></tr>'}</tbody>
        </table>
      </div>
    </section>`;
}

function getEffectiveSelfStatus(): {
  status: "ok" | "warn" | "error";
  badgeClass: string;
  badgeText: string;
  unackErrors: number;
  missingCount: number;
} {
  const serverUnack = state.selfCheck?.unacknowledged_error_count ?? 0;
  const localCount = state.localSelfErrors.length;
  const unackErrors = serverUnack + localCount;
  const missingCount = state.selfCheck?.missing_count ?? 0;

  if (state.selfCheck?.overall_status === "error" || localCount > 0) {
    return {
      status: "error",
      badgeClass: "error",
      badgeText: unackErrors > 0 ? `ERR (${unackErrors})` : "ERR",
      unackErrors,
      missingCount
    };
  }
  if (state.selfCheck?.overall_status === "warn") {
    return {
      status: "warn",
      badgeClass: "warn",
      badgeText: missingCount > 0 ? `WARN (${missingCount})` : "WARN",
      unackErrors,
      missingCount
    };
  }
  return {
    status: "ok",
    badgeClass: "ok",
    badgeText: "OK",
    unackErrors,
    missingCount
  };
}

function renderSelfCheckBanner(): string {
  if (state.tab === "selfcheck") return "";
  const summary = getEffectiveSelfStatus();
  if (summary.status === "ok" && summary.missingCount === 0 && summary.unackErrors === 0) {
    return "";
  }
  const stripClass =
    summary.status === "error" ? "selfcheck-strip-error" : "selfcheck-strip-warn";
  const label =
    summary.status === "error"
      ? `Auto-Check detectou ${summary.unackErrors} erro(s) interno(s) ou falha crítica`
      : `Auto-Check: ${summary.missingCount} item(ns) recomendado(s) pendente(s)`;

  return `
    <div class="selfcheck-strip ${stripClass}" role="status">
      <div class="selfcheck-strip-copy">
        <span class="badge badge-${esc(summary.badgeClass)}">${esc(summary.badgeText)}</span>
        <strong>${esc(label)}</strong>
      </div>
      <button id="btn-open-selfcheck" data-tab="selfcheck">Abrir Auto-Check</button>
    </div>`;
}

function renderSelfCheckTab(): string {
  const rep = state.selfCheck;
  const summary = getEffectiveSelfStatus();
  const origin = location.origin;
  const firstProj = state.projects[0];
  const sampleDsn = firstProj?.dsn_public_key
    ? `${origin.replace("://", `://${firstProj.dsn_public_key}@`)}/${firstProj.id}`
    : `${origin.replace("://", "://<KEY>@")}/1`;

  const rssMb = rep?.vm_rss_bytes != null ? (rep.vm_rss_bytes / (1024 * 1024)).toFixed(1) : "-";
  const dbMb = rep ? (rep.db_size_bytes / (1024 * 1024)).toFixed(2) : "-";

  const mergedErrors: Array<{
    source: string;
    component: string;
    severity: string;
    message: string;
    detail: string | null;
    count: number;
    time: string;
  }> = [
    ...state.localSelfErrors.map((e) => ({
      source: e.source,
      component: e.component,
      severity: e.severity,
      message: e.message,
      detail: e.detail || null,
      count: 1,
      time: e.timestamp.slice(11, 19)
    })),
    ...(rep?.self_errors || []).map((e) => ({
      source: e.source,
      component: e.component,
      severity: e.severity,
      message: e.message,
      detail: e.detail,
      count: e.count,
      time: new Date(e.timestamp_ms).toISOString().slice(11, 19)
    }))
  ];

  const errRows = mergedErrors.length
    ? mergedErrors
        .map(
          (e) => `
          <tr>
            <th scope="row" class="mono">${esc(e.source)}</th>
            <td data-label="Component" class="mono">${esc(e.component)}</td>
            <td data-label="Severity"><span class="badge badge-${esc(e.severity === "warn" ? "warn" : "error")}">${esc(e.severity)}</span></td>
            <td data-label="Message">
              <div>${esc(e.message)}</div>
              ${e.detail ? `<div class="mono">${esc(e.detail)}</div>` : ""}
            </td>
            <td data-label="Count / Time" class="tabular">${e.count}x &middot; ${esc(e.time)}</td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="5">Zero internal app errors captured in this session or runtime buffer.</td></tr>`;

  const checkRows = rep?.checks.length
    ? rep.checks
        .map(
          (c) => `
          <tr>
            <th scope="row">${esc(c.title)}</th>
            <td data-label="Category"><span class="badge badge-muted">${esc(c.category)}</span></td>
            <td data-label="Status"><span class="badge badge-${esc(c.status)}">${esc(c.status)}</span></td>
            <td data-label="Detail">${esc(c.detail)}</td>
            <td data-label="Fix">${c.fix ? esc(c.fix) : '<span class="badge badge-ok">Ready</span>'}</td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="5">Loading diagnostics...</td></tr>`;

  const probeHtml = state.lastProbe
    ? `
      <section class="card stack-col">
        <div class="row-gap">
          <h2>Resultado do Auto-Teste E2E</h2>
          <span class="badge badge-${state.lastProbe.ok ? "ok" : "error"}">${state.lastProbe.ok ? "ALL PASSED" : "FAILED"}</span>
        </div>
        <div class="probe-list">
          ${state.lastProbe.steps
            .map(
              (s) => `
              <div class="probe-item">
                <div>
                  <strong class="mono">${esc(s.name)}</strong>
                  <div>${esc(s.detail)}</div>
                </div>
                <span class="badge badge-${s.ok ? "ok" : "error"}">${s.ok ? "OK" : "FAIL"}</span>
              </div>`
            )
            .join("")}
        </div>
      </section>`
    : "";

  const totalErrCount = mergedErrors.length;
  const cmdServiceInstall = `./scripts/install.sh --service && bugfinder doctor`;
  const cmdDockerInstall = `./scripts/install.sh --docker`;
  const cmdMiniSdk = `<script src="${origin}/sdk/bugfinder-mini.js"></script>\n<script>\n  BugFinder.init({ dsn: "${sampleDsn}", environment: "production" });\n  BugFinder.logger.info("App started");\n</script>`;
  const cmdSentryEnv = `SENTRY_DSN=${sampleDsn}\nGLITCHTIP_ENABLED=true\nGLITCHTIP_DSN=${sampleDsn}\nGLITCHTIP_API_URL=${origin}\nGLITCHTIP_ORGANIZATION=${state.orgSlug}`;

  return `
    <div class="page-header">
      <h1 class="page-title">Auto-Check &amp; Self-Diagnostics</h1>
      <div class="row-gap">
        <button id="btn-refresh-selfcheck">Atualizar Diagnóstico</button>
        ${
          totalErrCount > 0 || (rep?.unacknowledged_error_count ?? 0) > 0
            ? `<button id="btn-ack-selfcheck" class="btn-danger">Reconhecer / Limpar Erros</button>`
            : ""
        }
        <div class="cta-dock">
          <button id="btn-run-self-probe" data-primary-cta="true" ${state.probeRunning ? "disabled" : ""}>
            ${state.probeRunning ? "Executando Auto-Teste..." : "Rodar Auto-Teste E2E"}
          </button>
        </div>
      </div>
    </div>

    <div class="kpi-grid">
      <div class="card">
        <div class="kpi-label">Status Geral</div>
        <div class="kpi-value"><span class="badge badge-${esc(summary.badgeClass)}">${esc(summary.badgeText)}</span></div>
      </div>
      <div class="card">
        <div class="kpi-label">Erros Internos</div>
        <div class="kpi-value tabular">${summary.unackErrors}</div>
      </div>
      <div class="card">
        <div class="kpi-label">Itens Faltando</div>
        <div class="kpi-value tabular">${summary.missingCount}</div>
      </div>
      <div class="card">
        <div class="kpi-label">RAM / Disco (${esc(rep?.engine || "sqlite")})</div>
        <div class="kpi-value tabular">${esc(rssMb)} MB / ${esc(dbMb)} MiB</div>
      </div>
    </div>

    <div class="stack-col">
      ${probeHtml}

      <section class="card stack-col">
        <h2>Erros Internos do Próprio App</h2>
        <div tabindex="0" role="region" aria-labelledby="self-err-cap" class="table-wrapper">
          <table class="data-table">
            <caption id="self-err-cap" class="hp-field">Internal application errors</caption>
            <thead><tr><th>Fonte</th><th>Componente</th><th>Severidade</th><th>Mensagem &amp; Detalhe</th><th>Qtd / Hora</th></tr></thead>
            <tbody>${errRows}</tbody>
          </table>
        </div>
      </section>

      <section class="card stack-col">
        <h2>Checklist de Auto-Check (Sistema &amp; O que está faltando)</h2>
        <div tabindex="0" role="region" aria-labelledby="self-chk-cap" class="table-wrapper">
          <table class="data-table">
            <caption id="self-chk-cap" class="hp-field">System readiness diagnostics</caption>
            <thead><tr><th>Verificação</th><th>Categoria</th><th>Status</th><th>Detalhe</th><th>Como Resolver</th></tr></thead>
            <tbody>${checkRows}</tbody>
          </table>
        </div>
      </section>

      <section class="card stack-col">
        <h2>Instalação em 1 Comando (Servidor + SDK do Projeto)</h2>
        <div>
          <p><strong>1. Instalar binário + serviço systemd --user + auto-check:</strong></p>
          <pre class="snippet-box">${esc(cmdServiceInstall)}</pre>
          <button data-copy-text="${esc(cmdServiceInstall)}">Copiar Instalação Serviço</button>
        </div>
        <div>
          <p><strong>2. Subir em Docker isolado (limite 32 MB RAM):</strong></p>
          <pre class="snippet-box">${esc(cmdDockerInstall)}</pre>
          <button data-copy-text="${esc(cmdDockerInstall)}">Copiar Comando Docker</button>
        </div>
        <div>
          <p><strong>3. Browser Mini-SDK (&lt;3 KB zero-dep, com captura de erros + logs):</strong></p>
          <pre class="snippet-box">${esc(cmdMiniSdk)}</pre>
          <button data-copy-text="${esc(cmdMiniSdk)}">Copiar Snippet Browser</button>
        </div>
        <div>
          <p><strong>4. .env para Sentry SDKs / RoleLane / GlitchTip:</strong></p>
          <pre class="snippet-box">${esc(cmdSentryEnv)}</pre>
          <button data-copy-text="${esc(cmdSentryEnv)}">Copiar Variáveis .env</button>
        </div>
      </section>
    </div>`;
}

function render(): void {
  const root = document.getElementById("app");
  if (!root) return;
  inRender = true;
  try {
    if (state.loading) {
      root.innerHTML = `<main class="auth-wrap"><div class="card">Loading Bug-Finder...</div></main>`;
      return;
    }

    if (!state.user) {
      const localErrBanner = state.localSelfErrors.length
        ? `<div class="selfcheck-strip selfcheck-strip-error" role="status"><strong>Erro interno no app:</strong> ${esc(state.localSelfErrors[0].message)}</div>`
        : "";
      root.innerHTML =
        renderAuthScreen() +
        localErrBanner +
        (state.toast ? `<div class="toast">${esc(state.toast)}</div>` : "");
      bindAuthHandlers();
      return;
    }

    let bodyHtml = "";
    if (state.tab === "issues") bodyHtml = renderIssuesTab();
    else if (state.tab === "logs") bodyHtml = renderLogsTab();
    else if (state.tab === "perf") bodyHtml = renderPerfTab();
    else if (state.tab === "uptime") bodyHtml = renderUptimeTab();
    else if (state.tab === "selfcheck") bodyHtml = renderSelfCheckTab();
    else bodyHtml = renderProjectsTab();

    const selfSummary = getEffectiveSelfStatus();

    root.innerHTML = `
      <div id="app-chrome" class="shell">
        <aside class="sidebar">
          <div class="brand-row">
            <div class="brand-title"><span class="brand-mark">BF</span> Bug-Finder</div>
          </div>
          <div class="mono">Org: ${esc(state.orgSlug)}</div>
          <nav class="nav-list" aria-label="Main navigation">
            <button class="nav-link" data-tab="issues" ${state.tab === "issues" ? 'aria-current="page"' : ""}>Issues</button>
            <button class="nav-link" data-tab="logs" ${state.tab === "logs" ? 'aria-current="page"' : ""}>Logs &amp; Tail</button>
            <button class="nav-link" data-tab="perf" ${state.tab === "perf" ? 'aria-current="page"' : ""}>Performance</button>
            <button class="nav-link" data-tab="uptime" ${state.tab === "uptime" ? 'aria-current="page"' : ""}>Uptime &amp; Alerts</button>
            <button class="nav-link" data-tab="projects" ${state.tab === "projects" ? 'aria-current="page"' : ""}>Projects &amp; SDK</button>
            <button class="nav-link" data-tab="selfcheck" ${state.tab === "selfcheck" ? 'aria-current="page"' : ""}>
              <span>Auto-Check</span>
              <span class="badge badge-${esc(selfSummary.badgeClass)}">${esc(selfSummary.badgeText)}</span>
            </button>
          </nav>
          <div class="sidebar-foot">
            <label>Theme
              <select id="theme-select">
                <option value="system" ${state.themePref === "system" ? "selected" : ""}>System</option>
                <option value="light" ${state.themePref === "light" ? "selected" : ""}>Light</option>
                <option value="dark" ${state.themePref === "dark" ? "selected" : ""}>Dark</option>
              </select>
            </label>
            <button id="btn-cmdk">Command Palette (Ctrl+K)</button>
            <button id="btn-logout">Sign Out (${esc(state.user.name)})</button>
          </div>
        </aside>

        <div>
          <header class="mobile-top-bar">
            <div class="brand-title"><span class="brand-mark">BF</span> Bug-Finder</div>
            <button data-tab="selfcheck" aria-label="Open Auto-Check">
              <span>Auto-Check</span>
              <span class="badge badge-${esc(selfSummary.badgeClass)}">${esc(selfSummary.badgeText)}</span>
            </button>
          </header>
          <main class="main-pane">${renderSelfCheckBanner()}${bodyHtml}</main>
        </div>

        <nav class="mobile-tabbar" aria-label="Mobile navigation">
          <button class="nav-link" data-tab="issues" ${state.tab === "issues" ? 'aria-current="page"' : ""}>Issues</button>
          <button class="nav-link" data-tab="logs" ${state.tab === "logs" ? 'aria-current="page"' : ""}>Logs</button>
          <button class="nav-link" data-tab="perf" ${state.tab === "perf" ? 'aria-current="page"' : ""}>Perf</button>
          <button class="nav-link" data-tab="uptime" ${state.tab === "uptime" ? 'aria-current="page"' : ""}>Uptime</button>
          <button class="nav-link" data-tab="projects" ${state.tab === "projects" ? 'aria-current="page"' : ""}>SDK</button>
        </nav>
      </div>
      ${renderDialogs()}
      ${state.toast ? `<div class="toast" role="status">${esc(state.toast)}</div>` : ""}`;

    bindDashboardHandlers();
  } finally {
    inRender = false;
  }
}

function renderDialogs(): string {
  const issue = state.selectedIssue;
  const ev = state.selectedIssueEvent;
  let framesHtml = "";
  const excVals = ev?.payload?.exception?.values;
  if (Array.isArray(excVals)) {
    framesHtml = excVals
      .map((exc: any) => {
        const frames = exc?.stacktrace?.frames || [];
        return frames
          .slice()
          .reverse()
          .map((fr: any) => {
            const pre = Array.isArray(fr.pre_context) ? fr.pre_context.join("\n") : "";
            const ctx = fr.context_line ? `<span class="code-line-active">${esc(fr.context_line)}</span>` : "";
            const post = Array.isArray(fr.post_context) ? fr.post_context.join("\n") : "";
            return `
              <div class="stack-frame">
                <div class="stack-frame-head">
                  <span>${esc(fr.filename || fr.abs_path || "?")} : ${esc(fr.lineno ?? "?")} (${esc(fr.function || "anon")})</span>
                  <span>${fr.source_mapped ? '<span class="badge badge-ok">source-mapped</span>' : ""}</span>
                </div>
                ${ctx ? `<pre class="code-ctx">${esc(pre)}\n${ctx}${esc(post)}</pre>` : ""}
              </div>`;
          })
          .join("");
      })
      .join("");
  }

  const crumbs = Array.isArray(ev?.payload?.breadcrumbs?.values) ? ev.payload.breadcrumbs.values : [];
  const crumbsHtml = crumbs.length
    ? crumbs
        .slice(-15)
        .map((b: any) => `<li><span class="mono">[${esc(b.category || "default")}]</span> ${esc(b.message || "")}</li>`)
        .join("")
    : "<li>No breadcrumbs captured.</li>";

  return `
    <dialog id="dlg-issue" class="bf-dialog" closedby="any" aria-labelledby="dlg-issue-title">
      <div class="dialog-head">
        <h2 id="dlg-issue-title">${issue ? `${esc(issue.shortId)} — ${esc(issue.title)}` : "Issue"}</h2>
        <button id="dlg-issue-close">Close</button>
      </div>
      ${
        issue
          ? `<div class="stack-col">
               <div class="row-gap">
                 <span class="badge badge-${esc(issue.status)}">${esc(issue.status)}</span>
                 <button data-issue-status="resolved" data-issue-id="${issue.id}" data-issue-rel="${esc(issue.last_release || "")}">Resolve</button>
                 <button data-issue-status="ignored" data-issue-id="${issue.id}">Ignore</button>
                 <button data-issue-status="unresolved" data-issue-id="${issue.id}">Reopen</button>
                 ${ev?.trace_id ? `<button data-open-trace="${esc(ev.trace_id)}">Inspect Trace Logs</button>` : ""}
               </div>
               <h3>Stack Trace</h3>
               <div>${framesHtml || "<p>No stacktrace attached to latest event.</p>"}</div>
               <h3>Breadcrumbs</h3>
               <ul>${crumbsHtml}</ul>
             </div>`
          : ""
      }
    </dialog>

    <dialog id="dlg-trace" class="bf-dialog" closedby="any" aria-labelledby="dlg-trace-title">
      <div class="dialog-head">
        <h2 id="dlg-trace-title">Trace Correlation</h2>
        <button id="dlg-trace-close">Close</button>
      </div>
      <pre class="snippet-box">${esc(state.traceView ? JSON.stringify(state.traceView, null, 2) : "")}</pre>
    </dialog>

    <dialog id="dlg-filters" class="bf-dialog" closedby="any" aria-labelledby="dlg-filters-title">
      <div class="dialog-head">
        <h2 id="dlg-filters-title">Issue Filters</h2>
        <button id="dlg-filters-close">Close</button>
      </div>
      <div class="stack-col">
        <label>Status
          <select id="filter-status-sel">
            <option value="unresolved" ${state.issueFilterStatus === "unresolved" ? "selected" : ""}>Unresolved</option>
            <option value="resolved" ${state.issueFilterStatus === "resolved" ? "selected" : ""}>Resolved</option>
            <option value="ignored" ${state.issueFilterStatus === "ignored" ? "selected" : ""}>Ignored</option>
            <option value="" ${state.issueFilterStatus === "" ? "selected" : ""}>All</option>
          </select>
        </label>
        <button id="btn-apply-filters">Apply Filters</button>
      </div>
    </dialog>

    <dialog id="dlg-create" class="bf-dialog" closedby="any" aria-labelledby="dlg-create-title">
      <div class="dialog-head">
        <h2 id="dlg-create-title">Create Resource</h2>
        <button id="dlg-create-close">Close</button>
      </div>
      <div id="dlg-create-body"></div>
    </dialog>

    <dialog id="dlg-cmdk" class="bf-dialog" closedby="any" aria-labelledby="dlg-cmdk-title">
      <div class="dialog-head">
        <h2 id="dlg-cmdk-title">Quick Jump</h2>
        <button id="dlg-cmdk-close">Close</button>
      </div>
      <div class="stack-col">
        <button data-cmdk-tab="issues">Go to Issues Inbox</button>
        <button data-cmdk-tab="logs">Go to Structured Logs &amp; Live Tail</button>
        <button data-cmdk-tab="perf">Go to Performance &amp; Release Health</button>
        <button data-cmdk-tab="uptime">Go to Uptime Monitors &amp; Alerts</button>
        <button data-cmdk-tab="projects">Go to Projects, DSN &amp; SDK Snippets</button>
        <button data-cmdk-tab="selfcheck">Go to Auto-Check &amp; One-Command Install</button>
      </div>
    </dialog>`;
}

function bindAuthHandlers(): void {
  const setupForm = document.getElementById("setup-form") as HTMLFormElement | null;
  if (setupForm) {
    setupForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(setupForm);
      const res = await apiFetch<any>("/api/auth/setup", {
        method: "POST",
        body: Object.fromEntries(fd.entries())
      });
      if (!res.ok) {
        showToast(res.error || "Setup failed");
        return;
      }
      await boot();
    });
  }

  const loginForm = document.getElementById("login-form") as HTMLFormElement | null;
  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(loginForm);
      const res = await apiFetch<any>("/api/auth/login", {
        method: "POST",
        body: Object.fromEntries(fd.entries())
      });
      if (!res.ok) {
        showToast(res.error || "Invalid credentials");
        return;
      }
      await boot();
    });
  }
}

function bindDashboardHandlers(): void {
  document.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const target = btn.dataset.tab as TabId;
      if (target !== "logs") stopLiveTail();
      state.tab = target;
      await loadCurrentTabData();
      render();
    });
  });

  const themeSel = document.getElementById("theme-select") as HTMLSelectElement | null;
  themeSel?.addEventListener("change", () => {
    applyTheme(themeSel.value as "system" | "light" | "dark");
  });

  document.getElementById("btn-logout")?.addEventListener("click", async () => {
    stopLiveTail();
    await apiFetch("/api/auth/logout", { method: "POST", body: {} });
    state.user = null;
    setCsrfToken("");
    render();
  });

  document.getElementById("btn-cmdk")?.addEventListener("click", () => {
    const dlg = document.getElementById("dlg-cmdk") as HTMLDialogElement | null;
    if (dlg) openDialog(dlg);
  });
  document.getElementById("dlg-cmdk-close")?.addEventListener("click", () => {
    (document.getElementById("dlg-cmdk") as HTMLDialogElement | null)?.close();
  });
  document.querySelectorAll<HTMLButtonElement>("[data-cmdk-tab]").forEach((b) => {
    b.addEventListener("click", async () => {
      (document.getElementById("dlg-cmdk") as HTMLDialogElement | null)?.close();
      state.tab = b.dataset.cmdkTab as TabId;
      await loadCurrentTabData();
      render();
    });
  });

  document.getElementById("btn-refresh-issues")?.addEventListener("click", async () => {
    const inp = document.getElementById("issue-search-input") as HTMLInputElement | null;
    if (inp) state.issueSearch = inp.value;
    await loadCurrentTabData();
    render();
  });
  document.getElementById("issue-search-input")?.addEventListener("keydown", async (e) => {
    if (e.key === "Enter") {
      state.issueSearch = (e.target as HTMLInputElement).value;
      await loadCurrentTabData();
      render();
    }
  });

  document.getElementById("btn-open-issue-filters")?.addEventListener("click", () => {
    const dlg = document.getElementById("dlg-filters") as HTMLDialogElement | null;
    if (dlg) openDialog(dlg);
  });
  document.getElementById("dlg-filters-close")?.addEventListener("click", () => {
    (document.getElementById("dlg-filters") as HTMLDialogElement | null)?.close();
  });
  document.getElementById("btn-apply-filters")?.addEventListener("click", async () => {
    const sel = document.getElementById("filter-status-sel") as HTMLSelectElement | null;
    if (sel) state.issueFilterStatus = sel.value;
    (document.getElementById("dlg-filters") as HTMLDialogElement | null)?.close();
    await loadCurrentTabData();
    render();
  });

  document.querySelectorAll<HTMLButtonElement>("[data-open-issue]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = Number(btn.dataset.openIssue);
      const found = state.issues.find((i) => i.id === id) || null;
      state.selectedIssue = found;
      const evRes = await apiFetch<IssueEventDetail>(
        `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/issues/${id}/events/latest/`
      );
      state.selectedIssueEvent = evRes.ok ? evRes.data : null;
      render();
      const dlg = document.getElementById("dlg-issue") as HTMLDialogElement | null;
      if (dlg) openDialog(dlg);
    });
  });
  document.getElementById("dlg-issue-close")?.addEventListener("click", () => {
    (document.getElementById("dlg-issue") as HTMLDialogElement | null)?.close();
  });

  // Optimistic status update (<50ms Doherty Threshold)
  document.querySelectorAll<HTMLButtonElement>("[data-issue-status]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = Number(btn.dataset.issueId);
      const newStatus = btn.dataset.issueStatus || "resolved";
      const rel = btn.dataset.issueRel || undefined;
      const prevStatus = state.selectedIssue?.status;
      if (state.selectedIssue && state.selectedIssue.id === id) {
        state.selectedIssue.status = newStatus;
      }
      const inList = state.issues.find((i) => i.id === id);
      if (inList) inList.status = newStatus;
      render();
      const dlg = document.getElementById("dlg-issue") as HTMLDialogElement | null;
      if (dlg && !dlg.open) openDialog(dlg);

      const res = await apiFetch<IssueSummary>(
        `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/issues/${id}/`,
        { method: "PUT", body: { status: newStatus, resolved_in_release: rel } }
      );
      if (!res.ok) {
        if (inList && prevStatus) inList.status = prevStatus;
        showToast(res.error || "Failed updating status");
        render();
      } else {
        showToast(`Issue marked ${newStatus}`);
      }
    });
  });

  document.getElementById("btn-toggle-live")?.addEventListener("click", toggleLiveTail);
  document.getElementById("btn-search-logs")?.addEventListener("click", async () => {
    const inp = document.getElementById("log-search-input") as HTMLInputElement | null;
    const sel = document.getElementById("log-level-select") as HTMLSelectElement | null;
    if (inp) state.logSearch = inp.value;
    if (sel) state.logLevelFilter = sel.value;
    await loadCurrentTabData();
    render();
  });

  document.querySelectorAll<HTMLButtonElement>("[data-open-trace]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const tid = btn.dataset.openTrace;
      if (!tid) return;
      const res = await apiFetch<any>(
        `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/traces/${encodeURIComponent(tid)}/`
      );
      if (res.ok && res.data) {
        state.traceView = res.data;
        render();
        const dlg = document.getElementById("dlg-trace") as HTMLDialogElement | null;
        if (dlg) openDialog(dlg);
      }
    });
  });
  document.getElementById("dlg-trace-close")?.addEventListener("click", () => {
    (document.getElementById("dlg-trace") as HTMLDialogElement | null)?.close();
  });

  document.getElementById("btn-refresh-perf")?.addEventListener("click", async () => {
    await loadCurrentTabData();
    render();
  });

  document.querySelectorAll<HTMLButtonElement>("[data-ping-monitor]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const uuid = btn.dataset.pingMonitor!;
      const res = await apiFetch(
        `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/heartbeat_check/${encodeURIComponent(uuid)}/`,
        { method: "POST", body: {} }
      );
      showToast(res.ok ? "Heartbeat recorded (UP)" : res.error || "Ping failed");
      await loadCurrentTabData();
      render();
    });
  });

  document.querySelectorAll<HTMLButtonElement>("[data-test-alert]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.testAlert!;
      const res = await apiFetch(
        `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/alerts/${id}/test/`,
        { method: "POST", body: {} }
      );
      showToast(res.ok ? "Test alert dispatched" : res.error || "Alert dispatch failed");
    });
  });

  document.querySelectorAll<HTMLButtonElement>("[data-copy-text]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await navigator.clipboard?.writeText(btn.dataset.copyText || "").catch(() => {});
      showToast("Copied to clipboard");
    });
  });

  document.querySelectorAll<HTMLButtonElement>("[data-enable-tunnel]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const slug = btn.dataset.enableTunnel!;
      const res = await apiFetch(
        `/api/0/projects/${encodeURIComponent(state.orgSlug)}/${encodeURIComponent(slug)}/tunnel/`,
        { method: "POST", body: {} }
      );
      if (res.ok) showToast("Anti-AdBlock tunnel enabled");
      await loadCurrentTabData();
      render();
    });
  });

  document.getElementById("btn-create-token")?.addEventListener("click", async () => {
    const res = await apiFetch<{ token: string }>(
      `/api/0/api-tokens/`,
      { method: "POST", body: { name: `Token ${new Date().toISOString().slice(0, 10)}`, role: "admin" } }
    );
    if (res.ok && res.data) {
      state.lastCreatedToken = res.data.token;
      await loadCurrentTabData();
      render();
    } else {
      showToast(res.error || "Token creation failed");
    }
  });

  document.querySelectorAll<HTMLButtonElement>("[data-del-token]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.delToken!;
      await apiFetch(`/api/0/api-tokens/${id}/`, { method: "DELETE" });
      await loadCurrentTabData();
      render();
    });
  });

  document.getElementById("btn-new-project")?.addEventListener("click", () => openCreateDialog("project"));
  document.getElementById("btn-new-monitor")?.addEventListener("click", () => openCreateDialog("monitor"));
  document.getElementById("btn-new-alert")?.addEventListener("click", () => openCreateDialog("alert"));
  document.getElementById("dlg-create-close")?.addEventListener("click", () => {
    (document.getElementById("dlg-create") as HTMLDialogElement | null)?.close();
  });

  document.getElementById("btn-refresh-selfcheck")?.addEventListener("click", async () => {
    await refreshSelfCheck();
    showToast("Diagnóstico atualizado");
    render();
  });

  document.getElementById("btn-run-self-probe")?.addEventListener("click", async () => {
    state.probeRunning = true;
    render();
    const res = await apiFetch<SelfProbeResult>(
      `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/self-check/probe/`,
      { method: "POST", body: { send_test_log: true } }
    );
    state.probeRunning = false;
    if (res.ok && res.data) {
      state.lastProbe = res.data;
      state.selfCheck = res.data.report;
      showToast(res.data.ok ? "Auto-Teste E2E concluído com sucesso" : "Auto-Teste E2E detectou falhas");
    } else {
      showToast(res.error || "Falha ao executar Auto-Teste E2E");
    }
    render();
  });

  document.getElementById("btn-ack-selfcheck")?.addEventListener("click", async () => {
    state.localSelfErrors = [];
    const res = await apiFetch<SelfCheckReport>(
      `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/self-check/ack/`,
      { method: "POST", body: { clear: true } }
    );
    if (res.ok && res.data) {
      state.selfCheck = res.data;
      showToast("Erros internos reconhecidos e limpos");
    } else {
      showToast(res.error || "Falha ao limpar erros internos");
    }
    render();
  });
}

function openCreateDialog(kind: "project" | "monitor" | "alert"): void {
  const dlg = document.getElementById("dlg-create") as HTMLDialogElement | null;
  const body = document.getElementById("dlg-create-body");
  if (!dlg || !body) return;
  const projOptions = state.projects
    .map((p) => `<option value="${p.id}">${esc(p.name)}</option>`)
    .join("");

  if (kind === "project") {
    body.innerHTML = `
      <form id="create-res-form" class="stack-col">
        <label>Project Name <input name="name" required placeholder="RoleLane Web"></label>
        <label>Platform
          <select name="platform">
            <option value="javascript">JavaScript / Browser</option>
            <option value="node">Node.js</option>
            <option value="php">PHP / Laravel</option>
            <option value="python">Python</option>
            <option value="rust">Rust</option>
          </select>
        </label>
        <button type="submit">Create Project</button>
      </form>`;
  } else if (kind === "monitor") {
    body.innerHTML = `
      <form id="create-res-form" class="stack-col">
        <label>Project <select name="project_id">${projOptions}</select></label>
        <label>Monitor Name <input name="name" required placeholder="Nightly Backup Cron"></label>
        <label>Expected Interval (sec) <input name="expected_interval_sec" type="number" value="60" min="10"></label>
        <button type="submit">Create Monitor</button>
      </form>`;
  } else {
    body.innerHTML = `
      <form id="create-res-form" class="stack-col">
        <label>Project <select name="project_id">${projOptions}</select></label>
        <label>Rule Name <input name="name" required placeholder="Notify Slack on new error"></label>
        <label>Trigger
          <select name="trigger_type">
            <option value="new_issue">New Issue</option>
            <option value="regression">Regression</option>
            <option value="fatal_log">Fatal Log</option>
            <option value="uptime_down">Uptime Down</option>
          </select>
        </label>
        <label>Channel
          <select name="channel_type">
            <option value="webhook">Webhook (JSON + HMAC)</option>
            <option value="slack">Slack Webhook</option>
            <option value="discord">Discord Webhook</option>
          </select>
        </label>
        <label>HTTPS Target URL <input name="target_url" type="url" required placeholder="https://hooks.slack.com/services/..."></label>
        <button type="submit">Save Alert Rule</button>
      </form>`;
  }

  const form = document.getElementById("create-res-form") as HTMLFormElement | null;
  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const raw = Object.fromEntries(new FormData(form).entries()) as Record<string, any>;
    if (raw.project_id) raw.project_id = Number(raw.project_id);
    if (raw.expected_interval_sec) raw.expected_interval_sec = Number(raw.expected_interval_sec);
    const url =
      kind === "project"
        ? `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/projects/`
        : kind === "monitor"
        ? `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/monitors/`
        : `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/alerts/`;
    const res = await apiFetch(url, { method: "POST", body: raw });
    if (!res.ok) {
      showToast(res.error || "Failed creating item");
      return;
    }
    dlg.close();
    await loadCurrentTabData();
    render();
  });

  openDialog(dlg);
}

window.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k" && state.user) {
    e.preventDefault();
    const dlg = document.getElementById("dlg-cmdk") as HTMLDialogElement | null;
    if (dlg && !dlg.open) openDialog(dlg);
  }
});

boot();
