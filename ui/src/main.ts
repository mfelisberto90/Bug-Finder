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
  type MemberItem,
  type Organization,
  type Project,
  type ProjectFilters,
  type ProjectKeyItem,
  type QuarantineItem,
  type ReleaseHealth,
  type SecurityEventItem,
  type SelfCheckReport,
  type SelfProbeResult,
  type ShieldPolicy,
  type ShieldSummary,
  type TransactionSummary,
  type UptimeMonitor,
  type UserInfo
} from "./api";

type TabId = "issues" | "logs" | "perf" | "uptime" | "projects" | "shield" | "selfcheck";
type MountedMode = "none" | "loading" | "setup" | "login" | "dashboard";

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
  issueSort: "date" | "freq" | "new";
  issueOffset: number;
  issueTotalHits: number;
  selectedIssue: IssueSummary | null;
  selectedIssueEvent: IssueEventDetail | null;
  logs: LogEventItem[];
  logSearch: string;
  logLevelFilter: string;
  logsHasMore: boolean;
  liveTailOn: boolean;
  liveEntries: LogEventItem[];
  transactions: TransactionSummary[];
  releases: ReleaseHealth[];
  monitors: UptimeMonitor[];
  alerts: AlertRule[];
  tokens: ApiTokenItem[];
  members: MemberItem[];
  shieldEvents: SecurityEventItem[];
  shieldSummary: ShieldSummary;
  shieldQuarantine: QuarantineItem[];
  shieldProjectFilter: number | null;
  activeProjectModalId: number | null;
  activeProjectKeys: ProjectKeyItem[];
  lastCreatedToken: string | null;
  traceView: Record<string, any> | null;
  themePref: "system" | "light" | "dark";
  selfCheck: SelfCheckReport | null;
  lastProbe: SelfProbeResult | null;
  localSelfErrors: LocalSelfError[];
  probeRunning: boolean;
}

const ISSUES_PAGE_SIZE = 25;
const LOGS_PAGE_SIZE = 50;

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
  issueSort: "date",
  issueOffset: 0,
  issueTotalHits: 0,
  selectedIssue: null,
  selectedIssueEvent: null,
  logs: [],
  logSearch: "",
  logLevelFilter: "",
  logsHasMore: false,
  liveTailOn: false,
  liveEntries: [],
  transactions: [],
  releases: [],
  monitors: [],
  alerts: [],
  tokens: [],
  members: [],
  shieldEvents: [],
  shieldSummary: { events_24h: 0, high_critical_24h: 0, secret_leaks_24h: 0, active_quarantines: 0 },
  shieldQuarantine: [],
  shieldProjectFilter: null,
  activeProjectModalId: null,
  activeProjectKeys: [],
  lastCreatedToken: null,
  traceView: null,
  themePref: readSavedTheme(),
  selfCheck: null,
  lastProbe: null,
  localSelfErrors: [],
  probeRunning: false
};

let sseSource: EventSource | null = null;
let mountedMode: MountedMode = "none";
let localErrSeq = 1;
let toastSeq = 1;
let toastTimer: number | null = null;
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
  const themeSel = document.getElementById("theme-select") as HTMLSelectElement | null;
  if (themeSel && themeSel.value !== pref) themeSel.value = pref;
  try {
    if (pref === "system") localStorage.removeItem("bf-color-scheme");
    else localStorage.setItem("bf-color-scheme", pref);
  } catch {}
}

window.addEventListener("storage", (e) => {
  if (e.key === "bf-color-scheme") {
    applyTheme(readSavedTheme());
  }
});

function esc(val: unknown): string {
  return String(val ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function ensureRoots(): {
  shell: HTMLElement;
  dialogs: HTMLElement;
  toast: HTMLElement;
} | null {
  const app = document.getElementById("app");
  if (!app) return null;
  let shell = document.getElementById("shell-root");
  let dialogs = document.getElementById("dialogs-root");
  let toast = document.getElementById("toast-root");
  if (!shell || !dialogs || !toast) {
    app.innerHTML =
      '<div id="shell-root"></div><div id="dialogs-root"></div><div id="toast-root" aria-live="polite"></div>';
    shell = document.getElementById("shell-root");
    dialogs = document.getElementById("dialogs-root");
    toast = document.getElementById("toast-root");
  }
  if (!shell || !dialogs || !toast) return null;
  return { shell, dialogs, toast };
}

function showToast(msg: string): void {
  const roots = ensureRoots();
  if (!roots) return;
  const seq = ++toastSeq;
  if (toastTimer !== null) {
    window.clearTimeout(toastTimer);
    toastTimer = null;
  }
  roots.toast.innerHTML = `<div class="toast" popover="manual" role="status">${esc(msg)}</div>`;
  const toastEl = roots.toast.firstElementChild as HTMLElement | null;
  if (toastEl && "showPopover" in toastEl) {
    try {
      (toastEl as any).showPopover();
    } catch {}
  }
  toastTimer = window.setTimeout(() => {
    if (toastSeq === seq) {
      roots.toast.innerHTML = "";
      toastTimer = null;
    }
  }, 3200);
}

function wireDialogBehavior(dlg: HTMLDialogElement): void {
  if (dlg.dataset.bfWired === "1") return;
  dlg.dataset.bfWired = "1";

  dlg.addEventListener("close", () => {
    dlg.returnValue = "";
  });

  // Safari fallback alongside declarative closedby="any": require both press and release outside dialog box
  if (!("closedBy" in HTMLDialogElement.prototype)) {
    const outside = (e: PointerEvent): boolean => {
      const r = dlg.getBoundingClientRect();
      return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
    };
    let pressedOutside = false;
    dlg.addEventListener("pointerdown", (e) => {
      pressedOutside = outside(e);
    });
    dlg.addEventListener("pointerup", (e) => {
      if (pressedOutside && outside(e)) {
        dlg.close();
      }
      pressedOutside = false;
    });
  }
}

function openDialog(dlg: HTMLDialogElement): void {
  wireDialogBehavior(dlg);
  if (!dlg.open) {
    dlg.showModal();
  }
}

function closeAllDialogs(): void {
  document.querySelectorAll<HTMLDialogElement>("#dialogs-root dialog[open]").forEach((d) => {
    try {
      d.close();
    } catch {}
  });
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

function syncSelfCheckSlots(): void {
  if (!state.user) {
    const authSlot = document.getElementById("auth-selfcheck-slot");
    if (authSlot) {
      authSlot.innerHTML = state.localSelfErrors.length
        ? `<div class="selfcheck-strip selfcheck-strip-error" role="status"><strong>Erro interno no app:</strong> ${esc(state.localSelfErrors[0].message)}</div>`
        : "";
    }
    return;
  }

  const summary = getEffectiveSelfStatus();
  document.querySelectorAll<HTMLElement>("[data-selfcheck-badge]").forEach((badge) => {
    badge.className = `badge badge-${summary.badgeClass}`;
    badge.textContent = summary.badgeText;
  });

  const bannerSlot = document.getElementById("selfcheck-banner-slot");
  if (bannerSlot) {
    bannerSlot.innerHTML = renderSelfCheckBanner();
    document.getElementById("btn-open-selfcheck")?.addEventListener("click", () => {
      void switchTab("selfcheck");
    });
  }

  if (state.tab === "selfcheck" && mountedMode === "dashboard") {
    renderMainPane();
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
    syncSelfCheckSlots();
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
          syncSelfCheckSlots();
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
    state.orgs = me.data.organizations || [];
    const preferredExists = state.orgs.some((o) => o.slug === state.orgSlug);
    if (!preferredExists) {
      state.orgSlug = me.data.organization_slug || state.orgs[0]?.slug || "";
    }
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

async function fetchIssuesPage(append: boolean): Promise<void> {
  const qParts: string[] = [];
  if (state.issueFilterStatus) qParts.push(`is:${state.issueFilterStatus}`);
  if (state.issueSearch.trim()) qParts.push(state.issueSearch.trim());
  const offset = append ? state.issues.length : 0;
  const params = new URLSearchParams({
    query: qParts.join(" "),
    sort: state.issueSort,
    limit: String(ISSUES_PAGE_SIZE),
    offset: String(offset)
  });
  const res = await apiFetch<IssueSummary[]>(
    `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/issues/?${params.toString()}`
  );
  if (res.ok && res.data) {
    if (append) {
      const seen = new Set(state.issues.map((i) => i.id));
      for (const item of res.data) {
        if (!seen.has(item.id)) state.issues.push(item);
      }
    } else {
      state.issues = res.data;
    }
    state.issueOffset = state.issues.length;
    state.issueTotalHits = res.hits ?? state.issues.length;
  }
}

async function fetchLogsPage(append: boolean): Promise<void> {
  const params = new URLSearchParams();
  if (state.logLevelFilter) params.set("level", state.logLevelFilter);
  if (state.logSearch.trim()) params.set("query", state.logSearch.trim());
  params.set("limit", String(LOGS_PAGE_SIZE));
  if (append && state.logs.length > 0) {
    params.set("cursor", state.logs[state.logs.length - 1].id);
  }
  const res = await apiFetch<LogEventItem[]>(
    `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/logs/?${params.toString()}`
  );
  if (res.ok && res.data) {
    if (append) {
      const seen = new Set(state.logs.map((l) => l.id));
      for (const item of res.data) {
        if (!seen.has(item.id)) state.logs.push(item);
      }
    } else {
      state.logs = res.data;
    }
    state.logsHasMore = res.data.length === LOGS_PAGE_SIZE;
  }
}

async function loadCurrentTabData(): Promise<void> {
  if (!state.orgSlug) return;
  const projRes = await apiFetch<Project[]>(
    `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/projects/`
  );
  if (projRes.ok && projRes.data) state.projects = projRes.data;

  if (state.tab === "issues") {
    await fetchIssuesPage(false);
  } else if (state.tab === "logs") {
    await fetchLogsPage(false);
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
    const [tokRes, memRes] = await Promise.all([
      apiFetch<ApiTokenItem[]>(`/api/0/api-tokens/`),
      apiFetch<MemberItem[]>(`/api/0/organizations/${encodeURIComponent(state.orgSlug)}/members/`)
    ]);
    if (tokRes.ok && tokRes.data) state.tokens = tokRes.data;
    if (memRes.ok && memRes.data) state.members = memRes.data;
  } else if (state.tab === "shield") {
    const q = state.shieldProjectFilter ? `?project_id=${state.shieldProjectFilter}` : "";
    const [evRes, qRes] = await Promise.all([
      apiFetch<{ summary: ShieldSummary; events: SecurityEventItem[] }>(
        `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/shield/events/${q}`
      ),
      apiFetch<QuarantineItem[]>(
        `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/shield/quarantine/${q}`
      )
    ]);
    if (evRes.ok && evRes.data) {
      state.shieldEvents = evRes.data.events || [];
      state.shieldSummary = evRes.data.summary || state.shieldSummary;
    }
    if (qRes.ok && qRes.data) state.shieldQuarantine = qRes.data;
  } else if (state.tab === "selfcheck") {
    await refreshSelfCheck();
  }
}

async function switchTab(target: TabId): Promise<void> {
  if (target !== "logs") stopLiveTail();
  state.tab = target;
  await loadCurrentTabData();
  render();
}

async function switchOrganization(slug: string): Promise<void> {
  if (!slug || slug === state.orgSlug) return;
  stopLiveTail();
  closeAllDialogs();
  state.orgSlug = slug;
  state.issues = [];
  state.issueOffset = 0;
  state.issueTotalHits = 0;
  state.logs = [];
  state.liveEntries = [];
  state.logsHasMore = false;
  state.selectedIssue = null;
  state.selectedIssueEvent = null;
  await Promise.all([loadCurrentTabData(), refreshSelfCheck()]);
  render();
}

function stopLiveTail(): void {
  if (sseSource) {
    sseSource.close();
    sseSource = null;
  }
  state.liveTailOn = false;
}

function renderLogRowsHtml(items: LogEventItem[]): string {
  return items.length
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
                  ? `<button type="button" class="row-trigger" data-open-trace="${esc(l.traceID)}">${esc(l.traceID.slice(0, 12))}...</button>`
                  : "-"
              }
            </td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="5">No structured logs yet. Post to Sentry Envelope (type=log) or OTLP /v1/logs.</td></tr>`;
}

function updateLiveTailDomInPlace(): void {
  const tbody = document.getElementById("logs-tbody");
  if (!tbody) return;
  const items = state.liveTailOn ? state.liveEntries : state.logs;
  tbody.innerHTML = renderLogRowsHtml(items);
  bindTraceOpenButtons(tbody);
  const toggleBtn = document.getElementById("btn-toggle-live");
  if (toggleBtn) {
    toggleBtn.textContent = state.liveTailOn ? "Pause Live Tail" : "Start Live Tail (SSE)";
  }
  const pager = document.getElementById("logs-pager-row");
  if (pager) {
    pager.classList.toggle("is-hidden", state.liveTailOn || !state.logsHasMore);
  }
}

function toggleLiveTail(): void {
  if (state.liveTailOn) {
    stopLiveTail();
    updateLiveTailDomInPlace();
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
      if (state.tab === "logs" && state.liveTailOn) {
        updateLiveTailDomInPlace();
      }
    } catch {}
  };
  sseSource.addEventListener("log", onMsg);
  sseSource.addEventListener("issue", onMsg);
  updateLiveTailDomInPlace();
}

function renderAuthScreen(): string {
  const errBanner = state.localSelfErrors.length
    ? `<div class="selfcheck-strip selfcheck-strip-error" role="status"><strong>Erro interno no app:</strong> ${esc(state.localSelfErrors[0].message)}</div>`
    : "";

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
            <label for="setup-org-name">Organization Name
              <input id="setup-org-name" name="org_name" type="text" required autocomplete="organization" enterkeyhint="next" value="Acme Engineering">
            </label>
            <label for="setup-org-slug">Organization Slug
              <input id="setup-org-slug" name="org_slug" type="text" required pattern="[a-z0-9_\\-]{2,40}" autocomplete="off" spellcheck="false" enterkeyhint="next" value="acme">
            </label>
            <label for="setup-name">Your Name
              <input id="setup-name" name="name" type="text" required autocomplete="name" enterkeyhint="next" value="Owner">
            </label>
            <label for="setup-email">Email
              <input id="setup-email" name="email" type="email" required autocomplete="email" spellcheck="false" enterkeyhint="next" placeholder="you@company.com">
            </label>
            <label for="setup-password">Password (min 8 chars)
              <input id="setup-password" name="password" type="password" required minlength="8" autocomplete="new-password" enterkeyhint="next">
            </label>
            <label for="setup-project-name">First Project Name
              <input id="setup-project-name" name="project_name" type="text" required autocomplete="off" enterkeyhint="done" value="Main App">
            </label>
            <div class="cta-dock">
              <button type="submit" data-primary-cta="true">Complete Setup</button>
            </div>
          </form>
        </section>
      </main>
      <div id="auth-selfcheck-slot">${errBanner}</div>`;
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
          <label for="login-email">Email
            <input id="login-email" name="email" type="email" required autocomplete="username" spellcheck="false" enterkeyhint="next">
          </label>
          <label for="login-password">Password
            <input id="login-password" name="password" type="password" required autocomplete="current-password" enterkeyhint="done">
          </label>
          <div class="cta-dock">
            <button type="submit" data-primary-cta="true">Sign In</button>
          </div>
        </form>
      </section>
    </main>
    <div id="auth-selfcheck-slot">${errBanner}</div>`;
}

function renderIssuesTab(): string {
  const unresolvedCount = state.issues.filter((i) => i.status === "unresolved").length;
  const totalEvents = state.issues.reduce((acc, i) => acc + i.count, 0);
  const regressions = state.issues.filter((i) => i.is_regression).length;
  const totalLabel = Math.max(state.issueTotalHits, state.issues.length);

  const rowsHtml = state.issues.length
    ? state.issues
        .map(
          (it) => `
          <tr>
            <th scope="row">
              <button type="button" class="row-trigger" data-open-issue="${it.id}">
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
          <button type="button" id="btn-refresh-issues" data-primary-cta="true">Refresh Issues</button>
        </div>
      </div>
    </div>

    <div class="kpi-grid">
      <div class="card"><div class="kpi-label">Loaded / Total</div><div class="kpi-value tabular">${state.issues.length} / ${totalLabel}</div></div>
      <div class="card"><div class="kpi-label">Unresolved</div><div class="kpi-value tabular">${unresolvedCount}</div></div>
      <div class="card"><div class="kpi-label">Regressions</div><div class="kpi-value tabular">${regressions}</div></div>
      <div class="card"><div class="kpi-label">Events Counted</div><div class="kpi-value tabular">${totalEvents}</div></div>
    </div>

    <div class="toolbar">
      <input id="issue-search-input" name="issue_search" class="search-box" type="search" aria-label="Search issues" autocomplete="off" placeholder="Search issues (FTS)..." value="${esc(state.issueSearch)}">
      <select id="issue-sort-select" name="issue_sort" aria-label="Sort issues">
        <option value="date" ${state.issueSort === "date" ? "selected" : ""}>Sort: Last Seen</option>
        <option value="freq" ${state.issueSort === "freq" ? "selected" : ""}>Sort: Most Frequent</option>
        <option value="new" ${state.issueSort === "new" ? "selected" : ""}>Sort: Newest</option>
      </select>
      <button type="button" id="btn-open-issue-filters">Filters (${esc(state.issueFilterStatus || "all")})</button>
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
    </div>

    <div class="pager-row">
      <span class="mono">Showing ${state.issues.length} of ${totalLabel} issues</span>
      ${
        state.issues.length < state.issueTotalHits
          ? `<button type="button" id="btn-load-more-issues">Carregar Mais</button>`
          : ""
      }
    </div>`;
}

function renderLogsTab(): string {
  const items = state.liveTailOn ? state.liveEntries : state.logs;
  const rowsHtml = renderLogRowsHtml(items);
  const showMore = !state.liveTailOn && state.logsHasMore && state.logs.length > 0;

  return `
    <div class="page-header">
      <h1 class="page-title">Structured Logs &amp; Live Tail</h1>
      <div class="cta-dock">
        <button type="button" id="btn-toggle-live" data-primary-cta="true">${state.liveTailOn ? "Pause Live Tail" : "Start Live Tail (SSE)"}</button>
      </div>
    </div>

    <div class="toolbar">
      <input id="log-search-input" name="log_search" class="search-box" type="search" aria-label="Search structured logs" autocomplete="off" placeholder="Full-text search log bodies..." value="${esc(state.logSearch)}">
      <select id="log-level-select" name="log_level" aria-label="Log level filter">
        <option value="" ${state.logLevelFilter === "" ? "selected" : ""}>All levels</option>
        <option value="trace" ${state.logLevelFilter === "trace" ? "selected" : ""}>trace</option>
        <option value="debug" ${state.logLevelFilter === "debug" ? "selected" : ""}>debug</option>
        <option value="info" ${state.logLevelFilter === "info" ? "selected" : ""}>info</option>
        <option value="warn" ${state.logLevelFilter === "warn" ? "selected" : ""}>warn</option>
        <option value="error" ${state.logLevelFilter === "error" ? "selected" : ""}>error</option>
        <option value="fatal" ${state.logLevelFilter === "fatal" ? "selected" : ""}>fatal</option>
      </select>
      <button type="button" id="btn-search-logs">Search</button>
    </div>

    <div tabindex="0" role="region" aria-labelledby="logs-cap" class="table-wrapper">
      <table class="data-table">
        <caption id="logs-cap" class="hp-field">Structured logs stream</caption>
        <thead>
          <tr><th>Time</th><th>Level</th><th>Service</th><th>Message Body</th><th>Trace ID</th></tr>
        </thead>
        <tbody id="logs-tbody">${rowsHtml}</tbody>
      </table>
    </div>

    <div id="logs-pager-row" class="pager-row ${showMore ? "" : "is-hidden"}">
      <span class="mono">Loaded ${state.logs.length} logs</span>
      <button type="button" id="btn-load-more-logs">Carregar Mais</button>
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
        <button type="button" id="btn-refresh-perf" data-primary-cta="true">Refresh Metrics</button>
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
            <td data-label="Actions">
              <div class="row-gap">
                <button type="button" data-ping-monitor="${esc(m.uuid)}">Ping Now</button>
                <button type="button" class="btn-danger" data-del-monitor="${m.id}">Delete</button>
              </div>
            </td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="5">No uptime heartbeat monitors configured.</td></tr>`;

  const alertRows = state.alerts.length
    ? state.alerts
        .map((a) => {
          const target = a.channel_type === "email" ? a.email_to : a.target_url;
          const trig =
            a.trigger_type === "threshold"
              ? `${a.trigger_type} (>=${a.threshold_count}/${a.window_sec}s)`
              : a.trigger_type;
          return `
          <tr>
            <th scope="row">${esc(a.name)}</th>
            <td data-label="Trigger">${esc(trig)}</td>
            <td data-label="Channel">${esc(a.channel_type)}${a.has_secret ? ' <span class="badge badge-muted">HMAC</span>' : ""}</td>
            <td data-label="Target" class="mono">${esc(target)}</td>
            <td data-label="Actions">
              <div class="row-gap">
                <button type="button" data-test-alert="${a.id}">Test</button>
                <button type="button" class="btn-danger" data-del-alert="${a.id}">Delete</button>
              </div>
            </td>
          </tr>`;
        })
        .join("")
    : `<tr><td colspan="5">No alert rules yet.</td></tr>`;

  return `
    <div class="page-header">
      <h1 class="page-title">Uptime Heartbeats &amp; Alerts</h1>
      <div class="row-gap">
        <button type="button" id="btn-new-alert">New Alert Rule</button>
        <div class="cta-dock">
          <button type="button" id="btn-new-monitor" data-primary-cta="true">New Heartbeat Monitor</button>
        </div>
      </div>
    </div>

    <div class="stack-col">
      <section class="card">
        <h2>Heartbeat Monitors</h2>
        <div tabindex="0" role="region" aria-labelledby="mon-cap" class="table-wrapper">
          <table class="data-table">
            <caption id="mon-cap" class="hp-field">Monitors</caption>
            <thead><tr><th>Name</th><th>Status</th><th>Interval</th><th>Check-in Endpoint</th><th>Actions</th></tr></thead>
            <tbody>${monRows}</tbody>
          </table>
        </div>
      </section>

      <section class="card">
        <h2>Alert Rules (Webhook / Slack / Discord / SMTP)</h2>
        <div tabindex="0" role="region" aria-labelledby="al-cap" class="table-wrapper">
          <table class="data-table">
            <caption id="al-cap" class="hp-field">Alerts</caption>
            <thead><tr><th>Name</th><th>Trigger</th><th>Channel</th><th>Target</th><th>Actions</th></tr></thead>
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
            <button type="button" data-copy-text="${esc(dsn)}">Copy DSN</button>
            <button type="button" data-open-proj-settings="${p.id}">Filters &amp; Scrubbing</button>
            <button type="button" data-open-proj-keys="${p.id}">DSN Keys</button>
            ${
              p.tunnel_slug
                ? `<span class="mono">Tunnel: /t/${esc(p.tunnel_slug)}</span>`
                : `<button type="button" data-enable-tunnel="${esc(p.slug)}">Enable Anti-AdBlock Tunnel</button>`
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
        <td data-label="Revoke"><button type="button" class="btn-danger" data-del-token="${t.id}">Revoke</button></td>
      </tr>`
    )
    .join("");

  const memberRows = state.members
    .map((m) => {
      const isSelf = state.user?.id === m.user_id;
      return `
      <tr>
        <th scope="row">
          <div>${esc(m.name)}</div>
          <div class="mono">${esc(m.email)}</div>
        </th>
        <td data-label="Role">
          <select id="member-role-${m.user_id}" name="member_role_${m.user_id}" aria-label="Role for ${esc(m.email)}" data-member-role="${m.user_id}" ${isSelf ? "disabled" : ""}>
            <option value="owner" ${m.role === "owner" ? "selected" : ""}>owner</option>
            <option value="admin" ${m.role === "admin" ? "selected" : ""}>admin</option>
            <option value="member" ${m.role === "member" ? "selected" : ""}>member</option>
            <option value="viewer" ${m.role === "viewer" ? "selected" : ""}>viewer</option>
          </select>
        </td>
        <td data-label="Status">
          <span class="badge badge-${m.is_active ? "ok" : "muted"}">${m.is_active ? "active" : "inactive"}</span>
        </td>
        <td data-label="Action">
          <button type="button" class="btn-danger" data-del-member="${m.user_id}" ${isSelf ? "disabled" : ""}>Remove</button>
        </td>
      </tr>`;
    })
    .join("");

  return `
    <div class="page-header">
      <h1 class="page-title">Projects, DSNs &amp; SDK Integrations</h1>
      <div class="cta-dock">
        <button type="button" id="btn-new-project" data-primary-cta="true">Create Project</button>
      </div>
    </div>

    <div class="grid-2">${projCards}</div>

    <section class="card stack-col">
      <div class="row-gap">
        <h2>Team Members</h2>
        <button type="button" id="btn-add-member">Add Member</button>
      </div>
      <div tabindex="0" role="region" aria-labelledby="mem-cap" class="table-wrapper">
        <table class="data-table">
          <caption id="mem-cap" class="hp-field">Team Members</caption>
          <thead><tr><th>Member</th><th>Role</th><th>Status</th><th>Action</th></tr></thead>
          <tbody>${memberRows || '<tr><td colspan="4">No team members found.</td></tr>'}</tbody>
        </table>
      </div>
    </section>

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
        <button type="button" id="btn-create-token">Generate API Token</button>
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

function renderShieldTab(): string {
  const origin = location.origin;
  const firstProj = state.projects[0];
  const sampleDsn = firstProj?.dsn_public_key
    ? `${origin.replace("://", `://${firstProj.dsn_public_key}@`)}/${firstProj.id}`
    : `${origin.replace("://", "://<KEY>@")}/1`;
  const pid = firstProj ? firstProj.id : 1;
  const pslug = firstProj?.slug || "app";
  const org = state.orgSlug;
  const mode = firstProj?.filters?.shield?.mode || "detect";
  const s = state.shieldSummary;

  const projOpts = state.projects
    .map(
      (p) =>
        `<option value="${p.id}" ${state.shieldProjectFilter === p.id ? "selected" : ""}>${esc(p.name)}</option>`
    )
    .join("");

  const qRows = state.shieldQuarantine.length
    ? state.shieldQuarantine
        .map(
          (q) => `
          <tr>
            <th scope="row"><span class="badge badge-${q.subject_type === "ip" ? "error" : "warn"}">${esc(q.subject_type)}</span></th>
            <td data-label="Subject HMAC" class="mono">${esc(q.subject_hmac.slice(0, 16))}...</td>
            <td data-label="Reason">${esc(q.reason)}</td>
            <td data-label="Score" class="tabular">${q.risk_score}</td>
            <td data-label="Expires" class="tabular">${esc(q.expires_at.slice(0, 19).replace("T", " "))}</td>
            <td data-label="Action"><button type="button" class="btn-danger" data-del-quarantine="${q.id}">Liberar</button></td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="6">Nenhuma sessão ou IP em quarentena ativa.</td></tr>`;

  const evRows = state.shieldEvents.length
    ? state.shieldEvents
        .map(
          (e) => `
          <tr>
            <th scope="row" class="mono">${esc(e.signal_type)}</th>
            <td data-label="Category"><span class="badge badge-muted">${esc(e.category)}</span></td>
            <td data-label="Severity / Score">
              <span class="badge badge-${e.severity === "critical" || e.severity === "high" ? "error" : e.severity === "medium" ? "warn" : "info"}">${esc(e.severity)} (${e.risk_score})</span>
            </td>
            <td data-label="Source / Path" class="mono">${esc(e.source_kind)} &middot; ${esc(e.path || "-")}</td>
            <td data-label="Action / Time" class="tabular">${esc(e.action_taken)} &middot; ${esc(e.timestamp.slice(11, 19))}</td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="5">Nenhum evento Anti-REA, Log-IDS ou vazamento detectado ainda.</td></tr>`;

  const snipBrowser = `<script src="${origin}/sdk/bugfinder-shield.js"></script>
<script>
  BugFinderShield.init({
    dsn: "${sampleDsn}",
    mode: "${mode}",
    threshold: 80,
    canaryGlobals: ["__BF_INTERNAL_SECRETS__"],
    clearStorageKeys: ["auth_token"]
  });
</script>`;

  const snipNode = `// Express Anti-REA & Blocklist Middleware
const crypto = require("node:crypto");
const cache = { etag: "", ipKey: "", ips: new Set(), sids: new Set(), exp: 0 };
async function syncBlocklist() {
  if (Date.now() < cache.exp) return;
  const r = await fetch("${origin}/api/0/projects/${org}/${pslug}/shield/blocklist/", {
    headers: { Authorization: "Bearer <API_TOKEN>", "If-None-Match": cache.etag }
  });
  cache.exp = Date.now() + 10000;
  if (r.status === 200) {
    cache.etag = r.headers.get("etag") || "";
    const { ip_hmac_key, entries } = await r.json();
    cache.ipKey = ip_hmac_key || "";
    cache.ips = new Set(entries.filter((e) => e.subject_type === "ip").map((e) => e.subject_hmac));
    cache.sids = new Set(entries.filter((e) => e.subject_type === "session").map((e) => e.subject_hmac));
  }
}
app.use(async (req, res, next) => {
  await syncBlocklist().catch(() => {});
  if (cache.ipKey && cache.ips.has(crypto.createHmac("sha256", cache.ipKey).update(req.ip || "").digest("hex"))) {
    return res.status(403).end();
  }
  if (req.path.endsWith(".js.map") || req.path === "/.env" || req.path === "/.git/config") {
    void fetch("${origin}/api/${pid}/shield/", {
      method: "POST",
      headers: { Authorization: "Bearer <API_TOKEN>", "Content-Type": "application/json" },
      body: JSON.stringify({ signals: [req.path.endsWith(".map") ? "sourcemap_harvest" : "canary_route_hit"], actor_ip: req.ip, path: req.path })
    }).catch(() => {});
    return res.status(404).end();
  }
  next();
});`;

  const snipPhp = `// Laravel / RoleLane Shield + SourceMap & Canary Guard
if (str_ends_with($request->path(), '.js.map') || in_array('/' . ltrim($request->path(), '/'), ['/.env', '/.git/config'], true)) {
    Http::withToken(config('services.bugfinder.api_token'))->timeout(1)->post(
        '${origin}/api/${pid}/shield/',
        ['signals' => [str_ends_with($request->path(), '.js.map') ? 'sourcemap_harvest' : 'canary_route_hit'], 'actor_ip' => $request->ip(), 'path' => '/' . $request->path()]
    );
    abort(404);
}`;

  const snipPython = `# FastAPI Anti-REA + Debugger Check + Blocklist Sync
import sys, httpx
if sys.gettrace() is not None:
    httpx.post("${origin}/api/${pid}/shield/", headers={"Authorization": "Bearer <API_TOKEN>"}, json={"signals": ["runtime_debugger_attached"], "path": "/startup"}, timeout=1.5)`;

  return `
    <div class="page-header">
      <h1 class="page-title">Anti-REA Shield &amp; Mini-IDS</h1>
      <div class="row-gap">
        <button type="button" id="btn-shield-settings">Configurar Shield do Projeto</button>
        <div class="cta-dock">
          <button type="button" id="btn-refresh-shield" data-primary-cta="true">Atualizar Escudo</button>
        </div>
      </div>
    </div>

    <div class="toolbar">
      <label for="shield-project-filter">Projeto
        <select id="shield-project-filter" name="shield_project_id">
          <option value="" ${state.shieldProjectFilter === null ? "selected" : ""}>Todos os Projetos</option>
          ${projOpts}
        </select>
      </label>
    </div>

    <div class="kpi-grid">
      <div class="card"><div class="kpi-label">Ameaças (24h)</div><div class="kpi-value tabular">${s.events_24h}</div></div>
      <div class="card"><div class="kpi-label">Alta / Crítica</div><div class="kpi-value tabular">${s.high_critical_24h}</div></div>
      <div class="card"><div class="kpi-label">Segredos Interceptados</div><div class="kpi-value tabular">${s.secret_leaks_24h}</div></div>
      <div class="card"><div class="kpi-label">Quarentenas Ativas</div><div class="kpi-value tabular">${s.active_quarantines}</div></div>
    </div>

    <div class="stack-col">
      <section class="card stack-col">
        <h2>Quarentena Ativa (CGNAT-Safe: Sessões Browser / IPs Verificados Backend)</h2>
        <div tabindex="0" role="region" aria-labelledby="sh-q-cap" class="table-wrapper">
          <table class="data-table">
            <caption id="sh-q-cap" class="hp-field">Active quarantine entries</caption>
            <thead><tr><th>Tipo</th><th>HMAC</th><th>Motivo</th><th>Score</th><th>Expira</th><th>Ação</th></tr></thead>
            <tbody>${qRows}</tbody>
          </table>
        </div>
      </section>

      <section class="card stack-col">
        <h2>Eventos Anti-REA, Log-IDS &amp; Secret Leak Radar</h2>
        <div tabindex="0" role="region" aria-labelledby="sh-ev-cap" class="table-wrapper">
          <table class="data-table">
            <caption id="sh-ev-cap" class="hp-field">Security events</caption>
            <thead><tr><th>Sinal</th><th>Categoria</th><th>Severidade / Score</th><th>Fonte &amp; Rota</th><th>Ação / Hora</th></tr></thead>
            <tbody>${evRows}</tbody>
          </table>
        </div>
      </section>

      <section class="card stack-col">
        <h2>Proteções Prontas para o App Monitorado (1-Clique)</h2>
        <div>
          <p><strong>1. Browser Anti-REA Shield (~3 KB gzip, zero-dep, CDP/Hook/Canary Guard):</strong></p>
          <pre class="snippet-box">${esc(snipBrowser)}</pre>
          <button type="button" data-copy-text="${esc(snipBrowser)}">Copiar Snippet Browser</button>
        </div>
        <div>
          <p><strong>2. Node / Express Middleware (Blocklist ETag + SourceMap &amp; Canary Trap):</strong></p>
          <pre class="snippet-box">${esc(snipNode)}</pre>
          <button type="button" data-copy-text="${esc(snipNode)}">Copiar Middleware Node</button>
        </div>
        <div>
          <p><strong>3. Laravel / PHP Middleware (RoleLane):</strong></p>
          <pre class="snippet-box">${esc(snipPhp)}</pre>
          <button type="button" data-copy-text="${esc(snipPhp)}">Copiar Middleware PHP</button>
        </div>
        <div>
          <p><strong>4. Python / FastAPI Debugger &amp; Anti-REA Guard:</strong></p>
          <pre class="snippet-box">${esc(snipPython)}</pre>
          <button type="button" data-copy-text="${esc(snipPython)}">Copiar Snippet Python</button>
        </div>
      </section>
    </div>`;
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
      <button type="button" id="btn-open-selfcheck" data-tab="selfcheck">Abrir Auto-Check</button>
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
        <button type="button" id="btn-refresh-selfcheck">Atualizar Diagnóstico</button>
        ${
          totalErrCount > 0 || (rep?.unacknowledged_error_count ?? 0) > 0
            ? `<button type="button" id="btn-ack-selfcheck" class="btn-danger">Reconhecer / Limpar Erros</button>`
            : ""
        }
        <div class="cta-dock">
          <button type="button" id="btn-run-self-probe" data-primary-cta="true" ${state.probeRunning ? "disabled" : ""}>
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
          <button type="button" data-copy-text="${esc(cmdServiceInstall)}">Copiar Instalação Serviço</button>
        </div>
        <div>
          <p><strong>2. Subir em Docker isolado (limite 32 MB RAM):</strong></p>
          <pre class="snippet-box">${esc(cmdDockerInstall)}</pre>
          <button type="button" data-copy-text="${esc(cmdDockerInstall)}">Copiar Comando Docker</button>
        </div>
        <div>
          <p><strong>3. Browser Mini-SDK (&lt;3 KB zero-dep, com captura de erros + logs):</strong></p>
          <pre class="snippet-box">${esc(cmdMiniSdk)}</pre>
          <button type="button" data-copy-text="${esc(cmdMiniSdk)}">Copiar Snippet Browser</button>
        </div>
        <div>
          <p><strong>4. .env para Sentry SDKs / RoleLane / GlitchTip:</strong></p>
          <pre class="snippet-box">${esc(cmdSentryEnv)}</pre>
          <button type="button" data-copy-text="${esc(cmdSentryEnv)}">Copiar Variáveis .env</button>
        </div>
      </section>
    </div>`;
}

function mountDashboardShell(shellRoot: HTMLElement, dialogsRoot: HTMLElement): void {
  shellRoot.innerHTML = `
    <div id="app-chrome" class="shell">
      <aside class="sidebar">
        <div class="brand-row">
          <div class="brand-title"><span class="brand-mark">BF</span> Bug-Finder</div>
        </div>
        <label for="org-select">Organization
          <select id="org-select" name="org_slug"></select>
        </label>
        <nav class="nav-list" aria-label="Main navigation">
          <button type="button" class="nav-link" data-tab="issues">Issues</button>
          <button type="button" class="nav-link" data-tab="logs">Logs &amp; Tail</button>
          <button type="button" class="nav-link" data-tab="perf">Performance</button>
          <button type="button" class="nav-link" data-tab="uptime">Uptime &amp; Alerts</button>
          <button type="button" class="nav-link" data-tab="projects">Projects &amp; SDK</button>
          <button type="button" class="nav-link" data-tab="shield">Security Shield</button>
          <button type="button" class="nav-link" data-tab="selfcheck">
            <span>Auto-Check</span>
            <span class="badge badge-ok" data-selfcheck-badge="1">OK</span>
          </button>
        </nav>
        <div class="sidebar-foot">
          <label for="theme-select">Theme
            <select id="theme-select" name="theme">
              <option value="system">System</option>
              <option value="light">Light</option>
              <option value="dark">Dark</option>
            </select>
          </label>
          <button type="button" id="btn-cmdk">Command Palette (Ctrl+K)</button>
          <button type="button" id="btn-logout">Sign Out</button>
        </div>
      </aside>

      <div>
        <header class="mobile-top-bar">
          <div class="brand-title"><span class="brand-mark">BF</span> Bug-Finder</div>
          <div class="row-gap">
            <button type="button" data-tab="shield" aria-label="Open Security Shield">Shield</button>
            <button type="button" data-tab="selfcheck" aria-label="Open Auto-Check">
              <span>Auto-Check</span>
              <span class="badge badge-ok" data-selfcheck-badge="1">OK</span>
            </button>
          </div>
        </header>
        <div id="selfcheck-banner-slot"></div>
        <main id="main-pane" class="main-pane"></main>
      </div>

      <nav class="mobile-tabbar" aria-label="Mobile navigation">
        <button type="button" class="nav-link" data-tab="issues">Issues</button>
        <button type="button" class="nav-link" data-tab="logs">Logs</button>
        <button type="button" class="nav-link" data-tab="perf">Perf</button>
        <button type="button" class="nav-link" data-tab="uptime">Uptime</button>
        <button type="button" class="nav-link" data-tab="projects">SDK</button>
      </nav>
    </div>`;

  dialogsRoot.innerHTML = `
    <dialog id="dlg-issue" class="bf-dialog" closedby="any" aria-labelledby="dlg-issue-title">
      <div class="dialog-head">
        <h2 id="dlg-issue-title">Issue</h2>
        <button type="button" id="dlg-issue-close">Close</button>
      </div>
      <div id="dlg-issue-body"></div>
    </dialog>

    <dialog id="dlg-trace" class="bf-dialog" closedby="any" aria-labelledby="dlg-trace-title">
      <div class="dialog-head">
        <h2 id="dlg-trace-title">Trace Correlation</h2>
        <button type="button" id="dlg-trace-close">Close</button>
      </div>
      <div id="dlg-trace-body"></div>
    </dialog>

    <dialog id="dlg-filters" class="bf-dialog" closedby="any" aria-labelledby="dlg-filters-title">
      <div class="dialog-head">
        <h2 id="dlg-filters-title">Issue Filters</h2>
        <button type="button" id="dlg-filters-close">Close</button>
      </div>
      <div id="dlg-filters-body" class="stack-col">
        <label for="filter-status-sel">Status
          <select id="filter-status-sel" name="filter_status">
            <option value="unresolved">Unresolved</option>
            <option value="resolved">Resolved</option>
            <option value="ignored">Ignored</option>
            <option value="">All</option>
          </select>
        </label>
        <button type="button" id="btn-apply-filters">Apply Filters</button>
      </div>
    </dialog>

    <dialog id="dlg-create" class="bf-dialog" closedby="any" aria-labelledby="dlg-create-title">
      <div class="dialog-head">
        <h2 id="dlg-create-title">Create Resource</h2>
        <button type="button" id="dlg-create-close">Close</button>
      </div>
      <div id="dlg-create-body"></div>
    </dialog>

    <dialog id="dlg-proj-settings" class="bf-dialog" closedby="any" aria-labelledby="dlg-proj-settings-title">
      <div class="dialog-head">
        <h2 id="dlg-proj-settings-title">Project Filters &amp; Scrubbing</h2>
        <button type="button" id="dlg-proj-settings-close">Close</button>
      </div>
      <div id="dlg-proj-settings-body"></div>
    </dialog>

    <dialog id="dlg-proj-keys" class="bf-dialog" closedby="any" aria-labelledby="dlg-proj-keys-title">
      <div class="dialog-head">
        <h2 id="dlg-proj-keys-title">Project DSN Keys</h2>
        <button type="button" id="dlg-proj-keys-close">Close</button>
      </div>
      <div id="dlg-proj-keys-body"></div>
    </dialog>

    <dialog id="dlg-cmdk" class="bf-dialog" closedby="any" aria-labelledby="dlg-cmdk-title">
      <div class="dialog-head">
        <h2 id="dlg-cmdk-title">Quick Jump</h2>
        <button type="button" id="dlg-cmdk-close">Close</button>
      </div>
      <div class="stack-col">
        <button type="button" data-cmdk-tab="issues">Go to Issues Inbox</button>
        <button type="button" data-cmdk-tab="logs">Go to Structured Logs &amp; Live Tail</button>
        <button type="button" data-cmdk-tab="perf">Go to Performance &amp; Release Health</button>
        <button type="button" data-cmdk-tab="uptime">Go to Uptime Monitors &amp; Alerts</button>
        <button type="button" data-cmdk-tab="projects">Go to Projects, DSN &amp; SDK Snippets</button>
        <button type="button" data-cmdk-tab="shield">Go to Anti-REA Security Shield &amp; Mini-IDS</button>
        <button type="button" data-cmdk-tab="selfcheck">Go to Auto-Check &amp; One-Command Install</button>
      </div>
    </dialog>`;

  bindChromeHandlers();
}

function syncSidebarChrome(): void {
  document.querySelectorAll<HTMLButtonElement>("#app-chrome [data-tab]").forEach((btn) => {
    if (btn.dataset.tab === state.tab) {
      btn.setAttribute("aria-current", "page");
    } else {
      btn.removeAttribute("aria-current");
    }
  });

  const orgSel = document.getElementById("org-select") as HTMLSelectElement | null;
  if (orgSel) {
    const orgList = state.orgs.length
      ? state.orgs
      : state.orgSlug
      ? [{ id: 0, slug: state.orgSlug, name: state.orgSlug, role: state.user?.role || "" }]
      : [];
    const sig = orgList.map((o) => `${o.slug}:${o.name}`).join("|");
    if (orgSel.dataset.sig !== sig) {
      orgSel.dataset.sig = sig;
      orgSel.innerHTML = orgList
        .map((o) => `<option value="${esc(o.slug)}">${esc(o.name)} (${esc(o.slug)})</option>`)
        .join("");
    }
    if (orgSel.value !== state.orgSlug) {
      orgSel.value = state.orgSlug;
    }
  }

  const themeSel = document.getElementById("theme-select") as HTMLSelectElement | null;
  if (themeSel && themeSel.value !== state.themePref) {
    themeSel.value = state.themePref;
  }

  const logoutBtn = document.getElementById("btn-logout");
  if (logoutBtn && state.user) {
    logoutBtn.textContent = `Sign Out (${state.user.name})`;
  }

  const summary = getEffectiveSelfStatus();
  document.querySelectorAll<HTMLElement>("[data-selfcheck-badge]").forEach((badge) => {
    badge.className = `badge badge-${summary.badgeClass}`;
    badge.textContent = summary.badgeText;
  });

  const bannerSlot = document.getElementById("selfcheck-banner-slot");
  if (bannerSlot) {
    bannerSlot.innerHTML = renderSelfCheckBanner();
    document.getElementById("btn-open-selfcheck")?.addEventListener("click", () => {
      void switchTab("selfcheck");
    });
  }
}

function renderMainPane(): void {
  const mainPane = document.getElementById("main-pane");
  if (!mainPane) return;
  let bodyHtml = "";
  if (state.tab === "issues") bodyHtml = renderIssuesTab();
  else if (state.tab === "logs") bodyHtml = renderLogsTab();
  else if (state.tab === "perf") bodyHtml = renderPerfTab();
  else if (state.tab === "uptime") bodyHtml = renderUptimeTab();
  else if (state.tab === "shield") bodyHtml = renderShieldTab();
  else if (state.tab === "selfcheck") bodyHtml = renderSelfCheckTab();
  else bodyHtml = renderProjectsTab();

  mainPane.innerHTML = bodyHtml;
  bindMainPaneHandlers(mainPane);
}

function render(): void {
  const roots = ensureRoots();
  if (!roots) return;
  if (state.loading) {
    if (mountedMode !== "loading") {
      mountedMode = "loading";
      roots.dialogs.innerHTML = "";
      roots.shell.innerHTML = `<main class="auth-wrap"><div class="card">Loading Bug-Finder...</div></main>`;
    }
    return;
  }

  if (!state.user) {
    closeAllDialogs();
    const targetMode: MountedMode = state.needsSetup ? "setup" : "login";
    if (mountedMode !== targetMode) {
      mountedMode = targetMode;
      roots.dialogs.innerHTML = "";
      roots.shell.innerHTML = renderAuthScreen();
      bindAuthHandlers();
    } else {
      syncSelfCheckSlots();
    }
    return;
  }

  if (mountedMode !== "dashboard") {
    mountedMode = "dashboard";
    mountDashboardShell(roots.shell, roots.dialogs);
  }

  syncSidebarChrome();
  renderMainPane();
}

function populateIssueDialog(): void {
  const titleEl = document.getElementById("dlg-issue-title");
  const bodyEl = document.getElementById("dlg-issue-body");
  if (!titleEl || !bodyEl) return;

  const issue = state.selectedIssue;
  const ev = state.selectedIssueEvent;
  titleEl.textContent = issue ? `${issue.shortId} — ${issue.title}` : "Issue";
  if (!issue) {
    bodyEl.innerHTML = "";
    return;
  }

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

  bodyEl.innerHTML = `
    <div class="stack-col">
      <div class="row-gap">
        <span class="badge badge-${esc(issue.status)}">${esc(issue.status)}</span>
        <button type="button" data-issue-status="resolved" data-issue-id="${issue.id}" data-issue-rel="${esc(issue.last_release || "")}">Resolve</button>
        <button type="button" data-issue-status="ignored" data-issue-id="${issue.id}">Ignore</button>
        <button type="button" data-issue-status="unresolved" data-issue-id="${issue.id}">Reopen</button>
        ${ev?.trace_id ? `<button type="button" data-open-trace="${esc(ev.trace_id)}">Inspect Trace Logs</button>` : ""}
      </div>
      <h3>Stack Trace</h3>
      <div>${framesHtml || "<p>No stacktrace attached to latest event.</p>"}</div>
      <h3>Breadcrumbs</h3>
      <ul>${crumbsHtml}</ul>
    </div>`;

  bindTraceOpenButtons(bodyEl);
  bodyEl.querySelectorAll<HTMLButtonElement>("[data-issue-status]").forEach((btn) => {
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
      populateIssueDialog();
      if (state.tab === "issues") renderMainPane();

      const res = await apiFetch<IssueSummary>(
        `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/issues/${id}/`,
        { method: "PUT", body: { status: newStatus, resolved_in_release: rel } }
      );
      if (!res.ok) {
        if (state.selectedIssue && state.selectedIssue.id === id && prevStatus) {
          state.selectedIssue.status = prevStatus;
        }
        if (inList && prevStatus) inList.status = prevStatus;
        populateIssueDialog();
        if (state.tab === "issues") renderMainPane();
        showToast(res.error || "Failed updating status");
      } else {
        showToast(`Issue marked ${newStatus}`);
      }
    });
  });
}

function populateTraceDialog(): void {
  const bodyEl = document.getElementById("dlg-trace-body");
  if (!bodyEl) return;
  bodyEl.innerHTML = `<pre class="snippet-box">${esc(state.traceView ? JSON.stringify(state.traceView, null, 2) : "")}</pre>`;
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

function bindChromeHandlers(): void {
  document.querySelectorAll<HTMLButtonElement>("#app-chrome [data-tab]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await switchTab(btn.dataset.tab as TabId);
    });
  });

  const orgSel = document.getElementById("org-select") as HTMLSelectElement | null;
  orgSel?.addEventListener("change", () => {
    void switchOrganization(orgSel.value);
  });

  const themeSel = document.getElementById("theme-select") as HTMLSelectElement | null;
  themeSel?.addEventListener("change", () => {
    applyTheme(themeSel.value as "system" | "light" | "dark");
  });

  document.getElementById("btn-logout")?.addEventListener("click", async () => {
    stopLiveTail();
    closeAllDialogs();
    await apiFetch("/api/auth/logout", { method: "POST", body: {} });
    state.user = null;
    state.orgs = [];
    setCsrfToken("");
    render();
  });

  document.getElementById("btn-cmdk")?.addEventListener("click", () => {
    const dlg = document.getElementById("dlg-cmdk") as HTMLDialogElement | null;
    if (dlg) openDialog(dlg);
  });

  document.querySelectorAll<HTMLButtonElement>("[data-cmdk-tab]").forEach((b) => {
    b.addEventListener("click", async () => {
      (document.getElementById("dlg-cmdk") as HTMLDialogElement | null)?.close();
      await switchTab(b.dataset.cmdkTab as TabId);
    });
  });

  document.getElementById("dlg-issue-close")?.addEventListener("click", () => {
    (document.getElementById("dlg-issue") as HTMLDialogElement | null)?.close();
  });
  document.getElementById("dlg-trace-close")?.addEventListener("click", () => {
    (document.getElementById("dlg-trace") as HTMLDialogElement | null)?.close();
  });
  document.getElementById("dlg-filters-close")?.addEventListener("click", () => {
    (document.getElementById("dlg-filters") as HTMLDialogElement | null)?.close();
  });
  document.getElementById("dlg-create-close")?.addEventListener("click", () => {
    (document.getElementById("dlg-create") as HTMLDialogElement | null)?.close();
  });
  document.getElementById("dlg-proj-settings-close")?.addEventListener("click", () => {
    (document.getElementById("dlg-proj-settings") as HTMLDialogElement | null)?.close();
  });
  document.getElementById("dlg-proj-keys-close")?.addEventListener("click", () => {
    (document.getElementById("dlg-proj-keys") as HTMLDialogElement | null)?.close();
  });
  document.getElementById("dlg-cmdk-close")?.addEventListener("click", () => {
    (document.getElementById("dlg-cmdk") as HTMLDialogElement | null)?.close();
  });

  document.getElementById("btn-apply-filters")?.addEventListener("click", async () => {
    const sel = document.getElementById("filter-status-sel") as HTMLSelectElement | null;
    if (sel) state.issueFilterStatus = sel.value;
    (document.getElementById("dlg-filters") as HTMLDialogElement | null)?.close();
    await loadCurrentTabData();
    renderMainPane();
  });
}

function bindTraceOpenButtons(scope: ParentNode): void {
  scope.querySelectorAll<HTMLButtonElement>("[data-open-trace]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const tid = btn.dataset.openTrace;
      if (!tid) return;
      const res = await apiFetch<any>(
        `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/traces/${encodeURIComponent(tid)}/`
      );
      if (res.ok && res.data) {
        state.traceView = res.data;
        populateTraceDialog();
        const dlg = document.getElementById("dlg-trace") as HTMLDialogElement | null;
        if (dlg) openDialog(dlg);
      } else {
        showToast(res.error || "Failed loading trace");
      }
    });
  });
}

function bindCopyButtons(scope: ParentNode): void {
  scope.querySelectorAll<HTMLButtonElement>("[data-copy-text]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await navigator.clipboard?.writeText(btn.dataset.copyText || "").catch(() => {});
      showToast("Copied to clipboard");
    });
  });
}

function bindMainPaneHandlers(mainPane: HTMLElement): void {
  bindCopyButtons(mainPane);
  bindTraceOpenButtons(mainPane);

  // Issues tab handlers
  document.getElementById("btn-refresh-issues")?.addEventListener("click", async () => {
    const inp = document.getElementById("issue-search-input") as HTMLInputElement | null;
    if (inp) state.issueSearch = inp.value;
    await fetchIssuesPage(false);
    renderMainPane();
  });

  document.getElementById("issue-search-input")?.addEventListener("keydown", async (e) => {
    if (e.key === "Enter") {
      state.issueSearch = (e.target as HTMLInputElement).value;
      await fetchIssuesPage(false);
      renderMainPane();
    }
  });

  const issueSortSel = document.getElementById("issue-sort-select") as HTMLSelectElement | null;
  issueSortSel?.addEventListener("change", async () => {
    state.issueSort = (issueSortSel.value as "date" | "freq" | "new") || "date";
    await fetchIssuesPage(false);
    renderMainPane();
  });

  document.getElementById("btn-load-more-issues")?.addEventListener("click", async () => {
    await fetchIssuesPage(true);
    renderMainPane();
  });

  document.getElementById("btn-open-issue-filters")?.addEventListener("click", () => {
    const sel = document.getElementById("filter-status-sel") as HTMLSelectElement | null;
    if (sel) sel.value = state.issueFilterStatus;
    const dlg = document.getElementById("dlg-filters") as HTMLDialogElement | null;
    if (dlg) openDialog(dlg);
  });

  mainPane.querySelectorAll<HTMLButtonElement>("[data-open-issue]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = Number(btn.dataset.openIssue);
      state.selectedIssue = state.issues.find((i) => i.id === id) || null;
      const evRes = await apiFetch<IssueEventDetail>(
        `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/issues/${id}/events/latest/`
      );
      state.selectedIssueEvent = evRes.ok ? evRes.data : null;
      populateIssueDialog();
      const dlg = document.getElementById("dlg-issue") as HTMLDialogElement | null;
      if (dlg) openDialog(dlg);
    });
  });

  // Logs tab handlers
  document.getElementById("btn-toggle-live")?.addEventListener("click", toggleLiveTail);

  document.getElementById("btn-search-logs")?.addEventListener("click", async () => {
    const inp = document.getElementById("log-search-input") as HTMLInputElement | null;
    const sel = document.getElementById("log-level-select") as HTMLSelectElement | null;
    if (inp) state.logSearch = inp.value;
    if (sel) state.logLevelFilter = sel.value;
    if (state.liveTailOn) {
      stopLiveTail();
      state.liveEntries = [];
      toggleLiveTail();
    } else {
      await fetchLogsPage(false);
      renderMainPane();
    }
  });

  document.getElementById("btn-load-more-logs")?.addEventListener("click", async () => {
    await fetchLogsPage(true);
    renderMainPane();
  });

  // Perf tab handlers
  document.getElementById("btn-refresh-perf")?.addEventListener("click", async () => {
    await loadCurrentTabData();
    renderMainPane();
  });

  // Uptime & Alerts tab handlers
  document.getElementById("btn-new-monitor")?.addEventListener("click", () => openCreateDialog("monitor"));
  document.getElementById("btn-new-alert")?.addEventListener("click", () => openCreateDialog("alert"));

  mainPane.querySelectorAll<HTMLButtonElement>("[data-ping-monitor]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const uuid = btn.dataset.pingMonitor!;
      const res = await apiFetch(
        `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/heartbeat_check/${encodeURIComponent(uuid)}/`,
        { method: "POST", body: {} }
      );
      showToast(res.ok ? "Heartbeat recorded (UP)" : res.error || "Ping failed");
      await loadCurrentTabData();
      renderMainPane();
    });
  });

  mainPane.querySelectorAll<HTMLButtonElement>("[data-del-monitor]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.delMonitor!;
      const res = await apiFetch(
        `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/monitors/${encodeURIComponent(id)}/`,
        { method: "DELETE" }
      );
      if (!res.ok) {
        showToast(res.error || "Failed deleting monitor");
        return;
      }
      showToast("Monitor deleted");
      await loadCurrentTabData();
      renderMainPane();
    });
  });

  mainPane.querySelectorAll<HTMLButtonElement>("[data-test-alert]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.testAlert!;
      const res = await apiFetch(
        `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/alerts/${encodeURIComponent(id)}/test/`,
        { method: "POST", body: {} }
      );
      showToast(res.ok ? "Test alert dispatched" : res.error || "Alert dispatch failed");
    });
  });

  mainPane.querySelectorAll<HTMLButtonElement>("[data-del-alert]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.delAlert!;
      const res = await apiFetch(
        `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/alerts/${encodeURIComponent(id)}/`,
        { method: "DELETE" }
      );
      if (!res.ok) {
        showToast(res.error || "Failed deleting alert rule");
        return;
      }
      showToast("Alert rule deleted");
      await loadCurrentTabData();
      renderMainPane();
    });
  });

  // Projects, Members & API Tokens handlers
  document.getElementById("btn-new-project")?.addEventListener("click", () => openCreateDialog("project"));
  document.getElementById("btn-add-member")?.addEventListener("click", () => openCreateDialog("member"));

  mainPane.querySelectorAll<HTMLButtonElement>("[data-enable-tunnel]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const slug = btn.dataset.enableTunnel!;
      const res = await apiFetch(
        `/api/0/projects/${encodeURIComponent(state.orgSlug)}/${encodeURIComponent(slug)}/tunnel/`,
        { method: "POST", body: {} }
      );
      showToast(res.ok ? "Anti-AdBlock tunnel enabled" : res.error || "Tunnel update failed");
      await loadCurrentTabData();
      renderMainPane();
    });
  });

  mainPane.querySelectorAll<HTMLButtonElement>("[data-open-proj-settings]").forEach((btn) => {
    btn.addEventListener("click", () => {
      openProjectSettingsDialog(Number(btn.dataset.openProjSettings));
    });
  });

  mainPane.querySelectorAll<HTMLButtonElement>("[data-open-proj-keys]").forEach((btn) => {
    btn.addEventListener("click", () => {
      void openProjectKeysDialog(Number(btn.dataset.openProjKeys));
    });
  });

  mainPane.querySelectorAll<HTMLSelectElement>("[data-member-role]").forEach((sel) => {
    sel.addEventListener("change", async () => {
      const uid = Number(sel.dataset.memberRole);
      const role = sel.value;
      const res = await apiFetch<MemberItem>(
        `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/members/${uid}/`,
        { method: "PUT", body: { role } }
      );
      if (!res.ok) {
        showToast(res.error || "Failed updating member role");
        await loadCurrentTabData();
        renderMainPane();
        return;
      }
      showToast("Member role updated");
      await loadCurrentTabData();
      renderMainPane();
    });
  });

  mainPane.querySelectorAll<HTMLButtonElement>("[data-del-member]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const uid = Number(btn.dataset.delMember);
      const res = await apiFetch(
        `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/members/${uid}/`,
        { method: "DELETE" }
      );
      if (!res.ok) {
        showToast(res.error || "Failed removing member");
        return;
      }
      showToast("Member removed");
      await loadCurrentTabData();
      renderMainPane();
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
      renderMainPane();
    } else {
      showToast(res.error || "Token creation failed");
    }
  });

  mainPane.querySelectorAll<HTMLButtonElement>("[data-del-token]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.delToken!;
      const res = await apiFetch(`/api/0/api-tokens/${encodeURIComponent(id)}/`, { method: "DELETE" });
      showToast(res.ok ? "API token revoked" : res.error || "Token revoke failed");
      await loadCurrentTabData();
      renderMainPane();
    });
  });

  // Auto-Check tab handlers
  document.getElementById("btn-refresh-selfcheck")?.addEventListener("click", async () => {
    await refreshSelfCheck();
    showToast("Diagnóstico atualizado");
    syncSelfCheckSlots();
  });

  document.getElementById("btn-run-self-probe")?.addEventListener("click", async () => {
    state.probeRunning = true;
    renderMainPane();
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
    syncSelfCheckSlots();
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
    syncSelfCheckSlots();
  });

  // Security Shield tab handlers
  document.getElementById("btn-refresh-shield")?.addEventListener("click", async () => {
    await loadCurrentTabData();
    renderMainPane();
    showToast("Escudo atualizado");
  });

  document.getElementById("btn-shield-settings")?.addEventListener("click", () => {
    const pid = state.shieldProjectFilter ?? state.projects[0]?.id;
    if (pid) openProjectSettingsDialog(pid);
  });

  const shProjSel = document.getElementById("shield-project-filter") as HTMLSelectElement | null;
  shProjSel?.addEventListener("change", async () => {
    state.shieldProjectFilter = shProjSel.value ? Number(shProjSel.value) : null;
    await loadCurrentTabData();
    renderMainPane();
  });

  mainPane.querySelectorAll<HTMLButtonElement>("[data-del-quarantine]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = Number(btn.dataset.delQuarantine);
      const res = await apiFetch(
        `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/shield/quarantine/${id}/`,
        { method: "DELETE" }
      );
      if (!res.ok) {
        showToast(res.error || "Falha ao liberar quarentena");
        return;
      }
      showToast("Quarentena liberada");
      await loadCurrentTabData();
      renderMainPane();
    });
  });
}

function splitFilterList(raw: string): string[] {
  return raw
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function openProjectSettingsDialog(projectId: number): void {
  const proj = state.projects.find((p) => p.id === projectId);
  const dlg = document.getElementById("dlg-proj-settings") as HTMLDialogElement | null;
  const titleEl = document.getElementById("dlg-proj-settings-title");
  const bodyEl = document.getElementById("dlg-proj-settings-body");
  if (!proj || !dlg || !titleEl || !bodyEl) return;

  state.activeProjectModalId = proj.id;
  const f = proj.filters;
  const sh: ShieldPolicy = f.shield || {
    enabled: true,
    mode: "detect",
    quarantine_threshold: 80,
    quarantine_ttl_sec: 900,
    enforce_origin_check: false,
    secret_leak_alerts: true,
    log_ids_enabled: true,
    canary_globals: ["__BF_INTERNAL_SECRETS__"]
  };
  titleEl.textContent = `Filters & Scrubbing — ${proj.name}`;
  bodyEl.innerHTML = `
    <form id="proj-settings-form" class="stack-col">
      <label for="pf-domains">Allowed Domains (one per line or comma-separated)
        <textarea id="pf-domains" name="allowed_domains" rows="2" placeholder="app.example.com">${esc((f.allowed_domains || []).join("\n"))}</textarea>
      </label>
      <label for="pf-ignore-msg">Ignored Error Patterns (one per line)
        <textarea id="pf-ignore-msg" name="ignore_messages" rows="2" placeholder="ResizeObserver loop">${esc((f.ignore_messages || []).join("\n"))}</textarea>
      </label>
      <label class="check-row" for="pf-ext">
        <input id="pf-ext" type="checkbox" name="ignore_browser_extensions" ${f.ignore_browser_extensions ? "checked" : ""}>
        <span>Ignore browser extension errors</span>
      </label>
      <label class="check-row" for="pf-crawl">
        <input id="pf-crawl" type="checkbox" name="ignore_crawlers" ${f.ignore_crawlers ? "checked" : ""}>
        <span>Ignore known bots / crawlers</span>
      </label>
      <label class="check-row" for="pf-local">
        <input id="pf-local" type="checkbox" name="ignore_localhost" ${f.ignore_localhost ? "checked" : ""}>
        <span>Ignore localhost events</span>
      </label>
      <label class="check-row" for="pf-ip">
        <input id="pf-ip" type="checkbox" name="scrub_ip_addresses" ${f.scrub_ip_addresses ? "checked" : ""}>
        <span>Scrub client IP addresses</span>
      </label>
      <label class="check-row" for="pf-emails">
        <input id="pf-emails" type="checkbox" name="scrub_emails" ${f.scrub_emails ? "checked" : ""}>
        <span>Scrub email addresses from payloads</span>
      </label>
      <label for="pf-storm-thresh">Storm Sample Threshold (events/min)
        <input id="pf-storm-thresh" name="storm_sample_threshold" type="number" min="0" value="${f.storm_sample_threshold}">
      </label>
      <label for="pf-storm-every">Storm Sample 1 in N
        <input id="pf-storm-every" name="storm_sample_every" type="number" min="1" value="${f.storm_sample_every}">
      </label>
      <label for="pf-promote">Auto-Promote Log Level to Issue
        <select id="pf-promote" name="auto_promote_log_level">
          <option value="" ${!f.auto_promote_log_level ? "selected" : ""}>Disabled</option>
          <option value="error" ${f.auto_promote_log_level === "error" ? "selected" : ""}>error</option>
          <option value="fatal" ${f.auto_promote_log_level === "fatal" ? "selected" : ""}>fatal</option>
        </select>
      </label>
      <label for="pf-safe-keys">Safe Keys Allowlist (comma-separated, never scrubbed)
        <input id="pf-safe-keys" name="safe_keys" type="text" autocomplete="off" value="${esc((f.safe_keys || []).join(", "))}">
      </label>
      <label for="pf-sens-keys">Extra Sensitive Keys (comma-separated)
        <input id="pf-sens-keys" name="sensitive_keys" type="text" autocomplete="off" value="${esc((f.sensitive_keys || []).join(", "))}">
      </label>
      <h3>Anti-REA Security Shield &amp; Mini-IDS</h3>
      <label class="check-row" for="pf-sh-en">
        <input id="pf-sh-en" type="checkbox" name="shield_enabled" ${sh.enabled ? "checked" : ""}>
        <span>Enable Anti-REA Shield &amp; Mini-IDS</span>
      </label>
      <label for="pf-sh-mode">Protection Mode
        <select id="pf-sh-mode" name="shield_mode">
          <option value="detect" ${sh.mode === "detect" ? "selected" : ""}>detect (Telemetry &amp; Alerts only)</option>
          <option value="defend" ${sh.mode === "defend" ? "selected" : ""}>defend (Clear ephemeral tokens on threat)</option>
          <option value="lockdown" ${sh.mode === "lockdown" ? "selected" : ""}>lockdown (Lock client runtime + quarantine)</option>
        </select>
      </label>
      <label for="pf-sh-thresh">Quarantine Risk Score Threshold (10-100)
        <input id="pf-sh-thresh" name="shield_threshold" type="number" min="10" max="100" value="${sh.quarantine_threshold}">
      </label>
      <label for="pf-sh-ttl">Quarantine TTL (seconds)
        <input id="pf-sh-ttl" name="shield_ttl" type="number" min="60" max="86400" value="${sh.quarantine_ttl_sec}">
      </label>
      <label class="check-row" for="pf-sh-orig">
        <input id="pf-sh-orig" type="checkbox" name="shield_enforce_origin" ${sh.enforce_origin_check ? "checked" : ""}>
        <span>Enforce Allowed Domains Origin check on Shield ingest</span>
      </label>
      <label class="check-row" for="pf-sh-leaks">
        <input id="pf-sh-leaks" type="checkbox" name="shield_secret_leaks" ${sh.secret_leak_alerts ? "checked" : ""}>
        <span>Secret Leak Radar (alert when live keys/JWTs are scrubbed)</span>
      </label>
      <label class="check-row" for="pf-sh-ids">
        <input id="pf-sh-ids" type="checkbox" name="shield_log_ids" ${sh.log_ids_enabled ? "checked" : ""}>
        <span>Log-Driven Mini-IDS (SQLi/Traversal/403 bursts)</span>
      </label>
      <label for="pf-sh-canaries">Canary Globals (comma-separated trap properties)
        <input id="pf-sh-canaries" name="shield_canaries" type="text" autocomplete="off" value="${esc((sh.canary_globals || []).join(", "))}">
      </label>
      <button type="submit" autofocus>Save Filters &amp; Scrubbing</button>
    </form>`;

  const form = document.getElementById("proj-settings-form") as HTMLFormElement | null;
  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const getChecked = (id: string) => (document.getElementById(id) as HTMLInputElement | null)?.checked ?? false;
    const getVal = (id: string) =>
      (document.getElementById(id) as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement | null)?.value || "";

    const payload: ProjectFilters = {
      allowed_domains: splitFilterList(getVal("pf-domains")),
      ignore_messages: splitFilterList(getVal("pf-ignore-msg")),
      ignore_browser_extensions: getChecked("pf-ext"),
      ignore_crawlers: getChecked("pf-crawl"),
      ignore_localhost: getChecked("pf-local"),
      scrub_ip_addresses: getChecked("pf-ip"),
      scrub_emails: getChecked("pf-emails"),
      storm_sample_threshold: Math.max(0, Number(getVal("pf-storm-thresh") || 0)),
      storm_sample_every: Math.max(1, Number(getVal("pf-storm-every") || 1)),
      auto_promote_log_level: getVal("pf-promote") || null,
      safe_keys: splitFilterList(getVal("pf-safe-keys")),
      sensitive_keys: splitFilterList(getVal("pf-sens-keys")),
      shield: {
        enabled: getChecked("pf-sh-en"),
        mode: getVal("pf-sh-mode") || "detect",
        quarantine_threshold: Math.min(100, Math.max(10, Number(getVal("pf-sh-thresh") || 80))),
        quarantine_ttl_sec: Math.min(86400, Math.max(60, Number(getVal("pf-sh-ttl") || 900))),
        enforce_origin_check: getChecked("pf-sh-orig"),
        secret_leak_alerts: getChecked("pf-sh-leaks"),
        log_ids_enabled: getChecked("pf-sh-ids"),
        canary_globals: splitFilterList(getVal("pf-sh-canaries"))
      }
    };

    const res = await apiFetch<Project>(
      `/api/0/projects/${encodeURIComponent(state.orgSlug)}/${encodeURIComponent(proj.slug)}/settings/`,
      { method: "PUT", body: payload }
    );
    if (!res.ok || !res.data) {
      showToast(res.error || "Failed saving project filters");
      return;
    }
    const idx = state.projects.findIndex((p) => p.id === proj.id);
    if (idx >= 0) state.projects[idx] = res.data;
    dlg.close();
    renderMainPane();
    showToast("Project filters saved");
  });

  openDialog(dlg);
}

function renderProjectKeysDialogBody(proj: Project): void {
  const bodyEl = document.getElementById("dlg-proj-keys-body");
  if (!bodyEl) return;
  const origin = location.origin;

  const keyRows = state.activeProjectKeys.length
    ? state.activeProjectKeys
        .map((k) => {
          const dsn = `${origin.replace("://", `://${k.public_key}@`)}/${proj.id}`;
          return `
          <tr>
            <th scope="row">${esc(k.label)}</th>
            <td data-label="Public Key" class="mono">${esc(k.public_key)}</td>
            <td data-label="Rate Limit" class="tabular">${k.rate_limit_per_min}/min</td>
            <td data-label="Actions">
              <div class="row-gap">
                <button type="button" data-copy-text="${esc(dsn)}">Copy DSN</button>
                <button type="button" class="btn-danger" data-del-proj-key="${k.id}">Revoke</button>
              </div>
            </td>
          </tr>`;
        })
        .join("")
    : `<tr><td colspan="4">No active DSN keys for this project.</td></tr>`;

  bodyEl.innerHTML = `
    <div class="stack-col">
      <form id="proj-key-create-form" class="row-gap">
        <label for="new-proj-key-label">New Key Label
          <input id="new-proj-key-label" name="label" type="text" required autocomplete="off" placeholder="Staging Browser" autofocus>
        </label>
        <button type="submit">Create DSN Key</button>
      </form>
      <div tabindex="0" role="region" aria-labelledby="pkeys-cap" class="table-wrapper">
        <table class="data-table">
          <caption id="pkeys-cap" class="hp-field">Project DSN Keys</caption>
          <thead><tr><th>Label</th><th>Public Key</th><th>Limit</th><th>Actions</th></tr></thead>
          <tbody>${keyRows}</tbody>
        </table>
      </div>
    </div>`;

  bindCopyButtons(bodyEl);

  const form = document.getElementById("proj-key-create-form") as HTMLFormElement | null;
  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const label = (document.getElementById("new-proj-key-label") as HTMLInputElement | null)?.value?.trim() || "";
    const res = await apiFetch<ProjectKeyItem>(
      `/api/0/projects/${encodeURIComponent(state.orgSlug)}/${encodeURIComponent(proj.slug)}/keys/`,
      { method: "POST", body: { label } }
    );
    if (!res.ok) {
      showToast(res.error || "Failed creating DSN key");
      return;
    }
    showToast("DSN key created");
    await refreshProjectKeysAndProjects(proj);
  });

  bodyEl.querySelectorAll<HTMLButtonElement>("[data-del-proj-key]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const keyId = Number(btn.dataset.delProjKey);
      const res = await apiFetch(
        `/api/0/projects/${encodeURIComponent(state.orgSlug)}/${encodeURIComponent(proj.slug)}/keys/${keyId}/`,
        { method: "DELETE" }
      );
      if (!res.ok) {
        showToast(res.error || "Failed revoking DSN key");
        return;
      }
      showToast("DSN key revoked");
      await refreshProjectKeysAndProjects(proj);
    });
  });
}

async function refreshProjectKeysAndProjects(proj: Project): Promise<void> {
  const [keysRes, projRes] = await Promise.all([
    apiFetch<ProjectKeyItem[]>(
      `/api/0/projects/${encodeURIComponent(state.orgSlug)}/${encodeURIComponent(proj.slug)}/keys/`
    ),
    apiFetch<Project[]>(`/api/0/organizations/${encodeURIComponent(state.orgSlug)}/projects/`)
  ]);
  if (keysRes.ok && keysRes.data) state.activeProjectKeys = keysRes.data;
  if (projRes.ok && projRes.data) state.projects = projRes.data;
  const freshProj = state.projects.find((p) => p.id === proj.id) || proj;
  renderProjectKeysDialogBody(freshProj);
  if (state.tab === "projects") renderMainPane();
}

async function openProjectKeysDialog(projectId: number): Promise<void> {
  const proj = state.projects.find((p) => p.id === projectId);
  const dlg = document.getElementById("dlg-proj-keys") as HTMLDialogElement | null;
  const titleEl = document.getElementById("dlg-proj-keys-title");
  if (!proj || !dlg || !titleEl) return;

  state.activeProjectModalId = proj.id;
  titleEl.textContent = `DSN Keys — ${proj.name}`;
  const res = await apiFetch<ProjectKeyItem[]>(
    `/api/0/projects/${encodeURIComponent(state.orgSlug)}/${encodeURIComponent(proj.slug)}/keys/`
  );
  if (!res.ok || !res.data) {
    showToast(res.error || "Failed loading DSN keys");
    return;
  }
  state.activeProjectKeys = res.data;
  renderProjectKeysDialogBody(proj);
  openDialog(dlg);
}

function openCreateDialog(kind: "project" | "monitor" | "alert" | "member"): void {
  const dlg = document.getElementById("dlg-create") as HTMLDialogElement | null;
  const title = document.getElementById("dlg-create-title");
  const body = document.getElementById("dlg-create-body");
  if (!dlg || !title || !body) return;
  const projOptions = state.projects
    .map((p) => `<option value="${p.id}">${esc(p.name)}</option>`)
    .join("");

  if (kind === "project") {
    title.textContent = "Create Project";
    body.innerHTML = `
      <form id="create-res-form" class="stack-col">
        <label for="cr-proj-name">Project Name
          <input id="cr-proj-name" name="name" type="text" required autocomplete="off" placeholder="RoleLane Web" autofocus>
        </label>
        <label for="cr-proj-plat">Platform
          <select id="cr-proj-plat" name="platform">
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
    title.textContent = "New Heartbeat Monitor";
    body.innerHTML = `
      <form id="create-res-form" class="stack-col">
        <label for="cr-mon-proj">Project
          <select id="cr-mon-proj" name="project_id">${projOptions}</select>
        </label>
        <label for="cr-mon-name">Monitor Name
          <input id="cr-mon-name" name="name" type="text" required autocomplete="off" placeholder="Nightly Backup Cron" autofocus>
        </label>
        <label for="cr-mon-int">Expected Interval (sec)
          <input id="cr-mon-int" name="expected_interval_sec" type="number" value="60" min="10">
        </label>
        <button type="submit">Create Monitor</button>
      </form>`;
  } else if (kind === "member") {
    title.textContent = "Add Team Member";
    body.innerHTML = `
      <form id="create-res-form" class="stack-col">
        <label for="cr-mem-email">Email
          <input id="cr-mem-email" name="email" type="email" required autocomplete="email" spellcheck="false" placeholder="dev@company.com" autofocus>
        </label>
        <label for="cr-mem-name">Name
          <input id="cr-mem-name" name="name" type="text" required autocomplete="name" placeholder="Developer Name">
        </label>
        <label for="cr-mem-pw">Temporary Password (min 8 chars)
          <input id="cr-mem-pw" name="password" type="password" required minlength="8" autocomplete="new-password">
        </label>
        <label for="cr-mem-role">Role
          <select id="cr-mem-role" name="role">
            <option value="member" selected>member</option>
            <option value="admin">admin</option>
            <option value="viewer">viewer</option>
            <option value="owner">owner</option>
          </select>
        </label>
        <button type="submit">Add Member</button>
      </form>`;
  } else {
    title.textContent = "New Alert Rule";
    body.innerHTML = `
      <form id="create-res-form" class="stack-col">
        <label for="cr-al-proj">Project
          <select id="cr-al-proj" name="project_id">${projOptions}</select>
        </label>
        <label for="cr-al-name">Rule Name
          <input id="cr-al-name" name="name" type="text" required autocomplete="off" placeholder="Notify on error" autofocus>
        </label>
        <label for="cr-al-trigger">Trigger
          <select id="cr-al-trigger" name="trigger_type">
            <option value="new_issue">New Issue</option>
            <option value="regression">Regression</option>
            <option value="threshold">Event Threshold</option>
            <option value="fatal_log">Fatal Log</option>
            <option value="uptime_down">Uptime Down</option>
            <option value="security_threat">Security Threat (Anti-REA / Mini-IDS)</option>
            <option value="secret_leak">Secret Leak Detected (Radar)</option>
          </select>
        </label>
        <div id="cr-al-thresh-wrap" class="stack-col is-hidden">
          <label for="cr-al-thresh-cnt">Threshold Event Count
            <input id="cr-al-thresh-cnt" name="threshold_count" type="number" min="1" value="5">
          </label>
          <label for="cr-al-window">Window (sec)
            <input id="cr-al-window" name="window_sec" type="number" min="10" max="86400" value="60">
          </label>
        </div>
        <label for="cr-al-channel">Channel
          <select id="cr-al-channel" name="channel_type">
            <option value="webhook">Webhook (JSON + HMAC)</option>
            <option value="slack">Slack Webhook</option>
            <option value="discord">Discord Webhook</option>
            <option value="email">Email (SMTP)</option>
          </select>
        </label>
        <div id="cr-al-webhook-wrap" class="stack-col">
          <label for="cr-al-url">HTTPS Target URL
            <input id="cr-al-url" name="target_url" type="url" required placeholder="https://hooks.slack.com/services/...">
          </label>
          <label for="cr-al-secret">Webhook HMAC Secret (optional)
            <input id="cr-al-secret" name="webhook_secret" type="password" autocomplete="new-password" placeholder="Optional X-BugFinder-Signature secret">
          </label>
        </div>
        <div id="cr-al-email-wrap" class="stack-col is-hidden">
          <label for="cr-al-email">Email Recipient
            <input id="cr-al-email" name="email_to" type="email" autocomplete="email" spellcheck="false" placeholder="oncall@company.com">
          </label>
        </div>
        <button type="submit">Save Alert Rule</button>
      </form>`;

    const trigSel = document.getElementById("cr-al-trigger") as HTMLSelectElement | null;
    const threshWrap = document.getElementById("cr-al-thresh-wrap");
    const syncThresh = () => {
      threshWrap?.classList.toggle("is-hidden", trigSel?.value !== "threshold");
    };
    trigSel?.addEventListener("change", syncThresh);
    syncThresh();

    const chSel = document.getElementById("cr-al-channel") as HTMLSelectElement | null;
    const webWrap = document.getElementById("cr-al-webhook-wrap");
    const emailWrap = document.getElementById("cr-al-email-wrap");
    const urlInput = document.getElementById("cr-al-url") as HTMLInputElement | null;
    const emailInput = document.getElementById("cr-al-email") as HTMLInputElement | null;
    const syncChannel = () => {
      const isEmail = chSel?.value === "email";
      webWrap?.classList.toggle("is-hidden", isEmail);
      emailWrap?.classList.toggle("is-hidden", !isEmail);
      if (urlInput) urlInput.required = !isEmail;
      if (emailInput) emailInput.required = isEmail;
    };
    chSel?.addEventListener("change", syncChannel);
    syncChannel();
  }

  const form = document.getElementById("create-res-form") as HTMLFormElement | null;
  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const raw = Object.fromEntries(new FormData(form).entries()) as Record<string, any>;
    if (raw.project_id) raw.project_id = Number(raw.project_id);
    if (raw.expected_interval_sec) raw.expected_interval_sec = Number(raw.expected_interval_sec);
    if (raw.threshold_count) raw.threshold_count = Number(raw.threshold_count);
    if (raw.window_sec) raw.window_sec = Number(raw.window_sec);
    if (kind === "alert") {
      if (raw.channel_type === "email") {
        delete raw.target_url;
        delete raw.webhook_secret;
      } else {
        delete raw.email_to;
      }
    }

    const url =
      kind === "project"
        ? `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/projects/`
        : kind === "monitor"
        ? `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/monitors/`
        : kind === "member"
        ? `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/members/`
        : `/api/0/organizations/${encodeURIComponent(state.orgSlug)}/alerts/`;

    const res = await apiFetch(url, { method: "POST", body: raw });
    if (!res.ok) {
      showToast(res.error || "Failed creating item");
      return;
    }
    dlg.close();
    await loadCurrentTabData();
    renderMainPane();
    showToast(
      kind === "project"
        ? "Project created"
        : kind === "monitor"
        ? "Monitor created"
        : kind === "member"
        ? "Member added"
        : "Alert rule saved"
    );
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
