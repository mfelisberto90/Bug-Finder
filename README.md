# Bug-Finder

[![Rust](https://img.shields.io/badge/Rust-Axum%20%2B%20Tokio-000000?logo=rust)](Cargo.toml)
[![Memory](https://img.shields.io/badge/VmRSS-~8--11%20MB-16a34a)](#measured-benchmarks-empirical-single-host-comparison)
[![Binary](https://img.shields.io/badge/Single%20Binary-~6.5%20MB-2563eb)](#quickstart)
[![Telemetry](https://img.shields.io/badge/Protocols-Sentry%20%7C%20GlitchTip%20%7C%20OTLP-7c3aed)](#connect-any-app-in-30-seconds)
[![Security](https://img.shields.io/badge/Defense-Anti--REA%20Shield%20%2B%20FORCE%20RLS-dc2626)](#anti-rea-security-shield-secret-leak-radar--mini-ids)
[![License: MIT](https://img.shields.io/badge/License-MIT-0d9488.svg)](Cargo.toml)

**Ultra-lightweight Error Tracking, Structured Logs, Performance Tracing, Uptime Heartbeats & Active Runtime Security (Anti-REA Shield + Mini-IDS) in pure Rust** — compiled into a single **~6.5 MB** native executable running at **~8–11 MB VmRSS**, with drop-in compatibility for **Sentry SDKs**, **GlitchTip clients**, and **OpenTelemetry OTLP/HTTP**.

![Bug-Finder Issues Inbox](docs/screenshots/issues-inbox.png)

## What Bug-Finder Covers (Full Capabilities)

Bug-Finder combines observability and application self-defense into one self-contained Rust server without external queues or caches:

1. **Error Tracking & SourceMap v3 Demangling** — Full-text FTS5 issue search, deterministic grouping & smart regression detection, stack traces with source context, breadcrumbs, CSV formula-safe exports, inbound filters (crawler/extension/domain allowlists), and LRU-cached SourceMap v3 VLQ demangling in pure Rust.
2. **Structured Logs, OpenTelemetry OTLP & Live Tail** — Ingest Sentry `log` v2 envelopes, OTLP/HTTP (`application/x-protobuf` and JSON on `/v1/logs`), direct JSON logs, or terminal streams via `bugfinder wrap`/`pipe`, all correlated by `trace_id`/`span_id` and streamed live via SSE or CLI `bugfinder tail`.
3. **Performance & Release Health** — Track endpoint latency percentiles (`p50` / `p95`), crash-free session rates, and issue volume across releases.
4. **Uptime Heartbeats & Multi-Channel Alerts** — Check-in endpoints (`/heartbeat_check/:uuid/`) for cron jobs and microservices, plus event/threshold/fatal/uptime/security alerting to **Telegram** (AEAD-encrypted bot token), **Discord** Rich Embeds, **Slack**, **HMAC-signed Webhooks**, and native **TLS SMTP**.
5. **Anti-REA Security Shield, Secret Leak Radar & Log-Driven Mini-IDS** — Active protection against reverse engineering, automated browser bots (CDP/Playwright/Puppeteer/WebDriver), monkey-patched hooks, source-map harvesting, canary endpoints (`/.env`, `/.git/config`), exploit payloads in logs, and accidental credential leaks (`JWT`, Bearer, PEM, API keys, Luhn PANs), paired with CGNAT-safe session/HMAC-IP quarantines and `ETag`-cached edge blocklist syncing.
6. **Zero-Leak Same-Origin Proxy Pattern** — Serve the `< 3 KB` Mini-SDK, Anti-REA Shield, and ingestion endpoints under neutral first-party paths (`/_obs/*`) while locking the admin UI completely behind Cloudflare Zero Trust Access or a private VPN.
7. **Enterprise Security, Auto-Check & AI MCP Server** — PostgreSQL 17 `ENABLE + FORCE ROW LEVEL SECURITY` (`NOBYPASSRLS`), `enc:v1:` AEAD at rest, immutable `SHA-256` hash-chained audit logs, TOTP 2FA + WebAuthn Passkeys + OIDC PKCE SSO, self-diagnostics (`Auto-Check` / `bugfinder doctor`), and a read-only stdio **MCP server** for AI debugging assistants.

---

## Measured Benchmarks (Empirical Single-Host Comparison)

Sequential benchmarks run on the same hardware (`Ubuntu 24.04 Linux x86_64`, 12 CPU threads, `postgres:17-alpine`) using an identical 1.53 KB Sentry envelope payload across 50 rotating fingerprints (3 stack frames, 5 breadcrumbs):

| Metric | Bug-Finder v1.0.0 (SQLite) | Bug-Finder (PG17 `FORCE RLS`) | GlitchTip 7.0.0 (PG17, No-Valkey) |
|---|---|---|---|
| **Binary / Container Size** | **6.5 MB single binary** | 6.5 MB binary + PG | 953 MB app image + PG |
| **Idle App RAM (`VmRSS`)** | **8.8 – 9.6 MiB** | **9.5 MiB** | 162.3 MiB |
| **Total Stack RAM Post-Load (App + DB)** | **14.3 MiB** | **71.8 MiB** | 379.7 MiB |
| **Cold Start to HTTP `200 /api/health`** | **18.7 – 21.0 ms** | **56.7 ms** (`SKIP_MIGRATIONS=1`) | 5,114 ms *(excl. 22.1 s init)* |
| **Sequential Ingest (`100 x 1`)** | **907.9 req/s** (`p50 = 1.04 ms`) | **892.8 req/s** (`p50 = 1.12 ms`) | 203.9 req/s (`p50 = 4.88 ms`) |
| **Burst Ingest (`1,000 x 16` threads)** | **2,248 – 2,421 req/s** (`p50 = 5.8–6.0 ms`) | **2,208.9 req/s** (`p50 = 6.08 ms`) | 517.5 req/s (`p50 = 29.14 ms`) |
| **Issues List API Read (`200 x 8` threads)** | **2,020.3 req/s** (`p50 = 3.50 ms`) | **1,979.1 req/s** (`p50 = 3.62 ms`) | 9.7 req/s (`p50 = 725.5 ms`) |
| **JSON Bandwidth (`/issues/?limit=100`, gzip)** | **2.2 KB** (`304 ETag` in **0.67 ms**) | **2.2 KB** (`304 ETag` in **0.63 ms**) | 50.8 KB |

> **Honest Trade-Offs:** Choose **GlitchTip 7.0.0** if you need native C/C++/Rust minidumps (`difs`), DuckDB/Parquet cold storage on S3/GCS, or Stripe SaaS billing out of the box. Choose **Bug-Finder** if you want a **~10 MiB** single-binary runtime, **sub-25 ms** cold starts, strict PostgreSQL `FORCE ROW LEVEL SECURITY`, hash-chained audit logs, and built-in runtime self-diagnostics + Anti-REA Shield without managing Django, workers, or cache tiers.

---

## Visual Tour (Real Application Screenshots)

### Stack Traces, Source Context & Breadcrumbs
Demangled SourceMap v3 frames, surrounding source context, breadcrumbs, redacted request secrets, and one-click correlated trace log inspection:

![Issue Detail Stack Trace](docs/screenshots/issue-detail.png)

### Structured Logs & Real-Time SSE Live Tail
Ingest via Sentry `log` v2 envelopes, direct JSON logs, OpenTelemetry OTLP/HTTP (Protobuf or JSON), or `bugfinder pipe`/`wrap`, with `trace_id` correlation and FTS5 search:

![Structured Logs & Live Tail](docs/screenshots/logs-live-tail.png)

### 1-Click Connect App Onboarding Wizard
Generate CSP-safe, SRI-verified 1-tag snippets, CLI setup commands, or drop-in `.env` blocks with live SSE arrival confirmation right inside the modal:

![1-Click Connect App Wizard](docs/screenshots/connect-app-wizard.png)

### Uptime Heartbeats & Multi-Channel Alerting
Monitor cron jobs and services via `/heartbeat_check/:uuid/` endpoints and dispatch severity-colored alerts via **Telegram** (AEAD-encrypted bot token), **Discord** Rich Embeds, **Slack**, **HMAC-signed Webhooks**, or **SMTP TLS**:

![Uptime Heartbeats & Alerts](docs/screenshots/uptime-alerts.png)

### Anti-REA Security Shield, Secret Leak Radar & Mini-IDS
Detect headless automation (`cdp_automation`, `webdriver_detected`), source-map harvesting, canary route probes (`/.env`, `/.git/config`), SQLi/SSRF/traversal log patterns, and leaked credentials (`Secret Leak Radar`) with CGNAT-safe browser-session or verified-IP quarantine:

![Anti-REA Shield & Active Quarantine](docs/screenshots/security-shield.png)

### Immutable SHA-256 Audit Chain, 2FA (TOTP) & WebAuthn Passkeys
Every sensitive action is appended to an immutable `SHA-256` hash-chained ledger verifiable in one click, alongside mandatory Step-Up re-authentication, RFC 6238 TOTP, Passkeys (`ES256`/`Ed25519`), and expiring scoped API tokens:

![Immutable Audit Log & Organization Policies](docs/screenshots/security-audit-chain.png)

### Built-In Auto-Check & Self-Diagnostics
Continuous self-monitoring of SQLite WAL / PostgreSQL `FORCE RLS`, memory (`VmRSS`), disk budget circuit breaker, AEAD/MFA/token posture, anti-ptrace integrity, internal crash handoff across restarts, and frontend transport errors:

![Auto-Check & Self-Diagnostics](docs/screenshots/auto-check-diagnostics.png)

### Responsive Mobile Operations View
Zero-dependency TypeScript SPA designed for fast mobile triage with bottom Thumb-Zone navigation and responsive card tables:

<p align="center">
  <img src="docs/screenshots/mobile-issues.png" alt="Bug-Finder Mobile Issues View" width="380" />
</p>

---

## Anti-REA Security Shield, Secret Leak Radar & Mini-IDS

Beyond passive crash logging, Bug-Finder ships an integrated active defense subsystem across three layers — **Browser Runtime**, **Backend Middleware**, and **Log/Payload Inspection** (`sdks/browser/bugfinder-shield.js` + `src/security/anti_rea.rs`):

### What Anti-REA & Mini-IDS Cover

| Layer | Detections & Active Controls |
|---|---|
| **Browser Anti-REA (`bugfinder-shield.js`)** | Detects `navigator.webdriver` / `HeadlessChrome` / `PhantomJS` (`webdriver_detected`), DevTools/CDP & automation bindings (`$cdc_*`, `cdc_*`, `__playwright__binding__`, `__pwInitScripts`, `_phantom`, `__nightmare`), post-init monkey-patching of `fetch`, `XMLHttpRequest.prototype.open`, `WebSocket`, or `Function.prototype.toString` (`runtime_hook_tamper`), getter traps on canary globals (`__BF_INTERNAL_SECRETS__` -> `honeypot_access`), and optional `MutationObserver` script-origin enforcement (`dom_script_injection`). |
| **Enforcement Modes (`detect` / `defend` / `lockdown`)** | Deduplicates identical signal signatures for 30s (`sendBeacon` / `keepalive` `fetch`); skips `localhost`/`127.0.0.1`/`::1` unless `allowLocalhost: true`. When `risk_score >= threshold` under `defend` or `lockdown`, clears configured `clearStorageKeys` across `localStorage`/`sessionStorage` and enters locked-down state (`isLockedDown()`). |
| **Backend Traps & Blocklist Sync** | Monitored backends can report server-side `sourcemap_harvest` (`*.js.map`) or `canary_route_hit` (`/.env`, `/.git/config`) signals with `Authorization: Bearer <API_TOKEN>` (`shield:write`) and sync `ETag`-cached HMAC-IP / session blocklists via `GET /api/0/projects/:org/:proj/shield/blocklist/` using project-derived HMAC keys (without exposing the master `app_key`). |
| **Log-Driven Mini-IDS (`Log-IDS`)** | Evaluates ingested logs in real time for SQL injection (`UNION SELECT`, sleep payloads), multi-level path traversal (`../../etc/passwd`, `.env`, `.git/config`), cloud metadata SSRF (`169.254.169.254/latest/meta-data`, `metadata.google.internal`), JNDI/SSTI (`${jndi:...}`, `{{ 7*7 }}`), and `401`/`403`/`404` IDOR/enumeration bursts (`>= 20` hits per actor in 60s, ignoring static assets). |
| **Secret Leak Radar** | Redacts emails, `Bearer` / JWT tokens, PEM private keys, API keys (`sk_live_...`, `ghp_...`, `bf_...`), URL query secrets, and Luhn-validated payment card numbers (`[Filtered]`) in-place before persistence or SSE broadcast, emitting security alerts when leaks hit logs or events. |
| **CGNAT-Safe Quarantine** | Unauthenticated browser signals can only quarantine the **browser `session_id`** (never a shared mobile/CGNAT IP); IP-level HMAC quarantines require `backend_verified` API token authentication. |
| **Self Runtime Integrity** | Inspects `/proc/self/status` (`TracerPid`), `/proc/self/maps` (`frida-agent`, `frida-gadget`, `libfrida`, `gdbserver`), and `LD_PRELOAD`/`LD_AUDIT` inside `Auto-Check`; optional `BUGFINDER_ANTI_PTRACE=1` calls `prctl(PR_SET_DUMPABLE, 0)` on Linux. |

### Threat Signal Weights (Capped at Score `100`)

| Signal | Weight | Category | Trigger Summary |
|---|---|---|---|
| `runtime_debugger_attached` | `80` | `anti_rea` | Attached process/runtime debugger check (`sys.gettrace()` / `TracerPid`) |
| `canary_route_hit` | `75` | `anti_rea` | Probe hit decoys such as `/.env` or `/.git/config` |
| `injection_probe` | `75` | `log_ids` | SQLi, traversal, cloud metadata SSRF, or JNDI/SSTI in logs/paths |
| `honeypot_access` | `70` | `anti_rea` | Access to trap getters defined in `canaryGlobals` |
| `sourcemap_harvest` | `65` | `anti_rea` | Unauthorized scraping of `.js.map` bundles |
| `idor_or_enum_burst` | `65` | `log_ids` | `>= 20` `401`/`403`/`404` hits from one actor within 60s |
| `secret_leak` | `60` | `secret_leak` | Credentials/secrets detected & redacted by Secret Leak Radar |
| `cdp_automation` | `50` | `anti_rea` | Headless ChromeDriver / Playwright / Nightmare / Phantom globals |
| `webdriver_detected` | `45` | `anti_rea` | `navigator.webdriver === true` or `HeadlessChrome` user-agent |
| `runtime_hook_tamper` | `40` | `anti_rea` | Post-init tampering of `fetch`, XHR, `WebSocket`, or `Function.prototype.toString` |
| `csp_script_tamper` | `40` | `csp` | CSP script tampering report |
| `dom_script_injection` | `35` | `anti_rea` | Dynamic third-party `<script src>` outside `allowedScriptOrigins` |

---

## Quickstart

### 1. One-Command Installer (Binary, `systemd --user`, or Docker)

```bash
# Install binary (~/.local/bin/bugfinder), locked-down 0600 config, and run `bugfinder doctor`
./scripts/install.sh

# Or install as an auto-starting user systemd service (64 MB RAM cap)
./scripts/install.sh --service

# Or build & launch in a hardened 32 MB RAM Docker container
./scripts/install.sh --docker
```

Convenience `Makefile` targets: `make install`, `make install-service`, `make install-docker`, `make doctor`.

### 2. Hardened Docker Compose (`32 MB` RAM Cap, Read-Only Rootfs)

```bash
docker compose up -d --build
```

Default `compose.yml` settings enforce `mem_limit: 32m`, `pids_limit: 64`, `read_only: true`, `cap_drop: [ALL]`, and `no-new-privileges:true`.

### 3. Manual Release Build (SQLite WAL + FTS5)

```bash
./scripts/build-release.sh
./target/release/bugfinder --headless --bind 127.0.0.1:8080 --data ./data
```

Launch with `--app` instead of `--headless` to open directly as a standalone local desktop window.

### 4. PostgreSQL 17 Multi-Tenant Mode (`ENABLE + FORCE RLS`)

Apply migrations first under the schema owner role (`bugfinder migrate`), then run the server under a **`NOSUPERUSER NOBYPASSRLS`** application role (`bugfinder_app`) with optional `BUGFINDER_SKIP_MIGRATIONS=1` for sub-60 ms startups:

```bash
# One-time / deploy step with DDL privileges:
./target/release/bugfinder migrate --db "postgres://bugfinder_migrator:SECRET@127.0.0.1:5432/bugfinder"

# Runtime under least-privilege NOBYPASSRLS role:
export DATABASE_URL="postgres://bugfinder_app:SECRET@127.0.0.1:5432/bugfinder"
export BUGFINDER_SKIP_MIGRATIONS=1
./target/release/bugfinder --headless --bind 127.0.0.1:8080
```

All tenant-scoped tables and capability lookup tables (`dsn_key_lookup`, `api_token_lookup`, `session_lookup`, `tunnel_lookup`, `invitation_lookup`) enforce `ENABLE` and `FORCE ROW LEVEL SECURITY` scoped by `NULLIF(current_setting('app.current_tenant_id', true), '')::bigint` in single-statement fail-closed transactions.

---

## Connect Any App in 30 Seconds

### Option A — 1-Tag Zero-Dep Browser Mini-SDK (`< 3 KB`, CSP + SRI Ready)

Open **Projects & SDK -> Connect App** (or paste into `<head>` with zero inline JavaScript):

```html
<script
  src="https://monitor.acme.example/sdk/bugfinder-mini.js"
  data-dsn="https://<PUBLIC_KEY>@monitor.acme.example/1"
  data-shield="detect"
  data-capture-fetch="true"
  data-capture-console="error"
  integrity="sha384-<MINI_SDK_SRI>"
  crossorigin="anonymous"
  async></script>
```

Automatically captures global runtime errors, unhandled Promise rejections, UI click breadcrumbs, optional HTTP `5xx` fetches/`console.error`, and optionally bootstraps `bugfinder-shield.js` cleanly via `data-shield`.

### Option B — Zero-Leak Same-Origin Reverse Proxy Pattern (Private Dashboard + White-Label Safe)

If you want `monitor.internal` locked **100% behind Cloudflare Zero Trust Access, Tailscale, or a VPN** with **zero public SDK or ingest routes**, reverse-proxy neutral same-origin paths on your main web app directly to Bug-Finder inside Docker (`http://bugfinder:8080`):

- `GET /_obs/m.js` -> `http://bugfinder:8080/sdk/bugfinder-mini.js`
- `GET /_obs/s.js` -> `http://bugfinder:8080/sdk/bugfinder-shield.js`
- `POST /_obs/e` -> `http://bugfinder:8080/t/<tunnel_slug>` (enforce same-origin `Origin` / `Sec-Fetch-Site` in your proxy!)
- `POST /_obs/s` -> `http://bugfinder:8080/api/<project_id>/shield/?sentry_key=<PUBLIC_KEY>`

Then inject one completely white-labeled, AdBlock-immune tag on your app (works cleanly under strict CSP `script-src 'self'` & `connect-src 'self'`):

```html
<script
  src="/_obs/m.js"
  data-dsn="https://<PUBLIC_KEY>@internal.local/<project_id>"
  data-tunnel="/_obs/e"
  data-shield="detect"
  data-shield-src="/_obs/s.js"
  data-shield-endpoint="/_obs/s"
  data-capture-fetch="true"
  data-capture-console="error"
  integrity="sha384-<MINI_SDK_SRI>"
  defer></script>
```

Because `bugfinder-mini.js` resolves relative `data-tunnel`, `data-shield-src`, and `data-shield-endpoint` paths against `location.origin`, zero internal telemetry hostnames appear in HTML, response headers, or browser devtools.

### Option C — Zero-Code Terminal Setup (`init`, `wrap`, `pipe`)

```bash
# Auto-detect Next.js/Vite/Node/Laravel/PHP/Python/Go/Rust, write .env (0600), and install stdlib helper
bugfinder init --dsn "http://<KEY>@127.0.0.1:8080/1"

# Wrap any server/worker: captures stack traces into Issues, streams logs, scrubs secrets, preserves exit code
bugfinder wrap --dsn "http://<KEY>@127.0.0.1:8080/1" --service api-worker -- node server.js

# Stream cron or shell script stderr/stdout cleanly
./backup.sh 2>&1 | bugfinder pipe --dsn "http://<KEY>@127.0.0.1:8080/1" --service nightly-backup
```

### Option D — Official Sentry SDKs & GlitchTip Drop-In

Point `@sentry/browser`, `@sentry/node`, `sentry-sdk`, `sentry-laravel`, or GlitchTip clients directly at Bug-Finder:

```env
SENTRY_DSN=https://<PUBLIC_KEY>@monitor.acme.example/1
GLITCHTIP_ENABLED=true
GLITCHTIP_DSN=https://<PUBLIC_KEY>@monitor.acme.example/1
GLITCHTIP_API_URL=https://monitor.acme.example
GLITCHTIP_ORGANIZATION=acme-cloud
```

Supported ingestion endpoints:
- `POST /api/:project_id/envelope/` (`event`, `log` v2, `transaction`, `session`, `check_in`, `attachment`)
- `POST /api/:project_id/store/`
- `POST /api/:project_id/security/` (CSP violation reports)
- `POST /t/:slug` (Anti-AdBlock Sentry tunnel)
- `POST /api/:project_id/shield/` (Anti-REA & canary signal ingest)

### Option E — OpenTelemetry OTLP/HTTP Logs (`/v1/logs` & `/api/:id/otlp/v1/logs`)

Accepts both binary **`application/x-protobuf`** (`ExportLogsServiceRequest`, decoded natively in pure Rust) and **`application/json`**, preserving `trace_id` and `span_id` correlation across errors, logs, and transactions:

```bash
curl -X POST "http://127.0.0.1:8080/api/1/otlp/v1/logs" \
  -H "Authorization: Bearer <PUBLIC_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"worker"}}]},"scopeLogs":[{"logRecords":[{"severityNumber":13,"severityText":"WARN","body":{"stringValue":"Queue lag above 200ms"}}]}]}]}'
```

---

## CLI & Read-Only MCP Server

```bash
# Verify DB health, permissions, RAM, and posture from CLI (JSON supported)
bugfinder doctor --url http://127.0.0.1:8080/api/health --json

# Lightweight container healthcheck probe
bugfinder healthcheck --url http://127.0.0.1:8080/api/health

# Live terminal SSE tail with filtering
bugfinder tail --url http://127.0.0.1:8080 --org acme-cloud --token bf_... --level error

# Online SQLite WAL backup
bugfinder backup --data ./data --out ./backups/bugfinder-$(date +%F).db

# Send synthetic verification event or structured log
bugfinder test-event --dsn http://<KEY>@127.0.0.1:8080/1
bugfinder test-log   --dsn http://<KEY>@127.0.0.1:8080/1

# Launch read-only MCP stdio server for AI coding assistants (issues, logs, traces, self-check)
bugfinder mcp --org acme-cloud --token bf_...
```

---

## Security Architecture

- **Tenant & Auth Isolation**: PostgreSQL `ENABLE + FORCE ROW LEVEL SECURITY` (`NOBYPASSRLS`) with single-statement transaction-scoped GUCs; 5 RBAC roles (`owner` > `manager` > `admin` > `member` > `viewer`) plus scoped, expiring API tokens (`token:sha256` lookup, instant cache invalidation).
- **Cryptography & MFA**: `scrypt` password hashing (`Semaphore(2)` bounded + `malloc_trim`), exponential backoff lockout, RFC 6238 TOTP (QR SVG + 10 single-use recovery codes), WebAuthn/FIDO2 Passkeys (`ES256`/`Ed25519`), optional OIDC SSO (`Authorization Code + PKCE S256`, JWKS verification via `ring`), Step-Up `/api/auth/reauth` before destructive mutations, and `HKDF-SHA256 + AES-256-GCM` (`enc:v1:`) encryption at rest.
- **Ingestion & Network Hardening**: Streaming `gzip`/`deflate`/`br`/`zstd` decompression with strict `BUGFINDER_MAX_UNZIPPED_BYTES` cap (`413` anti-zip-bomb), in-place `Cow<'a, str>` scrubbing, pre-connect DNS SSRF rejection of private/loopback/CGNAT/link-local/metadata IPs, CSV formula prefix neutralization, strict `BUGFINDER_ALLOWED_HOSTS` (no `*` wildcard), and multi-bucket `HMAC-SHA256` `BoundedMap` rate limiting (`429` + `X-Sentry-Rate-Limits`).
- **CSP & Asset Delivery**: Per-request cryptographic CSP nonces (`script-src` & `style-src`), zero inline styles (`scripts/security-lint.py` CI gate), pre-compressed static assets in `.rodata` (`build.rs`), and BREACH defense (never compressing dynamic auth/HTML responses).

---

## Environment Variables Reference

| Variable | Default | Description |
|---|---|---|
| `BUGFINDER_BIND` | `127.0.0.1:8080` | Bind `ip:port` (`127.0.0.1:0` in `--app` mode). |
| `BUGFINDER_DATA_DIR` | `./data` | Data directory (`0700`) for SQLite DB, `.app_key` (`0600`), and source maps. |
| `DATABASE_URL` | *(SQLite)* | Optional `postgres://...` / `postgresql://...` or `sqlite://...` connection URI. |
| `BUGFINDER_APP_KEY` | *(auto `.app_key`)* | 32-byte hex master key (or passphrase hashed via SHA-256) for AEAD & HMAC. |
| `BUGFINDER_ENV` | `dev` on loopback / `production` otherwise | Set `production` or `dev`/`development`. |
| `BUGFINDER_PUBLIC_URL` | *(unset)* | Canonical public HTTPS origin displayed in Connect App & OIDC callback URLs. |
| `BUGFINDER_ALLOWED_HOSTS` | *(empty)* | Comma-separated allowed `Host` headers (wildcard `*` rejected). |
| `BUGFINDER_TRUSTED_PROXIES` | *(empty)* | Comma-separated CIDRs/IPs or presets `loopback`, `private`, `cloudflare` (no `*`). |
| `BUGFINDER_FORCE_SECURE_COOKIES` | `false` | Set `1`/`true` to always emit `Secure` on session cookies behind TLS proxies. |
| `BUGFINDER_SESSION_TTL_HOURS` | `168` | Absolute session lifetime (`1–720` hours). |
| `BUGFINDER_SESSION_IDLE_HOURS` | `24` | Sliding idle session timeout (`1–720` hours). |
| `BUGFINDER_MAX_UNZIPPED_BYTES` | `2097152` | Max decompressed ingestion payload (`4 KiB – 32 MiB`, default `2 MiB`). |
| `BUGFINDER_MAX_DB_MB` | `512` | Storage disk budget (`>= 16` MiB) before ingestion circuit breaker trips. |
| `BUGFINDER_RETENTION_DAYS` | `30` | Event/log/audit retention window (`1–3650` days). |
| `BUGFINDER_SKIP_MIGRATIONS` | `false` | Set `1`/`true` in production after running `bugfinder migrate`. |
| `BUGFINDER_ANTI_PTRACE` | `false` | Set `1`/`true` to harden process dumpability (`PR_SET_DUMPABLE=0`). |
| `BUGFINDER_METRICS_TOKEN` | *(loopback only)* | Bearer token permitting remote Prometheus `GET /metrics` scraping. |
| `BUGFINDER_SMTP_HOST`, `_PORT`, `_TLS_MODE`, `_USER`, `_PASS`, `_FROM` | *(unset)* | Optional native Rust TLS SMTP relay for email alert rules (`587` STARTTLS / `465` implicit). |
| `BUGFINDER_OIDC_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_DISPLAY_NAME` | *(unset)* | Optional OIDC SSO login (requires HTTPS `BUGFINDER_PUBLIC_URL` & issuer outside dev). |

---

## Development & Verification

```bash
# Run frontend typecheck + production Vite bundle + security invariant linter
cd ui && npm ci && npm run build && cd ..
python3 scripts/security-lint.py

# Validate browser SDKs
node --check sdks/browser/bugfinder-mini.js
node --check sdks/browser/bugfinder-shield.js

# Run unit + integration tests (SQLite in-process; pass BUGFINDER_TEST_PG_* for live PG17 RLS tests)
cargo test
```

## Searchable Topics

`rust` · `error-tracking` · `sentry-alternative` · `glitchtip` · `observability` · `opentelemetry` · `log-aggregation` · `uptime-monitoring` · `self-hosted` · `low-memory` · `anti-reverse-engineering` · `security-monitoring` · `intrusion-detection` · `secret-scanning` · `sqlite` · `postgresql` · `row-level-security` · `mcp-server` · `axum` · `single-binary`

## License

MIT
