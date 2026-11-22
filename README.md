# Bug-Finder

Ultra-lightweight **Error Tracking, Structured Logs, Performance & Uptime Monitoring** platform in pure **Rust** — a single **5.5 MB** native binary running under **~8–9 MB VmRSS** with drop-in compatibility for **Sentry SDKs**, **GlitchTip** (`GlitchTipClient` / `GlitchTipReadClient`), and **OpenTelemetry OTLP/HTTP**.

## Measured Footprint vs Alternatives

| Engine | Typical `VmRSS` | Dependencies | Cold Start |
|---|---|---|---|
| Sentry Self-Hosted | 8 – 16+ GB | ~25 services (Python, Relay, ClickHouse, Kafka, Postgres, Redis) | 45 – 120 s |
| GlitchTip | 500 MB – 1.5 GB | Django, Celery, Valkey, PostgreSQL, Angular | 5 – 15 s |
| **Bug-Finder (Rust)** | **7.7 – 8.9 MB** | **Zero** (embedded SQLite WAL+FTS5 & embedded SPA) or PostgreSQL 17 RLS | **~36 ms** |

## Quickstart

### 1. One-Command Install (Recommended)
```bash
# Install binary (~/.local/bin/bugfinder), locked-down config (0600), and run self-check
./scripts/install.sh

# Or install as an auto-starting user systemd service (64 MB RAM cap)
./scripts/install.sh --service

# Or run in an isolated 32 MB Docker container
./scripts/install.sh --docker
```
Shortcuts via Make: `make install`, `make install-service`, `make install-docker`, `make doctor`.

### 2. Self-Check & Built-in Diagnostics
Bug-Finder monitors itself continuously (storage integrity, WAL / PostgreSQL `FORCE RLS`, VmRSS, disk budget, missing DSN/alerts/tokens, HTTP 5xx, `BatchWriter` queue/failures, panic crash persistence, and frontend runtime/transport errors) and surfaces issues directly inside the top **Auto-Check** banner/tab and CLI:
```bash
bugfinder doctor
bugfinder doctor --url http://127.0.0.1:8080/api/health --json
```

### 3. Manual Build & Run (SQLite WAL + FTS5, Zero External Deps)
```bash
./scripts/build-release.sh
./target/release/bugfinder --headless --bind 127.0.0.1:8080 --data ./data
```
Or launch as a standalone desktop window (`--app`) or Docker container (`docker compose up -d` with `mem_limit: 32m`).

### 4. PostgreSQL 17 Multi-Tenant Mode (`ENABLE + FORCE RLS`)
```bash
export DATABASE_URL="postgres://bugfinder_app:SECRET@127.0.0.1:5432/bugfinder"
./target/release/bugfinder --headless --bind 127.0.0.1:8080
```
Apply `migrations/postgres/001_init_rls.sql` as the migrator role; runtime queries operate strictly under the `NOBYPASSRLS` `bugfinder_app` role with transaction-local `app.current_tenant_id` and capability-GUC lookup tables.

---

## Plugue em qualquer app em 30 segundos

### Opção 1 — Navegador em 1 Tag `<script>` (0 JS inline, Compatível com CSP + SRI)
Copie esta única tag da aba **Projects -> Conectar App** para dentro do `<head>` de qualquer app web (HTML, Vite, Next, React, Vue):
```html
<script
  src="https://monitor.seudominio.com/sdk/bugfinder-mini.js"
  data-dsn="https://<KEY>@monitor.seudominio.com/1"
  data-shield="detect"
  integrity="sha384-<SRI_DA_UI>"
  crossorigin="anonymous"
  async></script>
```
Para capturar também `fetch` com status `>=500` e `console.error`, basta adicionar `data-capture-fetch="true" data-capture-console="error"`.

### Opção 2 — Zero Código no Terminal (`wrap` e `pipe`)
```bash
# Captura erros/tracebacks de stderr, envia saída normal como logs, remove segredos e preserva exit code
bugfinder wrap --dsn "http://<KEY>@127.0.0.1:8080/1" -- node server.js

# Ou capture direto de qualquer pipeline / systemd / cron
./seu-job.sh 2>&1 | bugfinder pipe --dsn "http://<KEY>@127.0.0.1:8080/1" --service backup-job
```

### Opção 3 — Setup Automático (`bugfinder init`)
```bash
# Detecta Next/Vite/Node/Laravel/PHP/Python/Go/Rust, grava .env (0600) + .env.example e cria conector stdlib zero-dep
bugfinder init --dsn "http://<KEY>@127.0.0.1:8080/1"
```

### Opção 4 — Sidecar Docker Compose (5 linhas)
```yaml
services:
  bugfinder:
    image: ghcr.io/murilofelisberto90/bugfinder:latest
    command: ["--headless", "--bind", "0.0.0.0:8080", "--data", "/data"]
    mem_limit: 32m
```

---

## Tracking Everything & Sending Structured Logs

### A. Zero-Dep Browser Mini-SDK (`< 3 KB`, served from `/sdk/bugfinder-mini.js`)
```html
<!-- Recommended 1-tag auto-init (or call BugFinder.init({ ... }) manually) -->
<script
  src="http://127.0.0.1:8080/sdk/bugfinder-mini.js"
  data-dsn="http://<KEY>@127.0.0.1:8080/1"
  data-env="production"
  data-release="1.0.0"
  crossorigin="anonymous"
  async></script>
```
Captures `window.onerror`, `unhandledrejection`, click breadcrumbs, opt-in HTTP `5xx` fetch failures & `console.error`, and sends **Sentry Envelope NDJSON** (`event` + `log` v2) with optional 1-tag Anti-REA Shield bootstrap (`data-shield="detect"`).

### B. Official Sentry SDKs (`@sentry/browser`, `@sentry/node`, `sentry-sdk`, `sentry-laravel`)
Point any Sentry SDK `dsn` (or `tunnel: "/t/<tunnel_slug>"` to bypass ad-blockers) directly to Bug-Finder. Supports:
- `POST /api/:project_id/envelope/` (`event`, `log` v2, `transaction`, `session`, `check_in`, `attachment`)
- `POST /api/:project_id/store/`
- `POST /api/:project_id/security/` (CSP reports)
- `POST /t/:slug` (Anti-AdBlocker Sentry Tunnel)

### C. OpenTelemetry OTLP/HTTP Logs (`/v1/logs` & `/api/:id/otlp/v1/logs`)
Accepts both `application/x-protobuf` (`ExportLogsServiceRequest` decoded in pure Rust) and `application/json`, correlating `trace_id` and `span_id` across logs, errors, and transactions.

### D. RoleLane / GlitchTip Drop-In `.env`
```env
GLITCHTIP_ENABLED=true
GLITCHTIP_DSN=http://<KEY>@127.0.0.1:8080/1
GLITCHTIP_API_URL=http://127.0.0.1:8080
GLITCHTIP_API_TOKEN=bf_<API_TOKEN>
GLITCHTIP_ORGANIZATION=<org_slug>
GLITCHTIP_UPTIME_MONITOR_UUID=<monitor_uuid>
```

### E. CLI Live Tail, Synthetic Probes & Read-Only MCP Server
```bash
# Stream live logs/errors from terminal
./target/release/bugfinder tail --url http://127.0.0.1:8080 --org acme --token bf_...

# Send synthetic verification event & log
./target/release/bugfinder test-event --dsn http://<KEY>@127.0.0.1:8080/1
./target/release/bugfinder test-log   --dsn http://<KEY>@127.0.0.1:8080/1

# Run read-only MCP stdio server for AI debugging agents
./target/release/bugfinder mcp --org acme --token bf_...
```

## Security Controls Built-In
- Streaming decompression (`gzip`/`deflate`/`br`/`zstd`) with hard byte cap (`413` anti-zip-bomb).
- In-place recursive PII, JWT, PEM private-key, API-secret, query-secret, and Luhn-validated PAN scrubber before persistence or SSE broadcast.
- `scrypt` password hashing (`Semaphore(2)` + `malloc_trim(0)`), exponential lockout, multi-bucket `HMAC-SHA256` `BoundedMap` rate limiter (`429` + `X-Sentry-Rate-Limits`).
- Strict per-request CSP nonces (`script-src` & `style-src`), zero inline styles, SSRF-blocked outbound webhooks with HMAC signatures, native TLS SMTP, and CSV formula sanitization.
