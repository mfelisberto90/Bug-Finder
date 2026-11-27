# Endpoints & End-to-End Security Reference

## Telemetry, Ingestion & Protection Endpoints

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /api/health` | Public (0 cookies) | Health status (`200` when DB & PG RLS active). |
| `GET /llms.txt` | Public (0 cookies) | AI integration specification listing all endpoints and CLI commands. |
| `GET /sdk/bugfinder-mini.js` | Public (`CORP: cross-origin`) | Pre-compressed `< 3 KB` zero-dep browser error/log/vitals SDK. |
| `GET /sdk/bugfinder-shield.js` | Public (`CORP: cross-origin`) | Browser Anti-REA Shield (`detect` / `defend` / `lockdown`). |
| `POST /api/:project_id/envelope/` | DSN key | Sentry-compatible envelope ingest (`event`, `log` v2, `transaction`, `session`, `check_in`). Honors `X-BugFinder-Check: dry-probe`. |
| `POST /api/:project_id/store/` | DSN key | Single JSON error event endpoint. Honors `X-BugFinder-Check: dry-probe`. |
| `POST /api/:project_id/otlp/v1/logs` | DSN key / `?project_id=` / `Bearer <DSN>` | OpenTelemetry OTLP/HTTP `ExportLogsServiceRequest` (`application/x-protobuf` & JSON). Also mounted at `POST /v1/logs`, with `POST /v1/traces` and `POST /v1/metrics` (`202` accepted). |
| `POST /api/v1/logs` | Project hint + DSN key | Direct JSON log batch ingest. |
| `POST /t/:slug` | Tunnel slug + envelope `dsn` header | Anti-AdBlock tunnel endpoint validated before decompression. |
| `POST /api/:project_id/security/` | DSN key | Browser Content-Security-Policy violation report ingest + tamper detection. |
| `POST /api/:project_id/shield/` | DSN key (`browser`) or `Bearer bf_...` `shield:write` (`backend_verified`) | Security telemetry & quarantine signal ingest (bounded decompression). |
| `POST /api/auth/reauth/passkey/begin`, `finish` | Active session | WebAuthn Passkey step-up re-authentication for sensitive organization and security mutations. |
| `GET /api/0/projects/:org/:proj/shield/blocklist/` | Session / `bf_` token (`shield:read`) | Returns `ip_hmac_key` and active quarantined subject HMACs with `ETag` (`304`). |
| `GET /api/0/projects/:org/:proj/ai-blueprint/` | Session / `bf_` token (`project:read`) | Generates complete stack-aware 1-prompt AI integration brief (`Cache-Control: no-store, private`). |
| `POST /api/0/projects/:org/:proj/releases/:version/sourcemaps/` | Session / `bf_` token (`project:releases`) | Uploads private `.js.map` bundles and `debug_id` metadata (max 10 MB per file). |
| `GET/POST /api/0/organizations/:org/heartbeat_check/:uuid/` | Monitor UUID | Uptime cron/service heartbeat ping. |
| `GET /metrics` | Loopback or `BUGFINDER_METRICS_TOKEN` | Prometheus metrics export. |

## End-to-End Security Controls (All 7 Zones)

1. **Client Pre-Wire Redaction (`bugfinder-mini.js` v2.1)**: Strips `#...` fragments (`#access_token=...`) and masks sensitive query parameter values (`token`, `code`, `secret`, `password`, `api_key`, etc.) before data leaves the browser, preserves `fetch(new Request(...))` headers, and guards `securitypolicyviolation` against feedback loops.
2. **RFC 9113 Multi-Header Extraction**: `extract_cookie` iterates `headers.get_all(header::COOKIE)` and `resolve_client_ip` iterates `headers.get_all("x-forwarded-for")` right-to-left behind verified `BUGFINDER_TRUSTED_PROXIES`, preventing HTTP/2 multi-header smuggling and left-side proxy header spoofing.
3. **SIMD Edge WAF & 16-Shard Isolation**: `src/security/waf.rs` inspects URIs (with 2-pass stack percent decoding), methods, and User-Agents in `< 1 µs`. `.js.map` requests return `404` without triggering CGNAT IP bans, and authenticated active sessions are exempted via CGNAT-safe `ScannerGuard` lookup so mobile carriers are never mass-blocked.
4. **Decompression, Depth & Clock-Skew Bounds**: Zstd frames are pre-validated against RFC 8878 (`window_size <= 8 MiB`) prior to decompression, JSON nested deeper than `32` levels is rejected (`400 Bad Request`), `\u0000` NUL bytes are stripped from JSON keys/values and log fields, and forged `timestamp` fields outside `now ± 24 hours` are clamped before storage.
5. **100% OS CSPRNG + `enc:v2:` AEAD + Step-Up Auth**: All nonces, salts, session secrets, API keys, TOTP secrets, and `BUGFINDER_APP_KEY` use `OsRng`. Secrets at rest use `HKDF-SHA256` + `AES-256-GCM` (`enc:v2:` with `BUGFINDER_PREVIOUS_APP_KEYS` rotation fallback). Sensitive operations require Passkey or TOTP/password step-up re-authentication, and `is_dev` defaults fail-closed to `false`.
6. **Immutable `audit_logs` & PG17 `FORCE RLS` (15 Tables)**: Multi-tenant queries execute inside single-statement fail-closed transactions under `NOBYPASSRLS` with `ENABLE + FORCE ROW LEVEL SECURITY` on all `15` tables (including `users` and `login_attempts`, plus `REVOKE DELETE, TRUNCATE ON users`). Both SQLite and PostgreSQL enforce SHA-256 hash chaining plus DB triggers (`trg_audit_logs_immutable_update` / `_delete`) rejecting any `UPDATE` or `DELETE` on `audit_logs`.
7. **DNS-Pinned Webhooks with `v2` Anti-Replay & Bounded Alert Queue**: `src/security/ssrf.rs` rejects private/loopback/CGNAT/link-local IPs plus IPv4/IPv6 cloud metadata (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`, `192.0.0.192`) with `redirects(0)`. Alert dispatch runs through a bounded `mpsc(256)` queue with separate HTTP (`8`) and SMTP (`4`) concurrency semaphores. Webhook alerts include:
   - `X-BugFinder-Delivery: <uuid_v4>`
   - `X-BugFinder-Timestamp: <unix_sec>`
   - `X-BugFinder-Signature: t=<unix_sec>,v1=<hmac_ts_body>,v2=<hmac_ts_delivery_body>`

Verify `v2` webhooks by checking that `|now - timestamp| <= 300`, that `X-BugFinder-Delivery` has not been processed previously, and that `HMAC-SHA256(secret, "{timestamp}.{delivery_id}.{raw_body}")` matches `v2` in constant time.
