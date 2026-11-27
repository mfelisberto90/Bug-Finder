# CLI Reference & 7-Layer Verification Shell

## Command Overview

| Command | Purpose |
|---|---|
| `bugfinder [--headless \| --app] [--bind ADDR] [--data DIR] [--db URL]` | Start server (headless HTTP or standalone desktop window). |
| `bugfinder ai-prompt --dsn DSN [--app-url URL] [--stack STACK] [--dir PATH]` | Print a complete 1-prompt autonomous AI integration brief. |
| `bugfinder check [--url URL] [--dsn DSN] [--app-url APP_URL] [--org ORG] [--project PROJ] [--token TOK] [--json]` | Run the 7-layer live plug-and-security verification shell (`< 250 ms`). |
| `bugfinder lint [--dir PATH]` | Run the native Rust security, CSP, `/v` pattern, `FORCE RLS`, and CI SHA-pinning linter (`< 3 ms`). |
| `bugfinder keygen` | Generate a 256-bit hex `BUGFINDER_APP_KEY` from OS `OsRng`. |
| `bugfinder init --dsn DSN [--dir PATH] [--stack ...] [--sdk zero-dep\|sentry]` | Auto-install a zero-dependency connector and `.env` (`0600`). |
| `bugfinder wrap --dsn DSN [--service NAME] [--heartbeat-url URL] -- CMD...` | Run a command while capturing crash tracebacks, logs, and optional heartbeat pings. |
| `bugfinder pipe --dsn DSN [--service NAME]` | Stream `stdin` into sanitized errors/logs. |
| `bugfinder sourcemaps upload --url URL --org ORG --project PROJ --release VER --token TOK --dir PATH [--delete-after-upload]` | Upload private `.js.map` files without public exposure. |
| `bugfinder tail --url URL --org ORG --token TOK [--project ID] [--level LVL] [--query Q]` | Stream real-time SSE logs and errors in the terminal. |
| `bugfinder doctor [--url URL] [--data DIR] [--db URL] [--json]` | Inspect DB WAL/RLS status, VmRSS, audit chain, and runtime posture. |
| `bugfinder healthcheck [--url URL]` | Container `HEALTHCHECK` probe (`0` = healthy). |
| `bugfinder migrate [--data DIR] [--db URL]` | Apply SQLite or PostgreSQL 17 `FORCE RLS` schema migrations. |
| `bugfinder backup --out FILE [--data DIR]` | Consistent online SQLite WAL hot backup. |
| `bugfinder mcp [--org ORG] [--token TOK] [--data DIR] [--db URL]` | Start the read-only STDIO MCP server for AI assistants. |

---

## Using the Verification Shell (`bugfinder check` & `./scripts/check.sh`)

Run `./scripts/check.sh` (or `bugfinder check`) inside your Bug-Finder or monitored app workspace after configuring Bug-Finder. Both exit `0` when all checks pass and `1` if any `[FAIL]` occurs.

### Checks Executed

1. **`server_health`**: Confirms `GET /api/health` returns `200` (`"status":"ok"`), strict CSP contains `style-src-attr 'none'`, and `GET /llms.txt` returns `200` with `0` `Set-Cookie` headers.
2. **`error_and_session_ingest`**: Sends an authenticated `X-BugFinder-Check: dry-probe` envelope containing an `event` and `session` item to `/api/:id/envelope/`, validating DSN key auth, parser, and scrubber without writing test issues.
3. **`logs_and_trace_ingest`**: Sends a `dry-probe` OTLP log payload carrying `traceId`/`spanId` to `/api/:id/otlp/v1/logs`.
4. **`shield_and_blocklist`**: Sends a `dry-probe` signal to `/api/:id/shield/` and (when `--token`, `--org`, `--project` are passed) verifies `/shield/blocklist/` returns `ETag`.
5. **`app_sdk_and_csp`** *(with `--app-url`)*: Fetches the app HTML and verifies the SDK script tag (`/_obs/m.js` or `/sdk/bugfinder-mini.js`), `data-release=`, SRI `sha384-`, `Content-Security-Policy` header, and HTTP `200` on the stealth proxy `/_obs/m.js`.
6. **`sourcemap_zero_leak`** *(with `--app-url`)*: Fetches the app's primary JS bundle to confirm zero `//# sourceMappingURL=` comments and confirms `<bundle>.js.map` is blocked/404 publicly.
7. **`app_edge_waf`** *(with `--app-url`)*: Verifies `GET /.well-known/security.txt` is NOT throttled (`!= 429`) and `GET /.env` is blocked (`403`/`404`/`429`, never `200`).

### Machine-Readable Output

```bash
./scripts/check.sh \
  --dsn "https://<PUBLIC_KEY>@bugs.example.com/1" \
  --app-url "https://app.example.com" \
  --json
```
