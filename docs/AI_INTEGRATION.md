# 1-Prompt Autonomous AI Integration & MCP Guide

Bug-Finder v2.0 is designed so you can point any AI coding assistant (Claude Code, Antigravity, Cursor, Codex, Windsurf, Copilot) at your repository and wire **every tracking and protection endpoint in a single prompt**.

## 1. Public Agent Discovery (`GET /llms.txt`)

Every Bug-Finder server exposes `GET /llms.txt` (`text/plain; charset=utf-8`, zero cookies, `Cache-Control: public, max-age=3600`) describing:
- Ingestion routes (envelopes, store, OTLP logs, anti-AdBlock tunnel `/t/:slug`),
- Security Shield reporting (`POST /api/:id/shield/`), ETag blocklist sync (`GET /api/0/projects/:org/:proj/shield/blocklist/`), and CSP report URI,
- Private hidden SourceMaps upload (`bugfinder sourcemaps upload`),
- Ephemeral diagnostic dry-probe header (`X-BugFinder-Check: dry-probe`),
- Verification commands (`bugfinder check` and `./scripts/check.sh`).

## 2. Generating a Project's Complete AI Prompt

### Option A: From the Web Dashboard
1. Go to **Projects & SDK -> Connect App**.
2. Keep the first tab selected: **AI Auto-Setup (1-Prompt)**.
3. Pick your target stack (`Auto-detect`, `Web / SPA`, `Node / Next`, `Rust`, `Python`, `Laravel / PHP`, or `Go`).
4. Click **Copy AI Prompt** and paste it into your AI agent.
5. When the agent finishes, run the **Verification Shell** command displayed in the modal.

### Option B: From CLI or Authenticated HTTP API
```bash
# CLI generator (auto-detects local stack from --dir when --stack=auto):
bugfinder ai-prompt \
  --dsn "https://<PUBLIC_KEY>@bugs.example.com/1" \
  --app-url "https://app.example.com" \
  --org acme \
  --project web \
  --dir /path/to/your/app

# Authenticated API endpoint (returns JSON with prompt, check_command, and all URLs):
curl -H "Authorization: Bearer bf_<TOKEN>" \
  "https://bugs.example.com/api/0/projects/acme/web/ai-blueprint/?stack=auto"
```

## 3. What the 1-Prompt Configures Automatically

1. **Same-Origin Stealth Proxy (`/_obs/*`)**: Proxies `/_obs/m.js`, `/_obs/s.js`, `/_obs/e`, and `/_obs/s` so browsers keep strict `script-src 'self'` / `connect-src 'self'` CSP and ad-blockers cannot drop telemetry.
2. **CSP-Nonce HTML Script Tag**: Injects `bugfinder-mini.js` with `integrity="sha384-..."`, `data-shield="detect"`, `data-capture-fetch="true"`, `data-trace-propagation="true"`, and `data-release`.
3. **Backend Exceptions, DB Errors & Distributed Traces**: Reads/generates W3C `traceparent` headers, forwards runtime exceptions + SQL failures (`SQLSTATE`), and ships structured JSON logs with `trace_id` to `/api/:id/otlp/v1/logs`.
4. **App Edge WAF + ETag Blocklist Sync**: Blocks `/.env*`, `/.git*`, root dotfiles (exempting `/.well-known/*`), and quarantined actors while syncing blocked HMAC digests from `/shield/blocklist/` every 30s.
5. **Private SourceMaps**: Builds hidden SourceMaps (`sourcemap: 'hidden'`), verifies `.js.map` returns `404` publicly, and runs `bugfinder sourcemaps upload --delete-after-upload` in CI/deploy.
6. **Mandatory Final Check Gate**: Instructs the agent to run `bugfinder check` and fix any `[FAIL]`/`[WARN]` items before reporting completion.

## 4. MCP Server for AI Debugging & Remediation

```bash
bugfinder mcp --org acme --token "bf_<TOKEN>"
```

Exposed read-only tools (telemetry wrapped in `<untrusted_error_telemetry>` Anti-Agentjacking boundaries):
- `list_issues`: Search and rank unresolved errors by recency or frequency.
- `get_issue_detail`: Fetch demangled stack frames, breadcrumbs, request context, and environment tags.
- `diagnose_issue`: Deterministic category classification, suspected root-cause file/function, and ready-to-use investigation brief.
- `query_logs`: Full-text FTS5 log query across services and severity levels.
- `get_trace_context`: Correlate transactions, errors, and structured logs sharing a `trace_id`.
