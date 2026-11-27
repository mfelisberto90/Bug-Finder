use std::path::Path;

pub fn sanitize_slug(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(80)
        .collect()
}

pub fn normalize_stack(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "web" | "spa" | "react" | "vue" | "vite" => "web",
        "node" | "express" | "fastify" | "next" | "nextjs" | "nestjs" => "node",
        "rust" | "axum" | "actix" => "rust",
        "python" | "fastapi" | "django" | "flask" => "python",
        "php" | "laravel" => "laravel",
        "go" | "golang" | "gin" | "fiber" => "go",
        _ => "auto",
    }
}

pub fn detect_stack_from_dir(dir: &Path) -> &'static str {
    if dir.join("Cargo.toml").is_file() {
        return "rust";
    }
    if dir.join("composer.json").is_file() || dir.join("artisan").is_file() {
        return "laravel";
    }
    if dir.join("go.mod").is_file() {
        return "go";
    }
    if dir.join("pyproject.toml").is_file() || dir.join("requirements.txt").is_file() {
        return "python";
    }
    if dir.join("package.json").is_file() {
        if let Ok(pkg) = std::fs::read_to_string(dir.join("package.json")) {
            let low = pkg.to_ascii_lowercase();
            if low.contains("\"express\"")
                || low.contains("\"fastify\"")
                || low.contains("\"next\"")
                || low.contains("\"@nestjs/core\"")
                || low.contains("\"hono\"")
            {
                return "node";
            }
        }
        return "web";
    }
    "auto"
}

/// Public, zero-cookie `/llms.txt` specification exposing Bug-Finder v2.0 architecture,
/// tracking/security endpoints, and autonomous AI setup instructions.
pub fn render_public_llms_txt(public_url: Option<&str>) -> String {
    let base = public_url
        .map(|s| s.trim().trim_end_matches('/'))
        .filter(|s| !s.is_empty())
        .unwrap_or("https://bugs.example.com");

    format!(
        "# Bug-Finder v2.0 Turbo: Autonomous Observability & Security Platform\n\
         \n\
         > Single-binary Rust (<15 MB VmRSS) error tracking, distributed tracing, structured logs, private SourceMaps, uptime monitoring, and sub-microsecond SIMD Edge WAF.\n\
         \n\
         Base URL: {base}\n\
         \n\
         ## Tracking & Protection Endpoints\n\
         - Health Check: `GET {base}/api/health`\n\
         - Browser Mini-SDK (zero-dependency): `GET {base}/sdk/bugfinder-mini.js`\n\
         - Browser Anti-REA Shield SDK: `GET {base}/sdk/bugfinder-shield.js`\n\
         - Sentry-Compatible Envelope Ingest (errors, sessions, check-ins, frontend logs): `POST {base}/api/<PROJECT_ID>/envelope/`\n\
         - Sentry-Compatible Event Store: `POST {base}/api/<PROJECT_ID>/store/`\n\
         - OTLP HTTP/JSON & Protobuf Logs Ingest: `POST {base}/api/<PROJECT_ID>/otlp/v1/logs` or `POST {base}/v1/logs`\n\
         - Direct JSON Logs Ingest: `POST {base}/api/v1/logs`\n\
         - Anti-AdBlock Tunnel Endpoint: `POST {base}/t/<TUNNEL_SLUG>`\n\
         - CSP Violation Report URI: `POST {base}/api/<PROJECT_ID>/security/`\n\
         - Security Shield Telemetry & Edge Quarantine Report: `POST {base}/api/<PROJECT_ID>/shield/`\n\
         - Edge WAF ETag Blocklist Feed: `GET {base}/api/0/projects/<ORG>/<PROJECT>/shield/blocklist/`\n\
         - Private SourceMaps Upload: `POST {base}/api/0/projects/<ORG>/<PROJECT>/releases/<RELEASE>/sourcemaps/`\n\
         - Ephemeral Dry-Probe Header (validates auth, scrubber & parser without writing): `X-BugFinder-Check: dry-probe`\n\
         - Autonomous Per-Project AI Blueprint (authenticated): `GET {base}/api/0/projects/<ORG>/<PROJECT>/ai-blueprint/?stack=auto`\n\
         \n\
         ## CLI & Verification Shell\n\
         - Generate complete 1-prompt AI implementation brief: `bugfinder ai-prompt --dsn \"<DSN>\" --app-url \"<APP_URL>\"`\n\
         - Verify all 7 telemetry & WAF layers end-to-end: `bugfinder check --dsn \"<DSN>\" --app-url \"<APP_URL>\"`\n\
         - Shell wrapper: `./scripts/check.sh --dsn \"<DSN>\" --app-url \"<APP_URL>\"`\n\
         - Upload hidden SourceMaps on deploy: `bugfinder sourcemaps upload --url {base} --org <ORG> --project <PROJECT> --release <VER> --token <TOKEN> --dir ./dist --delete-after-upload`\n\
         - Start STDIO MCP Server for AI triage (`list_issues`, `diagnose_issue`, `query_logs`, `get_trace_context`): `bugfinder mcp --org <ORG>`\n"
    )
}

pub struct ProjectBlueprintParams<'a> {
    pub base_url: &'a str,
    pub org_slug: &'a str,
    pub project_slug: &'a str,
    pub project_id: i64,
    pub dsn: &'a str,
    pub tunnel_slug: Option<&'a str>,
    pub app_url: Option<&'a str>,
    pub stack: &'a str,
    pub mini_sdk_sri: &'a str,
    pub shield_sdk_sri: &'a str,
}

/// Renders a complete, self-contained 1-prompt AI implementation brief pre-wired with
/// all Bug-Finder tracking, proxy, WAF, SourceMap, MCP, and `bugfinder check` verification steps.
pub fn render_project_ai_blueprint(p: &ProjectBlueprintParams<'_>) -> String {
    let base = p.base_url.trim().trim_end_matches('/');
    let org = sanitize_slug(p.org_slug);
    let proj = sanitize_slug(p.project_slug);
    let pid = p.project_id;
    let dsn = p.dsn.trim();
    let app_url = p
        .app_url
        .map(|s| s.trim().trim_end_matches('/'))
        .filter(|s| !s.is_empty())
        .unwrap_or("https://app.example.com");
    let stack = normalize_stack(p.stack);
    let mini_sri = p.mini_sdk_sri.trim();
    let shield_sri = p.shield_sdk_sri.trim();
    let tunnel_route = p
        .tunnel_slug
        .map(|t| format!("/t/{}", sanitize_slug(t)))
        .unwrap_or_else(|| format!("/api/{pid}/envelope/"));

    let sri_attr = if mini_sri.is_empty() {
        String::new()
    } else {
        format!(" integrity=\"{mini_sri}\"")
    };
    let shield_sri_attr = if shield_sri.is_empty() {
        String::new()
    } else {
        format!(" data-shield-sri=\"{shield_sri}\"")
    };

    let stack_hint = match stack {
        "web" => "Target Stack: Browser / SPA (React, Vue, Vite). Configure Vite `build.sourcemap = 'hidden'` and proxy `/_obs/*` via reverse proxy or BFF.",
        "node" => "Target Stack: Node.js / TypeScript Backend + Web. Install Express/Fastify/Next middleware on `/_obs/*`, global uncaughtException/unhandledRejection hooks, SQL error capture, and HTML injection.",
        "rust" => "Target Stack: Rust (Axum / Actix / Tokio). Add Axum/Tower middleware for `/_obs/*` proxy, panic hook + 5xx traceparent propagation, and Edge WAF guard.",
        "python" => "Target Stack: Python (FastAPI / Django / Flask). Add ASGI/WSGI middleware for `/_obs/*`, exception + DB error reporting, and trace_id structured OTLP logs.",
        "laravel" => "Target Stack: PHP / Laravel. Add Exception Handler reporter, DB query/5xx logging to OTLP, Edge WAF middleware, and Blade CSP nonce script tag.",
        "go" => "Target Stack: Go HTTP / Gin / Fiber. Add panic recovery middleware, reverse proxy `/_obs/*`, structured OTLP exporter, and Edge WAF blocker.",
        _ => "Target Stack: Auto-detect the repository stack (frontend, backend, reverse proxy / Nginx / Caddy, Docker) and wire every applicable step cleanly without duplicating dependencies.",
    };

    format!(
        "You are integrating **Bug-Finder v2.0** end-to-end into this application autonomously.\n\
         Implement every section below directly in the repository without asking intermediate questions.\n\
         \n\
         ## Project Connection Constants\n\
         - Bug-Finder Server: `{base}`\n\
         - Organization / Project: `{org}` / `{proj}` (project_id: `{pid}`)\n\
         - Project DSN: `{dsn}`\n\
         - Envelope Endpoint: `{base}/api/{pid}/envelope/` (Tunnel: `{base}{tunnel_route}`)\n\
         - OTLP Logs Endpoint: `{base}/api/{pid}/otlp/v1/logs`\n\
         - Security Shield Endpoint: `{base}/api/{pid}/shield/`\n\
         - WAF Blocklist Sync Endpoint: `{base}/api/0/projects/{org}/{proj}/shield/blocklist/`\n\
         - SourceMaps Upload Endpoint: `{base}/api/0/projects/{org}/{proj}/releases/<RELEASE>/sourcemaps/`\n\
         - Target App URL (for verification): `{app_url}`\n\
         - {stack_hint}\n\
         \n\
         ## Step 1: Same-Origin Stealth Proxy Routes (`/_obs/*`)\n\
         Configure reverse proxy or backend routes on `{app_url}` so telemetry stays first-party (zero third-party CSP relaxation and ad-blocker proof):\n\
         - `GET  /_obs/m.js` -> proxy to `{base}/sdk/bugfinder-mini.js`\n\
         - `GET  /_obs/s.js` -> proxy to `{base}/sdk/bugfinder-shield.js`\n\
         - `POST /_obs/e`    -> proxy to `{base}{tunnel_route}` (forward `Content-Type`, `Content-Encoding`, `X-Sentry-Auth`, `X-BugFinder-Check`)\n\
         - `POST /_obs/s`    -> proxy to `{base}/api/{pid}/shield/`\n\
         Keep `BUGFINDER_DSN` and `BUGFINDER_URL` read from environment variables with safe no-op fallback if unset.\n\
         \n\
         ## Step 2: Frontend Zero-Inline SDK + Anti-REA Shield Injection\n\
         Add this single CSP-nonce tag inside `<head>` of the main HTML/template layout (do NOT use inline `<script>` code):\n\
         ```html\n\
         <script src=\"/_obs/m.js\" nonce=\"{{CSP_NONCE}}\"{sri_attr} crossorigin=\"anonymous\"\n\
           data-dsn=\"{dsn}\"\n\
           data-tunnel=\"/_obs/e\"\n\
           data-shield-src=\"/_obs/s.js\"\n\
           data-shield-endpoint=\"/_obs/s\"{shield_sri_attr}\n\
           data-shield=\"detect\"\n\
           data-capture-fetch=\"true\"\n\
           data-capture-console=\"warn\"\n\
           data-trace-propagation=\"true\"\n\
           data-env=\"production\"\n\
           data-release=\"{{APP_RELEASE}}\" async></script>\n\
         ```\n\
         Note: `bugfinder-mini.js` v2.0 automatically strips URL `#fragments` and redacts sensitive query params in the browser before transmission, flushes logs on `visibilitychange`, and propagates `traceparent` strictly on same-origin `fetch` calls.\n\
         \n\
         ## Step 3: Backend Errors, SQL Failures, Distributed Traces & OTLP Logs\n\
         - Capture unhandled exceptions/panics, 5xx responses, slow requests (`> 5000 ms`), and DB errors (`SQLSTATE` / constraint / connection failures) and forward sanitized envelopes to `{base}/api/{pid}/envelope/` (auth via DSN).\n\
         - Extract incoming `traceparent` header (`00-<trace_id>-<span_id>-01`) if present or generate a 32-hex `trace_id`, include `contexts.trace.trace_id` on error events, and ship structured JSON logs with `trace_id` to `{base}/api/{pid}/otlp/v1/logs`.\n\
         - Never send raw passwords, tokens, authorization headers, emails, or credit cards.\n\
         \n\
         ## Step 4: App Edge WAF, Verified Shield Reporting & ETag Blocklist Sync\n\
         - Block/404 unauthenticated probes to `/.env*`, `/.git*`, `/.aws*`, `/.ssh*`, root dotfiles (MUST exempt `/.well-known/*`), `.sql`/`.bak`/`.js.map`, and double-encoded path traversal / SQLi / SSRF probes.\n\
         - Forward high-confidence attack detections to `POST {base}/api/{pid}/shield/` with `Authorization: Bearer $BUGFINDER_SHIELD_TOKEN` (keep token strictly in server env, never client JS).\n\
         - Poll `GET {base}/api/0/projects/{org}/{proj}/shield/blocklist/` every `30s` using `If-None-Match` (`ETag` -> `304 Not Modified`) and block quarantined IP HMACs computed with the returned `ip_hmac_key`.\n\
         \n\
         ## Step 5: Private SourceMaps Zero-Leak Pipeline\n\
         - Enable hidden SourceMaps (`sourcemap: 'hidden'` or equivalent so zero `//# sourceMappingURL=` comment is emitted in public bundles and `.js.map` returns `404` publicly).\n\
         - Update the deploy/build script to run:\n\
           `bugfinder sourcemaps upload --url \"{base}\" --org \"{org}\" --project \"{proj}\" --release \"$RELEASE\" --token \"$BUGFINDER_API_TOKEN\" --dir ./dist --delete-after-upload`\n\
         \n\
         ## Step 6: Wire MCP Diagnostics & Run Mandatory 7-Layer Verification\n\
         - Ensure MCP config points to `bugfinder mcp --org {org}` (exposes `list_issues`, `diagnose_issue`, `query_logs`, `get_trace_context`).\n\
         - After making all changes, run all project tests/linters AND verify every endpoint is plugged in by running:\n\
           `bugfinder check --dsn \"{dsn}\" --app-url \"{app_url}\"`\n\
           Do not finish until every check reports `[PASS]` (fix any `[FAIL]` or `[WARN]` detected by the check shell).\n"
    )
}
