use crate::domain::envelope::parse_dsn_url;
use crate::domain::models::ProjectFilters;
use crate::domain::scrubber::{strip_ansi_and_bidi, Scrubber};
use crate::mcp::run_synthetic_test;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedStack {
    NextJs,
    Vite,
    Node,
    Laravel,
    Php,
    FastApi,
    Django,
    Flask,
    Python,
    Rust,
    Go,
    WebHtml,
}

impl DetectedStack {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NextJs => "next",
            Self::Vite => "vite",
            Self::Node => "node",
            Self::Laravel => "laravel",
            Self::Php => "php",
            Self::FastApi => "fastapi",
            Self::Django => "django",
            Self::Flask => "flask",
            Self::Python => "python",
            Self::Rust => "rust",
            Self::Go => "go",
            Self::WebHtml => "web",
        }
    }

    pub fn from_cli_str(s: &str) -> Result<Option<Self>, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(None),
            "web" | "html" => Ok(Some(Self::WebHtml)),
            "node" | "express" => Ok(Some(Self::Node)),
            "next" | "nextjs" => Ok(Some(Self::NextJs)),
            "vite" | "react" | "vue" => Ok(Some(Self::Vite)),
            "laravel" => Ok(Some(Self::Laravel)),
            "php" => Ok(Some(Self::Php)),
            "fastapi" => Ok(Some(Self::FastApi)),
            "django" => Ok(Some(Self::Django)),
            "flask" => Ok(Some(Self::Flask)),
            "python" | "py" => Ok(Some(Self::Python)),
            "rust" | "cargo" => Ok(Some(Self::Rust)),
            "go" | "golang" => Ok(Some(Self::Go)),
            other => Err(format!("Unsupported stack '{other}'")),
        }
    }
}

pub fn detect_project_stack(dir: &Path) -> DetectedStack {
    if dir.join("Cargo.toml").is_file() {
        return DetectedStack::Rust;
    }
    if dir.join("go.mod").is_file() {
        return DetectedStack::Go;
    }
    if dir.join("artisan").is_file() || dir.join("composer.json").is_file() {
        let comp = fs::read_to_string(dir.join("composer.json"))
            .unwrap_or_default()
            .to_ascii_lowercase();
        if dir.join("artisan").is_file() || comp.contains("laravel/framework") {
            return DetectedStack::Laravel;
        }
        return DetectedStack::Php;
    }
    if dir.join("pyproject.toml").is_file() || dir.join("requirements.txt").is_file() {
        let py_meta = format!(
            "{}\n{}",
            fs::read_to_string(dir.join("pyproject.toml")).unwrap_or_default(),
            fs::read_to_string(dir.join("requirements.txt")).unwrap_or_default()
        )
        .to_ascii_lowercase();
        if py_meta.contains("fastapi") {
            return DetectedStack::FastApi;
        }
        if py_meta.contains("django") {
            return DetectedStack::Django;
        }
        if py_meta.contains("flask") {
            return DetectedStack::Flask;
        }
        return DetectedStack::Python;
    }
    if dir.join("package.json").is_file() {
        let pkg = fs::read_to_string(dir.join("package.json"))
            .unwrap_or_default()
            .to_ascii_lowercase();
        if pkg.contains("\"next\"") {
            return DetectedStack::NextJs;
        }
        if pkg.contains("\"vite\"") {
            return DetectedStack::Vite;
        }
        return DetectedStack::Node;
    }
    if dir.join("index.html").is_file() || dir.join("public").join("index.html").is_file() {
        return DetectedStack::WebHtml;
    }
    DetectedStack::WebHtml
}

fn parse_dsn_parts(dsn: &str) -> Result<(String, String, i64), String> {
    let trimmed = dsn.trim();
    let (pub_key, project_id) = parse_dsn_url(trimmed).ok_or_else(|| {
        "Invalid DSN format: expected http(s)://<KEY>@<HOST>/<PROJECT_ID>".to_string()
    })?;
    let (scheme, after_scheme) = trimmed
        .split_once("://")
        .ok_or_else(|| "Missing URL scheme".to_string())?;
    if scheme != "http" && scheme != "https" {
        return Err("DSN scheme must be http or https".into());
    }
    let (_, host_part) = after_scheme
        .split_once('@')
        .ok_or_else(|| "Invalid DSN userinfo".to_string())?;
    let host = host_part
        .split('/')
        .next()
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "Invalid DSN host".to_string())?;
    Ok((format!("{scheme}://{host}"), pub_key, project_id))
}

fn escape_html_attr(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn env_is_gitignored(dir: &Path) -> bool {
    let Ok(raw) = fs::read_to_string(dir.join(".gitignore")) else {
        return false;
    };
    raw.lines().any(|line| {
        let t = line.trim();
        matches!(t, ".env" | "/.env" | ".env*" | ".env.*" | "*.env")
    })
}

fn upsert_env_file(
    path: &Path,
    entries: &[(&str, &str)],
    dry_run: bool,
    force: bool,
    secret_mode: bool,
) -> Result<bool, String> {
    let existing = if path.exists() {
        fs::read_to_string(path).map_err(|e| format!("Read {}: {e}", path.display()))?
    } else {
        String::new()
    };

    let mut lines: Vec<String> = existing.lines().map(ToString::to_string).collect();
    let mut changed = false;

    for &(key, val) in entries {
        let prefix = format!("{key}=");
        if let Some(pos) = lines.iter().position(|l| l.trim_start().starts_with(&prefix)) {
            if force && lines[pos] != format!("{key}={val}") {
                lines[pos] = format!("{key}={val}");
                changed = true;
            }
        } else {
            lines.push(format!("{key}={val}"));
            changed = true;
        }
    }

    if !changed {
        return Ok(false);
    }
    if dry_run {
        return Ok(true);
    }

    let mut content = lines.join("\n");
    if !content.ends_with('\n') {
        content.push('\n');
    }

    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    if secret_mode {
        opts.mode(0o600);
    } else {
        opts.mode(0o644);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("Write {}: {e}", path.display()))?;
    f.write_all(content.as_bytes())
        .map_err(|e| format!("Write {}: {e}", path.display()))?;
    if secret_mode {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(true)
}

fn write_connector_file(
    path: &Path,
    content: &str,
    dry_run: bool,
    force: bool,
) -> Result<bool, String> {
    if path.exists() && !force {
        return Ok(false);
    }
    if dry_run {
        return Ok(true);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    fs::write(path, content).map_err(|e| format!("Write {}: {e}", path.display()))?;
    Ok(true)
}

fn inject_html_script_tag(
    html_path: &Path,
    origin: &str,
    dsn: &str,
    dry_run: bool,
) -> Result<bool, String> {
    let raw = fs::read_to_string(html_path)
        .map_err(|e| format!("Read {}: {e}", html_path.display()))?;
    if raw.contains("<!-- bugfinder:auto -->") || raw.contains("bugfinder-mini.js") {
        return Ok(false);
    }
    let script_tag = format!(
        "  <!-- bugfinder:auto -->\n  <script src=\"{}/sdk/bugfinder-mini.js\" data-dsn=\"{}\" crossorigin=\"anonymous\" async></script>\n",
        escape_html_attr(origin),
        escape_html_attr(dsn),
    );
    let lower = raw.to_ascii_lowercase();
    let updated = if let Some(idx) = lower.find("</head>") {
        format!("{}{}{}", &raw[..idx], script_tag, &raw[idx..])
    } else if let Some(idx) = lower.find("</body>") {
        format!("{}{}{}", &raw[..idx], script_tag, &raw[idx..])
    } else {
        format!("{raw}\n{script_tag}")
    };
    if !dry_run {
        fs::write(html_path, updated)
            .map_err(|e| format!("Write {}: {e}", html_path.display()))?;
    }
    Ok(true)
}

pub fn run_init_cli(
    dir: &Path,
    dsn: &str,
    stack_arg: &str,
    sdk_mode: &str,
    dry_run: bool,
    force: bool,
    no_test: bool,
) -> Result<(), String> {
    let (origin, _, project_id) = parse_dsn_parts(dsn)?;
    let use_sentry_sdk = match sdk_mode.trim().to_ascii_lowercase().as_str() {
        "" | "zero-dep" | "mini" => false,
        "sentry" | "glitchtip" => true,
        other => return Err(format!("Unknown --sdk '{other}': expected zero-dep or sentry")),
    };

    let stack = match DetectedStack::from_cli_str(stack_arg)? {
        Some(s) => s,
        None => detect_project_stack(dir),
    };

    println!(
        "[bugfinder init] Project dir: {} | Detected stack: {} | Mode: {}",
        dir.display(),
        stack.as_str(),
        if use_sentry_sdk { "sentry" } else { "zero-dep" }
    );
    if dry_run {
        println!("[bugfinder init] DRY RUN — no files will be modified.");
    }

    let mut env_entries: Vec<(&str, &str)> = vec![("BUGFINDER_DSN", dsn)];
    let mut ex_entries: Vec<(&str, &str)> = vec![(
        "BUGFINDER_DSN",
        "http://<PUBLIC_KEY>@127.0.0.1:8080/1",
    )];

    match stack {
        DetectedStack::Vite => {
            env_entries.push(("VITE_BUGFINDER_DSN", dsn));
            ex_entries.push((
                "VITE_BUGFINDER_DSN",
                "http://<PUBLIC_KEY>@127.0.0.1:8080/1",
            ));
        }
        DetectedStack::NextJs => {
            env_entries.push(("NEXT_PUBLIC_BUGFINDER_DSN", dsn));
            ex_entries.push((
                "NEXT_PUBLIC_BUGFINDER_DSN",
                "http://<PUBLIC_KEY>@127.0.0.1:8080/1",
            ));
        }
        DetectedStack::Laravel => {
            env_entries.push(("GLITCHTIP_ENABLED", "true"));
            env_entries.push(("GLITCHTIP_DSN", dsn));
            env_entries.push(("GLITCHTIP_API_URL", origin.as_str()));
            ex_entries.push(("GLITCHTIP_ENABLED", "true"));
            ex_entries.push(("GLITCHTIP_DSN", "http://<PUBLIC_KEY>@127.0.0.1:8080/1"));
            ex_entries.push(("GLITCHTIP_API_URL", "http://127.0.0.1:8080"));
        }
        _ => {}
    }
    if use_sentry_sdk {
        env_entries.push(("SENTRY_DSN", dsn));
        ex_entries.push(("SENTRY_DSN", "http://<PUBLIC_KEY>@127.0.0.1:8080/1"));
    }

    let env_changed = upsert_env_file(&dir.join(".env"), &env_entries, dry_run, force, true)?;
    let ex_changed = upsert_env_file(&dir.join(".env.example"), &ex_entries, dry_run, false, false)?;
    println!(
        "  - .env (0600): {}",
        if env_changed { "updated" } else { "already configured" }
    );
    println!(
        "  - .env.example: {}",
        if ex_changed { "updated" } else { "already configured" }
    );
    if dir.join(".git").exists() && !env_is_gitignored(dir) {
        eprintln!(
            "  [WARNING] .env is not listed in .gitignore — add '.env' before running git add!"
        );
    }

    match stack {
        DetectedStack::WebHtml => {
            let candidate = if dir.join("public").join("index.html").is_file() {
                dir.join("public").join("index.html")
            } else {
                dir.join("index.html")
            };
            if candidate.is_file() {
                let injected = inject_html_script_tag(&candidate, &origin, dsn, dry_run)?;
                println!(
                    "  - {}: {}",
                    candidate.display(),
                    if injected {
                        "injected 1-tag <script data-dsn>"
                    } else {
                        "already has Bug-Finder script tag"
                    }
                );
            } else {
                println!(
                    "  Add this 1 tag inside <head>:\n  <script src=\"{}/sdk/bugfinder-mini.js\" data-dsn=\"{}\" crossorigin=\"anonymous\" async></script>",
                    origin, dsn
                );
            }
        }
        DetectedStack::Node | DetectedStack::NextJs | DetectedStack::Vite => {
            if stack == DetectedStack::Vite && dir.join("index.html").is_file() {
                let injected =
                    inject_html_script_tag(&dir.join("index.html"), &origin, dsn, dry_run)?;
                println!(
                    "  - index.html: {}",
                    if injected {
                        "injected browser auto-init <script>"
                    } else {
                        "already configured"
                    }
                );
            }
            let (fname, body, hint) = if use_sentry_sdk {
                (
                    "bugfinder-sentry.mjs",
                    "import * as Sentry from \"@sentry/node\";\n\nif (process.env.SENTRY_DSN || process.env.BUGFINDER_DSN) {\n  Sentry.init({\n    dsn: process.env.SENTRY_DSN || process.env.BUGFINDER_DSN,\n    environment: process.env.NODE_ENV || \"production\",\n    enableLogs: true,\n  });\n}\nexport { Sentry };\n".to_string(),
                    "Import `./bugfinder-sentry.mjs` at the top of your entry file.",
                )
            } else {
                (
                    "bugfinder.mjs",
                    zero_dep_node_snippet(),
                    "Import `./bugfinder.mjs` once in your entry file (0 npm dependencies).",
                )
            };
            let wrote = write_connector_file(&dir.join(fname), &body, dry_run, force)?;
            println!(
                "  - {}: {} ({hint})",
                fname,
                if wrote { "created" } else { "kept existing (use --force to overwrite)" }
            );
        }
        DetectedStack::Python
        | DetectedStack::FastApi
        | DetectedStack::Django
        | DetectedStack::Flask => {
            let (fname, body, hint) = if use_sentry_sdk {
                (
                    "bugfinder_sentry.py",
                    "import os\nimport sentry_sdk\n\ndsn = os.getenv(\"SENTRY_DSN\") or os.getenv(\"BUGFINDER_DSN\")\nif dsn:\n    sentry_sdk.init(dsn=dsn, environment=os.getenv(\"ENV\", \"production\"))\n".to_string(),
                    "Import `bugfinder_sentry` at startup.",
                )
            } else {
                (
                    "bugfinder_client.py",
                    zero_dep_python_snippet(),
                    "Add `import bugfinder_client` at startup (0 pip dependencies).",
                )
            };
            let wrote = write_connector_file(&dir.join(fname), &body, dry_run, force)?;
            println!(
                "  - {}: {} ({hint})",
                fname,
                if wrote { "created" } else { "kept existing (use --force to overwrite)" }
            );
        }
        DetectedStack::Laravel | DetectedStack::Php => {
            if use_sentry_sdk {
                println!(
                    "  Laravel/Sentry `.env` ready. Point your SDK or GlitchTipClient to `GLITCHTIP_DSN` (project #{project_id})."
                );
            } else {
                let wrote = write_connector_file(
                    &dir.join("bugfinder.php"),
                    zero_dep_php_snippet(),
                    dry_run,
                    force,
                )?;
                println!(
                    "  - bugfinder.php: {} (require_once __DIR__ . '/bugfinder.php';)",
                    if wrote { "created" } else { "kept existing" }
                );
            }
        }
        DetectedStack::Go => {
            let wrote = write_connector_file(
                &dir.join("bugfinder_client.go"),
                zero_dep_go_snippet(),
                dry_run,
                force,
            )?;
            println!(
                "  - bugfinder_client.go: {} (stdlib net/http, call BugFinderCapture(err))",
                if wrote { "created" } else { "kept existing" }
            );
        }
        DetectedStack::Rust => {
            let cargo_txt = fs::read_to_string(dir.join("Cargo.toml")).unwrap_or_default();
            let is_workspace_root = cargo_txt.contains("[workspace]") && !dir.join("src").is_dir();
            if is_workspace_root {
                println!(
                    "  - Rust workspace detected (skipping orphan root src/bugfinder_hook.rs)."
                );
                println!(
                    "    Use `bugfinder wrap --dsn \"{dsn}\" -- <your-server-binary>` to capture backend crashes & stderr."
                );
                if dir.join("web").join("index.html").is_file() {
                    println!(
                        "    Frontend SPA detected at web/index.html — add `<script src=\"{origin}/sdk/bugfinder-mini.js\" data-dsn=\"{dsn}\" crossorigin=\"anonymous\" async></script>` (ensure CSP connect-src allows {origin})."
                    );
                }
            } else {
                let wrote = write_connector_file(
                    &dir.join("src").join("bugfinder_hook.rs"),
                    zero_dep_rust_snippet(),
                    dry_run,
                    force,
                )?;
                println!(
                    "  - src/bugfinder_hook.rs: {}",
                    if wrote { "created" } else { "kept existing" }
                );
            }
        }
    }

    if !dry_run && !no_test {
        match run_synthetic_test(dsn, false) {
            Ok(()) => {
                println!("[bugfinder init] Connectivity verified! Synthetic event accepted by {origin}/api/{project_id}/envelope/");
            }
            Err(e) => {
                eprintln!("[bugfinder init] Warning: synthetic check could not reach server ({e}). Config files were written.");
            }
        }
    }
    Ok(())
}

fn zero_dep_node_snippet() -> String {
    r#"// Zero-dependency Bug-Finder connector (Node 18+ / ESM)
const RAW_DSN = process.env.BUGFINDER_DSN || "";

function parseDsn(raw) {
  try {
    const u = new URL(raw);
    const key = decodeURIComponent(u.username || "");
    const pid = u.pathname.replace(/^\/+|\/+$/g, "").split("/").pop();
    if (!key || !pid) return null;
    return {
      endpoint: `${u.protocol}//${u.host}/api/${encodeURIComponent(pid)}/envelope/?sentry_key=${encodeURIComponent(key)}`,
      raw,
    };
  } catch {
    return null;
  }
}

const TARGET = parseDsn(RAW_DSN);

export function captureException(err, extra = {}) {
  if (!TARGET || typeof fetch !== "function") return;
  const e = err instanceof Error ? err : new Error(String(err || "Unknown error"));
  const eid = (crypto.randomUUID ? crypto.randomUUID().replace(/-/g, "") : String(Date.now()));
  const frames = String(e.stack || "")
    .split("\n")
    .slice(1, 25)
    .map((line) => ({ filename: line.trim().slice(0, 200), in_app: !line.includes("node_modules") }))
    .reverse();
  const body =
    JSON.stringify({ event_id: eid, sent_at: new Date().toISOString(), dsn: TARGET.raw }) + "\n" +
    JSON.stringify({ type: "event" }) + "\n" +
    JSON.stringify({
      event_id: eid,
      timestamp: Date.now() / 1000,
      platform: "node",
      level: "error",
      environment: process.env.NODE_ENV || "production",
      extra,
      exception: { values: [{ type: e.name || "Error", value: e.message || String(e), stacktrace: { frames } }] },
    }) + "\n";
  fetch(TARGET.endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-sentry-envelope" },
    body,
  }).catch(() => {});
}

if (TARGET && typeof process !== "undefined" && !globalThis.__bfHooked) {
  globalThis.__bfHooked = true;
  process.on("uncaughtException", (err) => captureException(err, { handler: "uncaughtException" }));
  process.on("unhandledRejection", (reason) => captureException(reason, { handler: "unhandledRejection" }));
}
"#
    .to_string()
}

fn zero_dep_python_snippet() -> String {
    r#""""Zero-dependency Bug-Finder connector using Python stdlib urllib."""
import json
import os
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request
import uuid


def _parse_dsn(raw: str):
    try:
        u = urllib.parse.urlparse(raw.strip())
        pid = u.path.strip("/").split("/")[-1]
        if not u.username or not u.netloc or not pid:
            return None
        base = f"{u.scheme}://{u.hostname}" + (f":{u.port}" if u.port else "")
        return f"{base}/api/{pid}/envelope/?sentry_key={urllib.parse.quote(u.username)}", raw
    except Exception:
        return None


_TARGET = _parse_dsn(os.getenv("BUGFINDER_DSN", ""))


def capture_exception(exc_or_type, exc=None, tb=None) -> None:
    if not _TARGET:
        return
    if exc is None and isinstance(exc_or_type, BaseException):
        exc = exc_or_type
        exc_type = type(exc)
        tb = exc.__traceback__
    else:
        exc_type = exc_or_type if isinstance(exc_or_type, type) else type(exc)
    eid = uuid.uuid4().hex
    frames = []
    if tb:
        for fr in traceback.extract_tb(tb)[-25:]:
            frames.append({
                "filename": fr.filename,
                "function": fr.name,
                "lineno": fr.lineno,
                "in_app": "site-packages" not in fr.filename,
            })
    body = (
        json.dumps({"event_id": eid, "dsn": _TARGET[1]}) + "\n"
        + json.dumps({"type": "event"}) + "\n"
        + json.dumps({
            "event_id": eid,
            "timestamp": time.time(),
            "platform": "python",
            "level": "error",
            "environment": os.getenv("ENV", "production"),
            "exception": {
                "values": [{
                    "type": getattr(exc_type, "__name__", "Error"),
                    "value": str(exc or exc_or_type),
                    "stacktrace": {"frames": frames},
                }]
            },
        }) + "\n"
    ).encode("utf-8")
    req = urllib.request.Request(
        _TARGET[0],
        data=body,
        headers={"Content-Type": "application/x-sentry-envelope"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=2.0).close()
    except Exception:
        pass


_ORIG_HOOK = sys.excepthook
_ORIG_THOOK = getattr(threading, "excepthook", None)


def _bf_excepthook(t, v, tb):
    capture_exception(t, v, tb)
    if _ORIG_HOOK:
        _ORIG_HOOK(t, v, tb)


def _bf_thread_hook(args):
    capture_exception(args.exc_type, args.exc_value, args.exc_traceback)
    if _ORIG_THOOK:
        _ORIG_THOOK(args)


if _TARGET:
    sys.excepthook = _bf_excepthook
    if _ORIG_THOOK is not None:
        threading.excepthook = _bf_thread_hook
"#
    .to_string()
}

fn zero_dep_php_snippet() -> &'static str {
    r#"<?php
// Zero-dependency Bug-Finder connector for PHP
(function (): void {
    $dsn = getenv('BUGFINDER_DSN') ?: ($_ENV['BUGFINDER_DSN'] ?? '');
    if ($dsn === '') {
        return;
    }
    $parts = parse_url($dsn);
    if (!$parts || empty($parts['scheme']) || empty($parts['host']) || empty($parts['user']) || empty($parts['path'])) {
        return;
    }
    $pid = trim((string) basename($parts['path']), '/');
    $port = isset($parts['port']) ? ':' . $parts['port'] : '';
    $endpoint = sprintf('%s://%s%s/api/%s/envelope/?sentry_key=%s', $parts['scheme'], $parts['host'], $port, rawurlencode($pid), rawurlencode($parts['user']));

    $send = function (\Throwable $e) use ($endpoint, $dsn): void {
        $eid = bin2hex(random_bytes(16));
        $frames = array_map(static function (array $f): array {
            return [
                'filename' => $f['file'] ?? '(internal)',
                'function' => $f['function'] ?? '',
                'lineno' => $f['line'] ?? 0,
                'in_app' => strpos($f['file'] ?? '', DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR) === false,
            ];
        }, array_reverse(array_slice($e->getTrace(), 0, 25)));
        $payload = json_encode(['event_id' => $eid, 'dsn' => $dsn]) . "\n"
            . json_encode(['type' => 'event']) . "\n"
            . json_encode([
                'event_id' => $eid,
                'timestamp' => microtime(true),
                'platform' => 'php',
                'level' => 'error',
                'environment' => getenv('APP_ENV') ?: 'production',
                'exception' => ['values' => [[
                    'type' => get_class($e),
                    'value' => $e->getMessage(),
                    'stacktrace' => ['frames' => $frames],
                ]]],
            ]) . "\n";
        $ctx = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/x-sentry-envelope\r\n",
                'content' => $payload,
                'timeout' => 2.0,
                'ignore_errors' => true,
            ],
        ]);
        @file_get_contents($endpoint, false, $ctx);
    };

    $prev = set_exception_handler(static function (\Throwable $e) use ($send, &$prev): void {
        $send($e);
        if ($prev) {
            $prev($e);
        }
    });
})();
"#
}

fn zero_dep_go_snippet() -> &'static str {
    r#"package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// BugFinderCapture sends an error event to Bug-Finder using Go stdlib net/http.
func BugFinderCapture(err error) {
	if err == nil {
		return
	}
	raw := strings.TrimSpace(os.Getenv("BUGFINDER_DSN"))
	u, perr := url.Parse(raw)
	if perr != nil || u.User == nil {
		return
	}
	key := u.User.Username()
	pid := strings.Trim(u.Path, "/")
	if key == "" || pid == "" {
		return
	}
	endpoint := fmt.Sprintf("%s://%s/api/%s/envelope/?sentry_key=%s", u.Scheme, u.Host, pid, url.QueryEscape(key))
	eid := fmt.Sprintf("%x", time.Now().UnixNano())
	h, _ := json.Marshal(map[string]any{"event_id": eid, "dsn": raw})
	item, _ := json.Marshal(map[string]any{"type": "event"})
	ev, _ := json.Marshal(map[string]any{
		"event_id":  eid,
		"timestamp": float64(time.Now().UnixMilli()) / 1000.0,
		"platform":  "go",
		"level":     "error",
		"message":   err.Error(),
	})
	var buf bytes.Buffer
	buf.Write(h)
	buf.WriteByte('\n')
	buf.Write(item)
	buf.WriteByte('\n')
	buf.Write(ev)
	buf.WriteByte('\n')
	client := &http.Client{Timeout: 2 * time.Second}
	resp, _ := client.Post(endpoint, "application/x-sentry-envelope", &buf)
	if resp != nil {
		_ = resp.Body.Close()
	}
}
"#
}

fn zero_dep_rust_snippet() -> &'static str {
    "// Tip: run your binary via `bugfinder wrap --dsn $BUGFINDER_DSN -- ./target/release/your-app`\n// for zero-code panic & stderr capture without extra dependencies, or configure the `sentry` crate with env `BUGFINDER_DSN`.\n"
}

pub fn looks_like_real_error_line(raw: &str) -> bool {
    let lower = raw.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }

    const BENIGN_EXCLUSIONS: &[&str] = &[
        "0 error",
        "0 errors",
        "no error",
        "without error",
        "error_count=0",
        "errors=0",
        "error_rate=0",
        "fatal_log_count=0",
        "err=nil",
        "err=<nil>",
        "\"error\":null",
        "\"error\": null",
        "\"errors\":[]",
        "\"errors\": []",
        "error: null",
        "error: none",
        "errorhandler",
        "error_handler",
        "error handler",
        "errorboundary",
        "error_middleware",
    ];
    if BENIGN_EXCLUSIONS.iter().any(|ex| lower.contains(ex)) {
        return false;
    }

    let has_explicit_crash = lower.contains("traceback")
        || lower.contains("panicked at")
        || lower.contains("uncaught")
        || lower.contains("fatal error");
    if !has_explicit_crash
        && (lower.contains("\" 200 ")
            || lower.contains("\" 201 ")
            || lower.contains("\" 204 ")
            || lower.contains("\" 304 ")
            || lower.ends_with(" 200 ok"))
    {
        return false;
    }

    const ERROR_PATTERNS: &[&str] = &[
        "traceback (most recent call last)",
        "panicked at ",
        "fatal error:",
        "php fatal error:",
        "uncaught ",
        "unhandledpromiserejection",
        "unhandled rejection",
        "segmentation fault",
        "out of memory",
        "stack overflow",
        "[error]",
        "[fatal]",
        "[err]",
        "-err]",
        "error trace]:",
        "fatal [",
        "level=error",
        "level=fatal",
        "\"level\":\"error\"",
        "\"level\":\"fatal\"",
        "\"level\": \"error\"",
        "\"level\": \"fatal\"",
        "error:",
        "fatal:",
        "exception:",
        "typeerror:",
        "referenceerror:",
        "syntaxerror:",
        "rangeerror:",
        "keyerror:",
        "valueerror:",
        "attributeerror:",
        "runtimeerror:",
        "zerodivisionerror:",
        "nullpointerexception",
        "sqlstate[",
    ];
    ERROR_PATTERNS.iter().any(|pat| lower.contains(pat))
}

fn is_stack_continuation(line: &str) -> bool {
    let t = line.trim_end();
    if t.is_empty() {
        return false;
    }
    line.starts_with("  ")
        || line.starts_with('\t')
        || t.starts_with("File \"")
        || t.starts_with("at ")
        || t.starts_with("Caused by:")
        || t.starts_with("stack backtrace:")
        || t.starts_with("goroutine ")
        || looks_like_real_error_line(t)
}

enum TelemetryMsg {
    Log {
        ts_sec: f64,
        level: &'static str,
        body: String,
    },
    ErrorEvent {
        title: String,
        level: &'static str,
        stack_lines: Vec<String>,
        breadcrumbs: Vec<String>,
    },
    FlushAndExit,
}

static DEFAULT_SCRUBBER: OnceLock<Scrubber> = OnceLock::new();

pub fn scrub_stream_line(raw: &str) -> String {
    let scrubber =
        DEFAULT_SCRUBBER.get_or_init(|| Scrubber::from_filters(&ProjectFilters::default()));
    let cleaned = strip_ansi_and_bidi(raw);
    let trimmed = cleaned.trim_end_matches(&['\r', '\n'][..]);
    let bounded: String = trimmed.chars().take(2048).collect();
    scrubber.scrub_string(&bounded)
}

fn post_envelope_blocking(agent: &ureq::Agent, endpoint: &str, body: &str) {
    let _ = agent
        .post(endpoint)
        .set("Content-Type", "application/x-sentry-envelope")
        .set("X-BugFinder-Source", "cli-wrap")
        .send_string(body);
}

fn flush_log_batch(
    agent: &ureq::Agent,
    endpoint: &str,
    dsn: &str,
    service: &str,
    env_name: &str,
    buf: &mut Vec<(f64, &'static str, String)>,
) {
    if buf.is_empty() {
        return;
    }
    let items: Vec<Value> = buf
        .drain(..)
        .map(|(ts, lvl, body)| {
            json!({
                "timestamp": ts,
                "level": lvl,
                "severity_number": if lvl == "error" { 17 } else { 9 },
                "body": body,
                "attributes": {
                    "service.name": { "value": service, "type": "string" },
                    "sentry.environment": { "value": env_name, "type": "string" }
                }
            })
        })
        .collect();
    let envelope = format!(
        "{}\n{}\n{}\n",
        json!({ "sent_at": chrono::Utc::now().to_rfc3339(), "dsn": dsn, "sdk": { "name": "bugfinder.wrap", "version": env!("CARGO_PKG_VERSION") } }),
        json!({ "type": "log", "item_count": items.len(), "content_type": "application/vnd.sentry.items.log+json" }),
        json!({ "version": 2, "items": items })
    );
    post_envelope_blocking(agent, endpoint, &envelope);
}

fn flush_error_event(
    agent: &ureq::Agent,
    endpoint: &str,
    dsn: &str,
    service: &str,
    env_name: &str,
    title: &str,
    level: &'static str,
    stack_lines: &[String],
    breadcrumbs: &[String],
) {
    let eid = uuid::Uuid::new_v4().simple().to_string();
    let crumbs: Vec<Value> = breadcrumbs
        .iter()
        .map(|b| json!({ "category": "stderr", "level": "info", "message": b }))
        .collect();
    let frames: Vec<Value> = stack_lines
        .iter()
        .take(30)
        .map(|l| json!({ "filename": l, "in_app": true }))
        .collect();
    let payload = json!({
        "event_id": eid,
        "timestamp": chrono::Utc::now().timestamp() as f64,
        "platform": "other",
        "level": level,
        "environment": env_name,
        "culprit": service,
        "breadcrumbs": { "values": crumbs },
        "exception": {
            "values": [{
                "type": service,
                "value": title,
                "stacktrace": { "frames": frames }
            }]
        }
    });
    let envelope = format!(
        "{}\n{}\n{}\n",
        json!({ "event_id": eid, "sent_at": chrono::Utc::now().to_rfc3339(), "dsn": dsn, "sdk": { "name": "bugfinder.wrap", "version": env!("CARGO_PKG_VERSION") } }),
        json!({ "type": "event", "content_type": "application/json" }),
        payload
    );
    post_envelope_blocking(agent, endpoint, &envelope);
}

fn sender_worker(
    rx: Receiver<TelemetryMsg>,
    endpoint: String,
    dsn: String,
    service: String,
    env_name: String,
) {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(2))
        .timeout(Duration::from_secs(3))
        .build();
    let mut log_buf: Vec<(f64, &'static str, String)> = Vec::with_capacity(25);
    let mut last_flush = Instant::now();

    loop {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(TelemetryMsg::Log { ts_sec, level, body }) => {
                log_buf.push((ts_sec, level, body));
                if log_buf.len() >= 25 || last_flush.elapsed() >= Duration::from_secs(1) {
                    flush_log_batch(&agent, &endpoint, &dsn, &service, &env_name, &mut log_buf);
                    last_flush = Instant::now();
                }
            }
            Ok(TelemetryMsg::ErrorEvent {
                title,
                level,
                stack_lines,
                breadcrumbs,
            }) => {
                flush_log_batch(&agent, &endpoint, &dsn, &service, &env_name, &mut log_buf);
                last_flush = Instant::now();
                flush_error_event(
                    &agent,
                    &endpoint,
                    &dsn,
                    &service,
                    &env_name,
                    &title,
                    level,
                    &stack_lines,
                    &breadcrumbs,
                );
            }
            Ok(TelemetryMsg::FlushAndExit) => {
                flush_log_batch(&agent, &endpoint, &dsn, &service, &env_name, &mut log_buf);
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if !log_buf.is_empty() && last_flush.elapsed() >= Duration::from_secs(1) {
                    flush_log_batch(&agent, &endpoint, &dsn, &service, &env_name, &mut log_buf);
                    last_flush = Instant::now();
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                flush_log_batch(&agent, &endpoint, &dsn, &service, &env_name, &mut log_buf);
                break;
            }
        }
    }
}

struct StreamAggregator {
    tx: SyncSender<TelemetryMsg>,
    ring: VecDeque<String>,
    pending_err: Option<(String, Vec<String>)>,
    last_sent: HashMap<String, Instant>,
    emitted_error: bool,
}

impl StreamAggregator {
    fn new(tx: SyncSender<TelemetryMsg>) -> Self {
        Self {
            tx,
            ring: VecDeque::with_capacity(64),
            pending_err: None,
            last_sent: HashMap::new(),
            emitted_error: false,
        }
    }

    fn flush_pending_error(&mut self) {
        if let Some((headline, stack)) = self.pending_err.take() {
            let final_title = stack
                .iter()
                .rev()
                .find(|l| {
                    let low = l.to_ascii_lowercase();
                    !l.starts_with("  ")
                        && !l.starts_with('\t')
                        && !low.starts_with("traceback ")
                        && looks_like_real_error_line(l)
                })
                .cloned()
                .unwrap_or(headline);
            let now = Instant::now();
            if self.last_sent.len() > 64 {
                self.last_sent.clear();
            }
            let allow = self
                .last_sent
                .get(&final_title)
                .map(|t| now.duration_since(*t) >= Duration::from_secs(2))
                .unwrap_or(true);
            if allow {
                self.last_sent.insert(final_title.clone(), now);
                self.emitted_error = true;
                let crumbs: Vec<String> = self.ring.iter().cloned().collect();
                let _ = self.tx.try_send(TelemetryMsg::ErrorEvent {
                    title: final_title,
                    level: "error",
                    stack_lines: stack,
                    breadcrumbs: crumbs,
                });
            }
        }
    }

    fn push_line(&mut self, scrubbed: String) {
        if scrubbed.is_empty() {
            return;
        }
        if self.ring.len() >= 64 {
            self.ring.pop_front();
        }
        self.ring.push_back(scrubbed.clone());

        if let Some((_, ref mut stack)) = self.pending_err {
            if stack.len() < 25 && is_stack_continuation(&scrubbed) {
                stack.push(scrubbed.clone());
                let ts_sec = (chrono::Utc::now().timestamp_millis() as f64) / 1000.0;
                let _ = self.tx.try_send(TelemetryMsg::Log {
                    ts_sec,
                    level: "error",
                    body: scrubbed,
                });
                return;
            }
            self.flush_pending_error();
        }

        let is_err = looks_like_real_error_line(&scrubbed);
        let ts_sec = (chrono::Utc::now().timestamp_millis() as f64) / 1000.0;
        let _ = self.tx.try_send(TelemetryMsg::Log {
            ts_sec,
            level: if is_err { "error" } else { "info" },
            body: scrubbed.clone(),
        });

        if is_err {
            self.pending_err = Some((scrubbed.clone(), vec![scrubbed]));
        }
    }
}

fn spawn_stream_pump<R: Read + Send + 'static, W: Write + Send + 'static>(
    reader: R,
    mut mirror: W,
    tx: SyncSender<TelemetryMsg>,
    analyze_errors: bool,
) -> std::thread::JoinHandle<Option<(bool, Vec<String>)>> {
    std::thread::spawn(move || {
        let mut br = BufReader::new(reader);
        let mut agg = if analyze_errors {
            Some(StreamAggregator::new(tx.clone()))
        } else {
            None
        };
        let mut buf = String::new();
        loop {
            buf.clear();
            match br.read_line(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let _ = mirror.write_all(buf.as_bytes());
                    let _ = mirror.flush();
                    let scrubbed = scrub_stream_line(&buf);
                    if let Some(ref mut a) = agg {
                        a.push_line(scrubbed);
                    } else if !scrubbed.is_empty() {
                        let ts_sec = (chrono::Utc::now().timestamp_millis() as f64) / 1000.0;
                        let _ = tx.try_send(TelemetryMsg::Log {
                            ts_sec,
                            level: "info",
                            body: scrubbed,
                        });
                    }
                }
            }
        }
        agg.map(|mut a| {
            a.flush_pending_error();
            (a.emitted_error, a.ring.into_iter().collect())
        })
    })
}

pub fn run_pipe_reader<R: BufRead>(
    mut reader: R,
    dsn: &str,
    service: Option<&str>,
    env_name: &str,
) -> Result<(), String> {
    let (origin, key, pid) = parse_dsn_parts(dsn)?;
    let endpoint = format!(
        "{origin}/api/{pid}/envelope/?sentry_key={}",
        percent_encode_val(&key)
    );
    let svc = service.unwrap_or("pipe").to_string();
    let (tx, rx) = mpsc::sync_channel::<TelemetryMsg>(512);
    let worker_tx_dsn = dsn.to_string();
    let worker_env = env_name.to_string();
    let worker = std::thread::spawn(move || {
        sender_worker(rx, endpoint, worker_tx_dsn, svc, worker_env);
    });

    let mut agg = StreamAggregator::new(tx.clone());
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let scrubbed = scrub_stream_line(&line);
                agg.push_line(scrubbed);
            }
            Err(e) => return Err(format!("Failed reading stdin: {e}")),
        }
    }
    agg.flush_pending_error();
    let _ = tx.send(TelemetryMsg::FlushAndExit);
    let _ = worker.join();
    Ok(())
}

pub fn run_pipe_cli(dsn: &str, service: Option<&str>, env_name: &str) -> Result<(), String> {
    let stdin = std::io::stdin();
    let locked = stdin.lock();
    run_pipe_reader(locked, dsn, service, env_name)
}

pub fn run_wrap_cli(
    dsn: &str,
    service: Option<&str>,
    env_name: &str,
    capture_stdout: bool,
    heartbeat_url: Option<&str>,
    cmd: &[String],
) -> Result<i32, String> {
    if cmd.is_empty() {
        return Err("wrap requires a command after '--'".into());
    }
    let (origin, key, pid) = parse_dsn_parts(dsn)?;
    let endpoint = format!(
        "{origin}/api/{pid}/envelope/?sentry_key={}",
        percent_encode_val(&key)
    );
    let svc = service
        .map(ToString::to_string)
        .unwrap_or_else(|| {
            Path::new(&cmd[0])
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("wrapped-app")
                .to_string()
        });

    let mut command = Command::new(&cmd[0]);
    if cmd.len() > 1 {
        command.args(&cmd[1..]);
    }
    command.stderr(Stdio::piped());
    if capture_stdout {
        command.stdout(Stdio::piped());
    } else {
        command.stdout(Stdio::inherit());
    }
    command.stdin(Stdio::inherit());

    let mut child = command
        .spawn()
        .map_err(|e| format!("Failed spawning '{}': {e}", cmd[0]))?;

    let (tx, rx) = mpsc::sync_channel::<TelemetryMsg>(512);
    let w_ep = endpoint;
    let w_dsn = dsn.to_string();
    let w_svc = svc.clone();
    let w_env = env_name.to_string();
    let worker = std::thread::spawn(move || {
        sender_worker(rx, w_ep, w_dsn, w_svc, w_env);
    });

    let stderr_handle = child
        .stderr
        .take()
        .map(|err_pipe| spawn_stream_pump(err_pipe, std::io::stderr(), tx.clone(), true));
    let stdout_handle = if capture_stdout {
        child
            .stdout
            .take()
            .map(|out_pipe| spawn_stream_pump(out_pipe, std::io::stdout(), tx.clone(), false))
    } else {
        None
    };

    let status = child
        .wait()
        .map_err(|e| format!("Failed waiting for child process: {e}"))?;
    let exit_code = status.code().unwrap_or(1);

    let (emitted_err, ring) = stderr_handle
        .and_then(|h| h.join().ok())
        .flatten()
        .unwrap_or((false, Vec::new()));
    if let Some(h) = stdout_handle {
        let _ = h.join();
    }

    if exit_code != 0 && !emitted_err {
        let _ = tx.try_send(TelemetryMsg::ErrorEvent {
            title: format!("{} exited with non-zero status {exit_code}", svc),
            level: "fatal",
            stack_lines: vec![format!("Process exited with code {exit_code}")],
            breadcrumbs: ring,
        });
    } else if exit_code != 0 {
        let _ = tx.try_send(TelemetryMsg::Log {
            ts_sec: (chrono::Utc::now().timestamp_millis() as f64) / 1000.0,
            level: "error",
            body: format!("{svc} exited with status {exit_code}"),
        });
    }

    let _ = tx.send(TelemetryMsg::FlushAndExit);
    let _ = worker.join();

    if exit_code == 0 {
        if let Some(hb) = heartbeat_url.map(str::trim).filter(|u| !u.is_empty()) {
            if hb.starts_with("http://") || hb.starts_with("https://") {
                let hb_agent = ureq::AgentBuilder::new()
                    .timeout_connect(Duration::from_secs(2))
                    .timeout(Duration::from_secs(3))
                    .build();
                let mut req = hb_agent
                    .post(hb)
                    .set("Content-Type", "application/json");
                if let Ok(tok) = std::env::var("BUGFINDER_TOKEN") {
                    let t = tok.trim();
                    if !t.is_empty() {
                        req = req.set("Authorization", &format!("Bearer {t}"));
                    }
                }
                let _ = req.send_string(
                    &json!({
                        "status": "up",
                        "exit_code": 0
                    })
                    .to_string(),
                );
            }
        }
    }

    Ok(exit_code)
}

fn percent_encode_val(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn stack_detection_handles_monorepo_root_and_frameworks() {
        let d_rust = TempDir::new().unwrap();
        fs::write(d_rust.path().join("Cargo.toml"), "[package]\nname=\"x\"\n").unwrap();
        fs::create_dir_all(d_rust.path().join("ui")).unwrap();
        fs::write(d_rust.path().join("ui/package.json"), "{}").unwrap();
        assert_eq!(detect_project_stack(d_rust.path()), DetectedStack::Rust);

        let d_next = TempDir::new().unwrap();
        fs::write(
            d_next.path().join("package.json"),
            r#"{"dependencies":{"next":"15.0.0"}}"#,
        )
        .unwrap();
        assert_eq!(detect_project_stack(d_next.path()), DetectedStack::NextJs);

        let d_vite = TempDir::new().unwrap();
        fs::write(
            d_vite.path().join("package.json"),
            r#"{"devDependencies":{"vite":"5.4.0"}}"#,
        )
        .unwrap();
        assert_eq!(detect_project_stack(d_vite.path()), DetectedStack::Vite);

        let d_lara = TempDir::new().unwrap();
        fs::write(d_lara.path().join("artisan"), "#!/usr/bin/env php\n").unwrap();
        assert_eq!(detect_project_stack(d_lara.path()), DetectedStack::Laravel);

        let d_fast = TempDir::new().unwrap();
        fs::write(d_fast.path().join("requirements.txt"), "uvicorn\nfastapi==0.115\n").unwrap();
        assert_eq!(detect_project_stack(d_fast.path()), DetectedStack::FastApi);

        let d_go = TempDir::new().unwrap();
        fs::write(d_go.path().join("go.mod"), "module example.com/app\n").unwrap();
        assert_eq!(detect_project_stack(d_go.path()), DetectedStack::Go);

        let d_html = TempDir::new().unwrap();
        fs::write(d_html.path().join("index.html"), "<html><head></head></html>").unwrap();
        assert_eq!(detect_project_stack(d_html.path()), DetectedStack::WebHtml);
    }

    #[test]
    fn init_cli_dry_run_idempotency_permissions_and_html_injection() {
        let d = TempDir::new().unwrap();
        fs::write(
            d.path().join("index.html"),
            "<!doctype html><html><head><title>Test</title></head><body></body></html>",
        )
        .unwrap();
        let dsn = "http://pub_key_abc123@127.0.0.1:8080/1";

        // Dry run creates nothing
        run_init_cli(d.path(), dsn, "web", "zero-dep", true, false, true).unwrap();
        assert!(!d.path().join(".env").exists());
        assert!(!d.path().join(".env.example").exists());

        // Real run injects tag cleanly and writes 0600 .env without secret in .env.example
        run_init_cli(d.path(), dsn, "web", "zero-dep", false, false, true).unwrap();
        let meta = fs::metadata(d.path().join(".env")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let env_txt = fs::read_to_string(d.path().join(".env")).unwrap();
        assert!(env_txt.contains("BUGFINDER_DSN=http://pub_key_abc123@127.0.0.1:8080/1"));
        let ex_txt = fs::read_to_string(d.path().join(".env.example")).unwrap();
        assert!(!ex_txt.contains("pub_key_abc123"), ".env.example must not leak real DSN");

        let html_1 = fs::read_to_string(d.path().join("index.html")).unwrap();
        assert_eq!(html_1.matches("<!-- bugfinder:auto -->").count(), 1);
        assert!(html_1.contains("data-dsn=\"http://pub_key_abc123@127.0.0.1:8080/1\""));

        // Second run is strictly idempotent (zero duplicate script tags or env keys)
        run_init_cli(d.path(), dsn, "web", "zero-dep", false, false, true).unwrap();
        let html_2 = fs::read_to_string(d.path().join("index.html")).unwrap();
        assert_eq!(html_2.matches("<!-- bugfinder:auto -->").count(), 1);
        let env_2 = fs::read_to_string(d.path().join(".env")).unwrap();
        assert_eq!(env_2.matches("BUGFINDER_DSN=").count(), 1);
    }

    #[test]
    fn error_line_detector_avoids_false_positives_and_scrubs_secrets() {
        // Real errors
        assert!(looks_like_real_error_line("Traceback (most recent call last):"));
        assert!(looks_like_real_error_line("RuntimeError: connection dropped"));
        assert!(looks_like_real_error_line("thread 'main' panicked at src/lib.rs:10:5"));
        assert!(looks_like_real_error_line("PHP Fatal error: Call to undefined foo()"));
        assert!(looks_like_real_error_line("[ERROR] failed loading config"));
        assert!(looks_like_real_error_line(r#"{"level":"error","msg":"db down"}"#));
        assert!(looks_like_real_error_line("[DB ERROR TRACE]: PoolTimedOut"));
        assert!(looks_like_real_error_line("[INTERNAL ERROR TRACE]: redis unreachable"));
        assert!(looks_like_real_error_line("FATAL [SEC-CFG-01]: refusing fail-open startup"));
        assert!(looks_like_real_error_line("[GEMINI-SDR-ERR] Model gemini-3.8-flash request error"));
        assert!(looks_like_real_error_line("[WEBCHAT-CRM-TX-ERR] tenant_id=1 err=deadlock"));

        // Exhaustive benign false-positive candidates MUST return false
        for benign in [
            "0 errors found in project",
            "Build finished with 0 error warnings",
            "Completed with no error",
            "Metric: error_count=0 errors=0 error_rate=0",
            "Healthcheck: fatal_log_count=0",
            "go-log: msg=startup err=nil",
            r#"{"status":"ok","error":null,"errors":[]}"#,
            "ErrorHandler initialized successfully",
            "ErrorBoundary mounted cleanly",
            r#"127.0.0.1 - - "GET /api/0/errors 200 12ms""#,
            "worker started listening on port 8080",
            "imob-on listening on http://127.0.0.1:3366",
            "[WEBCHAT-INIT-CHIPS-WARN] tenant_id=1 err=none",
            "[master-audit] ok",
        ] {
            assert!(
                !looks_like_real_error_line(benign),
                "False positive triggered on benign line: {benign}"
            );
        }

        // Local scrubber strips secrets before enqueue
        let scrubbed = scrub_stream_line(
            "\x1b[31mError:\x1b[0m auth failed Authorization: Bearer secret_leak_abc123token and ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
        );
        assert!(!scrubbed.contains("secret_leak_abc123token"));
        assert!(!scrubbed.contains("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"));
        assert!(!scrubbed.contains('\x1b'));
    }

    #[test]
    fn rust_workspace_init_skips_orphan_root_hook() {
        let d = TempDir::new().unwrap();
        fs::write(
            d.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/app\"]\n",
        )
        .unwrap();
        fs::create_dir_all(d.path().join("web")).unwrap();
        fs::write(d.path().join("web/index.html"), "<html></html>").unwrap();

        let dsn = "http://pub_key_ws@127.0.0.1:8080/1";
        run_init_cli(d.path(), dsn, "auto", "zero-dep", false, false, true).unwrap();
        assert!(
            !d.path().join("src/bugfinder_hook.rs").exists(),
            "workspace root without src/ must not get an orphan src/bugfinder_hook.rs"
        );
        assert!(d.path().join(".env").is_file());
    }
}
