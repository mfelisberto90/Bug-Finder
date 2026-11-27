use crate::domain::envelope::parse_dsn_url;
use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckState {
    Pass,
    Warn,
    Fail,
    Skip,
}

impl CheckState {
    fn tag(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ShellCheckItem {
    pub id: &'static str,
    pub title: &'static str,
    pub status: CheckState,
    pub latency_ms: u64,
    pub detail: String,
    pub fix: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShellCheckReport {
    pub ok: bool,
    pub server_url: String,
    pub app_url: Option<String>,
    pub pass_count: usize,
    pub warn_count: usize,
    pub fail_count: usize,
    pub skip_count: usize,
    pub checks: Vec<ShellCheckItem>,
}

pub struct CheckOptions {
    pub url: Option<String>,
    pub dsn: Option<String>,
    pub app_url: Option<String>,
    pub org: Option<String>,
    pub project: Option<String>,
    pub token: Option<String>,
    pub json: bool,
}

fn build_check_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(3))
        .timeout(Duration::from_secs(3))
        .redirects(0)
        .build()
}

fn split_origin(raw_url: &str) -> String {
    let trimmed = raw_url.trim().trim_end_matches('/');
    let parts: Vec<&str> = trimmed.split('/').take(3).collect();
    if parts.len() == 3 {
        parts.join("/")
    } else {
        trimmed.to_string()
    }
}

pub fn load_dotenv_hints(dir: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(raw) = fs::read_to_string(dir.join(".env")) else {
        return out;
    };
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let cleaned = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();
        if let Some((k, v)) = cleaned.split_once('=') {
            let key = k.trim().to_string();
            let val = v.trim();
            let unquoted = if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
                || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
            {
                val[1..val.len() - 1].to_string()
            } else {
                val.to_string()
            };
            if !key.is_empty() && !unquoted.is_empty() {
                out.insert(key, unquoted);
            }
        }
    }
    out
}

fn resolve_target(opts: &CheckOptions) -> (String, Option<(String, i64, String)>) {
    let env_map = load_dotenv_hints(Path::new("."));
    let dsn_raw = opts
        .dsn
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            env::var("BUGFINDER_DSN")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .or_else(|| env_map.get("BUGFINDER_DSN").cloned());

    let parsed_dsn = dsn_raw.as_deref().and_then(|d| {
        let (pub_key, pid) = parse_dsn_url(d)?;
        let origin = split_origin(d);
        let scheme_end = origin.find("://")?;
        let after_scheme = &origin[scheme_end + 3..];
        let host_part = after_scheme
            .rsplit_once('@')
            .map(|(_, h)| h)
            .unwrap_or(after_scheme);
        let clean_origin = format!("{}://{host_part}", &origin[..scheme_end]);
        Some((clean_origin, pid, pub_key))
    });

    let base_url = opts
        .url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(split_origin)
        .or_else(|| parsed_dsn.as_ref().map(|(o, _, _)| o.clone()))
        .or_else(|| {
            env::var("BUGFINDER_URL")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(|s| split_origin(&s))
        })
        .or_else(|| {
            env::var("BUGFINDER_PUBLIC_URL")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(|s| split_origin(&s))
        })
        .or_else(|| env_map.get("BUGFINDER_URL").map(|s| split_origin(s)))
        .or_else(|| env_map.get("BUGFINDER_PUBLIC_URL").map(|s| split_origin(s)))
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string());

    (base_url, parsed_dsn)
}

fn http_status_and_body(
    resp: Result<ureq::Response, ureq::Error>,
) -> Result<(u16, HashMap<String, String>, String), String> {
    match resp {
        Ok(r) => {
            let st = r.status();
            let mut hdrs = HashMap::new();
            for name in r.headers_names() {
                if let Some(val) = r.header(&name) {
                    hdrs.insert(name.to_ascii_lowercase(), val.to_string());
                }
            }
            let body = r.into_string().unwrap_or_default();
            Ok((st, hdrs, body))
        }
        Err(ureq::Error::Status(st, r)) => {
            let mut hdrs = HashMap::new();
            for name in r.headers_names() {
                if let Some(val) = r.header(&name) {
                    hdrs.insert(name.to_ascii_lowercase(), val.to_string());
                }
            }
            let body = r.into_string().unwrap_or_default();
            Ok((st, hdrs, body))
        }
        Err(e) => Err(e.to_string()),
    }
}

fn extract_first_script_src(html: &str) -> Option<String> {
    let mut rest = html;
    while let Some(pos) = rest.to_ascii_lowercase().find("<script") {
        let after = &rest[pos..];
        let Some(gt) = after.find('>') else {
            break;
        };
        let tag = &after[..gt];
        let tag_low = tag.to_ascii_lowercase();
        let src_pos_opt = tag_low
            .match_indices("src=")
            .find(|&(idx, _)| idx > 0 && tag_low.as_bytes()[idx - 1].is_ascii_whitespace())
            .map(|(idx, _)| idx);
        if let Some(src_pos) = src_pos_opt {
            let val_start = &tag[src_pos + 4..];
            let quote = val_start.chars().next();
            if let Some(q @ ('"' | '\'')) = quote {
                if let Some(end_q) = val_start[1..].find(q) {
                    let src = &val_start[1..1 + end_q];
                    if src.ends_with(".js") && !src.contains("/_obs/") && !src.contains("bugfinder")
                    {
                        return Some(src.to_string());
                    }
                }
            }
        }
        rest = &after[gt + 1..];
    }
    None
}

fn resolve_relative_url(app_origin: &str, asset_src: &str) -> String {
    if asset_src.starts_with("https://") || asset_src.starts_with("http://") {
        asset_src.to_string()
    } else if asset_src.starts_with('/') {
        format!("{}{}", app_origin.trim_end_matches('/'), asset_src)
    } else {
        format!("{}/{}", app_origin.trim_end_matches('/'), asset_src)
    }
}

/// Runs all 7 deterministic end-to-end checks verifying Bug-Finder server, ingest pipelines,
/// security headers, connected application SDK/CSP/SourceMaps, and Edge WAF blocking.
pub fn run_check_suite(opts: &CheckOptions) -> ShellCheckReport {
    let agent = build_check_agent();
    let (base_url, dsn_info) = resolve_target(opts);
    let app_url = opts
        .app_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('/').to_string());
    let mut checks = Vec::with_capacity(7);

    // 1. Server Health, CSP / Security Headers & /llms.txt AI Spec
    {
        let t0 = Instant::now();
        let health_url = format!("{base_url}/api/health");
        let llms_url = format!("{base_url}/llms.txt");
        let h_res = http_status_and_body(agent.get(&health_url).call());
        let l_res = http_status_and_body(agent.get(&llms_url).call());
        let ms = t0.elapsed().as_millis() as u64;
        match (h_res, l_res) {
            (Ok((st, hdrs, body)), Ok((l_st, l_hdrs, _)))
                if st == 200 && body.contains("\"ok\"") && l_st == 200 =>
            {
                let has_strict_csp = hdrs
                    .get("content-security-policy")
                    .is_some_and(|c| c.contains("style-src-attr 'none'"));
                let llms_clean = !l_hdrs.contains_key("set-cookie");
                if has_strict_csp && llms_clean {
                    checks.push(ShellCheckItem {
                        id: "server_health",
                        title: "Bug-Finder Health, Strict CSP & /llms.txt",
                        status: CheckState::Pass,
                        latency_ms: ms,
                        detail: format!("GET /api/health=200, /llms.txt=200 (0 cookies), strict CSP active ({ms} ms)"),
                        fix: None,
                    });
                } else {
                    checks.push(ShellCheckItem {
                        id: "server_health",
                        title: "Bug-Finder Health, Strict CSP & /llms.txt",
                        status: CheckState::Warn,
                        latency_ms: ms,
                        detail: format!("Server healthy ({ms} ms), CSP style-src-attr={has_strict_csp}, /llms.txt cookie-free={llms_clean}"),
                        fix: Some("Upgrade server binary to Bug-Finder v2.0+".into()),
                    });
                }
            }
            (Ok((st, _, body)), _) => {
                checks.push(ShellCheckItem {
                    id: "server_health",
                    title: "Bug-Finder Health, Strict CSP & /llms.txt",
                    status: CheckState::Fail,
                    latency_ms: ms,
                    detail: format!("Unexpected HTTP {st} from {health_url}: {body}"),
                    fix: Some(format!(
                        "Ensure Bug-Finder is running and reachable at {base_url}"
                    )),
                });
            }
            (Err(e), _) => {
                checks.push(ShellCheckItem {
                    id: "server_health",
                    title: "Bug-Finder Health, Strict CSP & /llms.txt",
                    status: CheckState::Fail,
                    latency_ms: ms,
                    detail: format!("Connection failed to {health_url}: {e}"),
                    fix: Some(format!(
                        "Start Bug-Finder or pass --url / --dsn (checked {base_url})"
                    )),
                });
            }
        }
    }

    // 2. Error & Session Envelope Dry-Probe
    if let Some((_, pid, ref pub_key)) = dsn_info {
        let t0 = Instant::now();
        let url = format!("{base_url}/api/{pid}/envelope/?sentry_key={pub_key}");
        let probe_payload = "{\"sent_at\":\"2026-01-01T00:00:00Z\",\"sdk\":{\"name\":\"bugfinder.check\",\"version\":\"2.0.0\"}}\n\
                             {\"type\":\"event\"}\n\
                             {\"event_id\":\"11111111111111111111111111111111\",\"level\":\"info\",\"message\":\"bugfinder dry-probe\"}\n\
                             {\"type\":\"session\"}\n\
                             {\"init\":true,\"status\":\"ok\",\"errors\":0,\"sid\":\"22222222222222222222222222222222\",\"attrs\":{\"release\":\"check@2.0.0\"}}\n";
        let res = http_status_and_body(
            agent
                .post(&url)
                .set("Content-Type", "text/plain;charset=utf-8")
                .set("X-BugFinder-Check", "dry-probe")
                .send_string(probe_payload),
        );
        let ms = t0.elapsed().as_millis() as u64;
        match res {
            Ok((200, _, body)) if body.contains("dry_probe") => {
                checks.push(ShellCheckItem {
                    id: "error_and_session_ingest",
                    title: "Error & Session Ingest (dry-probe)",
                    status: CheckState::Pass,
                    latency_ms: ms,
                    detail: format!("POST /api/{pid}/envelope/ accepted authenticated dry-probe without creating issue ({ms} ms)"),
                    fix: None,
                });
            }
            Ok((200, _, _)) => {
                checks.push(ShellCheckItem {
                    id: "error_and_session_ingest",
                    title: "Error & Session Ingest (dry-probe)",
                    status: CheckState::Warn,
                    latency_ms: ms,
                    detail:
                        "Endpoint returned 200 without dry_probe confirmation (older v1.x server)"
                            .into(),
                    fix: Some(
                        "Deploy Bug-Finder v2.0 so dry-probe never writes test issues".into(),
                    ),
                });
            }
            Ok((st, _, body)) => {
                checks.push(ShellCheckItem {
                    id: "error_and_session_ingest",
                    title: "Error & Session Ingest (dry-probe)",
                    status: CheckState::Fail,
                    latency_ms: ms,
                    detail: format!("Envelope probe failed HTTP {st}: {body}"),
                    fix: Some("Verify project DSN public key and project_id".into()),
                });
            }
            Err(e) => {
                checks.push(ShellCheckItem {
                    id: "error_and_session_ingest",
                    title: "Error & Session Ingest (dry-probe)",
                    status: CheckState::Fail,
                    latency_ms: ms,
                    detail: format!("Envelope probe error: {e}"),
                    fix: Some("Check network connectivity to Bug-Finder ingest URL".into()),
                });
            }
        }
    } else {
        checks.push(ShellCheckItem {
            id: "error_and_session_ingest",
            title: "Error & Session Ingest (dry-probe)",
            status: CheckState::Skip,
            latency_ms: 0,
            detail: "Skipped (no --dsn or BUGFINDER_DSN provided)".into(),
            fix: Some("Pass --dsn \"https://<KEY>@bugs.example.com/<ID>\" to verify ingest".into()),
        });
    }

    // 3. OTLP Logs & Distributed Trace Ingest Dry-Probe
    if let Some((_, pid, ref pub_key)) = dsn_info {
        let t0 = Instant::now();
        let url = format!("{base_url}/api/{pid}/otlp/v1/logs?sentry_key={pub_key}");
        let otlp_json = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[{\"key\":\"service.name\",\"value\":{\"stringValue\":\"check-shell\"}}]},\"scopeLogs\":[{\"logRecords\":[{\"timeUnixNano\":\"1700000000000000000\",\"severityNumber\":9,\"severityText\":\"INFO\",\"body\":{\"stringValue\":\"bugfinder trace dry-probe\"},\"traceId\":\"0af7651916cd43dd8448eb211c80319c\",\"spanId\":\"b7ad6b7169203331\"}]}]}]}";
        let res = http_status_and_body(
            agent
                .post(&url)
                .set("Content-Type", "application/json")
                .set("X-BugFinder-Check", "dry-probe")
                .send_string(otlp_json),
        );
        let ms = t0.elapsed().as_millis() as u64;
        match res {
            Ok((200, _, body)) if body.contains("dry_probe") => {
                checks.push(ShellCheckItem {
                    id: "logs_and_trace_ingest",
                    title: "OTLP Logs & Trace Correlation (dry-probe)",
                    status: CheckState::Pass,
                    latency_ms: ms,
                    detail: format!("POST /api/{pid}/otlp/v1/logs parsed trace_id log payload cleanly ({ms} ms)"),
                    fix: None,
                });
            }
            Ok((st, _, body)) => {
                checks.push(ShellCheckItem {
                    id: "logs_and_trace_ingest",
                    title: "OTLP Logs & Trace Correlation (dry-probe)",
                    status: CheckState::Fail,
                    latency_ms: ms,
                    detail: format!("OTLP dry-probe failed HTTP {st}: {body}"),
                    fix: Some("Check /api/:id/otlp/v1/logs route and DSN key".into()),
                });
            }
            Err(e) => {
                checks.push(ShellCheckItem {
                    id: "logs_and_trace_ingest",
                    title: "OTLP Logs & Trace Correlation (dry-probe)",
                    status: CheckState::Fail,
                    latency_ms: ms,
                    detail: format!("OTLP dry-probe error: {e}"),
                    fix: Some("Check Bug-Finder reachability".into()),
                });
            }
        }
    } else {
        checks.push(ShellCheckItem {
            id: "logs_and_trace_ingest",
            title: "OTLP Logs & Trace Correlation (dry-probe)",
            status: CheckState::Skip,
            latency_ms: 0,
            detail: "Skipped (no --dsn provided)".into(),
            fix: None,
        });
    }

    // 4. Security Shield & ETag Blocklist Sync
    if let Some((_, pid, ref pub_key)) = dsn_info {
        let t0 = Instant::now();
        let shield_url = format!("{base_url}/api/{pid}/shield/?sentry_key={pub_key}");
        let res = http_status_and_body(
            agent
                .post(&shield_url)
                .set("Content-Type", "application/json")
                .set("X-BugFinder-Check", "dry-probe")
                .send_string("{\"signals\":[\"canary_route_hit\"],\"path\":\"/check-probe\"}"),
        );
        let ms = t0.elapsed().as_millis() as u64;
        match res {
            Ok((200 | 202, _, _)) => {
                let mut detail = format!("POST /api/{pid}/shield/ accepted dry-probe ({ms} ms)");
                let mut status = CheckState::Pass;
                let mut fix = None;
                if let (Some(tok), Some(org), Some(proj)) = (
                    opts.token.as_deref().filter(|s| !s.is_empty()),
                    opts.org.as_deref().filter(|s| !s.is_empty()),
                    opts.project.as_deref().filter(|s| !s.is_empty()),
                ) {
                    let bl_url =
                        format!("{base_url}/api/0/projects/{org}/{proj}/shield/blocklist/");
                    match http_status_and_body(
                        agent
                            .get(&bl_url)
                            .set("Authorization", &format!("Bearer {tok}"))
                            .call(),
                    ) {
                        Ok((200, hdrs, _)) => {
                            let has_etag = hdrs.contains_key("etag");
                            detail.push_str(&format!(" + blocklist ETag={has_etag}"));
                            if !has_etag {
                                status = CheckState::Warn;
                                fix = Some("Ensure blocklist endpoint emits ETag header".into());
                            }
                        }
                        Ok((st, _, _)) => {
                            status = CheckState::Fail;
                            detail.push_str(&format!("; blocklist returned HTTP {st}"));
                            fix = Some("Check --token, --org, and --project permissions".into());
                        }
                        Err(e) => {
                            status = CheckState::Fail;
                            detail.push_str(&format!("; blocklist error: {e}"));
                        }
                    }
                }
                checks.push(ShellCheckItem {
                    id: "shield_and_blocklist",
                    title: "Shield Telemetry & ETag Blocklist",
                    status,
                    latency_ms: ms,
                    detail,
                    fix,
                });
            }
            Ok((403, _, _)) => {
                checks.push(ShellCheckItem {
                    id: "shield_and_blocklist",
                    title: "Shield Telemetry & ETag Blocklist",
                    status: CheckState::Pass,
                    latency_ms: ms,
                    detail: "Shield endpoint enforced strict allowed-domain origin policy (HTTP 403 on unoriginated probe)".into(),
                    fix: None,
                });
            }
            Ok((st, _, body)) => {
                checks.push(ShellCheckItem {
                    id: "shield_and_blocklist",
                    title: "Shield Telemetry & ETag Blocklist",
                    status: CheckState::Fail,
                    latency_ms: ms,
                    detail: format!("Shield probe returned HTTP {st}: {body}"),
                    fix: Some("Ensure Shield is enabled on the project".into()),
                });
            }
            Err(e) => {
                checks.push(ShellCheckItem {
                    id: "shield_and_blocklist",
                    title: "Shield Telemetry & ETag Blocklist",
                    status: CheckState::Fail,
                    latency_ms: ms,
                    detail: format!("Shield probe error: {e}"),
                    fix: None,
                });
            }
        }
    } else {
        checks.push(ShellCheckItem {
            id: "shield_and_blocklist",
            title: "Shield Telemetry & ETag Blocklist",
            status: CheckState::Skip,
            latency_ms: 0,
            detail: "Skipped (no --dsn provided)".into(),
            fix: None,
        });
    }

    // 5-7: Connected Application Live Checks (SDK, Proxy, CSP, SourceMaps, Edge WAF)
    if let Some(ref target_app) = app_url {
        let t0 = Instant::now();
        let app_res = http_status_and_body(agent.get(target_app).call());
        let ms = t0.elapsed().as_millis() as u64;
        let mut first_script: Option<String> = None;

        match app_res {
            Ok((200..=399, hdrs, html)) => {
                let has_sdk = html.contains("/_obs/m.js") || html.contains("bugfinder-mini.js");
                let has_proxy_path = html.contains("/_obs/m.js");
                let has_sri = html.contains("sha384-");
                let has_release = html.contains("data-release=");
                let has_csp = hdrs.contains_key("content-security-policy");
                first_script = extract_first_script_src(&html);

                let mut proxy_ok = true;
                if has_proxy_path {
                    proxy_ok = matches!(
                        http_status_and_body(agent.get(&format!("{target_app}/_obs/m.js")).call()),
                        Ok((200, _, ref body)) if body.contains("BugFinder")
                    );
                }

                if has_sdk && proxy_ok && has_sri && has_release {
                    checks.push(ShellCheckItem {
                        id: "app_sdk_and_csp",
                        title: "App HTML SDK, Stealth Proxy & CSP/SRI",
                        status: if has_csp { CheckState::Pass } else { CheckState::Warn },
                        latency_ms: ms,
                        detail: format!("SDK tag present (stealth={has_proxy_path}, sri={has_sri}, release={has_release}, csp={has_csp})"),
                        fix: if has_csp { None } else { Some("Add Content-Security-Policy header on app responses".into()) },
                    });
                } else {
                    checks.push(ShellCheckItem {
                        id: "app_sdk_and_csp",
                        title: "App HTML SDK, Stealth Proxy & CSP/SRI",
                        status: CheckState::Fail,
                        latency_ms: ms,
                        detail: format!("App HTML check incomplete: sdk={has_sdk}, proxy_200={proxy_ok}, sri={has_sri}, release={has_release}"),
                        fix: Some("Run `bugfinder ai-prompt` and apply Steps 1-2 to your app HTML and proxy".into()),
                    });
                }
            }
            Ok((st, _, _)) => {
                checks.push(ShellCheckItem {
                    id: "app_sdk_and_csp",
                    title: "App HTML SDK, Stealth Proxy & CSP/SRI",
                    status: CheckState::Fail,
                    latency_ms: ms,
                    detail: format!("GET {target_app} returned HTTP {st}"),
                    fix: Some("Verify --app-url points to the running web entrypoint".into()),
                });
            }
            Err(e) => {
                checks.push(ShellCheckItem {
                    id: "app_sdk_and_csp",
                    title: "App HTML SDK, Stealth Proxy & CSP/SRI",
                    status: CheckState::Fail,
                    latency_ms: ms,
                    detail: format!("Failed connecting to {target_app}: {e}"),
                    fix: Some("Start your app or pass the reachable URL via --app-url".into()),
                });
            }
        }

        // 6. SourceMap Zero-Leak Check
        let t1 = Instant::now();
        if let Some(ref script_src) = first_script {
            let js_url = resolve_relative_url(target_app, script_src);
            let map_url = format!("{js_url}.map");
            let js_res = http_status_and_body(agent.get(&js_url).call());
            let map_res = http_status_and_body(agent.get(&map_url).call());
            let sm_ms = t1.elapsed().as_millis() as u64;
            let js_clean =
                matches!(&js_res, Ok((200, _, body)) if !body.contains("sourceMappingURL="));
            let map_hidden =
                !matches!(&map_res, Ok((200, _, body)) if body.contains("\"mappings\""));
            if js_clean && map_hidden {
                checks.push(ShellCheckItem {
                    id: "sourcemap_zero_leak",
                    title: "Private SourceMaps (Zero Public .js.map Leak)",
                    status: CheckState::Pass,
                    latency_ms: sm_ms,
                    detail: format!(
                        "Bundle '{script_src}' has zero sourceMappingURL and .map is blocked/404"
                    ),
                    fix: None,
                });
            } else {
                checks.push(ShellCheckItem {
                    id: "sourcemap_zero_leak",
                    title: "Private SourceMaps (Zero Public .js.map Leak)",
                    status: CheckState::Fail,
                    latency_ms: sm_ms,
                    detail: format!("SourceMap leak risk on '{script_src}': js_clean={js_clean}, map_hidden={map_hidden}"),
                    fix: Some("Build with hidden sourcemaps and use `bugfinder sourcemaps upload --delete-after-upload`".into()),
                });
            }
        } else {
            checks.push(ShellCheckItem {
                id: "sourcemap_zero_leak",
                title: "Private SourceMaps (Zero Public .js.map Leak)",
                status: CheckState::Warn,
                latency_ms: 0,
                detail: "No external app bundle <script src=\"...js\"> discovered on landing page"
                    .into(),
                fix: None,
            });
        }

        // 7. Edge WAF Blocking & /.well-known Exemption on App (ALWAYS run last to avoid self-banning prior checks)
        let t2 = Instant::now();
        let wk_res = http_status_and_body(
            agent
                .get(&format!("{target_app}/.well-known/security.txt"))
                .call(),
        );
        let env_res = http_status_and_body(agent.get(&format!("{target_app}/.env")).call());
        let exploit_res = http_status_and_body(
            agent
                .get(&format!("{target_app}/?__bf_waf_test=../etc/passwd"))
                .call(),
        );
        let waf_ms = t2.elapsed().as_millis() as u64;
        let wk_ok = matches!(wk_res, Ok((st, _, _)) if st != 403 && st != 429 && st < 500);
        let env_blocked =
            matches!(env_res, Ok((403 | 404 | 429, _, body)) if !body.contains("APP_KEY="));
        let exploit_blocked = matches!(exploit_res, Ok((403 | 404 | 429, _, _)));
        if wk_ok && env_blocked && exploit_blocked {
            checks.push(ShellCheckItem {
                id: "app_edge_waf",
                title: "App Edge WAF (/.env & Traversal Blocked, /.well-known Safe)",
                status: CheckState::Pass,
                latency_ms: waf_ms,
                detail: format!(
                    "GET /.env and traversal probe blocked cleanly, /.well-known/ unblocked ({waf_ms} ms)"
                ),
                fix: None,
            });
        } else {
            checks.push(ShellCheckItem {
                id: "app_edge_waf",
                title: "App Edge WAF (/.env & Traversal Blocked, /.well-known Safe)",
                status: CheckState::Fail,
                latency_ms: waf_ms,
                detail: format!(
                    "Edge WAF check failed: well_known_ok={wk_ok}, env_blocked={env_blocked}, exploit_blocked={exploit_blocked}"
                ),
                fix: Some("Add Edge WAF middleware blocking /.env*, traversal probes, and root dotfiles while exempting /.well-known/*".into()),
            });
        }
    } else {
        for (id, title) in [
            ("app_sdk_and_csp", "App HTML SDK, Stealth Proxy & CSP/SRI"),
            (
                "sourcemap_zero_leak",
                "Private SourceMaps (Zero Public .js.map Leak)",
            ),
            (
                "app_edge_waf",
                "App Edge WAF (/.env Blocked, /.well-known Safe)",
            ),
        ] {
            checks.push(ShellCheckItem {
                id,
                title,
                status: CheckState::Skip,
                latency_ms: 0,
                detail: "Skipped (pass --app-url https://app.example.com to verify live app)"
                    .into(),
                fix: None,
            });
        }
    }

    let pass_count = checks
        .iter()
        .filter(|c| c.status == CheckState::Pass)
        .count();
    let warn_count = checks
        .iter()
        .filter(|c| c.status == CheckState::Warn)
        .count();
    let fail_count = checks
        .iter()
        .filter(|c| c.status == CheckState::Fail)
        .count();
    let skip_count = checks
        .iter()
        .filter(|c| c.status == CheckState::Skip)
        .count();

    ShellCheckReport {
        ok: fail_count == 0,
        server_url: base_url,
        app_url,
        pass_count,
        warn_count,
        fail_count,
        skip_count,
        checks,
    }
}

pub fn run_check_cli(opts: &CheckOptions) -> u8 {
    let report = run_check_suite(opts);
    if opts.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into())
        );
        return if report.ok { 0 } else { 1 };
    }

    println!("Bug-Finder End-to-End Check Shell");
    println!("Server: {}", report.server_url);
    if let Some(ref app) = report.app_url {
        println!("App:    {app}");
    }
    println!();
    for item in &report.checks {
        println!(
            "[{:<4}] {:<48} ({:>3} ms)  {}",
            item.status.tag(),
            item.title,
            item.latency_ms,
            item.detail
        );
        if let Some(ref fix) = item.fix {
            println!("       Fix: {fix}");
        }
    }
    println!();
    println!(
        "Summary: {} PASS, {} WARN, {} FAIL, {} SKIP",
        report.pass_count, report.warn_count, report.fail_count, report.skip_count
    );
    if report.ok {
        0
    } else {
        1
    }
}
