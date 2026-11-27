#![recursion_limit = "256"]

use bugfinder::ai_blueprint::{
    detect_stack_from_dir, render_project_ai_blueprint, ProjectBlueprintParams,
};
use bugfinder::cli_check::{run_check_cli, CheckOptions};
use bugfinder::cli_integrate::{
    run_init_cli, run_pipe_cli, run_sourcemaps_upload_cli, run_wrap_cli,
};
use bugfinder::config::{parse_cli_args, AppConfig, CliCommand};
use bugfinder::domain::envelope::parse_dsn_url;
use bugfinder::http::router::build_router;
use bugfinder::lint::run_lint_cli;
use bugfinder::mcp::{run_mcp_stdio, run_synthetic_test, run_tail_cli};
use bugfinder::runtime::{
    build_compact_tokio_runtime, init_low_ram_allocator, probe_existing_instance, run_healthcheck,
    spawn_desktop_window, wait_for_desktop_browser,
};
use bugfinder::security::auth::generate_app_key_hex;
use bugfinder::selfcheck::{install_panic_hook, run_doctor_cli};
use bugfinder::storage::batch_writer::spawn_alert_jobs;
use bugfinder::storage::postgres::PostgresStorage;
use bugfinder::storage::sqlite::SqliteStorage;
use bugfinder::{build_app_state, build_storage};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

fn main() -> ExitCode {
    init_low_ram_allocator();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args: Vec<String> = std::env::args().collect();
    let parsed = match parse_cli_args(&args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("bugfinder argument error: {e}");
            return ExitCode::from(2);
        }
    };

    match parsed.command {
        CliCommand::Help => {
            println!(
                "Bug-Finder v{}\n\n\
                 USAGE:\n  \
                   bugfinder [--headless | --app] [--bind ADDR] [--data DIR] [--db URL]\n  \
                   bugfinder ai-prompt --dsn DSN [--app-url URL] [--stack auto|web|node|rust|python|laravel|go] [--dir PATH]\n  \
                   bugfinder check [--url URL] [--dsn DSN] [--app-url APP_URL] [--org SLUG] [--project SLUG] [--token TOK] [--json]\n  \
                   bugfinder lint [--dir PATH]\n  \
                   bugfinder keygen\n  \
                   bugfinder init --dsn DSN [--dir PATH] [--stack auto|web|node|next|vite|python|laravel|go|rust] [--sdk zero-dep|sentry]\n  \
                   bugfinder wrap --dsn DSN [--service NAME] [--heartbeat-url URL] -- CMD...\n  \
                   bugfinder pipe --dsn DSN [--service NAME]\n  \
                   bugfinder sourcemaps upload --url URL --org SLUG --project SLUG --release VER --token TOK --dir PATH [--delete-after-upload]\n  \
                   bugfinder migrate [--data DIR] [--db URL]\n  \
                   bugfinder backup --out FILE [--data DIR]\n  \
                   bugfinder doctor [--url URL] [--data DIR] [--db URL] [--json]\n  \
                   bugfinder healthcheck [--url http://127.0.0.1:8080/api/health]\n  \
                   bugfinder tail --url URL --org SLUG --token TOKEN [--project ID] [--level LVL] [--query Q]\n  \
                   bugfinder mcp [--org SLUG] [--token TOKEN] [--data DIR] [--db URL]\n  \
                   bugfinder test-event --dsn DSN\n  \
                   bugfinder test-log --dsn DSN\n  \
                   bugfinder --version | --help",
                env!("CARGO_PKG_VERSION")
            );
            ExitCode::SUCCESS
        }
        CliCommand::Version => {
            println!("bugfinder {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        CliCommand::Migrate => {
            let cfg = match AppConfig::from_env_and_overrides(
                None,
                parsed.data_override,
                parsed.db_override,
                false,
            ) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("config error: {e}");
                    return ExitCode::FAILURE;
                }
            };
            if cfg.is_postgres() {
                let rt = match build_compact_tokio_runtime() {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("tokio init error: {e}");
                        return ExitCode::FAILURE;
                    }
                };
                let url = cfg.database_url.as_deref().unwrap_or("").to_string();
                let app_key = cfg.app_key;
                match rt.block_on(async move {
                    PostgresStorage::connect_with_key(&url, true, app_key).await
                }) {
                    Ok(_) => {
                        println!("PostgreSQL schema migrations verified/applied.");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("migrate error: {e}");
                        ExitCode::FAILURE
                    }
                }
            } else {
                match SqliteStorage::open_with_key(&cfg.sqlite_path(), cfg.app_key) {
                    Ok(_) => {
                        println!(
                            "SQLite schema migrations verified/applied: {}",
                            cfg.sqlite_path().display()
                        );
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("migrate error: {e}");
                        ExitCode::FAILURE
                    }
                }
            }
        }
        CliCommand::Backup { out_path } => {
            let cfg = match AppConfig::from_env_and_overrides(
                None,
                parsed.data_override,
                parsed.db_override,
                false,
            ) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("config error: {e}");
                    return ExitCode::FAILURE;
                }
            };
            if cfg.is_postgres() {
                eprintln!("backup subcommand is for SQLite databases; for PostgreSQL use pg_dump.");
                return ExitCode::from(2);
            }
            let src_path = cfg.sqlite_path();
            match SqliteStorage::backup_to_file(&src_path, &out_path) {
                Ok(bytes) => {
                    println!("Backup complete: {bytes} bytes -> {}", out_path.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("backup error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        CliCommand::Doctor { url, json } => {
            let cfg = match AppConfig::from_env_and_overrides(
                None,
                parsed.data_override,
                parsed.db_override,
                false,
            ) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("config error: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let rt = match build_compact_tokio_runtime() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("tokio init error: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let code = rt.block_on(async move { run_doctor_cli(&cfg, url.as_deref(), json).await });
            ExitCode::from(code as u8)
        }
        CliCommand::Healthcheck { url } => ExitCode::from(run_healthcheck(&url) as u8),
        CliCommand::Tail {
            base_url,
            token,
            org,
            project,
            level,
            query,
        } => match run_tail_cli(
            &base_url,
            &token,
            &org,
            project,
            level.as_deref(),
            query.as_deref(),
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("tail error: {e}");
                ExitCode::FAILURE
            }
        },
        CliCommand::TestEvent { dsn } => match run_synthetic_test(&dsn, false) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("test-event error: {e}");
                ExitCode::FAILURE
            }
        },
        CliCommand::TestLog { dsn } => match run_synthetic_test(&dsn, true) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("test-log error: {e}");
                ExitCode::FAILURE
            }
        },
        CliCommand::Init {
            dir,
            dsn,
            stack,
            sdk,
            dry_run,
            force,
            no_test,
        } => match run_init_cli(&dir, &dsn, &stack, &sdk, dry_run, force, no_test) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("init error: {e}");
                ExitCode::FAILURE
            }
        },
        CliCommand::Wrap {
            dsn,
            service,
            env_name,
            capture_stdout,
            heartbeat_url,
            cmd,
        } => match run_wrap_cli(
            &dsn,
            service.as_deref(),
            &env_name,
            capture_stdout,
            heartbeat_url.as_deref(),
            &cmd,
        ) {
            Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
            Err(e) => {
                eprintln!("wrap error: {e}");
                ExitCode::FAILURE
            }
        },
        CliCommand::Pipe {
            dsn,
            service,
            env_name,
        } => match run_pipe_cli(&dsn, service.as_deref(), &env_name) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("pipe error: {e}");
                ExitCode::FAILURE
            }
        },
        CliCommand::SourcemapsUpload {
            base_url,
            org,
            project,
            release,
            token,
            dir,
            delete_after_upload,
        } => match run_sourcemaps_upload_cli(
            &base_url,
            &org,
            &project,
            &release,
            &token,
            &dir,
            delete_after_upload,
        ) {
            Ok(count) => {
                println!("Uploaded {count} SourceMap file(s) for release '{release}'.");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("sourcemaps upload error: {e}");
                ExitCode::FAILURE
            }
        },
        CliCommand::Check {
            url,
            dsn,
            app_url,
            org,
            project,
            token,
            json,
        } => ExitCode::from(run_check_cli(&CheckOptions {
            url,
            dsn,
            app_url,
            org,
            project,
            token,
            json,
        })),
        CliCommand::AiPrompt {
            dsn,
            app_url,
            org,
            project,
            stack,
            dir,
        } => {
            let Some((_, pid)) = parse_dsn_url(&dsn) else {
                eprintln!("Invalid --dsn URL: {dsn}");
                return ExitCode::from(2);
            };
            let base_url = dsn
                .split('/')
                .take(3)
                .collect::<Vec<_>>()
                .join("/")
                .replace(|_| false, "");
            let clean_base = if let Some(scheme_end) = base_url.find("://") {
                let after = &base_url[scheme_end + 3..];
                let host = after.rsplit_once('@').map(|(_, h)| h).unwrap_or(after);
                format!("{}://{host}", &base_url[..scheme_end])
            } else {
                "https://bugs.example.com".to_string()
            };
            let eff_stack = if stack.eq_ignore_ascii_case("auto") {
                detect_stack_from_dir(&dir)
            } else {
                stack.as_str()
            };
            let (mini_sri, shield_sri) = bugfinder::http::router::sdk_sri_hashes();
            let prompt = render_project_ai_blueprint(&ProjectBlueprintParams {
                base_url: &clean_base,
                org_slug: org.as_deref().unwrap_or("default"),
                project_slug: project.as_deref().unwrap_or("app"),
                project_id: pid,
                dsn: &dsn,
                tunnel_slug: None,
                app_url: app_url.as_deref(),
                stack: eff_stack,
                mini_sdk_sri: mini_sri,
                shield_sdk_sri: shield_sri,
            });
            println!("{prompt}");
            ExitCode::SUCCESS
        }
        CliCommand::Lint { dir } => ExitCode::from(run_lint_cli(&dir)),
        CliCommand::Keygen => {
            println!("{}", generate_app_key_hex());
            ExitCode::SUCCESS
        }
        CliCommand::Mcp { org, token } => {
            let cfg = match AppConfig::from_env_and_overrides(
                None,
                parsed.data_override,
                parsed.db_override,
                false,
            ) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("config error: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let rt = match build_compact_tokio_runtime() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("tokio init error: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let res = rt.block_on(async move {
                let storage = build_storage(&cfg).await?;
                run_mcp_stdio(storage, &org, token.as_deref()).await
            });
            match res {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("mcp error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        CliCommand::Serve { desktop_app } => {
            let cfg = match AppConfig::from_env_and_overrides(
                parsed.bind_override,
                parsed.data_override,
                parsed.db_override,
                desktop_app,
            ) {
                Ok(c) => Arc::new(c),
                Err(e) => {
                    eprintln!("config error: {e}");
                    return ExitCode::FAILURE;
                }
            };

            if desktop_app {
                if let Some((_, port_s)) = cfg.bind_addr.rsplit_once(':') {
                    if let Ok(port) = port_s.parse::<u16>() {
                        if port > 0 && probe_existing_instance(port) {
                            let url = format!("http://127.0.0.1:{port}");
                            let _ = spawn_desktop_window(&url, &cfg.data_dir);
                            return ExitCode::SUCCESS;
                        }
                    }
                }
            }

            let rt = match build_compact_tokio_runtime() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("tokio init error: {e}");
                    return ExitCode::FAILURE;
                }
            };

            let code = rt.block_on(async move { run_server(cfg, desktop_app).await });
            ExitCode::from(code)
        }
    }
}

async fn run_server(config: Arc<AppConfig>, desktop_app: bool) -> u8 {
    bugfinder::security::anti_rea::apply_anti_ptrace_if_enabled(config.anti_ptrace);
    install_panic_hook(config.data_dir.clone());
    let storage = match build_storage(&config).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("storage init error: {e}");
            return 1;
        }
    };
    let state = build_app_state(config.clone(), storage.clone());

    // Periodic maintenance task (retention, DB size circuit-breaker, missed heartbeats)
    let maint_stop = Arc::new(tokio::sync::Notify::new());
    let maint_stop_rx = maint_stop.clone();
    let maint_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = maint_stop_rx.notified() => break,
            }
            match maint_state
                .storage
                .run_maintenance(
                    maint_state.config.retention_days,
                    maint_state.config.max_db_mb,
                )
                .await
            {
                Ok(alerts) => {
                    spawn_alert_jobs(
                        &maint_state.config,
                        &maint_state.metrics,
                        &maint_state.self_monitor,
                        alerts,
                    );
                }
                Err(err) => {
                    maint_state
                        .metrics
                        .self_errors_total
                        .fetch_add(1, Ordering::Relaxed);
                    maint_state.self_monitor.record(
                        "maintenance",
                        "error",
                        "storage",
                        "Background maintenance failed",
                        Some(&err),
                    );
                }
            }
        }
    });

    let listener = match TcpListener::bind(&config.bind_addr).await {
        Ok(l) => l,
        Err(err) if desktop_app => {
            eprintln!(
                "Port {} busy ({err}), falling back to ephemeral loopback port",
                config.bind_addr
            );
            match TcpListener::bind("127.0.0.1:0").await {
                Ok(l) => l,
                Err(e2) => {
                    eprintln!("bind error: {e2}");
                    return 1;
                }
            }
        }
        Err(err) => {
            eprintln!("bind error on {}: {err}", config.bind_addr);
            return 1;
        }
    };

    let local_addr = listener
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 8080)));
    let listen_url = format!("http://{local_addr}");
    println!("Bug-Finder listening on {listen_url}");

    let browser_child = if desktop_app {
        spawn_desktop_window(&listen_url, &config.data_dir)
    } else {
        None
    };

    let app = build_router(state.clone());
    let svc = app.into_make_service_with_connect_info::<SocketAddr>();

    let shutdown_tx_sig = state.shutdown_tx.clone();
    let shutdown_fut = async move {
        let ctrl_c = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        #[cfg(unix)]
        let sigterm = async {
            if let Ok(mut s) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                let _ = s.recv().await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        #[cfg(not(unix))]
        let sigterm = std::future::pending::<()>();

        let desktop_exit = async move {
            if let Some(child) = browser_child {
                wait_for_desktop_browser(child).await;
            } else {
                std::future::pending::<()>().await;
            }
        };

        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm => {}
            _ = desktop_exit => {}
        }
        // Immediately terminate active SSE streams so axum::serve drains cleanly before SIGKILL.
        let _ = shutdown_tx_sig.send(true);
    };

    // Pin the server future cleanly so LTO does not bloat worker thread stack
    use std::future::IntoFuture;
    let mut serve_fut = Box::pin(
        axum::serve(listener, svc)
            .with_graceful_shutdown(shutdown_fut)
            .into_future(),
    );
    let mut shutdown_rx = state.shutdown_tx.subscribe();
    let serve_res = tokio::select! {
        res = &mut serve_fut => res,
        _ = async {
            while !*shutdown_rx.borrow() {
                if shutdown_rx.changed().await.is_err() {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        } => {
            Ok(())
        }
    };

    maint_stop.notify_waiters();
    state.batch_writer.shutdown().await;
    state.storage.shutdown_checkpoint().await;

    if let Err(e) = serve_res {
        eprintln!("server error: {e}");
        return 1;
    }
    0
}
