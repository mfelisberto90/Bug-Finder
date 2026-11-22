#![recursion_limit = "256"]

use bugfinder::config::{parse_cli_args, AppConfig, CliCommand};
use bugfinder::http::router::build_router;
use bugfinder::mcp::{run_mcp_stdio, run_synthetic_test, run_tail_cli};
use bugfinder::runtime::{
    build_compact_tokio_runtime, init_low_ram_allocator, probe_existing_instance, run_healthcheck,
    spawn_desktop_window, wait_for_desktop_browser,
};
use bugfinder::selfcheck::{install_panic_hook, run_doctor_cli};
use bugfinder::storage::batch_writer::spawn_alert_jobs;
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
    let maint_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            match maint_state
                .storage
                .run_maintenance(maint_state.config.retention_days, maint_state.config.max_db_mb)
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
            eprintln!("Port {} busy ({err}), falling back to ephemeral loopback port", config.bind_addr);
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

    let local_addr = listener.local_addr().unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 8080)));
    let listen_url = format!("http://{local_addr}");
    println!("Bug-Finder listening on {listen_url}");

    let browser_child = if desktop_app {
        spawn_desktop_window(&listen_url, &config.data_dir)
    } else {
        None
    };

    let app = build_router(state.clone());
    let svc = app.into_make_service_with_connect_info::<SocketAddr>();

    let shutdown_state = state.clone();
    let shutdown_fut = async move {
        let ctrl_c = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        #[cfg(unix)]
        let sigterm = async {
            if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
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
        shutdown_state.batch_writer.shutdown().await;
    };

    // Pin the server future cleanly so LTO does not bloat worker thread stack
    use std::future::IntoFuture;
    if let Err(e) = Box::pin(
        axum::serve(listener, svc)
            .with_graceful_shutdown(shutdown_fut)
            .into_future(),
    )
    .await
    {
        eprintln!("server error: {e}");
        return 1;
    }
    0
}
