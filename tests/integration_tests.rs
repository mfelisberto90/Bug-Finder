use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use bugfinder::config::AppConfig;
use bugfinder::http::router::build_router;
use bugfinder::mcp::handle_mcp_request;
use bugfinder::security::auth::{hash_password, sha256_hex};
use bugfinder::storage::postgres::PostgresStorage;
use bugfinder::storage::sqlite::SqliteStorage;
use bugfinder::storage::StorageBackend;
use bugfinder::{build_app_state, AppState};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::io::Write;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

async fn setup_test_app() -> (TempDir, Arc<AppState>, axum::Router, String, i64) {
    let dir = TempDir::new().unwrap();
    let cfg = Arc::new(
        AppConfig::from_env_and_overrides(
            Some("127.0.0.1:0".into()),
            Some(dir.path().to_path_buf()),
            None,
            false,
        )
        .unwrap(),
    );
    let storage: Arc<dyn StorageBackend> =
        SqliteStorage::open_with_key(&cfg.sqlite_path(), cfg.app_key).unwrap();
    let state = build_app_state(cfg, storage.clone());
    let router = build_router(state.clone());

    let res = send_json(
        &router,
        "POST",
        "/api/auth/setup",
        &[],
        json!({
            "org_name": "Org Alpha",
            "org_slug": "alpha",
            "email": "owner@alpha.test",
            "name": "Alice",
            "password": "StrongPassword123!",
            "project_name": "RoleLane App",
            "project_slug": "rolelane"
        }),
    )
    .await;
    assert_eq!(res.0, StatusCode::CREATED);
    let project_id = res.2["project"]["id"].as_i64().unwrap();
    let dsn_key = res.2["project"]["dsn_public_key"]
        .as_str()
        .unwrap()
        .to_string();
    (dir, state, router, dsn_key, project_id)
}

async fn send_json(
    router: &axum::Router,
    method: &str,
    uri: &str,
    extra_headers: &[(&str, &str)],
    body: Value,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let bytes = serde_json::to_vec(&body).unwrap();
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    let req = builder.body(Body::from(bytes)).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let raw = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
    (status, headers, parsed)
}

async fn send_raw(
    router: &axum::Router,
    method: &str,
    uri: &str,
    extra_headers: &[(&str, &str)],
    body: Vec<u8>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    let req = builder.body(Body::from(body)).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let raw = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, headers, raw)
}

async fn login_cookie_and_csrf(
    router: &axum::Router,
    email: &str,
    password: &str,
) -> (String, String) {
    let (status, headers, body) = send_json(
        router,
        "POST",
        "/api/auth/login",
        &[],
        json!({ "email": email, "password": password }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login failed: {body}");
    let cookie = headers
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let csrf = body["csrf_token"].as_str().unwrap().to_string();
    (cookie, csrf)
}

#[tokio::test]
async fn end_to_end_sentry_envelope_logs_otlp_rolelane_sourcemap_and_mcp() {
    let (_dir, state, router, dsn_key, project_id) = setup_test_app().await;
    let (cookie, csrf) = login_cookie_and_csrf(&router, "owner@alpha.test", "StrongPassword123!").await;

    // 1. Upload JS SourceMap v3 for release 1.2.0
    let sm_bytes = br#"{
        "version": 3,
        "sources": ["src/pay.ts"],
        "names": ["chargeCard"],
        "sourcesContent": ["const x = 1;\nexport function chargeCard() {\n  throw new Error('card_declined');\n}\n"],
        "mappings": "AAEIA"
    }"#.to_vec();
    let (sm_st, _, _) = send_raw(
        &router,
        "POST",
        "/api/0/projects/alpha/rolelane/releases/1.2.0/sourcemaps/?filename=app.min.js.map",
        &[(header::COOKIE.as_str(), &cookie), ("x-csrf-token", &csrf)],
        sm_bytes,
    )
    .await;
    assert_eq!(sm_st, StatusCode::CREATED);

    // 2. Send gzip-compressed multi-item Sentry Envelope (JS error + Structured Log v2 + Transaction + Session)
    let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
    let env_body = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        json!({ "event_id": "11111111111111111111111111111111", "sent_at": "2026-11-21T23:00:00Z", "sdk": { "name": "sentry.javascript.browser", "version": "11.16.0" } }),
        json!({ "type": "event" }),
        json!({
            "event_id": "11111111111111111111111111111111",
            "platform": "javascript",
            "level": "error",
            "environment": "production",
            "release": "1.2.0",
            "contexts": { "trace": { "trace_id": trace_id, "span_id": "00f067aa0ba902b7" } },
            "request": { "url": "https://app.rolelane.co.uk/pay?token=supersecret", "headers": { "Authorization": "Bearer jwt_secret" } },
            "exception": { "values": [{ "type": "PaymentError", "value": "Card 4111-1111-1111-1111 declined", "stacktrace": { "frames": [{ "filename": "https://cdn.rolelane.co.uk/app.min.js", "lineno": 1, "colno": 0, "in_app": true }] } }] }
        }),
        json!({ "type": "log", "item_count": 1, "content_type": "application/vnd.sentry.items.log+json" }),
        json!({
            "version": 2,
            "items": [{
                "timestamp": 1700000000.5,
                "level": "error",
                "severity_number": 17,
                "body": "Gateway failed with sk_live_secret1234567890", // gitleaks:allow
                "trace_id": trace_id,
                "attributes": { "service.name": { "value": "checkout", "type": "string" }, "userPassword": { "value": "123456", "type": "string" } }
            }]
        }),
        json!({ "type": "transaction" }),
        json!({
            "transaction": "POST /checkout",
            "start_timestamp": 1700000000.0,
            "timestamp": 1700000000.25,
            "environment": "production",
            "release": "1.2.0",
            "contexts": { "trace": { "trace_id": trace_id, "span_id": "00f067aa0ba902b7", "op": "http.server", "status": "ok" } },
            "spans": []
        }),
        json!({ "type": "session" }),
        json!({ "init": true, "status": "ok", "errors": 0, "attrs": { "release": "1.2.0", "environment": "production" } })
    );

    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(env_body.as_bytes()).unwrap();
    let gz_bytes = gz.finish().unwrap();
    let sentry_auth = format!("Sentry sentry_version=7, sentry_client=sentry.js/11.16.0, sentry_key={dsn_key}");

    let (ing_st, _, ing_raw) = send_raw(
        &router,
        "POST",
        &format!("/api/{project_id}/envelope/"),
        &[
            ("content-encoding", "gzip"),
            ("x-sentry-auth", &sentry_auth),
            ("origin", "https://app.rolelane.co.uk"),
            ("user-agent", "Mozilla/5.0"),
        ],
        gz_bytes,
    )
    .await;
    assert_eq!(ing_st, StatusCode::OK, "envelope ingest failed: {}", String::from_utf8_lossy(&ing_raw));

    // 3. Send RoleLane GlitchTipClient.php `/store/` event + retry duplicate check
    let store_payload = json!({
        "event_id": "22222222222222222222222222222222",
        "level": "error",
        "message": "RoleLane webhook warning",
        "environment": "production",
        "release": "1.2.0"
    });
    let (st_st, _, st_val) = send_json(
        &router,
        "POST",
        &format!("/api/{project_id}/store/"),
        &[("x-sentry-auth", &sentry_auth)],
        store_payload.clone(),
    )
    .await;
    assert_eq!(st_st, StatusCode::OK);
    assert_eq!(st_val["id"], "22222222222222222222222222222222");

    // 4. Send OTLP/JSON log to `/api/:project_id/otlp/v1/logs`
    let bearer_dsn = format!("Bearer {dsn_key}");
    let (otlp_st, _, _) = send_json(
        &router,
        "POST",
        &format!("/api/{project_id}/otlp/v1/logs"),
        &[("authorization", &bearer_dsn)],
        json!({
            "resourceLogs": [{
                "resource": { "attributes": [{ "key": "service.name", "value": { "stringValue": "otlp-worker" } }] },
                "scopeLogs": [{ "logRecords": [{ "severityNumber": 13, "severityText": "WARN", "body": { "stringValue": "Retrying job" }, "traceId": trace_id }] }]
            }]
        }),
    )
    .await;
    assert_eq!(otlp_st, StatusCode::OK);

    // Deterministically flush micro-batch writer
    state.batch_writer.flush_now().await;

    // 5. RoleLane GlitchTipReadClient compatibility check: X-Hits + stats_v2 + heartbeat_check
    let (iss_st, iss_hdrs, iss_body) = send_raw(
        &router,
        "GET",
        "/api/0/organizations/alpha/issues/?query=is:unresolved&sort=date&statsPeriod=24h&limit=10",
        &[(header::COOKIE.as_str(), &cookie)],
        Vec::new(),
    )
    .await;
    assert_eq!(iss_st, StatusCode::OK);
    assert_eq!(iss_hdrs.get("x-hits").unwrap().to_str().unwrap(), "2");
    let issues_json: Value = serde_json::from_slice(&iss_body).unwrap();
    let first_issue_id = issues_json[0]["id"].as_i64().unwrap();

    // Check latest event was demangled by Source Map v3 AND scrubbed of card PAN / secrets!
    let (ev_st, _, ev_raw) = send_raw(
        &router,
        "GET",
        &format!("/api/0/organizations/alpha/issues/{first_issue_id}/events/latest/"),
        &[(header::COOKIE.as_str(), &cookie)],
        Vec::new(),
    )
    .await;
    assert_eq!(ev_st, StatusCode::OK);
    let ev_text = String::from_utf8(ev_raw).unwrap();
    assert!(!ev_text.contains("4111-1111-1111-1111"), "Luhn card leaked: {ev_text}");
    assert!(!ev_text.contains("supersecret"), "Query secret leaked: {ev_text}");

    // Verify trace correlation (transaction + error + 2 logs share trace_id)
    let (tr_st, _, tr_raw) = send_raw(
        &router,
        "GET",
        &format!("/api/0/organizations/alpha/traces/{trace_id}/"),
        &[(header::COOKIE.as_str(), &cookie)],
        Vec::new(),
    )
    .await;
    assert_eq!(tr_st, StatusCode::OK);
    let tr_json: Value = serde_json::from_slice(&tr_raw).unwrap();
    assert_eq!(tr_json["transactions"].as_array().unwrap().len(), 1);
    assert_eq!(tr_json["logs"].as_array().unwrap().len(), 2);
    let log_dump = serde_json::to_string(&tr_json["logs"]).unwrap();
    assert!(!log_dump.contains("sk_live_secret1234567890")); // gitleaks:allow
    assert!(!log_dump.contains("123456"));

    // Verify stats_v2
    let (sv2_st, _, sv2_raw) = send_raw(
        &router,
        "GET",
        "/api/0/organizations/alpha/stats_v2/?category=error&statsPeriod=24h",
        &[(header::COOKIE.as_str(), &cookie)],
        Vec::new(),
    )
    .await;
    assert_eq!(sv2_st, StatusCode::OK);
    let sv2: Value = serde_json::from_slice(&sv2_raw).unwrap();
    assert!(sv2["groups"][0]["totals"]["sum(quantity)"].as_i64().unwrap() >= 2);

    // Verify Anti-AdBlock Tunnel `/t/:slug`
    let (tun_st, _, tun_body) = send_json(
        &router,
        "POST",
        "/api/0/projects/alpha/rolelane/tunnel/",
        &[(header::COOKIE.as_str(), &cookie), ("x-csrf-token", &csrf)],
        json!({}),
    )
    .await;
    assert_eq!(tun_st, StatusCode::OK);
    let tunnel_slug = tun_body["tunnel_slug"].as_str().unwrap().to_string();
    let tun_env = format!(
        "{}\n{}\n{}\n",
        json!({ "dsn": format!("http://{dsn_key}@127.0.0.1/{project_id}") }),
        json!({ "type": "event" }),
        json!({ "message": "Caught via anti-adblock tunnel", "level": "warning" })
    );
    let (tpost_st, _, _) = send_raw(
        &router,
        "POST",
        &format!("/t/{tunnel_slug}"),
        &[],
        tun_env.into_bytes(),
    )
    .await;
    assert_eq!(tpost_st, StatusCode::OK);

    // Verify MCP stdio read-only tool call
    let ctx = bugfinder::domain::models::TenantCtx::from_session(
        1,
        "alpha".into(),
        1,
        bugfinder::domain::models::UserRole::Admin,
        None,
        None,
    );
    let mcp_res = handle_mcp_request(
        &state.storage,
        &ctx,
        "tools/call",
        &json!({ "name": "get_trace_context", "arguments": { "trace_id": trace_id } }),
    )
    .await
    .unwrap();
    assert!(mcp_res["content"][0]["text"].as_str().unwrap().contains("otlp-worker"));
}

#[tokio::test]
async fn negative_security_suite_401_403_409_413_429_ssrf_csv_and_headers() {
    let (_dir, _state, router, dsn_key, project_id) = setup_test_app().await;
    let (owner_cookie, owner_csrf) = login_cookie_and_csrf(&router, "owner@alpha.test", "StrongPassword123!").await;

    // 1. 401 Unauthenticated
    let (unauth_st, _, _) = send_raw(&router, "GET", "/api/0/organizations/alpha/issues/", &[], Vec::new()).await;
    assert_eq!(unauth_st, StatusCode::UNAUTHORIZED);

    // 2. Invite Viewer & enforce 403 BFLA on mutations
    let (inv_st, _, _) = send_json(
        &router,
        "POST",
        "/api/0/organizations/alpha/members/",
        &[(header::COOKIE.as_str(), &owner_cookie), ("x-csrf-token", &owner_csrf)],
        json!({
            "email": "viewer@alpha.test",
            "name": "Bob Viewer",
            "password": "BobPassPhrase!987",
            "role": "viewer"
        }),
    )
    .await;
    assert_eq!(inv_st, StatusCode::CREATED);
    let (v_cookie, v_csrf) = login_cookie_and_csrf(&router, "viewer@alpha.test", "BobPassPhrase!987").await;

    let (bfla_st, _, _) = send_json(
        &router,
        "POST",
        "/api/0/organizations/alpha/projects/",
        &[(header::COOKIE.as_str(), &v_cookie), ("x-csrf-token", &v_csrf)],
        json!({ "name": "Hacked" }),
    )
    .await;
    assert_eq!(bfla_st, StatusCode::FORBIDDEN);

    // 3. Cross-tenant isolation (Org A user accessing Org B gets 404)
    let (xt_st, _, _) = send_raw(
        &router,
        "GET",
        "/api/0/organizations/beta-other/issues/",
        &[(header::COOKIE.as_str(), &owner_cookie)],
        Vec::new(),
    )
    .await;
    assert_eq!(xt_st, StatusCode::NOT_FOUND);

    // 4. Payload-bound Idempotency 409 mismatch
    let (t1_st, _, _) = send_json(
        &router,
        "POST",
        "/api/0/api-tokens/",
        &[
            (header::COOKIE.as_str(), &owner_cookie),
            ("x-csrf-token", &owner_csrf),
            ("idempotency-key", "idem-1"),
        ],
        json!({ "name": "CI Token", "role": "member" }),
    )
    .await;
    assert_eq!(t1_st, StatusCode::CREATED);

    let (t2_st, t2_hdrs, _) = send_json(
        &router,
        "POST",
        "/api/0/api-tokens/",
        &[
            (header::COOKIE.as_str(), &owner_cookie),
            ("x-csrf-token", &owner_csrf),
            ("idempotency-key", "idem-1"),
        ],
        json!({ "name": "CI Token", "role": "member" }),
    )
    .await;
    assert_eq!(t2_st, StatusCode::CREATED);
    assert_eq!(t2_hdrs.get("x-idempotent-replay").unwrap(), "true");

    let (t3_st, _, _) = send_json(
        &router,
        "POST",
        "/api/0/api-tokens/",
        &[
            (header::COOKIE.as_str(), &owner_cookie),
            ("x-csrf-token", &owner_csrf),
            ("idempotency-key", "idem-1"),
        ],
        json!({ "name": "Different Name", "role": "member" }),
    )
    .await;
    assert_eq!(t3_st, StatusCode::CONFLICT);

    // 5. Zip bomb 413 Payload Too Large
    let bomb = vec![b'A'; 3 * 1024 * 1024];
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    gz.write_all(&bomb).unwrap();
    let gz_bomb = gz.finish().unwrap();
    let sentry_auth = format!("Sentry sentry_version=7, sentry_key={dsn_key}");
    let (bomb_st, _, _) = send_raw(
        &router,
        "POST",
        &format!("/api/{project_id}/envelope/"),
        &[("content-encoding", "gzip"), ("x-sentry-auth", &sentry_auth)],
        gz_bomb,
    )
    .await;
    assert_eq!(bomb_st, StatusCode::PAYLOAD_TOO_LARGE);

    // 6. SSRF rejection on webhook creation
    let (ssrf_st, _, _) = send_json(
        &router,
        "POST",
        "/api/0/organizations/alpha/alerts/",
        &[(header::COOKIE.as_str(), &owner_cookie), ("x-csrf-token", &owner_csrf)],
        json!({
            "project_id": project_id,
            "name": "Metadata Exploit",
            "trigger_type": "new_issue",
            "channel_type": "webhook",
            "target_url": "http://169.254.169.254/latest/meta-data"
        }),
    )
    .await;
    assert_eq!(ssrf_st, StatusCode::BAD_REQUEST);

    // 7. Exponential Lockout persists across wrong attempts -> 429
    for _ in 0..5 {
        let (st, _, _) = send_json(
            &router,
            "POST",
            "/api/auth/login",
            &[],
            json!({ "email": "owner@alpha.test", "password": "WrongPassword!" }),
        )
        .await;
        assert!(st == StatusCode::UNAUTHORIZED || st == StatusCode::TOO_MANY_REQUESTS);
    }
    let (locked_st, _, _) = send_json(
        &router,
        "POST",
        "/api/auth/login",
        &[],
        json!({ "email": "owner@alpha.test", "password": "StrongPassword123!" }),
    )
    .await;
    assert_eq!(locked_st, StatusCode::TOO_MANY_REQUESTS);

    // 8. A+ Security Headers + zero Set-Cookie on /robots.txt & /api/health
    let (rob_st, rob_hdrs, rob_raw) = send_raw(&router, "GET", "/robots.txt", &[], Vec::new()).await;
    assert_eq!(rob_st, StatusCode::OK);
    let rob_txt = String::from_utf8(rob_raw).unwrap();
    assert!(!rob_txt.contains("Disallow:"));
    assert!(rob_hdrs.get(header::SET_COOKIE).is_none());
    let csp = rob_hdrs.get("content-security-policy").unwrap().to_str().unwrap();
    assert!(!csp.contains("unsafe-inline"));
    assert!(csp.contains("nonce-"));
}

#[tokio::test]
#[ignore = "Requires live PostgreSQL 17 container on BUGFINDER_TEST_PG_ADMIN_URL & BUGFINDER_TEST_PG_APP_URL"]
async fn postgres_rls_live_isolation_test() {
    let admin_url = std::env::var("BUGFINDER_TEST_PG_ADMIN_URL")
        .expect("Set BUGFINDER_TEST_PG_ADMIN_URL");
    let app_url = std::env::var("BUGFINDER_TEST_PG_APP_URL")
        .expect("Set BUGFINDER_TEST_PG_APP_URL");

    // 1. Run DDL migrations as migrator/superuser
    let admin_pg = PostgresStorage::connect(&admin_url, true).await.unwrap();
    let bypass: bool = sqlx::query_scalar(
        "SELECT rolbypassrls FROM pg_roles WHERE rolname = 'bugfinder_app'",
    )
    .fetch_one(admin_pg.pool())
    .await
    .unwrap();
    assert!(!bypass, "bugfinder_app MUST NOT have BYPASSRLS");

    // 2. Connect as runtime NOBYPASSRLS role (`bugfinder_app`)
    let app_pg = PostgresStorage::connect(&app_url, false).await.unwrap();
    let app_backend: Arc<dyn StorageBackend> = app_pg.clone();

    let pw = hash_password("PgPassword123!".into()).await.unwrap();
    let dsn1_sha = sha256_hex(b"key_org1");
    let (org1, proj1) = app_backend
        .initial_setup("PG Org 1", "pg-org-1", "a@pg1.test", "A", &pw, "Proj1", "proj1", "key_org1", &dsn1_sha)
        .await
        .unwrap();

    // Fail-closed check: querying issues directly without app.current_tenant_id MUST return 0 rows!
    let leak_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projects")
        .fetch_one(app_pg.pool())
        .await
        .unwrap();
    assert_eq!(leak_count, 0, "FORCE RLS fail-closed failed when GUC unset");

    // Create second org via bootstrap GUC and verify Org 1 cannot see Org 2's project
    let mut tx = app_pg.pool().begin().await.unwrap();
    sqlx::query("SELECT set_config('app.setup_bootstrap', '1', true)")
        .execute(&mut *tx)
        .await
        .unwrap();
    let org2_id: i64 = sqlx::query_scalar(
        "INSERT INTO organizations (slug, name, created_at) VALUES ('pg-org-2', 'PG Org 2', 1) RETURNING id",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
        .bind(org2_id.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO projects (organization_id, slug, name, platform, filters_json, created_at)
         VALUES ($1, 'secret-proj-2', 'Secret Org2', 'rust', '{}'::jsonb, 1)",
    )
    .bind(org2_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // Querying as Org 1 must see ONLY Proj1 (never secret-proj-2)
    let ctx1 = bugfinder::domain::models::TenantCtx::from_session(
        org1.id,
        org1.slug,
        1,
        bugfinder::domain::models::UserRole::Owner,
        None,
        None,
    );
    let visible = app_backend.list_projects(&ctx1).await.unwrap();
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].id, proj1.id);

    // Capability-GUC DSN resolution works without BYPASSRLS
    let resolved = app_backend.resolve_dsn(proj1.id, &dsn1_sha).await.unwrap();
    let proj_auth = resolved.expect("resolve_dsn should return ProjectAuthInfo");

    // Health check & tunnel slug lookup under NOBYPASSRLS
    let health = app_backend.check_health().await.unwrap();
    assert!(health.ok && health.engine == "postgres");
    let slug = app_backend
        .enable_project_tunnel(&ctx1, "proj1", "tun-org1-pg")
        .await
        .unwrap();
    assert_eq!(slug.as_deref(), Some("tun-org1-pg"));
    assert!(app_backend.tunnel_slug_exists("tun-org1-pg").await.unwrap());
    assert!(!app_backend.tunnel_slug_exists("missing-tun").await.unwrap());

    // Alert rule creation + dispatch secret lookup + flush_ingest_batch triggering alert job
    let pg_webhook_secret = "pg_test_hmac_secret_000"; // gitleaks:allow
    let new_rule = app_backend
        .create_alert_rule(
            &ctx1,
            &bugfinder::storage::NewAlertRule {
                project_id: proj1.id,
                name: "PG New Issue Webhook".into(),
                trigger_type: "new_issue".into(),
                threshold_count: 1,
                window_sec: 60,
                cooldown_sec: 60,
                channel_type: "webhook".into(),
                target_url: "https://alerts.example.com/pg-hook".into(),
                webhook_secret: pg_webhook_secret.into(),
                email_to: String::new(),
            },
        )
        .await
        .unwrap();
    let (_, fetched_secret) = app_backend
        .get_alert_rule_for_dispatch(&ctx1, new_rule.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched_secret, pg_webhook_secret);

    let ev_jobs = app_backend
        .flush_ingest_batch(vec![bugfinder::storage::IngestWriteItem::Event {
            auth: proj_auth,
            meta: bugfinder::domain::fingerprint::ComputedIssueMetadata {
                event_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                fingerprint: "pg-fp-1".into(),
                title: "PG ParityPanic".into(),
                culprit: "pg::worker".into(),
                level: "error".into(),
                issue_type: bugfinder::domain::models::IssueType::Error,
                environment: "production".into(),
                release: Some("1.0.0".into()),
                trace_id: None,
                span_id: None,
                user_hash: None,
                tags: serde_json::json!({}),
                search_text: "PG ParityPanic".into(),
            },
            payload_json: br#"{"event_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.to_vec(),
            received_ms: bugfinder::domain::models::now_ms(),
        }])
        .await
        .unwrap();
    assert_eq!(ev_jobs.len(), 1);
    assert_eq!(ev_jobs[0].webhook_secret, pg_webhook_secret);
    assert_eq!(ev_jobs[0].project_slug, "proj1");

    // Overdue uptime monitor + expired session maintenance under NOBYPASSRLS + FORCE RLS
    app_backend
        .create_monitor(&ctx1, proj1.id, "PG Overdue Cron", "pg-mon-uuid", 10)
        .await
        .unwrap();
    app_backend
        .record_heartbeat(&ctx1, "pg-mon-uuid", true, "initial up")
        .await
        .unwrap();
    app_backend
        .create_alert_rule(
            &ctx1,
            &bugfinder::storage::NewAlertRule {
                project_id: proj1.id,
                name: "PG Uptime Down".into(),
                trigger_type: "uptime_down".into(),
                threshold_count: 1,
                window_sec: 60,
                cooldown_sec: 60,
                channel_type: "webhook".into(),
                target_url: "https://alerts.example.com/pg-down".into(),
                webhook_secret: String::new(),
                email_to: String::new(),
            },
        )
        .await
        .unwrap();

    let expired_sha = sha256_hex(b"expired_pg_session_tok");
    let mut mtx = app_pg.pool().begin().await.unwrap();
    sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
        .bind(org1.id.to_string())
        .execute(&mut *mtx)
        .await
        .unwrap();
    sqlx::query("UPDATE uptime_monitors SET last_heartbeat_at = 1 WHERE uuid = 'pg-mon-uuid'")
        .execute(&mut *mtx)
        .await
        .unwrap();
    let owner_uid: i64 = sqlx::query_scalar(
        "SELECT user_id FROM organization_members WHERE organization_id = $1 LIMIT 1",
    )
    .bind(org1.id)
    .fetch_one(&mut *mtx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sessions (token_sha256, user_id, organization_id, csrf_token, expires_at, created_at)
         VALUES ($1, $2, $3, 'csrf_expired', 1, 1)",
    )
    .bind(&expired_sha)
    .bind(owner_uid)
    .bind(org1.id)
    .execute(&mut *mtx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO session_lookup (token_sha256, organization_id, organization_slug, user_id, role, csrf_token, expires_at)
         VALUES ($1, $2, $3, $4, 'owner', 'csrf_expired', 1)",
    )
    .bind(&expired_sha)
    .bind(org1.id)
    .bind(&ctx1.organization_slug)
    .bind(owner_uid)
    .execute(&mut *mtx)
    .await
    .unwrap();
    mtx.commit().await.unwrap();

    assert!(
        app_backend.resolve_session(&expired_sha, 0, 86400).await.unwrap().is_some(),
        "Pre-maintenance expired row should still exist in session_lookup"
    );

    // Anti-REA Shield security_events & shield_quarantine FORCE RLS + NOBYPASSRLS verification
    let future_exp = bugfinder::domain::models::now_ms() / 1000 + 3600;
    let sec_ev = bugfinder::domain::models::NewSecurityEvent {
        organization_id: org1.id,
        project_id: proj1.id,
        project_slug: "proj1".into(),
        signal_type: "canary_route_hit".into(),
        category: "anti_rea".into(),
        severity: "high".into(),
        risk_score: 75,
        source_kind: "backend_verified".into(),
        actor_hmac: "pg_actor_hmac_1".into(),
        session_id: "pg_sess_1".into(),
        path: "/.env".into(),
        details_json: json!({ "test": true }),
        action_taken: "quarantined".into(),
        timestamp_ms: bugfinder::domain::models::now_ms(),
        quarantine: Some(("ip".into(), "pg_actor_hmac_1".into(), future_exp)),
    };
    let (rec_sec, _) = app_backend.record_security_event(&sec_ev).await.unwrap();
    assert_eq!(rec_sec.signal_type, "canary_route_hit");

    let sec_leak: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_events")
        .fetch_one(app_pg.pool())
        .await
        .unwrap();
    assert_eq!(sec_leak, 0, "FORCE RLS fail-closed failed on security_events");
    let q_leak: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM shield_quarantine")
        .fetch_one(app_pg.pool())
        .await
        .unwrap();
    assert_eq!(q_leak, 0, "FORCE RLS fail-closed failed on shield_quarantine");

    let (pg_evs, pg_sum) = app_backend.list_security_events(&ctx1, None, 20).await.unwrap();
    assert_eq!(pg_evs.len(), 1);
    assert_eq!(pg_sum.active_quarantines, 1);
    let pg_qs = app_backend.list_quarantine(&ctx1, None).await.unwrap();
    assert_eq!(pg_qs.len(), 1);
    assert!(app_backend.delete_quarantine(&ctx1, pg_qs[0].id).await.unwrap());
    assert!(app_backend.list_quarantine(&ctx1, None).await.unwrap().is_empty());

    // Insert an already-expired quarantine row to verify run_maintenance purges it cleanly
    let exp_sec = bugfinder::domain::models::NewSecurityEvent {
        organization_id: org1.id,
        project_id: proj1.id,
        project_slug: "proj1".into(),
        signal_type: "sourcemap_harvest".into(),
        category: "anti_rea".into(),
        severity: "medium".into(),
        risk_score: 65,
        source_kind: "backend_verified".into(),
        actor_hmac: "pg_expired_hmac".into(),
        session_id: String::new(),
        path: "/app.js.map".into(),
        details_json: json!({}),
        action_taken: "quarantined".into(),
        timestamp_ms: bugfinder::domain::models::now_ms(),
        quarantine: Some(("ip".into(), "pg_expired_hmac".into(), 1)),
    };
    app_backend.record_security_event(&exp_sec).await.unwrap();

    // Enterprise parity PG 17 FORCE RLS checks: Invitations, JSONB Audit Hash Chain, AEAD secret & Cascade Revocation
    let inv_leak: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM org_invitations")
        .fetch_one(app_pg.pool())
        .await
        .unwrap();
    assert_eq!(inv_leak, 0, "FORCE RLS fail-closed failed on org_invitations");
    let invl_leak: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invitation_lookup")
        .fetch_one(app_pg.pool())
        .await
        .unwrap();
    assert_eq!(invl_leak, 0, "FORCE RLS fail-closed failed on invitation_lookup");

    let pg_inv_tok_sha = sha256_hex(b"pg-live-invite-token-72h");
    let now_s = chrono::Utc::now().timestamp();
    let created_inv = app_backend
        .create_invitation(
            &ctx1,
            "pg-invitee@org1.test",
            bugfinder::domain::models::UserRole::Member,
            &pg_inv_tok_sha,
            now_s + 72 * 3600,
        )
        .await
        .unwrap();
    assert_eq!(created_inv.email, "pg-invitee@org1.test");
    let inv_lookup = app_backend
        .lookup_invitation(&pg_inv_tok_sha)
        .await
        .unwrap()
        .expect("lookup_invitation should resolve via capability GUC");
    assert_eq!(inv_lookup.organization_id, org1.id);
    let pg_pw = bugfinder::security::auth::hash_password("PgInviteeStrongPass!22".into())
        .await
        .unwrap();
    let (inv_uid, inv_oid, _, _, inv_role) = app_backend
        .accept_invitation(&pg_inv_tok_sha, "PG Invitee", &pg_pw, now_s)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inv_oid, org1.id);
    assert_eq!(inv_role, bugfinder::domain::models::UserRole::Member);

    // PG JSONB key-reordering must NOT break SHA-256 audit hash chain
    for (idx, meta) in [
        json!({ "z": 1, "a": { "y": 2, "x": "pg-chain" }, "arr": [3, 2, 1] }),
        json!({ "role": "member", "invite_id": created_inv.id, "actor": "owner" }),
        json!({ "nested": { "k2": true, "k1": "ok" }, "step": 3 }),
    ]
    .into_iter()
    .enumerate()
    {
        app_backend
            .append_audit_log(&bugfinder::storage::NewAuditLog {
                organization_id: org1.id,
                actor_user_id: Some(owner_uid),
                actor_email: "owner1@pg.test".into(),
                action: format!("pg.audit.step_{idx}"),
                target_type: "test".into(),
                target_id: idx.to_string(),
                ip_hmac: "pg_hmac".into(),
                metadata: meta,
            })
            .await
            .unwrap();
    }
    let pg_aud_ver = app_backend.verify_audit_chain(&ctx1).await.unwrap();
    assert!(pg_aud_ver.valid, "PG JSONB audit chain failed: {:?}", pg_aud_ver);
    assert!(pg_aud_ver.checked_entries >= 3);

    // AEAD check on alert_rules.webhook_secret inside raw PG row
    let mut aead_tx = app_pg.pool().begin().await.unwrap();
    sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
        .bind(org1.id.to_string())
        .execute(&mut *aead_tx)
        .await
        .unwrap();
    let raw_wh: String = sqlx::query_scalar("SELECT webhook_secret FROM alert_rules WHERE id = $1")
        .bind(new_rule.id)
        .fetch_one(&mut *aead_tx)
        .await
        .unwrap();
    aead_tx.commit().await.unwrap();
    assert!(raw_wh.starts_with("enc:v1:"), "PG webhook secret not AEAD sealed: {raw_wh}");

    // Cascade revocation on remove_member under NOBYPASSRLS
    let inv_sess_sha = sha256_hex(b"pg_member_live_sess");
    app_backend
        .create_session(&inv_sess_sha, inv_uid, org1.id, "csrf_m", "ua", "iph", now_s, now_s + 3600)
        .await
        .unwrap();
    let inv_tok_sha = sha256_hex(b"bf_pg_member_tok"); // gitleaks:allow
    let inv_ctx = bugfinder::domain::models::TenantCtx::from_session(
        org1.id,
        ctx1.organization_slug.clone(),
        inv_uid,
        bugfinder::domain::models::UserRole::Member,
        Some(now_s),
        None,
    );
    app_backend
        .create_api_token(&inv_ctx, "PG Mem Tok", &inv_tok_sha, "bf_pg_", bugfinder::domain::models::UserRole::Member, "event:read", Some(now_s + 3600))
        .await
        .unwrap();
    assert!(app_backend.resolve_session(&inv_sess_sha, now_s, 3600).await.unwrap().is_some());
    assert!(app_backend.resolve_api_token(&inv_tok_sha, None, now_s).await.unwrap().is_some());
    assert!(app_backend.remove_member(&ctx1, inv_uid).await.unwrap().unwrap());
    assert!(app_backend.resolve_session(&inv_sess_sha, now_s, 3600).await.unwrap().is_none());
    assert!(app_backend.resolve_api_token(&inv_tok_sha, None, now_s).await.unwrap().is_none());

    let maint_jobs = app_backend.run_maintenance(30, 512).await.unwrap();
    assert!(
        maint_jobs.iter().any(|j| j.title.contains("PG Overdue Cron")),
        "PG run_maintenance must emit uptime_down alert job, got {maint_jobs:?}"
    );
    assert!(
        app_backend.resolve_session(&expired_sha, 0, 86400).await.unwrap().is_none(),
        "Expired session must be deleted from sessions/session_lookup by run_maintenance"
    );
    assert!(
        app_backend.list_quarantine(&ctx1, None).await.unwrap().is_empty(),
        "Expired shield_quarantine row must be deleted by run_maintenance"
    );
}

#[tokio::test]
async fn self_check_monitor_probe_client_error_and_doctor_flow() {
    let (_dir, state, router, _dsn_key, _project_id) = setup_test_app().await;

    // 1. Unauthenticated access to self-check must return 401
    let (unauth_st, _, _) = send_json(&router, "GET", "/api/0/organizations/alpha/self-check/", &[], Value::Null).await;
    assert_eq!(unauth_st, StatusCode::UNAUTHORIZED);

    // 2. Public /api/health returns 200 OK when SQLite storage is healthy
    let (h_st, _, _) = send_raw(&router, "GET", "/api/health", &[], Vec::new()).await;
    assert_eq!(h_st, StatusCode::OK);

    let (cookie, csrf) = login_cookie_and_csrf(&router, "owner@alpha.test", "StrongPassword123!").await;
    let auth_hdrs = [
        (header::COOKIE.as_str(), cookie.as_str()),
        ("x-csrf-token", csrf.as_str()),
    ];

    // 3. Initial GET /self-check/ accurately reports missing alerts/tokens/telemetry as warn and storage as ok
    let (sc_st, _, sc_body) = send_json(
        &router,
        "GET",
        "/api/0/organizations/alpha/self-check/",
        &[(header::COOKIE.as_str(), cookie.as_str())],
        Value::Null,
    )
    .await;
    assert_eq!(sc_st, StatusCode::OK);
    let checks = sc_body["checks"].as_array().unwrap();
    let find_status = |id: &str| {
        checks
            .iter()
            .find(|c| c["id"] == id)
            .unwrap()["status"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(find_status("storage_health"), "ok");
    assert_eq!(find_status("projects_and_dsn"), "ok");
    assert_eq!(find_status("telemetry_received"), "warn");
    assert_eq!(find_status("alerts_configured"), "warn");
    assert_eq!(find_status("api_tokens_configured"), "warn");

    // 4. Report frontend client self-error containing a synthetic Bearer secret -> scrubbed + triggers error status
    let synthetic_secret = "Bearer secret_client_probe_0000000000"; // gitleaks:allow
    let (ce_st, _, _) = send_json(
        &router,
        "POST",
        "/api/0/organizations/alpha/self-check/client-error/",
        &auth_hdrs,
        json!({
            "message": format!("UI failed with {synthetic_secret}"),
            "component": "spa",
            "severity": "error",
            "detail": "stack line 42"
        }),
    )
    .await;
    assert_eq!(ce_st, StatusCode::ACCEPTED);

    let (sc2_st, _, sc2_body) = send_json(
        &router,
        "GET",
        "/api/0/organizations/alpha/self-check/",
        &[(header::COOKIE.as_str(), cookie.as_str())],
        Value::Null,
    )
    .await;
    assert_eq!(sc2_st, StatusCode::OK);
    assert_eq!(sc2_body["overall_status"], "error");
    assert_eq!(sc2_body["unacknowledged_error_count"], 1);
    let errs = sc2_body["self_errors"].as_array().unwrap();
    assert_eq!(errs.len(), 1);
    let recorded_msg = errs[0]["message"].as_str().unwrap();
    assert!(!recorded_msg.contains("secret_client_probe_0000000000"));
    assert!(recorded_msg.contains("[Filtered]"));

    // 5. Run live E2E probe -> all 5 steps pass & telemetry_received turns ok
    let (pr_st, _, pr_body) = send_json(
        &router,
        "POST",
        "/api/0/organizations/alpha/self-check/probe/",
        &auth_hdrs,
        json!({ "send_test_log": true }),
    )
    .await;
    assert_eq!(pr_st, StatusCode::OK);
    assert_eq!(pr_body["ok"], true);
    let steps = pr_body["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 5);
    assert!(steps.iter().all(|s| s["ok"] == true));
    let post_checks = pr_body["report"]["checks"].as_array().unwrap();
    assert_eq!(
        post_checks
            .iter()
            .find(|c| c["id"] == "telemetry_received")
            .unwrap()["status"],
        "ok"
    );

    // 6. Acknowledge / clear internal self-errors -> unacknowledged_error_count resets to 0
    let (ack_st, _, ack_body) = send_json(
        &router,
        "POST",
        "/api/0/organizations/alpha/self-check/ack/",
        &auth_hdrs,
        json!({ "clear": true }),
    )
    .await;
    assert_eq!(ack_st, StatusCode::OK);
    assert_eq!(ack_body["unacknowledged_error_count"], 0);
    assert!(ack_body["self_errors"].as_array().unwrap().is_empty());

    // 7. Doctor CLI check on the initialized data_dir exits 0 cleanly
    let doctor_code = bugfinder::selfcheck::run_doctor_cli(&state.config, None, true).await;
    assert_eq!(doctor_code, 0);
}

#[tokio::test]
async fn audit_security_and_stability_fixes_test() {
    let (_dir, state, router, dsn_key, project_id) = setup_test_app().await;
    let (owner_cookie, owner_csrf) =
        login_cookie_and_csrf(&router, "owner@alpha.test", "StrongPassword123!").await;
    let owner_hdrs = [
        (header::COOKIE.as_str(), owner_cookie.as_str()),
        ("x-csrf-token", owner_csrf.as_str()),
    ];

    // 1. POST /api/auth/setup when already initialized -> 409 Conflict immediately
    let (dup_setup_st, _, _) = send_json(
        &router,
        "POST",
        "/api/auth/setup",
        &[],
        json!({
            "org_name": "Org Beta",
            "org_slug": "beta",
            "email": "b@beta.test",
            "name": "Bob",
            "password": "StrongPassword123!",
            "project_name": "B"
        }),
    )
    .await;
    assert_eq!(dup_setup_st, StatusCode::CONFLICT);

    // 2. Invite viewer, verify logout CSRF (403 without header, 200 with CSRF), and Viewer RBAC on heartbeat_check (403)
    let (inv_st, _, _) = send_json(
        &router,
        "POST",
        "/api/0/organizations/alpha/members/",
        &owner_hdrs,
        json!({
            "email": "viewer@alpha.test",
            "name": "Viewer",
            "password": "StrongPassword123!",
            "role": "viewer"
        }),
    )
    .await;
    assert_eq!(inv_st, StatusCode::CREATED);

    let (mon_st, _, mon_body) = send_json(
        &router,
        "POST",
        "/api/0/organizations/alpha/monitors/",
        &owner_hdrs,
        json!({ "project_id": project_id, "name": "Cron", "expected_interval_sec": 60 }),
    )
    .await;
    assert_eq!(mon_st, StatusCode::CREATED);
    let mon_uuid = mon_body["uuid"].as_str().unwrap();

    let (viewer_cookie, viewer_csrf) =
        login_cookie_and_csrf(&router, "viewer@alpha.test", "StrongPassword123!").await;
    let (hb_deny_st, _, _) = send_json(
        &router,
        "POST",
        &format!("/api/0/organizations/alpha/heartbeat_check/{mon_uuid}/"),
        &[
            (header::COOKIE.as_str(), viewer_cookie.as_str()),
            ("x-csrf-token", viewer_csrf.as_str()),
        ],
        json!({}),
    )
    .await;
    assert_eq!(hb_deny_st, StatusCode::FORBIDDEN);

    let (logout_no_csrf, _, _) = send_json(
        &router,
        "POST",
        "/api/auth/logout",
        &[(header::COOKIE.as_str(), viewer_cookie.as_str())],
        json!({}),
    )
    .await;
    assert_eq!(logout_no_csrf, StatusCode::FORBIDDEN);

    let (logout_ok, _, _) = send_json(
        &router,
        "POST",
        "/api/auth/logout",
        &[
            (header::COOKIE.as_str(), viewer_cookie.as_str()),
            ("x-csrf-token", viewer_csrf.as_str()),
        ],
        json!({}),
    )
    .await;
    assert_eq!(logout_ok, StatusCode::OK);

    // 3. API token idempotency replay redacts plaintext token
    let (tk1_st, _, tk1_body) = send_json(
        &router,
        "POST",
        "/api/0/api-tokens/",
        &[
            (header::COOKIE.as_str(), owner_cookie.as_str()),
            ("x-csrf-token", owner_csrf.as_str()),
            ("idempotency-key", "audit-redact-1"),
        ],
        json!({ "name": "Redact Token", "role": "admin" }),
    )
    .await;
    assert_eq!(tk1_st, StatusCode::CREATED);
    assert!(tk1_body["token"].as_str().unwrap().starts_with("bf_"));

    let (tk2_st, tk2_hdrs, tk2_body) = send_json(
        &router,
        "POST",
        "/api/0/api-tokens/",
        &[
            (header::COOKIE.as_str(), owner_cookie.as_str()),
            ("x-csrf-token", owner_csrf.as_str()),
            ("idempotency-key", "audit-redact-1"),
        ],
        json!({ "name": "Redact Token", "role": "admin" }),
    )
    .await;
    assert_eq!(tk2_st, StatusCode::CREATED);
    assert_eq!(tk2_hdrs.get("x-idempotent-replay").unwrap(), "true");
    assert_eq!(tk2_body["token"], "[REDACTED_ON_REPLAY]");

    // 4. Upload sourcemap to nonexistent project -> 404 & zero files written to sourcemaps_dir
    let (sm_404, _, _) = send_raw(
        &router,
        "POST",
        "/api/0/projects/alpha/does-not-exist/releases/1.0.0/sourcemaps/?filename=ghost.js.map",
        &owner_hdrs,
        br#"{"version":3,"sources":["a.ts"],"mappings":"AAAA"}"#.to_vec(),
    )
    .await;
    assert_eq!(sm_404, StatusCode::NOT_FOUND);
    let sm_files = std::fs::read_dir(state.config.sourcemaps_dir())
        .map(|it| it.count())
        .unwrap_or(0);
    assert_eq!(sm_files, 0, "Orphan sourcemap blob must not be written for nonexistent project");

    // 5. Unknown tunnel slug -> 401 BEFORE gzip decompression (invalid gzip would be 400 if decompressed); >500 items direct log batch -> 413
    let (tun_unauth, _, _) = send_raw(
        &router,
        "POST",
        "/t/nonexistent-slug",
        &[("content-encoding", "gzip")],
        b"not-valid-gzip".to_vec(),
    )
    .await;
    assert_eq!(tun_unauth, StatusCode::UNAUTHORIZED);

    let sentry_auth = format!("Sentry sentry_version=7, sentry_key={dsn_key}");
    let too_many_logs: Vec<Value> = (0..501)
        .map(|i| json!({ "level": "info", "message": format!("line {i}") }))
        .collect();
    let (logs_413, _, _) = send_json(
        &router,
        "POST",
        &format!("/api/v1/logs?project_id={project_id}"),
        &[("x-sentry-auth", &sentry_auth)],
        json!(too_many_logs),
    )
    .await;
    assert_eq!(logs_413, StatusCode::PAYLOAD_TOO_LARGE);

    // 6. Upload real sourcemap, ingest event with ?v=99#top filename + scrubbed transaction + 2 distinct issues + aged FTS log
    let sm_bytes = br#"{
        "version": 3,
        "sources": ["src/checkout.ts"],
        "names": ["submitOrder"],
        "sourcesContent": ["export function submitOrder() {\n  throw new Error('boom');\n}\n"],
        "mappings": "AAAA"
    }"#
    .to_vec();
    let (sm_ok, _, _) = send_raw(
        &router,
        "POST",
        "/api/0/projects/alpha/rolelane/releases/2.0.0/sourcemaps/?filename=bundle.min.js.map",
        &owner_hdrs,
        sm_bytes,
    )
    .await;
    assert_eq!(sm_ok, StatusCode::CREATED);

    let trace_id = "abcdef1234567890abcdef1234567890";
    let tx_secret = "Bearer tx_secret_token_999900"; // gitleaks:allow
    let env_payload = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        json!({ "event_id": "22222222222222222222222222222222" }),
        json!({ "type": "event" }),
        json!({
            "event_id": "22222222222222222222222222222222",
            "platform": "javascript",
            "level": "error",
            "release": "2.0.0",
            "exception": { "values": [{ "type": "FirstErr", "value": "One", "stacktrace": { "frames": [{ "filename": "https://cdn.example.com/assets/bundle.min.js?v=99#top", "lineno": 1, "colno": 0, "in_app": true }] } }] }
        }),
        json!({ "type": "event" }),
        json!({
            "event_id": "33333333333333333333333333333333",
            "platform": "javascript",
            "level": "error",
            "exception": { "values": [{ "type": "SecondErr", "value": "Two" }] }
        }),
        json!({ "type": "transaction" }),
        json!({
            "transaction": format!("GET /secret {tx_secret}"),
            "start_timestamp": 1700000000.0,
            "timestamp": 1700000000.2,
            "contexts": { "trace": { "trace_id": trace_id, "span_id": "1122334455667788", "op": "http" } },
            "spans": [{ "description": format!("Auth {tx_secret}") }]
        }),
        json!({ "type": "log" }),
        json!({
            "version": 2,
            "items": [{
                "timestamp": 1700000000.0,
                "level": "info",
                "body": "ephemeralftsmarker log entry to purge",
                "trace_id": trace_id
            }]
        })
    );
    let (env_ok, _, _) = send_raw(
        &router,
        "POST",
        &format!("/api/{project_id}/envelope/"),
        &[("x-sentry-auth", &sentry_auth)],
        env_payload.into_bytes(),
    )
    .await;
    assert_eq!(env_ok, StatusCode::OK);
    state.batch_writer.flush_now().await;

    // 7. Pagination offset on issues + sourcemap demangling on ?v=99#top + scrubbed transaction trace
    let (p1_st, p1_hdrs, p1_body) = send_json(
        &router,
        "GET",
        "/api/0/organizations/alpha/issues/?limit=1&offset=0&sort=date",
        &[(header::COOKIE.as_str(), owner_cookie.as_str())],
        Value::Null,
    )
    .await;
    assert_eq!(p1_st, StatusCode::OK);
    assert_eq!(p1_hdrs.get("x-hits").unwrap(), "2");
    let first_id = p1_body[0]["id"].as_i64().unwrap();

    let (p2_st, _, p2_body) = send_json(
        &router,
        "GET",
        "/api/0/organizations/alpha/issues/?limit=1&offset=1&sort=date",
        &[(header::COOKIE.as_str(), owner_cookie.as_str())],
        Value::Null,
    )
    .await;
    assert_eq!(p2_st, StatusCode::OK);
    assert_eq!(p2_body.as_array().unwrap().len(), 1);
    let second_id = p2_body[0]["id"].as_i64().unwrap();
    assert_ne!(first_id, second_id);

    // Check whichever issue corresponds to FirstErr has source_mapped = true
    let first_err_id = p1_body
        .as_array()
        .unwrap()
        .iter()
        .chain(p2_body.as_array().unwrap().iter())
        .find(|i| i["title"].as_str().unwrap_or("").contains("FirstErr"))
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    let (ev_st, _, ev_body) = send_json(
        &router,
        "GET",
        &format!("/api/0/organizations/alpha/issues/{first_err_id}/events/latest/"),
        &[(header::COOKIE.as_str(), owner_cookie.as_str())],
        Value::Null,
    )
    .await;
    assert_eq!(ev_st, StatusCode::OK);
    let frame0 = &ev_body["payload"]["exception"]["values"][0]["stacktrace"]["frames"][0];
    assert_eq!(frame0["source_mapped"], true);
    assert_eq!(frame0["filename"], "src/checkout.ts");

    let (tr_st, _, tr_body) = send_json(
        &router,
        "GET",
        &format!("/api/0/organizations/alpha/traces/{trace_id}/"),
        &[(header::COOKIE.as_str(), owner_cookie.as_str())],
        Value::Null,
    )
    .await;
    assert_eq!(tr_st, StatusCode::OK);
    let tr_str = tr_body.to_string();
    assert!(!tr_str.contains("tx_secret_token_999900"));
    assert!(tr_str.contains("[Filtered]"));

    // 8. run_maintenance purges old logs and cleans logs_fts so FTS search returns empty
    state.storage.run_maintenance(1, 512).await.unwrap();
    let (fts_st, _, fts_body) = send_json(
        &router,
        "GET",
        "/api/0/organizations/alpha/logs/?query=ephemeralftsmarker",
        &[(header::COOKIE.as_str(), owner_cookie.as_str())],
        Value::Null,
    )
    .await;
    assert_eq!(fts_st, StatusCode::OK);
    assert!(fts_body.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn anti_rea_shield_secret_radar_log_ids_and_false_positives_test() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let (_dir, state, router, dsn_key, project_id) = setup_test_app().await;
    let (owner_cookie, owner_csrf) =
        login_cookie_and_csrf(&router, "owner@alpha.test", "StrongPassword123!").await;
    let owner_hdrs = [
        (header::COOKIE.as_str(), owner_cookie.as_str()),
        ("x-csrf-token", owner_csrf.as_str()),
    ];

    // 1. Browser Shield SDK served cleanly
    let (sdk_st, sdk_hdrs, sdk_raw) =
        send_raw(&router, "GET", "/sdk/bugfinder-shield.js", &[], Vec::new()).await;
    assert_eq!(sdk_st, StatusCode::OK);
    let sdk_ct = sdk_hdrs.get(header::CONTENT_TYPE).unwrap().to_str().unwrap();
    assert!(sdk_ct.contains("javascript"));
    let sdk_txt = String::from_utf8(sdk_raw).unwrap();
    assert!(sdk_txt.contains("BugFinderShield"));

    // 2. Invalid DSN on /shield/ -> 401
    let (bad_dsn_st, _, _) = send_json(
        &router,
        "POST",
        &format!("/api/{project_id}/shield/?sentry_key=wrong_key"),
        &[],
        json!({ "signals": ["webdriver_detected"] }),
    )
    .await;
    assert_eq!(bad_dsn_st, StatusCode::UNAUTHORIZED);

    // 3. Configure Shield policy + allowed_domains with enforce_origin_check = true
    let (upd_st, _, _) = send_json(
        &router,
        "PUT",
        "/api/0/projects/alpha/rolelane/settings/",
        &owner_hdrs,
        json!({
            "allowed_domains": ["https://app.example.com"],
            "shield": {
                "enabled": true,
                "mode": "defend",
                "quarantine_threshold": 70,
                "quarantine_ttl_sec": 900,
                "enforce_origin_check": true,
                "log_ids_enabled": true,
                "secret_leak_alerts": true
            }
        }),
    )
    .await;
    assert_eq!(upd_st, StatusCode::OK);

    // 4. Browser DSN report from disallowed Origin -> 403
    let (bad_orig_st, _, _) = send_json(
        &router,
        "POST",
        &format!("/api/{project_id}/shield/?sentry_key={dsn_key}"),
        &[("origin", "https://evil.test")],
        json!({ "signals": ["cdp_automation", "honeypot_access"], "session_id": "sess_browser_123456" }),
    )
    .await;
    assert_eq!(bad_orig_st, StatusCode::FORBIDDEN);

    // 5. Valid browser report -> CGNAT-safe quarantine (session ONLY, never IP)
    let (br_ok_st, _, br_ok_body) = send_json(
        &router,
        "POST",
        &format!("/api/{project_id}/shield/?sentry_key={dsn_key}"),
        &[("origin", "https://app.example.com")],
        json!({
            "signals": ["cdp_automation", "honeypot_access"],
            "session_id": "sess_browser_123456",
            "path": "/checkout"
        }),
    )
    .await;
    assert_eq!(br_ok_st, StatusCode::ACCEPTED);
    assert_eq!(br_ok_body["action"], "quarantined");
    assert_eq!(br_ok_body["risk_score"], 100);

    let (q1_st, _, q1_body) = send_json(
        &router,
        "GET",
        "/api/0/organizations/alpha/shield/quarantine/",
        &[(header::COOKIE.as_str(), owner_cookie.as_str())],
        Value::Null,
    )
    .await;
    assert_eq!(q1_st, StatusCode::OK);
    let q1_arr = q1_body.as_array().unwrap();
    assert_eq!(q1_arr.len(), 1);
    assert_eq!(q1_arr[0]["subject_type"], "session");

    // 6. Backend-verified API token report quarantines actor IP HMAC + blocklist ETag / 304 + HMAC match
    let (tk_st, _, tk_body) = send_json(
        &router,
        "POST",
        "/api/0/api-tokens/",
        &owner_hdrs,
        json!({ "name": "Shield Middleware", "role": "member" }),
    )
    .await;
    assert_eq!(tk_st, StatusCode::CREATED);
    let api_tok = tk_body["token"].as_str().unwrap().to_string();
    let bearer_auth = format!("Bearer {api_tok}");

    let (be_st, _, be_body) = send_json(
        &router,
        "POST",
        &format!("/api/{project_id}/shield/"),
        &[(header::AUTHORIZATION.as_str(), &bearer_auth)],
        json!({
            "signals": ["canary_route_hit"],
            "actor_ip": "203.0.113.42",
            "path": "/.env"
        }),
    )
    .await;
    assert_eq!(be_st, StatusCode::ACCEPTED);
    assert_eq!(be_body["action"], "quarantined");

    let (bl_st, bl_hdrs, bl_body) = send_json(
        &router,
        "GET",
        "/api/0/projects/alpha/rolelane/shield/blocklist/",
        &[(header::AUTHORIZATION.as_str(), &bearer_auth)],
        Value::Null,
    )
    .await;
    assert_eq!(bl_st, StatusCode::OK);
    let etag = bl_hdrs.get(header::ETAG).unwrap().to_str().unwrap().to_string();
    let ip_key = bl_body["ip_hmac_key"].as_str().unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(ip_key.as_bytes()).unwrap();
    mac.update(b"203.0.113.42");
    let expected_ip_hmac = hex::encode(mac.finalize().into_bytes());
    let entries = bl_body["entries"].as_array().unwrap();
    assert!(entries
        .iter()
        .any(|e| e["subject_type"] == "ip" && e["subject_hmac"] == expected_ip_hmac));

    let (bl304_st, _, _) = send_raw(
        &router,
        "GET",
        "/api/0/projects/alpha/rolelane/shield/blocklist/",
        &[
            (header::AUTHORIZATION.as_str(), &bearer_auth),
            (header::IF_NONE_MATCH.as_str(), &etag),
        ],
        Vec::new(),
    )
    .await;
    assert_eq!(bl304_st, StatusCode::NOT_MODIFIED);

    // 7. RBAC: Viewer cannot release quarantine (403); Owner releases cleanly (204)
    let _ = send_json(
        &router,
        "POST",
        "/api/0/organizations/alpha/members/",
        &owner_hdrs,
        json!({
            "email": "shieldviewer@alpha.test",
            "name": "Shield Viewer",
            "password": "StrongPassword123!",
            "role": "viewer"
        }),
    )
    .await;
    let (v_cookie, v_csrf) =
        login_cookie_and_csrf(&router, "shieldviewer@alpha.test", "StrongPassword123!").await;
    let session_q_id = q1_arr[0]["id"].as_i64().unwrap();
    let (del_deny, _, _) = send_json(
        &router,
        "DELETE",
        &format!("/api/0/organizations/alpha/shield/quarantine/{session_q_id}/"),
        &[(header::COOKIE.as_str(), &v_cookie), ("x-csrf-token", &v_csrf)],
        Value::Null,
    )
    .await;
    assert_eq!(del_deny, StatusCode::FORBIDDEN);

    let (del_ok, _, _) = send_json(
        &router,
        "DELETE",
        &format!("/api/0/organizations/alpha/shield/quarantine/{session_q_id}/"),
        &owner_hdrs,
        Value::Null,
    )
    .await;
    assert_eq!(del_ok, StatusCode::NO_CONTENT);

    // 8. Alert rules accept security_threat and secret_leak
    for trig in ["security_threat", "secret_leak"] {
        let (al_st, _, _) = send_json(
            &router,
            "POST",
            "/api/0/organizations/alpha/alerts/",
            &owner_hdrs,
            json!({
                "project_id": project_id,
                "name": format!("Alert {trig}"),
                "trigger_type": trig,
                "channel_type": "email",
                "email_to": "sec@example.com"
            }),
        )
        .await;
        assert_eq!(al_st, StatusCode::CREATED);
    }

    // 9. False-positive guardrails BEFORE positive triggers (avoiding cooldown masking)
    // 9a. Test key + already filtered string must NOT fire secret_leak
    // 9b. Normal SQL prose, ../../src/app.ts, and 25x /favicon.ico 404 must NOT fire log_ids
    let test_prefix = "sk_test_";
    let fp_test_key = format!("{test_prefix}51234567890abcdef1234567890");
    let mut benign_logs = vec![
        json!({
            "level": "info",
            "body": format!("Loaded sandbox {fp_test_key} and token=[Filtered]"),
            "service": "web"
        }),
        json!({
            "level": "info",
            "body": "User selected items from cart at ../../src/app.ts",
            "service": "web",
            "attributes": { "url.path": "/cart" }
        }),
    ];
    for _ in 0..25 {
        benign_logs.push(json!({
            "level": "warn",
            "body": "not found",
            "service": "web",
            "attributes": {
                "http.status_code": 404,
                "url.path": "/favicon.ico",
                "client.address": "198.51.100.7"
            }
        }));
    }
    let (fp_log_st, _, _) = send_json(
        &router,
        "POST",
        &format!("/api/v1/logs?project_id={project_id}&sentry_key={dsn_key}"),
        &[],
        json!({ "items": benign_logs }),
    )
    .await;
    assert_eq!(fp_log_st, StatusCode::ACCEPTED);

    // 9c. Browser extension CSP report must NOT fire csp_script_tamper
    let (fp_csp_st, _, _) = send_json(
        &router,
        "POST",
        &format!("/api/{project_id}/security/?sentry_key={dsn_key}"),
        &[],
        json!({
            "csp-report": {
                "violated-directive": "script-src",
                "blocked-uri": "chrome-extension://abc/inject.js"
            }
        }),
    )
    .await;
    assert_eq!(fp_csp_st, StatusCode::CREATED);

    let (ev_fp_st, _, ev_fp_body) = send_json(
        &router,
        "GET",
        "/api/0/organizations/alpha/shield/events/",
        &[(header::COOKIE.as_str(), owner_cookie.as_str())],
        Value::Null,
    )
    .await;
    assert_eq!(ev_fp_st, StatusCode::OK);
    let fp_events = ev_fp_body["events"].as_array().unwrap();
    assert!(
        !fp_events
            .iter()
            .any(|e| matches!(e["category"].as_str(), Some("secret_leak" | "log_ids" | "csp"))),
        "False positive fired on benign telemetry: {fp_events:?}"
    );

    // 10. Positive detections: live secret leak, SQLi/Traversal, 20x 403 IDOR burst, external CSP tamper
    let live_secret = ["sk", "live", "51234567890abcdef1234567890"].join("_"); // gitleaks:allow
    let mut attack_logs = vec![
        json!({
            "level": "error",
            "body": format!("Stripe init failed key={live_secret}"),
            "service": "billing"
        }),
        json!({
            "level": "warn",
            "body": "GET /search?q=1 UNION ALL SELECT NULL,NULL--",
            "service": "api",
            "attributes": { "url.path": "/search" }
        }),
        json!({
            "level": "warn",
            "body": "GET /download?f=../../etc/passwd",
            "service": "api",
            "attributes": { "url.path": "/download" }
        }),
    ];
    for i in 0..20 {
        attack_logs.push(json!({
            "level": "warn",
            "body": "Forbidden",
            "service": "api",
            "attributes": {
                "http.status_code": 403,
                "url.path": format!("/api/admin/users/{i}"),
                "client.address": "198.51.100.8"
            }
        }));
    }
    let (atk_st, _, _) = send_json(
        &router,
        "POST",
        &format!("/api/v1/logs?project_id={project_id}&sentry_key={dsn_key}"),
        &[],
        json!({ "items": attack_logs }),
    )
    .await;
    assert_eq!(atk_st, StatusCode::ACCEPTED);
    state.batch_writer.flush_now().await;

    // Verify stored logs scrubbed the live secret
    let (logs_st, _, logs_body) = send_json(
        &router,
        "GET",
        "/api/0/organizations/alpha/logs/?service=billing",
        &[(header::COOKIE.as_str(), owner_cookie.as_str())],
        Value::Null,
    )
    .await;
    assert_eq!(logs_st, StatusCode::OK);
    let log_str = logs_body.to_string();
    assert!(!log_str.contains(&live_secret));
    assert!(log_str.contains("[Filtered]"));

    // External CSP tamper triggers csp_script_tamper
    let (atk_csp_st, _, _) = send_json(
        &router,
        "POST",
        &format!("/api/{project_id}/security/?sentry_key={dsn_key}"),
        &[],
        json!({
            "csp-report": {
                "effective-directive": "script-src",
                "blocked-uri": "https://evil.cdn/hook.js"
            }
        }),
    )
    .await;
    assert_eq!(atk_csp_st, StatusCode::CREATED);

    let (ev2_st, _, ev2_body) = send_json(
        &router,
        "GET",
        "/api/0/organizations/alpha/shield/events/",
        &[(header::COOKIE.as_str(), owner_cookie.as_str())],
        Value::Null,
    )
    .await;
    assert_eq!(ev2_st, StatusCode::OK);
    let ev2_arr = ev2_body["events"].as_array().unwrap();
    let has_sig = |sig: &str| ev2_arr.iter().any(|e| e["signal_type"] == sig);
    assert!(has_sig("honeypot_access"));
    assert!(has_sig("canary_route_hit"));
    assert!(has_sig("secret_leak"));
    assert!(has_sig("injection_probe"));
    assert!(has_sig("idor_or_enum_burst"));
    assert!(has_sig("csp_script_tamper"));
    assert!(ev2_body["summary"]["secret_leaks_24h"].as_i64().unwrap() >= 1);
}

#[tokio::test]
async fn security_rbac_scopes_revocation_and_session_only_test() {
    let (_dir, state, router, dsn_key, project_id) = setup_test_app().await;
    let (owner_cookie, owner_csrf) =
        login_cookie_and_csrf(&router, "owner@alpha.test", "StrongPassword123!").await;
    let owner_hdrs = [
        (header::COOKIE.as_str(), owner_cookie.as_str()),
        ("x-csrf-token", owner_csrf.as_str()),
    ];

    // Seed 1 issue so PUT /issues/:id can be exercised by scoped token
    let sentry_auth = format!("Sentry sentry_version=7, sentry_key={dsn_key}");
    let (st_ev, _, ev_res) = send_json(
        &router,
        "POST",
        &format!("/api/{project_id}/store/"),
        &[("x-sentry-auth", &sentry_auth)],
        json!({ "level": "error", "message": "Scoped token test issue" }),
    )
    .await;
    assert_eq!(st_ev, StatusCode::OK, "seed event failed: {ev_res}");
    state.batch_writer.flush_now().await;

    let (_, _, issues_list) = send_json(
        &router,
        "GET",
        "/api/0/organizations/alpha/issues/",
        &[(header::COOKIE.as_str(), owner_cookie.as_str())],
        Value::Null,
    )
    .await;
    let issue_id = issues_list[0]["id"].as_i64().unwrap();

    // 1. Mint narrow `event:read` token with 30-day expiry
    let (tk_st, _, tk_body) = send_json(
        &router,
        "POST",
        "/api/0/api-tokens/",
        &owner_hdrs,
        json!({
            "name": "Read-Only CI",
            "role": "member",
            "scopes": ["event:read"],
            "expires_in_days": 30
        }),
    )
    .await;
    assert_eq!(tk_st, StatusCode::CREATED, "token create: {tk_body}");
    let read_tok = tk_body["token"].as_str().unwrap().to_string();
    let bearer = format!("Bearer {read_tok}");
    assert!(tk_body["meta"]["expires_at"].as_str().is_some());

    // Read works, writes return 403, /api-tokens/ is Session-Only (403)
    let (r_st, _, _) = send_raw(
        &router,
        "GET",
        "/api/0/organizations/alpha/issues/",
        &[(header::AUTHORIZATION.as_str(), &bearer)],
        Vec::new(),
    )
    .await;
    assert_eq!(r_st, StatusCode::OK);

    let (w_proj, _, _) = send_json(
        &router,
        "POST",
        "/api/0/organizations/alpha/projects/",
        &[(header::AUTHORIZATION.as_str(), &bearer)],
        json!({ "name": "Blocked" }),
    )
    .await;
    assert_eq!(w_proj, StatusCode::FORBIDDEN);

    let (w_iss, _, _) = send_json(
        &router,
        "PUT",
        &format!("/api/0/organizations/alpha/issues/{issue_id}/"),
        &[(header::AUTHORIZATION.as_str(), &bearer)],
        json!({ "status": "resolved" }),
    )
    .await;
    assert_eq!(w_iss, StatusCode::FORBIDDEN);

    let (tok_list_st, _, _) = send_raw(
        &router,
        "GET",
        "/api/0/api-tokens/",
        &[(header::AUTHORIZATION.as_str(), &bearer)],
        Vec::new(),
    )
    .await;
    assert_eq!(tok_list_st, StatusCode::FORBIDDEN);

    // 2. MCP with project:read-only token (missing event:read) rejected
    let (ptk_st, _, ptk_body) = send_json(
        &router,
        "POST",
        "/api/0/api-tokens/",
        &owner_hdrs,
        json!({ "name": "ProjReadOnly", "role": "viewer", "scopes": ["project:read"] }),
    )
    .await;
    assert_eq!(ptk_st, StatusCode::CREATED);
    let proj_tok = ptk_body["token"].as_str().unwrap();
    let now_s = chrono::Utc::now().timestamp();
    let proj_ctx = state
        .storage
        .resolve_api_token(&sha256_hex(proj_tok.as_bytes()), Some("alpha"), now_s)
        .await
        .unwrap()
        .unwrap();
    let mcp_err = handle_mcp_request(
        &state.storage,
        &proj_ctx,
        "tools/call",
        &json!({ "name": "list_issues", "arguments": {} }),
    )
    .await
    .unwrap_err();
    assert_eq!(mcp_err.0, -32001);

    // 3. Expired API token rejected with 401
    let db_path = state.config.sqlite_path();
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE api_tokens SET expires_at = 1 WHERE name = 'Read-Only CI'",
            [],
        )
        .unwrap();
    }
    let (exp_st, _, _) = send_raw(
        &router,
        "GET",
        "/api/0/organizations/alpha/issues/",
        &[(header::AUTHORIZATION.as_str(), &bearer)],
        Vec::new(),
    )
    .await;
    assert_eq!(exp_st, StatusCode::UNAUTHORIZED);

    // 4. Manager role + 72h Expirable Invite Link lifecycle
    let (mgr_inv, _, _) = send_json(
        &router,
        "POST",
        "/api/0/organizations/alpha/members/",
        &owner_hdrs,
        json!({
            "email": "mgr@alpha.test",
            "name": "Morgan Manager",
            "password": "ManagerPass!9876", // gitleaks:allow
            "role": "manager"
        }),
    )
    .await;
    assert_eq!(mgr_inv, StatusCode::CREATED);
    let (mgr_cookie, mgr_csrf) =
        login_cookie_and_csrf(&router, "mgr@alpha.test", "ManagerPass!9876").await;
    let mgr_hdrs = [
        (header::COOKIE.as_str(), mgr_cookie.as_str()),
        ("x-csrf-token", mgr_csrf.as_str()),
    ];

    // Manager cannot invite owner (403)
    let (mgr_esc, _, _) = send_json(
        &router,
        "POST",
        "/api/0/organizations/alpha/invitations/",
        &mgr_hdrs,
        json!({ "email": "boss@alpha.test", "role": "owner" }),
    )
    .await;
    assert_eq!(mgr_esc, StatusCode::FORBIDDEN);

    // Manager creates 72h invite for member
    let (inv_c, _, inv_b) = send_json(
        &router,
        "POST",
        "/api/0/organizations/alpha/invitations/",
        &mgr_hdrs,
        json!({ "email": "joiner@alpha.test", "role": "admin" }),
    )
    .await;
    assert_eq!(inv_c, StatusCode::CREATED, "create invite: {inv_b}");
    let inv_tok = inv_b["token"].as_str().unwrap().to_string();

    let (lk_st, _, lk_b) = send_json(
        &router,
        "GET",
        &format!("/api/auth/invites/{inv_tok}"),
        &[],
        Value::Null,
    )
    .await;
    assert_eq!(lk_st, StatusCode::OK);
    assert_eq!(lk_b["email"], "joiner@alpha.test");

    let (acc_st, acc_hdrs, acc_b) = send_json(
        &router,
        "POST",
        &format!("/api/auth/invites/{inv_tok}/accept"),
        &[],
        json!({ "name": "Jane Joiner", "password": "JaneSecretVault!99" }), // gitleaks:allow
    )
    .await;
    assert_eq!(acc_st, StatusCode::CREATED, "accept invite: {acc_b}");
    let joiner_uid = acc_b["user"]["id"].as_i64().unwrap();
    let joiner_cookie = acc_hdrs
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let joiner_csrf = acc_b["csrf_token"].as_str().unwrap().to_string();

    // Reuse of consumed invite -> 410 Gone
    let (reuse_st, _, _) = send_json(
        &router,
        "POST",
        &format!("/api/auth/invites/{inv_tok}/accept"),
        &[],
        json!({ "name": "Replay", "password": "ReplayPassPhrase!99" }), // gitleaks:allow
    )
    .await;
    assert_eq!(reuse_st, StatusCode::GONE);

    // 5. Bug #1 Fix: Instant cascade revocation on update_member_role AND remove_member
    let (jtk_st, _, jtk_b) = send_json(
        &router,
        "POST",
        "/api/0/api-tokens/",
        &[
            (header::COOKIE.as_str(), joiner_cookie.as_str()),
            ("x-csrf-token", joiner_csrf.as_str()),
        ],
        json!({ "name": "Joiner Admin Tok", "role": "admin" }),
    )
    .await;
    assert_eq!(jtk_st, StatusCode::CREATED);
    let joiner_tok = jtk_b["token"].as_str().unwrap().to_string();
    let joiner_bearer = format!("Bearer {joiner_tok}");

    let (ok_s, _, _) = send_raw(
        &router,
        "GET",
        "/api/0/organizations/alpha/issues/",
        &[(header::COOKIE.as_str(), joiner_cookie.as_str())],
        Vec::new(),
    )
    .await;
    assert_eq!(ok_s, StatusCode::OK);
    let (ok_t, _, _) = send_raw(
        &router,
        "GET",
        "/api/0/organizations/alpha/issues/",
        &[(header::AUTHORIZATION.as_str(), joiner_bearer.as_str())],
        Vec::new(),
    )
    .await;
    assert_eq!(ok_t, StatusCode::OK);

    // Downgrade joiner to viewer -> BOTH previous session & previous API token instantly 401
    let (down_st, _, _) = send_json(
        &router,
        "PUT",
        &format!("/api/0/organizations/alpha/members/{joiner_uid}/"),
        &owner_hdrs,
        json!({ "role": "viewer" }),
    )
    .await;
    assert_eq!(down_st, StatusCode::OK);

    let (rev_s, _, _) = send_raw(
        &router,
        "GET",
        "/api/auth/me",
        &[(header::COOKIE.as_str(), joiner_cookie.as_str())],
        Vec::new(),
    )
    .await;
    assert_eq!(rev_s, StatusCode::UNAUTHORIZED);
    let (rev_t, _, _) = send_raw(
        &router,
        "GET",
        "/api/0/organizations/alpha/issues/",
        &[(header::AUTHORIZATION.as_str(), joiner_bearer.as_str())],
        Vec::new(),
    )
    .await;
    assert_eq!(rev_t, StatusCode::UNAUTHORIZED);

    // Re-login then remove_member -> immediate 401
    let (j2_cookie, _) =
        login_cookie_and_csrf(&router, "joiner@alpha.test", "JaneSecretVault!99").await;
    let (rem_st, _, _) = send_raw(
        &router,
        "DELETE",
        &format!("/api/0/organizations/alpha/members/{joiner_uid}/"),
        &owner_hdrs,
        Vec::new(),
    )
    .await;
    assert_eq!(rem_st, StatusCode::NO_CONTENT);
    let (gone_st, _, _) = send_raw(
        &router,
        "GET",
        "/api/auth/me",
        &[(header::COOKIE.as_str(), j2_cookie.as_str())],
        Vec::new(),
    )
    .await;
    assert_eq!(gone_st, StatusCode::UNAUTHORIZED);

    // 6. Step-Up Re-Authentication check
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute("UPDATE sessions SET reauth_at = 1", []).unwrap();
    }
    let (su_fail, _, su_body) = send_json(
        &router,
        "POST",
        "/api/0/api-tokens/",
        &owner_hdrs,
        json!({ "name": "Needs StepUp", "role": "member" }),
    )
    .await;
    assert_eq!(su_fail, StatusCode::FORBIDDEN);
    assert_eq!(su_body["reauth_required"], true);

    let (reauth_ok, _, _) = send_json(
        &router,
        "POST",
        "/api/auth/reauth",
        &owner_hdrs,
        json!({ "password": "StrongPassword123!" }),
    )
    .await;
    assert_eq!(reauth_ok, StatusCode::OK);

    let (su_ok, _, _) = send_json(
        &router,
        "POST",
        "/api/0/api-tokens/",
        &owner_hdrs,
        json!({ "name": "After StepUp", "role": "member" }),
    )
    .await;
    assert_eq!(su_ok, StatusCode::CREATED);
}

#[tokio::test]
async fn security_mfa_totp_recovery_lockout_and_webauthn_test() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    use sha2::{Digest, Sha256};

    let (_dir, state, router, _, _) = setup_test_app().await;
    let (owner_cookie, owner_csrf) =
        login_cookie_and_csrf(&router, "owner@alpha.test", "StrongPassword123!").await;
    let owner_hdrs = [
        (header::COOKIE.as_str(), owner_cookie.as_str()),
        ("x-csrf-token", owner_csrf.as_str()),
        (header::HOST.as_str(), "127.0.0.1:8090"),
    ];

    // 1. TOTP enroll & CSP-clean QR SVG check
    let (en_st, _, en_b) = send_json(
        &router,
        "POST",
        "/api/auth/mfa/totp/enroll",
        &owner_hdrs,
        json!({}),
    )
    .await;
    assert_eq!(en_st, StatusCode::OK, "enroll: {en_b}");
    let qr_svg = en_b["qr_svg"].as_str().unwrap();
    assert!(qr_svg.starts_with("<svg class=\"qr-svg\""));
    assert!(!qr_svg.contains("style="));
    let secret_b32 = en_b["secret_b32"].as_str().unwrap();
    let secret_bytes = bugfinder::security::mfa::decode_base32(secret_b32).unwrap();

    // Confirm TOTP
    let now_s = chrono::Utc::now().timestamp();
    let totp_code = bugfinder::security::mfa::totp_code_at(&secret_bytes, now_s);
    let (cf_st, _, cf_b) = send_json(
        &router,
        "POST",
        "/api/auth/mfa/totp/confirm",
        &owner_hdrs,
        json!({ "code": totp_code }),
    )
    .await;
    assert_eq!(cf_st, StatusCode::OK, "confirm: {cf_b}");
    let rec_codes: Vec<String> = cf_b["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(rec_codes.len(), 10);

    // 2. Password login now yields 2-step mfa_required without cookie
    let (lg_st, lg_hdrs, lg_b) = send_json(
        &router,
        "POST",
        "/api/auth/login",
        &[],
        json!({ "email": "owner@alpha.test", "password": "StrongPassword123!" }),
    )
    .await;
    assert_eq!(lg_st, StatusCode::OK);
    assert_eq!(lg_b["mfa_required"], true);
    assert!(lg_hdrs.get(header::SET_COOKIE).is_none());
    let chall = lg_b["challenge_token"].as_str().unwrap().to_string();

    // 3. 5 bad MFA attempts trigger persistent lockout (429)
    let mut locked = false;
    for _ in 0..6 {
        let (bad_st, _, bad_b) = send_json(
            &router,
            "POST",
            "/api/auth/mfa/verify",
            &[],
            json!({ "challenge_token": chall, "code": "000000" }),
        )
        .await;
        if bad_st == StatusCode::TOO_MANY_REQUESTS {
            assert!(bad_b["retry_after"].as_i64().unwrap() > 0);
            locked = true;
            break;
        }
    }
    assert!(locked, "MFA brute-force lockout did not trigger");

    // Clear lockout so we can test valid code (same TOTP step used at confirm -> rejected until cleared or next step; use +30s? Even cleaner: test replay directly against confirm step first!)
    let db_path = state.config.sqlite_path();
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute("UPDATE user_mfa SET failed_attempts = 0, locked_until = NULL", [])
            .unwrap();
    }
    // Replay of SAME code used at confirm must fail 401
    let (rep_st, _, _) = send_json(
        &router,
        "POST",
        "/api/auth/mfa/verify",
        &[],
        json!({ "challenge_token": chall, "code": totp_code }),
    )
    .await;
    assert_eq!(rep_st, StatusCode::UNAUTHORIZED);

    // Move last_used_step back by 2 so current step is accepted cleanly, then test replay
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE user_mfa SET last_used_step = last_used_step - 2, failed_attempts = 0, locked_until = NULL",
            [],
        )
        .unwrap();
    }
    let fresh_code = bugfinder::security::mfa::totp_code_at(&secret_bytes, chrono::Utc::now().timestamp());
    let (ok_mfa, ok_hdrs, _) = send_json(
        &router,
        "POST",
        "/api/auth/mfa/verify",
        &[],
        json!({ "challenge_token": chall, "code": fresh_code }),
    )
    .await;
    assert_eq!(ok_mfa, StatusCode::OK);
    assert!(ok_hdrs.get(header::SET_COOKIE).is_some());

    // 4. Recovery code single-use verification
    let (_, _, lg2_b) = send_json(
        &router,
        "POST",
        "/api/auth/login",
        &[],
        json!({ "email": "owner@alpha.test", "password": "StrongPassword123!" }),
    )
    .await;
    let chall2 = lg2_b["challenge_token"].as_str().unwrap().to_string();
    let (rc_ok, rc_hdrs, _) = send_json(
        &router,
        "POST",
        "/api/auth/mfa/verify",
        &[],
        json!({ "challenge_token": chall2, "recovery_code": rec_codes[0] }),
    )
    .await;
    assert_eq!(rc_ok, StatusCode::OK);
    assert!(rc_hdrs.get(header::SET_COOKIE).is_some());

    // Reusing same recovery code must fail
    let (_, _, lg3_b) = send_json(
        &router,
        "POST",
        "/api/auth/login",
        &[],
        json!({ "email": "owner@alpha.test", "password": "StrongPassword123!" }),
    )
    .await;
    let chall3 = lg3_b["challenge_token"].as_str().unwrap().to_string();
    let (rc_reuse, _, _) = send_json(
        &router,
        "POST",
        "/api/auth/mfa/verify",
        &[],
        json!({ "challenge_token": chall3, "recovery_code": rec_codes[0] }),
    )
    .await;
    assert_eq!(rc_reuse, StatusCode::UNAUTHORIZED);

    // 5. Real ES256 WebAuthn Passkey registration + assertion + counter rollback rejection
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let pub_uncompressed = kp.public_key().as_ref();
    let cred_id = b"integ-passkey-id-001";

    let (pb_st, _, pb_b) = send_json(
        &router,
        "POST",
        "/api/auth/passkey/register/begin",
        &owner_hdrs,
        json!({}),
    )
    .await;
    assert_eq!(pb_st, StatusCode::OK);
    let reg_chall = pb_b["challenge"].as_str().unwrap();
    let reg_cdj = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "type": "webauthn.create",
            "challenge": reg_chall,
            "origin": "http://127.0.0.1:8090"
        }))
        .unwrap(),
    );

    // Build minimal CBOR attestationObject with authData (rpHash(32)|flags=0x41|signCount=0|aaguid(16)|len|credId|COSE_P256)
    fn enc_bytes(b: &[u8]) -> Vec<u8> {
        let mut o = if b.len() < 24 { vec![0x40 | (b.len() as u8)] } else { vec![0x58, b.len() as u8] };
        o.extend_from_slice(b);
        o
    }
    let mut cose = vec![0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21];
    cose.extend_from_slice(&enc_bytes(&pub_uncompressed[1..33]));
    cose.push(0x22);
    cose.extend_from_slice(&enc_bytes(&pub_uncompressed[33..65]));

    let mut reg_auth_data = Vec::new();
    reg_auth_data.extend_from_slice(&Sha256::digest(b"127.0.0.1"));
    reg_auth_data.push(0x41);
    reg_auth_data.extend_from_slice(&0u32.to_be_bytes());
    reg_auth_data.extend_from_slice(&[0u8; 16]);
    reg_auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    reg_auth_data.extend_from_slice(cred_id);
    reg_auth_data.extend_from_slice(&cose);

    let mut att_obj = vec![0xA2, 0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e', 0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a'];
    if reg_auth_data.len() < 256 {
        att_obj.push(0x58);
        att_obj.push(reg_auth_data.len() as u8);
    } else {
        att_obj.push(0x59);
        att_obj.extend_from_slice(&(reg_auth_data.len() as u16).to_be_bytes());
    }
    att_obj.extend_from_slice(&reg_auth_data);

    let (pf_st, _, pf_b) = send_json(
        &router,
        "POST",
        "/api/auth/passkey/register/finish",
        &owner_hdrs,
        json!({
            "name": "CI ES256 Passkey",
            "clientDataJSON": reg_cdj,
            "attestationObject": URL_SAFE_NO_PAD.encode(&att_obj),
        }),
    )
    .await;
    assert_eq!(pf_st, StatusCode::CREATED, "passkey reg finish: {pf_b}");

    // Passkey login assertion with sign_count = 1
    let sign_assertion = |chal: &str, count: u32| -> (String, String, String) {
        let cdj = serde_json::to_vec(&json!({
            "type": "webauthn.get",
            "challenge": chal,
            "origin": "http://127.0.0.1:8090"
        }))
        .unwrap();
        let mut ad = Vec::new();
        ad.extend_from_slice(&Sha256::digest(b"127.0.0.1"));
        ad.push(0x01);
        ad.extend_from_slice(&count.to_be_bytes());
        let mut msg = ad.clone();
        msg.extend_from_slice(&Sha256::digest(&cdj));
        let sig = kp.sign(&rng, &msg).unwrap();
        (
            URL_SAFE_NO_PAD.encode(&cdj),
            URL_SAFE_NO_PAD.encode(&ad),
            URL_SAFE_NO_PAD.encode(sig.as_ref()),
        )
    };

    let (lb_st, _, lb_b) = send_json(
        &router,
        "POST",
        "/api/auth/passkey/login/begin",
        &[(header::HOST.as_str(), "127.0.0.1:8090")],
        json!({ "email": "owner@alpha.test" }),
    )
    .await;
    assert_eq!(lb_st, StatusCode::OK);
    let (l_cdj, l_ad, l_sig) = sign_assertion(lb_b["challenge"].as_str().unwrap(), 1);
    let (lf_st, lf_hdrs, lf_b) = send_json(
        &router,
        "POST",
        "/api/auth/passkey/login/finish",
        &[(header::HOST.as_str(), "127.0.0.1:8090")],
        json!({
            "credentialId": URL_SAFE_NO_PAD.encode(cred_id),
            "clientDataJSON": l_cdj,
            "authenticatorData": l_ad,
            "signature": l_sig,
        }),
    )
    .await;
    assert_eq!(lf_st, StatusCode::OK, "passkey login finish: {lf_b}");
    let sess_from_pk = lf_hdrs
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let pk_csrf = lf_b["csrf_token"].as_str().unwrap().to_string();

    // Counter rollback (sign_count = 1 <= stored 1) rejected -> 401
    let (_, _, lb2_b) = send_json(
        &router,
        "POST",
        "/api/auth/passkey/login/begin",
        &[(header::HOST.as_str(), "127.0.0.1:8090")],
        json!({ "email": "owner@alpha.test" }),
    )
    .await;
    let (rb_cdj, rb_ad, rb_sig) = sign_assertion(lb2_b["challenge"].as_str().unwrap(), 1);
    let (rb_st, _, _) = send_json(
        &router,
        "POST",
        "/api/auth/passkey/login/finish",
        &[(header::HOST.as_str(), "127.0.0.1:8090")],
        json!({
            "credentialId": URL_SAFE_NO_PAD.encode(cred_id),
            "clientDataJSON": rb_cdj,
            "authenticatorData": rb_ad,
            "signature": rb_sig,
        }),
    )
    .await;
    assert_eq!(rb_st, StatusCode::UNAUTHORIZED);

    // 6. Password change rotates current session and revokes concurrent session
    let (pwc_st, pwc_hdrs, pwc_b) = send_json(
        &router,
        "POST",
        "/api/auth/password/change",
        &[
            (header::COOKIE.as_str(), sess_from_pk.as_str()),
            ("x-csrf-token", pk_csrf.as_str()),
        ],
        json!({
            "current_password": "StrongPassword123!",
            "new_password": "MasterVaultRotate!999" // gitleaks:allow
        }),
    )
    .await;
    assert_eq!(pwc_st, StatusCode::OK, "pw change: {pwc_b}");
    let rotated_cookie = pwc_hdrs
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let (old_me, _, _) = send_raw(
        &router,
        "GET",
        "/api/auth/me",
        &[(header::COOKIE.as_str(), owner_cookie.as_str())],
        Vec::new(),
    )
    .await;
    assert_eq!(old_me, StatusCode::UNAUTHORIZED);
    let (new_me, _, _) = send_raw(
        &router,
        "GET",
        "/api/auth/me",
        &[(header::COOKIE.as_str(), rotated_cookie.as_str())],
        Vec::new(),
    )
    .await;
    assert_eq!(new_me, StatusCode::OK);
}

#[tokio::test]
async fn security_aead_audit_chain_and_network_hardening_test() {
    let (_dir, state, router, dsn_key, project_id) = setup_test_app().await;
    let (owner_cookie, owner_csrf) =
        login_cookie_and_csrf(&router, "owner@alpha.test", "StrongPassword123!").await;
    let owner_hdrs = [
        (header::COOKIE.as_str(), owner_cookie.as_str()),
        ("x-csrf-token", owner_csrf.as_str()),
    ];

    // 1. AEAD sealing verification in raw SQLite for both MFA TOTP secret and Webhook HMAC secret
    let (_, _, _) = send_json(&router, "POST", "/api/auth/mfa/totp/enroll", &owner_hdrs, json!({})).await;
    let plain_wh = "whsec_raw_plaintext_test_only_12345"; // gitleaks:allow
    let (al_st, _, al_b) = send_json(
        &router,
        "POST",
        "/api/0/organizations/alpha/alerts/",
        &owner_hdrs,
        json!({
            "project_id": project_id,
            "name": "AEAD Hook",
            "trigger_type": "new_issue",
            "channel_type": "webhook",
            "target_url": "https://93.184.216.34/bf",
            "webhook_secret": plain_wh
        }),
    )
    .await;
    assert_eq!(al_st, StatusCode::CREATED, "alert create: {al_b}");

    let db_path = state.config.sqlite_path();
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let mfa_enc: String = conn
            .query_row("SELECT totp_secret_enc FROM user_mfa LIMIT 1", [], |r| r.get(0))
            .unwrap();
        let wh_enc: String = conn
            .query_row("SELECT webhook_secret FROM alert_rules WHERE name = 'AEAD Hook'", [], |r| r.get(0))
            .unwrap();
        assert!(mfa_enc.starts_with("enc:v1:"), "got {mfa_enc}");
        assert!(wh_enc.starts_with("enc:v1:"), "got {wh_enc}");
        assert!(!wh_enc.contains("whsec_raw_plaintext"));
    }

    // 2. Hash-chained audit log verification + tamper detection
    let (aud_st, _, aud_b) = send_json(
        &router,
        "GET",
        "/api/0/organizations/alpha/audit-logs/",
        &[(header::COOKIE.as_str(), owner_cookie.as_str())],
        Value::Null,
    )
    .await;
    assert_eq!(aud_st, StatusCode::OK);
    assert!(aud_b.as_array().unwrap().len() >= 3);

    let (ver_st, _, ver_b) = send_json(
        &router,
        "GET",
        "/api/0/organizations/alpha/audit-logs/verify/",
        &[(header::COOKIE.as_str(), owner_cookie.as_str())],
        Value::Null,
    )
    .await;
    assert_eq!(ver_st, StatusCode::OK);
    assert_eq!(ver_b["valid"], true);

    // 3. ALLOWED_HOSTS & X-Robots-Tag verification with production config
    {
        let prod_dir = TempDir::new().unwrap();
        let mut prod_cfg = AppConfig::from_env_and_overrides(
            Some("127.0.0.1:0".into()),
            Some(prod_dir.path().to_path_buf()),
            None,
            false,
        )
        .unwrap();
        prod_cfg.is_dev = false;
        prod_cfg.allowed_hosts = vec!["bugs.example.com".into()];
        let prod_storage: Arc<dyn StorageBackend> =
            SqliteStorage::open_with_key(&prod_cfg.sqlite_path(), prod_cfg.app_key).unwrap();
        let prod_router = build_router(build_app_state(Arc::new(prod_cfg), prod_storage));

        let (bad_host, _, _) = send_raw(
            &prod_router,
            "GET",
            "/api/health",
            &[(header::HOST.as_str(), "evil.attacker")],
            Vec::new(),
        )
        .await;
        assert_eq!(bad_host, StatusCode::FORBIDDEN);

        let (good_host, good_hdrs, _) = send_raw(
            &prod_router,
            "GET",
            "/api/health",
            &[(header::HOST.as_str(), "bugs.example.com")],
            Vec::new(),
        )
        .await;
        assert_eq!(good_host, StatusCode::OK);
        assert_eq!(
            good_hdrs.get("x-robots-tag").unwrap().to_str().unwrap(),
            "noindex, nofollow, noarchive"
        );
    }

    // 4. Cross-origin mutation rejected -> 403
    let (xo_st, _, _) = send_json(
        &router,
        "POST",
        "/api/0/organizations/alpha/projects/",
        &[
            (header::COOKIE.as_str(), owner_cookie.as_str()),
            ("x-csrf-token", owner_csrf.as_str()),
            (header::HOST.as_str(), "127.0.0.1:8090"),
            (header::ORIGIN.as_str(), "https://evil.test"),
        ],
        json!({ "name": "CrossOriginProj" }),
    )
    .await;
    assert_eq!(xo_st, StatusCode::FORBIDDEN);

    // 5. Strict CORS (Vary: Origin), event_throttle_rate=100 drop, org IP scrub override & aggressive_key_match
    let (pset_st, _, _) = send_json(
        &router,
        "PUT",
        "/api/0/projects/alpha/rolelane/settings/",
        &owner_hdrs,
        json!({
            "allowed_domains": ["app.example.com"],
            "scrub_ip_addresses": false,
            "aggressive_key_match": true,
            "event_throttle_rate": 0
        }),
    )
    .await;
    assert_eq!(pset_st, StatusCode::OK);

    let sentry_auth = format!("Sentry sentry_version=7, sentry_key={dsn_key}");
    let (_, bad_cors_hdrs, _) = send_json(
        &router,
        "POST",
        &format!("/api/{project_id}/store/"),
        &[
            ("x-sentry-auth", &sentry_auth),
            (header::ORIGIN.as_str(), "https://evil.test"),
        ],
        json!({ "event_id": "22222222222222222222222222222221", "message": "cors deny" }),
    )
    .await;
    assert!(bad_cors_hdrs.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    assert_eq!(bad_cors_hdrs.get(header::VARY).unwrap(), "Origin");

    let (_, ok_cors_hdrs, _) = send_json(
        &router,
        "POST",
        &format!("/api/{project_id}/store/"),
        &[
            ("x-sentry-auth", &sentry_auth),
            (header::ORIGIN.as_str(), "https://app.example.com"),
        ],
        json!({ "event_id": "22222222222222222222222222222222", "message": "cors allow" }),
    )
    .await;
    assert_eq!(
        ok_cors_hdrs.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
        "https://app.example.com"
    );
    assert_eq!(ok_cors_hdrs.get(header::VARY).unwrap(), "Origin");

    // Org security settings: event_throttle_rate = 100 drops event
    let (oset1, _, _) = send_json(
        &router,
        "PUT",
        "/api/0/organizations/alpha/security-settings/",
        &owner_hdrs,
        json!({ "scrub_ip_addresses": true, "event_throttle_rate": 100, "require_mfa_for_admins": false }),
    )
    .await;
    assert_eq!(oset1, StatusCode::OK);
    let (drop_st, _, drop_b) = send_json(
        &router,
        "POST",
        &format!("/api/{project_id}/store/"),
        &[("x-sentry-auth", &sentry_auth)],
        json!({ "event_id": "33333333333333333333333333333333", "message": "should drop" }),
    )
    .await;
    assert_eq!(drop_st, StatusCode::OK);
    assert_eq!(drop_b["filtered"], true);

    // Lower org throttle to 0 while keeping org scrub_ip_addresses=true; test aggressive_key_match
    let (oset2, _, _) = send_json(
        &router,
        "PUT",
        "/api/0/organizations/alpha/security-settings/",
        &owner_hdrs,
        json!({ "scrub_ip_addresses": true, "event_throttle_rate": 0, "require_mfa_for_admins": false }),
    )
    .await;
    assert_eq!(oset2, StatusCode::OK);

    let (_, _, stored_res) = send_json(
        &router,
        "POST",
        &format!("/api/{project_id}/store/"),
        &[("x-sentry-auth", &sentry_auth)],
        json!({
            "event_id": "44444444444444444444444444444444",
            "message": "scrub override",
            "user": { "ip_address": "198.51.100.42" },
            "extra": { "custom_auth_token": "tok_leak_999" } // gitleaks:allow
        }),
    )
    .await;
    let stored_eid = stored_res["id"].as_str().unwrap().to_string();
    state.batch_writer.flush_now().await;

    let (_, _, issues_b) = send_json(
        &router,
        "GET",
        "/api/0/organizations/alpha/issues/",
        &[(header::COOKIE.as_str(), owner_cookie.as_str())],
        Value::Null,
    )
    .await;
    let target_issue_id = issues_b
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["title"].as_str().unwrap_or("").contains("scrub override"))
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    let (_, _, ev_det) = send_json(
        &router,
        "GET",
        &format!("/api/0/organizations/alpha/issues/{target_issue_id}/events/{stored_eid}/"),
        &[(header::COOKIE.as_str(), owner_cookie.as_str())],
        Value::Null,
    )
    .await;
    let payload_txt = ev_det["payload"].to_string();
    assert!(!payload_txt.contains("198.51.100.42"), "Org IP scrub failed: {payload_txt}");
    assert!(!payload_txt.contains("tok_leak_999"), "aggressive_key_match failed: {payload_txt}");

    // 6. Negative DSN cache hits 401 and blocks bad key in-memory
    let (bad_dsn, _, _) = send_json(
        &router,
        "POST",
        &format!("/api/{project_id}/store/?sentry_key=bad_dsn_key_999"),
        &[],
        json!({ "message": "x" }),
    )
    .await;
    assert_eq!(bad_dsn, StatusCode::UNAUTHORIZED);
    assert!(state
        .invalid_dsn_cache
        .is_blocked(project_id, &sha256_hex(b"bad_dsn_key_999")));

    // 7. Self-check exposes all 5 new security checks + audit tamper triggers valid=false
    let (sc_st, _, sc_b) = send_json(
        &router,
        "GET",
        "/api/0/organizations/alpha/self-check/",
        &[(header::COOKIE.as_str(), owner_cookie.as_str())],
        Value::Null,
    )
    .await;
    assert_eq!(sc_st, StatusCode::OK);
    let chk_ids: Vec<&str> = sc_b["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    for want in [
        "allowed_hosts_configured",
        "mfa_owner_posture",
        "audit_chain_integrity",
        "api_token_hygiene",
        "aead_secret_encryption",
    ] {
        assert!(chk_ids.contains(&want), "missing self-check item {want}");
    }

    // Tamper audit_logs metadata in SQLite -> verify_audit_chain returns valid == false
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE audit_logs SET metadata_json = '{\"tampered\":true}' WHERE id = (SELECT MIN(id) FROM audit_logs)",
            [],
        )
        .unwrap();
    }
    let (_, _, tamp_b) = send_json(
        &router,
        "GET",
        "/api/0/organizations/alpha/audit-logs/verify/",
        &[(header::COOKIE.as_str(), owner_cookie.as_str())],
        Value::Null,
    )
    .await;
    assert_eq!(tamp_b["valid"], false);
    assert!(tamp_b["broken_at_id"].as_i64().is_some());
}
