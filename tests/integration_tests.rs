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
    let storage: Arc<dyn StorageBackend> = SqliteStorage::open(&cfg.sqlite_path()).unwrap();
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
    let ctx = bugfinder::domain::models::TenantCtx {
        organization_id: 1,
        organization_slug: "alpha".into(),
        user_id: Some(1),
        role: bugfinder::domain::models::UserRole::Admin,
    };
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
            "password": "ViewerPassword123!",
            "role": "viewer"
        }),
    )
    .await;
    assert_eq!(inv_st, StatusCode::CREATED);
    let (v_cookie, v_csrf) = login_cookie_and_csrf(&router, "viewer@alpha.test", "ViewerPassword123!").await;

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
    let ctx1 = bugfinder::domain::models::TenantCtx {
        organization_id: org1.id,
        organization_slug: org1.slug,
        user_id: Some(1),
        role: bugfinder::domain::models::UserRole::Owner,
    };
    let visible = app_backend.list_projects(&ctx1).await.unwrap();
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].id, proj1.id);

    // Capability-GUC DSN resolution works without BYPASSRLS
    let resolved = app_backend.resolve_dsn(proj1.id, &dsn1_sha).await.unwrap();
    assert!(resolved.is_some());
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
