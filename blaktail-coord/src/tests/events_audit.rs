//! Audit, traffic, notification and automation API tests (drafts 17, 18, 22).

use super::*;

fn session(user_id: &str, role: Role) -> Session {
    Session {
        user_id: user_id.into(),
        role,
        name: user_id.into(),
        email: format!("{user_id}@example.com"),
    }
}

async fn api(
    router: &Router,
    method: Method,
    uri: &str,
    org_id: Uuid,
    token: &str,
    body: serde_json::Value,
) -> Response {
    let token = if token.starts_with("test:") {
        sign_test_assertion(token)
    } else {
        token.to_owned()
    };
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .header("content-type", "application/json")
                .header("x-blaktail-organisation", org_id.to_string())
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn api_client(
    router: &Router,
    org_id: Uuid,
    owner: &str,
    name: &str,
    scopes: &[&str],
) -> String {
    let created: crate::admin::ApiClientCreated = body(
        call(
            router,
            Method::POST,
            &format!("/v1/orgs/{org_id}/api-clients"),
            serde_json::json!({"name": name, "scopes": scopes}),
            Some(owner),
        )
        .await,
    )
    .await;
    created.token
}

async fn text(response: Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

async fn seed_audit(store: &Store, org_id: Uuid, count: usize) {
    let actor = session("seed-admin", Role::Admin);
    let mut tx = store.pool.begin().await.unwrap();
    for i in 0..count {
        append_audit(
            &mut tx,
            org_id,
            &actor,
            if i % 2 == 0 { "node.seeded" } else { "policy.seeded" },
            "node",
            Some(&format!("n-{i}")),
            &serde_json::json!({"i": i, "client_secret": "hunter2", "note": "btk_aaaaaaaaaaaaaaaaaaaaaaaa"}),
        )
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
}

async fn verify_report(
    router: &Router,
    org_id: Uuid,
    token: &str,
) -> crate::audit_log::ChainReport {
    body(
        call(
            router,
            Method::GET,
            &format!("/v1/orgs/{org_id}/audit/verify"),
            serde_json::Value::Null,
            Some(token),
        )
        .await,
    )
    .await
}

#[tokio::test]
async fn audit_pages_beyond_one_hundred_with_filters_redaction_and_chain() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "audit-pages").await;
    let member = signed_session(org.id, "member-1", Role::Member, now() + 60);
    seed_audit(&store, org.id, 230).await;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE org_id=$1")
        .bind(org.id.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert!(total > 200);

    // Every row, exactly once, across pages of 100 — even though most rows
    // share one created_at second and only the id breaks the tie.
    let mut seen = BTreeSet::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let uri = match &cursor {
            Some(before) => format!("/v1/orgs/{}/audit?limit=100&before={before}", org.id),
            None => format!("/v1/orgs/{}/audit?limit=100", org.id),
        };
        let page: Vec<AuditEvent> = body(
            call(
                &router,
                Method::GET,
                &uri,
                serde_json::Value::Null,
                Some(&member),
            )
            .await,
        )
        .await;
        if page.is_empty() {
            break;
        }
        pages += 1;
        for event in &page {
            assert!(seen.insert(event.id.clone()), "duplicate {}", event.id);
            let rendered = event.details.to_string();
            assert!(!rendered.contains("hunter2"), "{rendered}");
            assert!(!rendered.contains("btk_"), "{rendered}");
        }
        let last = page.last().unwrap();
        cursor = Some(format!("{}:{}", last.created_at, last.id));
    }
    assert_eq!(seen.len() as i64, total);
    assert!(pages >= 3);

    // Filters: action prefix, actor, target id and an empty date window.
    let filtered: Vec<AuditEvent> = body(
        call(
            &router,
            Method::GET,
            &format!(
                "/v1/orgs/{}/audit?limit=200&action=node.*&actor=SEED-ADMIN@example.com",
                org.id
            ),
            serde_json::Value::Null,
            Some(&member),
        )
        .await,
    )
    .await;
    assert_eq!(filtered.len(), 115);
    assert!(filtered.iter().all(|event| event.action == "node.seeded"));
    let one: Vec<AuditEvent> = body(
        call(
            &router,
            Method::GET,
            &format!("/v1/orgs/{}/audit?target_id=n-7&target_type=node", org.id),
            serde_json::Value::Null,
            Some(&member),
        )
        .await,
    )
    .await;
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].details["client_secret"], "[redacted]");
    let future: Vec<AuditEvent> = body(
        call(
            &router,
            Method::GET,
            &format!("/v1/orgs/{}/audit?since={}", org.id, now() + 3600),
            serde_json::Value::Null,
            Some(&member),
        )
        .await,
    )
    .await;
    assert!(future.is_empty());
    assert_eq!(
        call(
            &router,
            Method::GET,
            &format!("/v1/orgs/{}/audit?since=10&until=5", org.id),
            serde_json::Value::Null,
            Some(&member),
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );

    // The hash chain verifies, then detects an edit and a deletion.
    let report = verify_report(&router, org.id, &member).await;
    assert!(report.intact, "{:?}", report.problems);
    assert_eq!(report.chained_events, 230);
    assert_eq!(
        report.unchained_events, 1,
        "bootstrap row predates the chain"
    );
    sqlx::query(
        "UPDATE audit_events SET details_json='{\"i\":-1}' WHERE org_id=$1 AND target_id='n-5'",
    )
    .bind(org.id.to_string())
    .execute(&store.pool)
    .await
    .unwrap();
    let report = verify_report(&router, org.id, &member).await;
    assert!(!report.intact);
    assert!(
        report.problems[0].contains("does not match"),
        "{:?}",
        report.problems
    );
    sqlx::query("DELETE FROM audit_events WHERE org_id=$1 AND target_id='n-100'")
        .bind(org.id.to_string())
        .execute(&store.pool)
        .await
        .unwrap();
    let report = verify_report(&router, org.id, &member).await;
    assert!(
        report.problems.iter().any(|p| p.contains("missing")),
        "{:?}",
        report.problems
    );
}

#[tokio::test]
async fn audit_export_is_permissioned_audited_and_org_scoped() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "audit-export").await;
    let other = create_test_org(&router, "audit-export-other").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let auditor = signed_session(org.id, "auditor-1", Role::Auditor, now() + 60);
    let member = signed_session(org.id, "member-1", Role::Member, now() + 60);
    let network_admin = signed_session(org.id, "netadmin-1", Role::NetworkAdmin, now() + 60);
    let other_owner = signed_session(other.id, "owner-2", Role::Owner, now() + 60);
    seed_audit(&store, org.id, 5).await;
    seed_audit(&store, other.id, 3).await;

    let export_uri = format!("/v1/orgs/{}/audit/export?format=csv&action=node.", org.id);
    for (who, token) in [("member", &member), ("network admin", &network_admin)] {
        assert_eq!(
            call(
                &router,
                Method::GET,
                &export_uri,
                serde_json::Value::Null,
                Some(token)
            )
            .await
            .status(),
            StatusCode::FORBIDDEN,
            "{who} must not export"
        );
    }
    // Another organisation's owner cannot reach this organisation's export.
    let cross = call(
        &router,
        Method::GET,
        &export_uri,
        serde_json::Value::Null,
        Some(&other_owner),
    )
    .await
    .status();
    assert!(
        matches!(cross, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
        "{cross}"
    );

    let response = call(
        &router,
        Method::GET,
        &export_uri,
        serde_json::Value::Null,
        Some(&auditor),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers()[axum::http::header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("text/csv"));
    assert_eq!(response.headers()["x-blaktail-export-truncated"], "false");
    let csv = text(response).await;
    assert_eq!(csv.lines().count(), 1 + 3, "{csv}");
    assert!(!csv.contains("hunter2") && !csv.contains("btk_"), "{csv}");

    let json: crate::audit_log::ExportBody = body(
        call(
            &router,
            Method::GET,
            &format!("/v1/orgs/{}/audit/export?format=json", org.id),
            serde_json::Value::Null,
            Some(&owner),
        )
        .await,
    )
    .await;
    assert!(!json.truncated);
    assert!(json
        .data
        .iter()
        .all(|event| event.target_type != "organisation"
            || event.target_id.as_deref() != Some(&other.id.to_string())));
    assert!(json
        .data
        .iter()
        .any(|event| event.action == "audit.exported"));
    assert_eq!(
        call(
            &router,
            Method::GET,
            &format!("/v1/orgs/{}/audit/export?format=xml", org.id),
            serde_json::Value::Null,
            Some(&owner),
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );

    let exports: Vec<(String, String)> = sqlx::query_as(
        "SELECT actor_user_id,details_json FROM audit_events WHERE org_id=$1 AND action='audit.exported' ORDER BY chain_seq",
    )
    .bind(org.id.to_string())
    .fetch_all(&store.pool)
    .await
    .unwrap();
    assert_eq!(exports.len(), 2);
    assert_eq!(exports[0].0, "auditor-1");
    assert!(exports[0].1.contains("\"count\":3"), "{}", exports[0].1);
    let other_exports: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE org_id=$1 AND action='audit.exported'",
    )
    .bind(other.id.to_string())
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(other_exports, 0);

    // Automation: audit:read cannot export, audit:export can, and a token
    // never reaches another organisation.
    let reader = api_client(&router, org.id, &owner, "reader", &["audit:read"]).await;
    let exporter = api_client(&router, org.id, &owner, "exporter", &["audit:export"]).await;
    assert_eq!(
        api(
            &router,
            Method::GET,
            "/api/v1/audit/export",
            org.id,
            &reader,
            serde_json::Value::Null
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        api(
            &router,
            Method::GET,
            "/api/v1/audit/export?format=csv",
            org.id,
            &exporter,
            serde_json::Value::Null
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        api(
            &router,
            Method::GET,
            "/api/v1/audit/export",
            other.id,
            &exporter,
            serde_json::Value::Null
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let page: serde_json::Value = body(
        api(
            &router,
            Method::GET,
            "/api/v1/audit?limit=2&action=node.*",
            org.id,
            &reader,
            serde_json::Value::Null,
        )
        .await,
    )
    .await;
    assert_eq!(page["data"].as_array().unwrap().len(), 2);
    assert!(page["next_cursor"].is_string());
    let verify: serde_json::Value = body(
        api(
            &router,
            Method::GET,
            "/api/v1/audit/verify",
            org.id,
            &reader,
            serde_json::Value::Null,
        )
        .await,
    )
    .await;
    assert_eq!(verify["data"]["intact"], true);
}

fn flow_record(org_id: Uuid, device_id: Uuid) -> serde_json::Value {
    let bucket = now() - 120;
    serde_json::json!({
        "org_id": org_id,
        "device_id": device_id,
        "service": "ssh",
        "start_bucket": bucket,
        "end_bucket": bucket + 60,
        "proto": "tcp",
        "port": 22,
        "bytes": 4096,
        "packets": 12,
        "transport": "direct",
        "decision": "allowed",
    })
}

async fn upload(router: &Router, node: &RegisterResponse, payload: serde_json::Value) -> Response {
    call(
        router,
        Method::POST,
        &format!("/v1/nodes/{}/flows", node.id),
        payload,
        Some(&node.node_token),
    )
    .await
}

#[tokio::test]
async fn traffic_is_owner_opt_in_and_ingest_rejects_disabled_foreign_and_payload_uploads() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "traffic-org").await;
    let other = create_test_org(&router, "traffic-other").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let admin = signed_session(org.id, "admin-1", Role::Admin, now() + 60);
    let auditor = signed_session(org.id, "auditor-1", Role::Auditor, now() + 60);
    let other_owner = signed_session(other.id, "owner-2", Role::Owner, now() + 60);
    let node = register_test_node(&router, org.id, &owner, "laptop", "traffic-key", &[]).await;
    let foreign = register_test_node(
        &router,
        other.id,
        &other_owner,
        "foreign",
        "foreign-key",
        &[],
    )
    .await;
    let summary_uri = format!("/v1/orgs/{}/traffic/summary", org.id);
    let settings_uri = format!("/v1/orgs/{}/traffic/settings", org.id);

    // Off by default: nothing is accepted and the summary says so.
    let summary: crate::traffic::TrafficSummary = body(
        call(
            &router,
            Method::GET,
            &summary_uri,
            serde_json::Value::Null,
            Some(&auditor),
        )
        .await,
    )
    .await;
    assert_eq!(summary.state, "disabled");
    assert!(!summary.settings.enabled);
    let disabled = upload(
        &router,
        &node,
        serde_json::json!({"records":[flow_record(org.id, node.id)]}),
    )
    .await;
    assert_eq!(disabled.status(), StatusCode::CONFLICT);

    // Only an owner can opt in.
    for token in [&admin, &auditor] {
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &settings_uri,
                serde_json::json!({"enabled":true}),
                Some(token)
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        call(
            &router,
            Method::PUT,
            &settings_uri,
            serde_json::json!({"enabled":true,"sampling_rate":0}),
            Some(&owner)
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &router,
            Method::PUT,
            &settings_uri,
            serde_json::json!({"enabled":true,"retention_days":90}),
            Some(&owner)
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let enabled: crate::traffic::TrafficSettings = body(
        call(
            &router,
            Method::PUT,
            &settings_uri,
            serde_json::json!({"enabled":true,"retention_days":3}),
            Some(&owner),
        )
        .await,
    )
    .await;
    assert!(enabled.enabled);
    assert_eq!(enabled.retention_days, 3);
    let summary: crate::traffic::TrafficSummary = body(
        call(
            &router,
            Method::GET,
            &summary_uri,
            serde_json::Value::Null,
            Some(&auditor),
        )
        .await,
    )
    .await;
    assert_eq!(summary.state, "no_data");
    assert_eq!(summary.confidence.level, "none");

    // Payload-shaped, unknown, foreign-org and foreign-device uploads fail.
    let mut with_url = flow_record(org.id, node.id);
    with_url["url"] = serde_json::json!("https://bank.example/login");
    let mut with_query = flow_record(org.id, node.id);
    with_query["dns_query"] = serde_json::json!("bank.example");
    let mut with_unknown = flow_record(org.id, node.id);
    with_unknown["peer_hostname_hint"] = serde_json::json!("x");
    let mut named_service = flow_record(org.id, node.id);
    named_service["service"] = serde_json::json!("bank.example");
    for bad in [with_url, with_query, with_unknown, named_service] {
        assert_eq!(
            upload(&router, &node, serde_json::json!({"records":[bad]}))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        upload(
            &router,
            &node,
            serde_json::json!({"records":[flow_record(other.id, node.id)]})
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        upload(
            &router,
            &node,
            serde_json::json!({"records":[flow_record(org.id, foreign.id)]})
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    // The other organisation never opted in.
    assert_eq!(
        upload(
            &router,
            &foreign,
            serde_json::json!({"records":[flow_record(other.id, foreign.id)]})
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    let wrong_token = call(
        &router,
        Method::POST,
        &format!("/v1/nodes/{}/flows", node.id),
        serde_json::json!({"records":[]}),
        Some(&foreign.node_token),
    )
    .await;
    assert_eq!(wrong_token.status(), StatusCode::UNAUTHORIZED);
    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM flow_records")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(stored, 0);

    let mut denied = flow_record(org.id, node.id);
    denied["decision"] = serde_json::json!("denied");
    denied["transport"] = serde_json::json!("udp_relay");
    denied["port"] = serde_json::json!(3389);
    let accepted: crate::traffic::UploadResult = body(
        upload(
            &router,
            &node,
            serde_json::json!({"records":[flow_record(org.id, node.id), denied]}),
        )
        .await,
    )
    .await;
    assert_eq!(accepted.accepted, 2);
    let summary: crate::traffic::TrafficSummary = body(
        call(
            &router,
            Method::GET,
            &summary_uri,
            serde_json::Value::Null,
            Some(&auditor),
        )
        .await,
    )
    .await;
    assert_eq!(summary.state, "current");
    assert_eq!(summary.allowed.bytes, 4096);
    assert_eq!(summary.denied.records, 1);
    assert_eq!(summary.by_transport["udp_relay"].records, 1);
    assert_eq!(summary.confidence.reporting_devices, 1);
    assert_eq!(summary.buckets.len(), 1);
    // The other organisation's owner sees nothing of it.
    let cross = call(
        &router,
        Method::GET,
        &summary_uri,
        serde_json::Value::Null,
        Some(&other_owner),
    )
    .await
    .status();
    assert!(matches!(
        cross,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ));

    // Turning it off stops the very next upload.
    call(
        &router,
        Method::PUT,
        &settings_uri,
        serde_json::json!({"enabled":false}),
        Some(&owner),
    )
    .await;
    assert_eq!(
        upload(
            &router,
            &node,
            serde_json::json!({"records":[flow_record(org.id, node.id)]})
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    let summary: crate::traffic::TrafficSummary = body(
        call(
            &router,
            Method::GET,
            &summary_uri,
            serde_json::Value::Null,
            Some(&auditor),
        )
        .await,
    )
    .await;
    assert_eq!(summary.state, "disabled");

    // Retention purge and owner deletion are bounded and audited.
    sqlx::query("UPDATE flow_records SET created_at=created_at-4*86400")
        .execute(&store.pool)
        .await
        .unwrap();
    assert_eq!(crate::traffic::purge_expired(&store).await.unwrap(), 2);
    assert_eq!(
        call(
            &router,
            Method::DELETE,
            &format!("/v1/orgs/{}/traffic/records", org.id),
            serde_json::Value::Null,
            Some(&admin)
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE org_id=$1 AND action LIKE 'traffic.%' ORDER BY chain_seq",
    )
    .bind(org.id.to_string())
    .fetch_all(&store.pool)
    .await
    .unwrap();
    assert_eq!(
        actions,
        vec!["traffic.settings_updated", "traffic.settings_updated"]
    );
}

async fn outbox(store: &Store, destination_id: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT event_type FROM webhook_outbox WHERE destination_id=$1 ORDER BY event_type",
    )
    .bind(destination_id.to_string())
    .fetch_all(&store.pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn webhook_subscriptions_filter_new_events_and_reject_unsafe_destinations() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "notify-org").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let member = signed_session(org.id, "member-1", Role::Member, now() + 60);
    let hooks = format!("/v1/orgs/{}/webhooks", org.id);

    for unsafe_url in [
        "https://169.254.169.254/latest/meta-data",
        "https://[::ffff:169.254.169.254]/latest",
        "https://[fd00:ec2::254]/latest",
        "https://100.100.100.200/latest",
        "https://metadata.google.internal/computeMetadata/v1",
        "https://localhost/hook",
    ] {
        let response = call(
            &router,
            Method::POST,
            &hooks,
            serde_json::json!({"name":"bad","url":unsafe_url}),
            Some(&owner),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{unsafe_url}");
    }
    assert_eq!(
        call(&router, Method::POST, &hooks, serde_json::json!({"name":"bad","url":"http://127.0.0.1:9/x","event_types":["email.digest"]}), Some(&owner))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );

    let everything: crate::webhooks::WebhookDestination = body(
        call(
            &router,
            Method::POST,
            &hooks,
            serde_json::json!({"name":"all","url":"http://127.0.0.1:9/all"}),
            Some(&owner),
        )
        .await,
    )
    .await;
    assert_eq!(everything.event_types, vec!["*"]);
    let routes_only: crate::webhooks::WebhookDestination = body(
        call(
            &router,
            Method::POST,
            &hooks,
            serde_json::json!({"name":"routes","url":"http://127.0.0.1:9/routes","event_types":["route.approved"]}),
            Some(&owner),
        )
        .await,
    )
    .await;
    let security: crate::webhooks::WebhookDestination = body(
        call(
            &router,
            Method::POST,
            &hooks,
            serde_json::json!({"name":"security","url":"http://127.0.0.1:9/sec"}),
            Some(&owner),
        )
        .await,
    )
    .await;
    let subscriptions = format!("/v1/orgs/{}/webhooks/{}/subscriptions", org.id, security.id);
    assert_eq!(
        call(
            &router,
            Method::PUT,
            &subscriptions,
            serde_json::json!({"event_types":["posture.failed"]}),
            Some(&member)
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &router,
            Method::PUT,
            &subscriptions,
            serde_json::json!({"event_types":["slack.message"]}),
            Some(&owner)
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let updated: crate::notifications::SubscriptionView = body(
        call(
            &router,
            Method::PUT,
            &subscriptions,
            serde_json::json!({"event_types":["service_user.suspended","posture.failed","credential.expiring","traffic.settings_changed"]}),
            Some(&owner),
        )
        .await,
    )
    .await;
    assert_eq!(updated.event_types.len(), 4);

    // Enrolment via join key, route approval, posture regression, service
    // user suspension, credential expiry and the traffic toggle.
    let node = register_test_node(
        &router,
        org.id,
        &owner,
        "gateway",
        "gateway-key",
        &["10.9.0.0/24"],
    )
    .await;
    assert_eq!(
        call(
            &router,
            Method::PUT,
            &format!("/v1/orgs/{}/nodes/{}/routes", org.id, node.id),
            serde_json::json!({"approved_routes":["10.9.0.0/24"]}),
            Some(&owner),
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    let check = call(
        &router,
        Method::POST,
        &format!("/v1/orgs/{}/posture-checks", org.id),
        serde_json::json!({"name":"baseline","definition":{"min_agent_version":"1.0.0"}}),
        Some(&owner),
    )
    .await;
    assert_eq!(check.status(), StatusCode::CREATED);
    assert_eq!(
        call(
            &router,
            Method::PUT,
            &format!("/v1/orgs/{}/acl", org.id),
            serde_json::json!({"defaults":"deny","groups":{"crew":["owner-1"]},"rules":[{"action":"allow","src_groups":["crew"],"dst_groups":["crew"],"dst_ports":["22"],"protocols":["tcp"],"posture":["baseline"]}]}),
            Some(&owner),
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    for version in ["1.2.0", "0.9.0"] {
        let response = call(
            &router,
            Method::GET,
            &format!("/v1/nodes/{}/peers?agent_version={version}", node.id),
            serde_json::Value::Null,
            Some(&node.node_token),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    let client: crate::admin::ApiClientCreated = body(
        call(
            &router,
            Method::POST,
            &format!("/v1/orgs/{}/api-clients", org.id),
            serde_json::json!({"name":"ci","scopes":["status:read"]}),
            Some(&owner),
        )
        .await,
    )
    .await;
    assert_eq!(
        call(
            &router,
            Method::POST,
            &format!("/v1/orgs/{}/api-clients/{}/suspend", org.id, client.id),
            serde_json::Value::Null,
            Some(&owner),
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    sqlx::query("UPDATE nodes SET credential_expires_at=$1 WHERE id=$2")
        .bind(now() + 3600)
        .bind(node.id.to_string())
        .execute(&store.pool)
        .await
        .unwrap();
    crate::notifications::enqueue_expiring_credentials(&store, now())
        .await
        .unwrap();
    crate::notifications::enqueue_expiring_credentials(&store, now())
        .await
        .unwrap();
    call(
        &router,
        Method::PUT,
        &format!("/v1/orgs/{}/traffic/settings", org.id),
        serde_json::json!({"enabled":true}),
        Some(&owner),
    )
    .await;

    assert_eq!(outbox(&store, routes_only.id).await, vec!["route.approved"]);
    assert_eq!(
        outbox(&store, security.id).await,
        vec![
            "credential.expiring",
            "posture.failed",
            "service_user.suspended",
            "traffic.settings_changed"
        ],
        "one expiry notice despite two sweeps"
    );
    let all = outbox(&store, everything.id).await;
    for event in [
        "device.enrolled",
        "join_key.used",
        "route.approved",
        "posture.failed",
        "service_user.suspended",
        "credential.expiring",
        "traffic.settings_changed",
        "policy.published",
    ] {
        assert!(
            all.contains(&event.to_owned()),
            "{event} missing from {all:?}"
        );
    }
    let payload: String = sqlx::query_scalar(
        "SELECT payload_json FROM webhook_outbox WHERE destination_id=$1 AND event_type='posture.failed'",
    )
    .bind(security.id.to_string())
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert!(payload.contains("baseline"), "{payload}");

    // A disabled destination receives nothing further.
    call(
        &router,
        Method::DELETE,
        &format!("{hooks}/{}", routes_only.id),
        serde_json::Value::Null,
        Some(&owner),
    )
    .await;
    call(
        &router,
        Method::PUT,
        &format!("/v1/orgs/{}/nodes/{}/routes", org.id, node.id),
        serde_json::json!({"approved_routes":[]}),
        Some(&owner),
    )
    .await;
    assert_eq!(outbox(&store, routes_only.id).await, vec!["route.approved"]);

    // Role changes arrive from the console as their own catalogued event.
    assert_eq!(
        call(
            &router,
            Method::POST,
            &format!("{hooks}/events"),
            serde_json::json!({"event_type":"membership.role_changed","payload":{"membership_id":"m-1","role":"auditor"}}),
            Some(&owner),
        )
        .await
        .status(),
        StatusCode::ACCEPTED
    );
    assert!(outbox(&store, everything.id)
        .await
        .contains(&"membership.role_changed".to_owned()));

    let catalogue: Vec<serde_json::Value> = body(
        call(
            &router,
            Method::GET,
            &format!("/v1/orgs/{}/events/catalogue", org.id),
            serde_json::Value::Null,
            Some(&member),
        )
        .await,
    )
    .await;
    assert!(catalogue
        .iter()
        .any(|kind| kind["event_type"] == "posture.failed" && kind["severity"] == "warning"));
}

#[tokio::test]
async fn automation_api_shares_console_permissions_and_validation() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "parity-org").await;
    let other = create_test_org(&router, "parity-other").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let auditor = signed_session(org.id, "auditor-1", Role::Auditor, now() + 60);
    let writer = api_client(
        &router,
        org.id,
        &owner,
        "tf-writer",
        &["policy:write", "devices:read", "keys:write"],
    )
    .await;
    let reader = api_client(
        &router,
        org.id,
        &owner,
        "tf-reader",
        &["devices:read", "keys:read"],
    )
    .await;

    // Same invalid posture definition: same status and message on both paths.
    let invalid = serde_json::json!({"name":"bad","definition":{"os_families":["beos"]}});
    let console = call(
        &router,
        Method::POST,
        &format!("/v1/orgs/{}/posture-checks", org.id),
        invalid.clone(),
        Some(&owner),
    )
    .await;
    let automation = api(
        &router,
        Method::POST,
        "/api/v1/posture-checks",
        org.id,
        &writer,
        invalid,
    )
    .await;
    assert_eq!(console.status(), StatusCode::BAD_REQUEST);
    assert_eq!(automation.status(), StatusCode::BAD_REQUEST);
    let console_error: serde_json::Value = body(console).await;
    let automation_error: serde_json::Value = body(automation).await;
    assert_eq!(console_error["error"], automation_error["error"]);
    let empty = serde_json::json!({"name":"empty","definition":{}});
    let console = call(
        &router,
        Method::POST,
        &format!("/v1/orgs/{}/posture-checks", org.id),
        empty.clone(),
        Some(&owner),
    )
    .await;
    let automation = api(
        &router,
        Method::POST,
        "/api/v1/posture-checks",
        org.id,
        &writer,
        empty,
    )
    .await;
    assert_eq!(
        body::<serde_json::Value>(console).await["error"],
        body::<serde_json::Value>(automation).await["error"]
    );

    // Same invalid DNS draft.
    let bad_dns = serde_json::json!({"dns":{"global_resolvers":["not-an-ip"]}});
    let console = call(
        &router,
        Method::POST,
        &format!("/v1/orgs/{}/dns/validate", org.id),
        bad_dns.clone(),
        Some(&owner),
    )
    .await;
    let automation = api(
        &router,
        Method::POST,
        "/api/v1/dns/validate",
        org.id,
        &reader,
        bad_dns,
    )
    .await;
    assert_eq!(console.status(), automation.status());
    assert_eq!(
        body::<serde_json::Value>(console).await["error"],
        body::<serde_json::Value>(automation).await["error"]
    );

    // Same role rule: an auditor's console session is refused by both.
    let check = serde_json::json!({"name":"baseline","definition":{"min_agent_version":"1.0.0"}});
    assert_eq!(
        call(
            &router,
            Method::POST,
            &format!("/v1/orgs/{}/posture-checks", org.id),
            check.clone(),
            Some(&auditor)
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        api(
            &router,
            Method::POST,
            "/api/v1/posture-checks",
            org.id,
            &auditor,
            check.clone()
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    // Read-only tokens cannot mutate; wrong-org header fails.
    assert_eq!(
        api(
            &router,
            Method::POST,
            "/api/v1/posture-checks",
            org.id,
            &reader,
            check.clone()
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        api(
            &router,
            Method::GET,
            "/api/v1/posture-checks",
            other.id,
            &reader,
            serde_json::Value::Null
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );

    // Lifecycle through the API, with optimistic concurrency.
    let created: serde_json::Value = body(
        api(
            &router,
            Method::POST,
            "/api/v1/posture-checks",
            org.id,
            &writer,
            check,
        )
        .await,
    )
    .await;
    let id = created["data"]["id"].as_str().unwrap().to_owned();
    let listed: serde_json::Value = body(
        api(
            &router,
            Method::GET,
            "/api/v1/posture-checks",
            org.id,
            &reader,
            serde_json::Value::Null,
        )
        .await,
    )
    .await;
    assert_eq!(listed["data"][0]["name"], "baseline");
    let update = serde_json::json!({"version":1,"definition":{"min_agent_version":"1.1.0"}});
    assert_eq!(
        api(
            &router,
            Method::PUT,
            &format!("/api/v1/posture-checks/{id}"),
            org.id,
            &writer,
            update.clone()
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        api(
            &router,
            Method::PUT,
            &format!("/api/v1/posture-checks/{id}"),
            org.id,
            &writer,
            update
        )
        .await
        .status(),
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(
        api(
            &router,
            Method::DELETE,
            &format!("/api/v1/posture-checks/{id}"),
            other.id,
            &writer,
            serde_json::Value::Null
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        api(
            &router,
            Method::DELETE,
            &format!("/api/v1/posture-checks/{id}"),
            org.id,
            &writer,
            serde_json::Value::Null
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    let audited: String = sqlx::query_scalar(
        "SELECT actor_role FROM audit_events WHERE org_id=$1 AND action='posture_check.deleted'",
    )
    .bind(org.id.to_string())
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(audited, "api_client");

    // Join-key metadata: list never exposes the secret; revoke is scoped.
    let minted: serde_json::Value = body(
        api(
            &router,
            Method::POST,
            "/api/v1/keys",
            org.id,
            &writer,
            serde_json::json!({"expires_in_seconds":600}),
        )
        .await,
    )
    .await;
    let key_id = minted["data"]["id"].as_str().unwrap().to_owned();
    let secret_key = minted["data"]["key"].as_str().unwrap().to_owned();
    let keys = text(
        api(
            &router,
            Method::GET,
            "/api/v1/keys",
            org.id,
            &reader,
            serde_json::Value::Null,
        )
        .await,
    )
    .await;
    assert!(
        keys.contains(&key_id) && !keys.contains(&secret_key),
        "{keys}"
    );
    assert_eq!(
        api(
            &router,
            Method::DELETE,
            &format!("/api/v1/keys/{key_id}"),
            org.id,
            &reader,
            serde_json::Value::Null
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let missing = Uuid::new_v4();
    assert_eq!(
        api(
            &router,
            Method::DELETE,
            &format!("/api/v1/keys/{missing}"),
            org.id,
            &writer,
            serde_json::Value::Null
        )
        .await
        .status(),
        call(
            &router,
            Method::DELETE,
            &format!("/v1/orgs/{}/join-keys/{missing}", org.id),
            serde_json::Value::Null,
            Some(&owner)
        )
        .await
        .status(),
    );
    assert_eq!(
        api(
            &router,
            Method::DELETE,
            &format!("/api/v1/keys/{key_id}"),
            org.id,
            &writer,
            serde_json::Value::Null
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn agents_learn_traffic_settings_and_report_peer_and_direction() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "agent-traffic").await;
    let other = create_test_org(&router, "agent-traffic-other").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let auditor = signed_session(org.id, "auditor-1", Role::Auditor, now() + 60);
    let other_owner = signed_session(other.id, "owner-2", Role::Owner, now() + 60);
    let node = register_test_node(&router, org.id, &owner, "laptop", "agent-traffic-a", &[]).await;
    let peer = register_test_node(&router, org.id, &owner, "server", "agent-traffic-b", &[]).await;
    let foreign = register_test_node(
        &router,
        other.id,
        &other_owner,
        "foreign",
        "agent-traffic-c",
        &[],
    )
    .await;
    let settings_uri = format!("/v1/orgs/{}/traffic/settings", org.id);
    let revision = || async {
        sqlx::query_scalar::<_, i64>("SELECT control_revision FROM orgs WHERE id=$1")
            .bind(org.id.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap()
    };
    let peer_map = |node: &RegisterResponse| {
        let uri = format!("/v1/nodes/{}/peers", node.id);
        let token = node.node_token.clone();
        let router = router.clone();
        async move {
            body::<serde_json::Value>(
                call(
                    &router,
                    Method::GET,
                    &uri,
                    serde_json::Value::Null,
                    Some(&token),
                )
                .await,
            )
            .await
        }
    };

    // Off: the peer map says nothing, so agents do not count or report.
    assert!(peer_map(&node).await.get("traffic").is_none());
    let before = revision().await;
    call(
        &router,
        Method::PUT,
        &settings_uri,
        serde_json::json!({"enabled":true,"sampling_rate":0.5}),
        Some(&owner),
    )
    .await;
    assert!(revision().await > before, "opt-in must wake agents");
    let map = peer_map(&node).await;
    assert_eq!(map["traffic"]["enabled"], true);
    assert_eq!(map["traffic"]["sampling_rate"], 0.5);
    assert_eq!(map["traffic"]["org_id"], org.id.to_string());
    // Changing retention alone does not wake every agent.
    let before = revision().await;
    call(
        &router,
        Method::PUT,
        &settings_uri,
        serde_json::json!({"enabled":true,"retention_days":2}),
        Some(&owner),
    )
    .await;
    assert_eq!(revision().await, before);
    call(
        &router,
        Method::PUT,
        &settings_uri,
        serde_json::json!({"enabled":true,"sampling_rate":1}),
        Some(&owner),
    )
    .await;

    let mut inbound = flow_record(org.id, node.id);
    inbound["peer_id"] = serde_json::json!(peer.id);
    inbound["direction"] = serde_json::json!("inbound");
    let mut outbound = flow_record(org.id, node.id);
    outbound["peer_id"] = serde_json::json!(peer.id);
    outbound["direction"] = serde_json::json!("outbound");
    outbound["proto"] = serde_json::json!("all");
    outbound["port"] = serde_json::json!(0);
    outbound["service"] = serde_json::json!("tunnel");
    let mut denied = flow_record(org.id, node.id);
    denied["decision"] = serde_json::json!("denied");
    denied["direction"] = serde_json::json!("inbound");
    denied["port"] = serde_json::json!(3389);
    denied["service"] = serde_json::json!("rdp");
    let accepted: crate::traffic::UploadResult = body(
        upload(
            &router,
            &node,
            serde_json::json!({"records":[inbound, outbound, denied]}),
        )
        .await,
    )
    .await;
    assert_eq!(accepted.accepted, 3);

    // A peer from another organisation, or an address, is refused.
    let mut foreign_peer = flow_record(org.id, node.id);
    foreign_peer["peer_id"] = serde_json::json!(foreign.id);
    assert_eq!(
        upload(
            &router,
            &node,
            serde_json::json!({"records":[foreign_peer]})
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let mut address_peer = flow_record(org.id, node.id);
    address_peer["peer_id"] = serde_json::json!("100.64.0.2");
    let mut bad_direction = flow_record(org.id, node.id);
    bad_direction["direction"] = serde_json::json!("sideways");
    for bad in [address_peer, bad_direction] {
        assert_eq!(
            upload(&router, &node, serde_json::json!({"records":[bad]}))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }

    let summary: crate::traffic::TrafficSummary = body(
        call(
            &router,
            Method::GET,
            &format!("/v1/orgs/{}/traffic/summary", org.id),
            serde_json::Value::Null,
            Some(&auditor),
        )
        .await,
    )
    .await;
    assert_eq!(summary.state, "current");
    assert_eq!(summary.by_direction["inbound"].records, 2);
    assert_eq!(summary.by_direction["outbound"].records, 1);
    assert_eq!(summary.denied.records, 1);
    assert_eq!(summary.by_service["tunnel"].records, 1);
    let stored: Vec<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT peer_id,direction FROM flow_records ORDER BY direction")
            .fetch_all(&store.pool)
            .await
            .unwrap();
    assert!(stored.contains(&(Some(peer.id.to_string()), Some("outbound".into()))));

    // Off again: the next peer map tells agents to stop.
    let before = revision().await;
    call(
        &router,
        Method::PUT,
        &settings_uri,
        serde_json::json!({"enabled":false}),
        Some(&owner),
    )
    .await;
    assert!(revision().await > before);
    assert!(peer_map(&node).await.get("traffic").is_none());
}
