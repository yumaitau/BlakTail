//! MDM/EDR posture integration tests (draft 08, ADR 0005) against a local
//! FleetDM-shaped mock server. No live vendor tenant is used.

use super::*;
use crate::posture_integrations::tests::{
    fleet_router, mock_config_json, serve, Mock, FLEET_TOKEN,
};
use std::sync::{atomic::Ordering, Arc};

const LAPTOP_SERIAL: &str = "C02XK1ABCD";

async fn put_policy(router: &Router, org_id: Uuid, session: &str, posture: &str) {
    let response = call(
        router,
        Method::PUT,
        &format!("/v1/orgs/{org_id}/acl"),
        serde_json::json!({
            "defaults": "deny",
            "groups": {"crew": ["owner-1"]},
            "rules": [
                {"action":"allow","src_groups":["crew"],"dst_groups":["crew"],"dst_ports":["8080"],"protocols":["tcp"]},
                {"action":"allow","src_groups":["crew"],"dst_groups":["crew"],"dst_ports":["9000"],"protocols":["tcp"],"posture":[posture]}
            ]
        }),
        Some(session),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

async fn raw(response: Response) -> (StatusCode, String) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn create_integration(
    router: &Router,
    org_id: Uuid,
    session: &str,
    base: &str,
    acknowledged: bool,
) -> Response {
    call(
        router,
        Method::POST,
        &format!("/v1/orgs/{org_id}/posture-integrations"),
        serde_json::json!({
            "kind": "fleetdm",
            "name": "fleet",
            "config": mock_config_json("fleetdm", base),
            "secret": FLEET_TOKEN,
            "privacy_acknowledged": acknowledged,
        }),
        Some(session),
    )
    .await
}

async fn sync(router: &Router, org_id: Uuid, session: &str, id: &str) -> serde_json::Value {
    let response = call(
        router,
        Method::POST,
        &format!("/v1/orgs/{org_id}/posture-integrations/{id}/sync"),
        serde_json::Value::Null,
        Some(session),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    body(response).await
}

async fn ports_from(router: &Router, server: &RegisterResponse, laptop: Uuid) -> Vec<String> {
    let response = call(
        router,
        Method::GET,
        &format!("/v1/nodes/{}/peers", server.id),
        serde_json::Value::Null,
        Some(&server.node_token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot: PeersResponse = body(response).await;
    snapshot
        .peers
        .iter()
        .find(|peer| peer.id == laptop)
        .and_then(|peer| peer.ingress.clone())
        .map(|ingress| ingress.tcp)
        .unwrap_or_default()
}

async fn report_serial(router: &Router, node: &RegisterResponse, serial: &str) {
    report_query(
        router,
        node,
        &format!("serial_number={serial}&mac_addresses=3c:22:fb:11:22:33,02:42:ac:11:00:02"),
    )
    .await;
}

async fn report_query(router: &Router, node: &RegisterResponse, query: &str) {
    let response = call(
        router,
        Method::GET,
        &format!("/v1/nodes/{}/peers?{query}", node.id),
        serde_json::Value::Null,
        Some(&node.node_token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

async fn create_check(
    router: &Router,
    org_id: Uuid,
    session: &str,
    integration_id: &str,
    extra: serde_json::Value,
) -> Response {
    let mut requirement =
        serde_json::json!({"integration_id": integration_id, "max_age_secs": 600});
    for (key, value) in extra.as_object().unwrap() {
        requirement[key] = value.clone();
    }
    call(
        router,
        Method::POST,
        &format!("/v1/orgs/{org_id}/posture-checks"),
        serde_json::json!({"name": "edr", "definition": {"integration": requirement}}),
        Some(session),
    )
    .await
}

#[tokio::test]
async fn integration_signal_gates_only_its_rule_and_fails_closed_on_outage() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "edr-org").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let admin = signed_session(org.id, "admin-1", Role::Admin, now() + 60);
    let member = signed_session(org.id, "member-1", Role::Member, now() + 60);
    let mock = Arc::new(Mock::default());
    let base = serve(mock.clone(), fleet_router).await;

    // Credentials are owner-only, and the privacy notice comes first.
    assert_eq!(
        create_integration(&router, org.id, &admin, &base, true)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        create_integration(&router, org.id, &owner, &base, false)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let (status, text) = raw(create_integration(&router, org.id, &owner, &base, true).await).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(!text.contains(FLEET_TOKEN));
    let created: serde_json::Value = serde_json::from_str(&text).unwrap();
    let id = created["id"].as_str().unwrap().to_owned();
    let sealed: String =
        sqlx::query_scalar("SELECT sealed_secret FROM posture_integrations WHERE id=$1")
            .bind(&id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert!(!sealed.contains(FLEET_TOKEN));

    let laptop = register_test_node(&router, org.id, &owner, "laptop", "laptop-key", &[]).await;
    let server = register_test_node(&router, org.id, &owner, "server", "server-key", &[]).await;
    report_serial(&router, &laptop, LAPTOP_SERIAL).await;
    let response = call(
        &router,
        Method::POST,
        &format!("/v1/orgs/{}/posture-integrations/{id}/sync", org.id),
        serde_json::Value::Null,
        Some(&admin),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let report = sync(&router, org.id, &owner, &id).await;
    assert_eq!(report["ok"], true);
    assert_eq!(report["devices"], 501);

    // Members may not reference checks; policy editors may.
    assert_eq!(
        create_check(&router, org.id, &member, &id, serde_json::json!({}))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let check: serde_json::Value =
        body(create_check(&router, org.id, &owner, &id, serde_json::json!({})).await).await;
    put_policy(&router, org.id, &owner, "edr").await;
    assert_eq!(
        ports_from(&router, &server, laptop.id).await,
        vec!["8080", "9000"]
    );

    // Listing shows counts and status, never the secret.
    let (status, listing) = raw(call(
        &router,
        Method::GET,
        &format!("/v1/orgs/{}/posture-integrations", org.id),
        serde_json::Value::Null,
        Some(&member),
    )
    .await)
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!listing.contains(FLEET_TOKEN));
    let listing: serde_json::Value = serde_json::from_str(&listing).unwrap();
    let view = &listing["integrations"][0];
    assert_eq!(view["matched_devices"], 1);
    assert_eq!(view["unmatched_devices"], 1);
    assert_eq!(view["unmatched_records"], 500);
    assert_eq!(view["referenced_by"], serde_json::json!(["edr"]));
    assert_eq!(view["name"], "fleet");
    assert_eq!(view["kind"], "fleetdm");
    // Configuration and credential metadata are for security managers.
    for field in ["config", "secret_fingerprint", "privacy_acknowledged_by"] {
        assert!(view.get(field).is_none(), "{field} shown to a member");
    }
    assert_eq!(listing["providers"].as_array().unwrap().len(), 5);
    let managed: serde_json::Value = body(
        call(
            &router,
            Method::GET,
            &format!("/v1/orgs/{}/posture-integrations", org.id),
            serde_json::Value::Null,
            Some(&owner),
        )
        .await,
    )
    .await;
    let view = &managed["integrations"][0];
    assert!(view["config"].is_object());
    assert!(view["config"].get("api_base_override").is_none());
    assert!(view["secret_fingerprint"].is_string());

    // The device assessment names the vendor signal and its source.
    let assessment: serde_json::Value = body(
        call(
            &router,
            Method::GET,
            &format!("/v1/orgs/{}/nodes/{}/posture", org.id, laptop.id),
            serde_json::Value::Null,
            Some(&member),
        )
        .await,
    )
    .await;
    let device = &assessment["devices"][0];
    assert_eq!(device["integrations"][0]["match"]["state"], "matched");
    assert_eq!(device["integrations"][0]["source"], "provider_reported");
    assert_eq!(
        device["assessments"][0]["reasons"][0]["source"],
        "provider_reported"
    );

    // A failing provider verdict removes only the gated port.
    mock.failing.store(1, Ordering::SeqCst);
    sync(&router, org.id, &owner, &id).await;
    assert_eq!(ports_from(&router, &server, laptop.id).await, vec!["8080"]);
    mock.failing.store(0, Ordering::SeqCst);
    sync(&router, org.id, &owner, &id).await;
    assert_eq!(
        ports_from(&router, &server, laptop.id).await,
        vec!["8080", "9000"]
    );

    // Outage: stored signals are kept while fresh.
    mock.down.store(true, Ordering::SeqCst);
    let failed = sync(&router, org.id, &owner, &id).await;
    assert_eq!(failed["ok"], false);
    assert_eq!(failed["error_code"], "provider_error");
    assert_eq!(
        ports_from(&router, &server, laptop.id).await,
        vec!["8080", "9000"]
    );
    // Once stale, the default fails closed.
    sqlx::query("UPDATE posture_integration_devices SET synced_at=$1 WHERE integration_id=$2")
        .bind(now() - 3_600)
        .bind(&id)
        .execute(&store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE orgs SET control_revision=control_revision+1 WHERE id=$1")
        .bind(org.id.to_string())
        .execute(&store.pool)
        .await
        .unwrap();
    assert_eq!(ports_from(&router, &server, laptop.id).await, vec!["8080"]);
    // An editor may choose fail-open for outages.
    let response = call(
        &router,
        Method::PUT,
        &format!(
            "/v1/orgs/{}/posture-checks/{}",
            org.id,
            check["id"].as_str().unwrap()
        ),
        serde_json::json!({"version": 1, "definition": {"integration": {
            "integration_id": id, "max_age_secs": 600, "on_outage": "pass"}}}),
        Some(&owner),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        ports_from(&router, &server, laptop.id).await,
        vec!["8080", "9000"]
    );
    // Recovery clears the outage and refreshes the signal.
    mock.down.store(false, Ordering::SeqCst);
    assert_eq!(sync(&router, org.id, &owner, &id).await["ok"], true);
    let outage: Option<i64> =
        sqlx::query_scalar("SELECT outage_since FROM posture_integrations WHERE id=$1")
            .bind(&id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(outage, None);

    // Referenced integrations cannot be deleted; settings changes need the secret.
    let response = call(
        &router,
        Method::DELETE,
        &format!("/v1/orgs/{}/posture-integrations/{id}", org.id),
        serde_json::Value::Null,
        Some(&owner),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let mut moved = mock_config_json("fleetdm", &base);
    moved["server_url"] = serde_json::json!("https://exfil.example.com");
    let response = call(
        &router,
        Method::PUT,
        &format!("/v1/orgs/{}/posture-integrations/{id}", org.id),
        serde_json::json!({"config": moved}),
        Some(&owner),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // The audit trail records the lifecycle without the credential.
    let (status, audit) = raw(call(
        &router,
        Method::GET,
        &format!("/v1/orgs/{}/audit", org.id),
        serde_json::Value::Null,
        Some(&owner),
    )
    .await)
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(audit.contains("posture_integration.created"));
    assert!(audit.contains("posture_integration.tested"));
    assert!(!audit.contains(FLEET_TOKEN));
}

#[tokio::test]
async fn another_organisations_integration_cannot_satisfy_a_check() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "edr-home").await;
    let other = create_test_org(&router, "edr-other").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let other_owner = signed_session(other.id, "owner-1", Role::Owner, now() + 60);
    let mock = Arc::new(Mock::default());
    let base = serve(mock, fleet_router).await;
    let created: serde_json::Value =
        body(create_integration(&router, org.id, &owner, &base, true).await).await;
    let id = created["id"].as_str().unwrap().to_owned();
    sync(&router, org.id, &owner, &id).await;

    // The other organisation cannot reference, sync or edit it.
    assert_eq!(
        create_check(&router, other.id, &other_owner, &id, serde_json::json!({}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    for (method, path) in [
        (
            Method::POST,
            format!("/v1/orgs/{}/posture-integrations/{id}/sync", other.id),
        ),
        (
            Method::DELETE,
            format!("/v1/orgs/{}/posture-integrations/{id}", other.id),
        ),
    ] {
        let response = call(
            &router,
            method,
            &path,
            serde_json::Value::Null,
            Some(&other_owner),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    let cross = call(
        &router,
        Method::POST,
        &format!("/v1/orgs/{}/posture-integrations/{id}/sync", org.id),
        serde_json::Value::Null,
        Some(&other_owner),
    )
    .await;
    assert!(matches!(
        cross.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ));

    // Even a check stored with a foreign id (bypassing validation) fails:
    // matching only ever loads the device's own organisation's integrations.
    sqlx::query("INSERT INTO posture_checks(id,org_id,name,version,definition_json,created_at,updated_at) VALUES($1,$2,'edr',1,$3,$4,$4)")
        .bind(Uuid::new_v4().to_string())
        .bind(other.id.to_string())
        .bind(serde_json::json!({"integration": {"integration_id": id, "max_age_secs": 600}}).to_string())
        .bind(now())
        .execute(&store.pool)
        .await
        .unwrap();
    put_policy(&router, other.id, &other_owner, "edr").await;
    let laptop =
        register_test_node(&router, other.id, &other_owner, "laptop", "o-laptop", &[]).await;
    let server =
        register_test_node(&router, other.id, &other_owner, "server", "o-server", &[]).await;
    report_serial(&router, &laptop, LAPTOP_SERIAL).await;
    assert_eq!(ports_from(&router, &server, laptop.id).await, vec!["8080"]);
}

#[tokio::test]
async fn copied_serial_fails_only_the_later_claimant_and_leases_are_exclusive() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "edr-ambiguous").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let mock = Arc::new(Mock::default());
    let base = serve(mock, fleet_router).await;
    let created: serde_json::Value =
        body(create_integration(&router, org.id, &owner, &base, true).await).await;
    let id = created["id"].as_str().unwrap().to_owned();

    // A new integration is due at once; only one claimant wins the lease.
    assert_eq!(
        crate::posture_integrations::claim_due(&store.pool, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(crate::posture_integrations::claim_due(&store.pool, 10)
        .await
        .unwrap()
        .is_empty());

    sync(&router, org.id, &owner, &id).await;
    create_check(&router, org.id, &owner, &id, serde_json::json!({})).await;
    put_policy(&router, org.id, &owner, "edr").await;
    let laptop = register_test_node(&router, org.id, &owner, "laptop", "laptop-key", &[]).await;
    let impostor = register_test_node(&router, org.id, &owner, "impostor", "imp-key", &[]).await;
    let server = register_test_node(&router, org.id, &owner, "server", "server-key", &[]).await;
    report_serial(&router, &laptop, LAPTOP_SERIAL).await;
    assert_eq!(
        ports_from(&router, &server, laptop.id).await,
        vec!["8080", "9000"]
    );
    // A second device claiming the same serial gains nothing and cannot
    // lock the genuine device out: the first reporter keeps the match.
    report_serial(&router, &impostor, LAPTOP_SERIAL).await;
    assert_eq!(
        ports_from(&router, &server, impostor.id).await,
        vec!["8080"]
    );
    assert_eq!(
        ports_from(&router, &server, laptop.id).await,
        vec!["8080", "9000"]
    );
    let held: Option<String> = sqlx::query_scalar("SELECT serial_number FROM nodes WHERE id=$1")
        .bind(impostor.id.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(held, None);
    assert_eq!(
        posture_state(&router, org.id, &owner, impostor.id).await,
        "identity_changed"
    );
    let (_, audit) = raw(call(
        &router,
        Method::GET,
        &format!("/v1/orgs/{}/audit", org.id),
        serde_json::Value::Null,
        Some(&owner),
    )
    .await)
    .await;
    assert!(audit.contains("node.hardware_clash"));
    assert!(audit.contains(&laptop.id.to_string()));
    assert!(!audit.contains(LAPTOP_SERIAL));
}

async fn posture_state(router: &Router, org_id: Uuid, session: &str, node: Uuid) -> String {
    let assessment: serde_json::Value = body(
        call(
            router,
            Method::GET,
            &format!("/v1/orgs/{org_id}/nodes/{node}/posture"),
            serde_json::Value::Null,
            Some(session),
        )
        .await,
    )
    .await;
    assessment["devices"][0]["integrations"][0]["match"]["state"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn approve_hardware(router: &Router, org_id: Uuid, session: &str, node: Uuid) -> StatusCode {
    call(
        router,
        Method::POST,
        &format!("/v1/orgs/{org_id}/posture-integrations/devices/{node}/approve-hardware"),
        serde_json::Value::Null,
        Some(session),
    )
    .await
    .status()
}

#[tokio::test]
async fn changed_hardware_fails_until_a_security_manager_approves_it() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "edr-pins").await;
    let other = create_test_org(&router, "edr-pins-other").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let admin = signed_session(org.id, "admin-1", Role::Admin, now() + 60);
    let other_owner = signed_session(other.id, "owner-1", Role::Owner, now() + 60);
    let mock = Arc::new(Mock::default());
    let base = serve(mock, fleet_router).await;
    let created: serde_json::Value =
        body(create_integration(&router, org.id, &owner, &base, true).await).await;
    let id = created["id"].as_str().unwrap().to_owned();
    sync(&router, org.id, &owner, &id).await;
    create_check(&router, org.id, &owner, &id, serde_json::json!({})).await;
    put_policy(&router, org.id, &owner, "edr").await;
    let laptop = register_test_node(&router, org.id, &owner, "laptop", "laptop-key", &[]).await;
    let server = register_test_node(&router, org.id, &owner, "server", "server-key", &[]).await;

    // The first report pins the identifiers; a later serial is not taken
    // on the device's word, even when the provider knows it.
    report_query(&router, &laptop, "serial_number=PF3UNKNOWN").await;
    assert_eq!(
        posture_state(&router, org.id, &owner, laptop.id).await,
        "unmatched"
    );
    report_query(&router, &laptop, &format!("serial_number={LAPTOP_SERIAL}")).await;
    assert_eq!(ports_from(&router, &server, laptop.id).await, vec!["8080"]);
    assert_eq!(
        posture_state(&router, org.id, &owner, laptop.id).await,
        "identity_changed"
    );

    // Only a security manager of the device's own organisation approves.
    assert_eq!(
        approve_hardware(&router, org.id, &admin, laptop.id).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        approve_hardware(&router, other.id, &other_owner, laptop.id).await,
        StatusCode::NOT_FOUND
    );
    assert!(matches!(
        approve_hardware(&router, org.id, &other_owner, laptop.id).await,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ));
    assert_eq!(
        approve_hardware(&router, org.id, &owner, laptop.id).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        approve_hardware(&router, org.id, &owner, laptop.id).await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        ports_from(&router, &server, laptop.id).await,
        vec!["8080", "9000"]
    );
    let (_, audit) = raw(call(
        &router,
        Method::GET,
        &format!("/v1/orgs/{}/audit", org.id),
        serde_json::Value::Null,
        Some(&owner),
    )
    .await)
    .await;
    assert!(audit.contains("node.hardware_changed"));
    assert!(audit.contains("node.hardware_approved"));
}

#[tokio::test]
async fn provider_failures_never_log_the_credential() {
    use std::io::Write;
    #[derive(Clone, Default)]
    struct Buffer(Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for Buffer {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buffer = Buffer::default();
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    // Other test threads may have cached "never" interest for these
    // callsites before this scoped subscriber existed.
    tracing::callsite::rebuild_interest_cache();

    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "edr-logs").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let mock = Arc::new(Mock::default());
    let base = serve(mock, fleet_router).await;
    let wrong = "not-the-fleet-token-but-secret";
    let created: serde_json::Value = body(
        call(
            &router,
            Method::POST,
            &format!("/v1/orgs/{}/posture-integrations", org.id),
            serde_json::json!({"kind":"fleetdm","name":"fleet","config": mock_config_json("fleetdm", &base),
                "secret": wrong, "privacy_acknowledged": true}),
            Some(&owner),
        )
        .await,
    )
    .await;
    let report = sync(&router, org.id, &owner, created["id"].as_str().unwrap()).await;
    assert_eq!(report["error_code"], "auth_failed");
    assert!(!report.to_string().contains(wrong));
    let logged = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
    assert!(logged.contains("posture integration reconcile failed"));
    assert!(!logged.contains(wrong));
    let last_error: String =
        sqlx::query_scalar("SELECT last_error FROM posture_integrations WHERE org_id=$1")
            .bind(org.id.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert!(!last_error.contains(wrong));
}
