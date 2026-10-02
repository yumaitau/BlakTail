//! Posture, SSH fail-closed and explain integration tests (drafts 07/08).

use super::*;

async fn put_policy(router: &Router, org_id: Uuid, session: &str, policy: serde_json::Value) {
    let response = call(
        router,
        Method::PUT,
        &format!("/v1/orgs/{org_id}/acl"),
        policy,
        Some(session),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

async fn create_check(
    router: &Router,
    org_id: Uuid,
    session: &str,
    name: &str,
    definition: serde_json::Value,
) -> Response {
    call(
        router,
        Method::POST,
        &format!("/v1/orgs/{org_id}/posture-checks"),
        serde_json::json!({"name": name, "definition": definition}),
        Some(session),
    )
    .await
}

async fn peers(router: &Router, node: &RegisterResponse, query: &str) -> PeersResponse {
    let response = call(
        router,
        Method::GET,
        &format!("/v1/nodes/{}/peers{query}", node.id),
        serde_json::Value::Null,
        Some(&node.node_token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    body(response).await
}

fn ingress_from(snapshot: &PeersResponse, peer: Uuid) -> PeerIngress {
    snapshot
        .peers
        .iter()
        .find(|candidate| candidate.id == peer)
        .and_then(|candidate| candidate.ingress.clone())
        .expect("peer with ingress")
}

fn posture_policy() -> serde_json::Value {
    serde_json::json!({
        "defaults": "deny",
        "groups": {"crew": ["owner-1"]},
        "rules": [
            {"action":"allow","src_groups":["crew"],"dst_groups":["crew"],"dst_ports":["8080"],"protocols":["tcp"]},
            {"action":"allow","src_groups":["crew"],"dst_groups":["crew"],"dst_ports":["9000"],"protocols":["tcp"],"posture":["baseline"]}
        ]
    })
}

#[tokio::test]
async fn posture_failure_removes_only_the_referencing_rule_grant() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "posture-org").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let laptop = register_test_node(&router, org.id, &owner, "laptop", "laptop-key", &[]).await;
    let server = register_test_node(&router, org.id, &owner, "server", "server-key", &[]).await;
    assert_eq!(
        create_check(
            &router,
            org.id,
            &owner,
            "baseline",
            serde_json::json!({"min_agent_version":"0.2.0","os_families":["linux"]}),
        )
        .await
        .status(),
        StatusCode::CREATED
    );
    put_policy(&router, org.id, &owner, posture_policy()).await;

    // Registration reported no OS or agent version: the check fails closed.
    let at_server = peers(&router, &server, "").await;
    assert_eq!(ingress_from(&at_server, laptop.id).tcp, vec!["8080"]);

    // An outdated agent still keeps the unreferenced grant.
    peers(&router, &laptop, "?agent_version=0.1.9&os_version=24.04").await;
    sqlx::query("UPDATE nodes SET os='linux' WHERE id=$1")
        .bind(laptop.id.to_string())
        .execute(&store.pool)
        .await
        .unwrap();
    let at_server = peers(&router, &server, "").await;
    assert_eq!(ingress_from(&at_server, laptop.id).tcp, vec!["8080"]);

    // Upgrading restores exactly the posture-gated port.
    peers(&router, &laptop, "?agent_version=0.2.1").await;
    let at_server = peers(&router, &server, "").await;
    let ingress = ingress_from(&at_server, laptop.id);
    assert_eq!(ingress.tcp, vec!["8080", "9000"]);
}

#[tokio::test]
async fn posture_uses_only_the_owning_organisations_checks_and_signals() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "strict-org").await;
    let other = create_test_org(&router, "lenient-org").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let other_owner = signed_session(other.id, "owner-1", Role::Owner, now() + 60);
    let laptop = register_test_node(&router, org.id, &owner, "laptop", "laptop-key", &[]).await;
    let server = register_test_node(&router, org.id, &owner, "server", "server-key", &[]).await;
    let foreign = register_test_node(
        &router,
        other.id,
        &other_owner,
        "foreign",
        "foreign-key",
        &[],
    )
    .await;
    create_check(
        &router,
        org.id,
        &owner,
        "baseline",
        serde_json::json!({"min_agent_version":"0.2.0"}),
    )
    .await;
    // Same name, permissive definition, different organisation.
    create_check(
        &router,
        other.id,
        &other_owner,
        "baseline",
        serde_json::json!({"min_agent_version":"0.0.1"}),
    )
    .await;
    put_policy(&router, org.id, &owner, posture_policy()).await;
    peers(&router, &laptop, "?agent_version=0.1.0").await;
    // A foreign node reporting a passing version must not satisfy anything here.
    peers(&router, &foreign, "?agent_version=9.9.9").await;
    sqlx::query("UPDATE nodes SET agent_version='9.9.9' WHERE org_id=$1")
        .bind(other.id.to_string())
        .execute(&store.pool)
        .await
        .unwrap();
    let at_server = peers(&router, &server, "").await;
    assert_eq!(ingress_from(&at_server, laptop.id).tcp, vec!["8080"]);
    assert!(at_server.peers.iter().all(|peer| peer.id != foreign.id));

    // The other organisation cannot read or explain this organisation's devices.
    let foreign_explain = call(
        &router,
        Method::POST,
        &format!("/v1/orgs/{}/policy/explain", other.id),
        serde_json::json!({"source_node_id": laptop.id, "destination_node_id": server.id}),
        Some(&other_owner),
    )
    .await;
    assert_eq!(foreign_explain.status(), StatusCode::NOT_FOUND);
    let cross_path = call(
        &router,
        Method::POST,
        &format!("/v1/orgs/{}/policy/explain", org.id),
        serde_json::json!({"source_node_id": laptop.id, "destination_node_id": server.id}),
        Some(&other_owner),
    )
    .await;
    assert!(matches!(
        cross_path.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ));
    let foreign_posture = call(
        &router,
        Method::GET,
        &format!("/v1/orgs/{}/nodes/{}/posture", other.id, laptop.id),
        serde_json::Value::Null,
        Some(&other_owner),
    )
    .await;
    assert_eq!(foreign_posture.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn members_may_explain_and_read_posture_but_not_change_it() {
    let store = Store::memory().await.unwrap();
    let router = app(store, "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "member-org").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let member = signed_session(org.id, "member-1", Role::Member, now() + 60);
    let laptop = register_test_node(&router, org.id, &owner, "laptop", "laptop-key", &[]).await;
    let server = register_test_node(&router, org.id, &owner, "server", "server-key", &[]).await;
    assert_eq!(
        create_check(
            &router,
            org.id,
            &member,
            "baseline",
            serde_json::json!({"require_approved_peer":true})
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let created: serde_json::Value = body(
        create_check(
            &router,
            org.id,
            &owner,
            "baseline",
            serde_json::json!({"require_approved_peer":true}),
        )
        .await,
    )
    .await;
    let id = created["id"].as_str().unwrap().to_owned();
    for (method, value) in [
        (
            Method::PUT,
            serde_json::json!({"version":1,"definition":{"require_approved_peer":true}}),
        ),
        (Method::DELETE, serde_json::Value::Null),
    ] {
        let response = call(
            &router,
            method,
            &format!("/v1/orgs/{}/posture-checks/{id}", org.id),
            value,
            Some(&member),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    for path in ["posture-checks", "posture-assessments"] {
        let response = call(
            &router,
            Method::GET,
            &format!("/v1/orgs/{}/{path}", org.id),
            serde_json::Value::Null,
            Some(&member),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    let explained = call(
        &router,
        Method::POST,
        &format!("/v1/orgs/{}/policy/explain", org.id),
        serde_json::json!({"source_node_id": laptop.id, "destination_node_id": server.id, "protocol":"tcp", "port": 443}),
        Some(&member),
    )
    .await;
    assert_eq!(explained.status(), StatusCode::OK);
}

#[tokio::test]
async fn posture_check_versions_conflicts_and_references_are_enforced() {
    let store = Store::memory().await.unwrap();
    let router = app(store, "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "crud-org").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    assert_eq!(
        create_check(
            &router,
            org.id,
            &owner,
            "Bad Name",
            serde_json::json!({"require_approved_peer":true})
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        create_check(&router, org.id, &owner, "empty", serde_json::json!({}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let created: serde_json::Value = body(
        create_check(
            &router,
            org.id,
            &owner,
            "baseline",
            serde_json::json!({"min_agent_version":"0.2.0"}),
        )
        .await,
    )
    .await;
    let id = created["id"].as_str().unwrap().to_owned();
    assert_eq!(
        create_check(
            &router,
            org.id,
            &owner,
            "baseline",
            serde_json::json!({"min_agent_version":"0.3.0"})
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    let path = format!("/v1/orgs/{}/posture-checks/{id}", org.id);
    let update = |version: i64| serde_json::json!({"version": version, "definition": {"min_agent_version":"0.3.0"}});
    assert_eq!(
        call(&router, Method::PUT, &path, update(1), Some(&owner))
            .await
            .status(),
        StatusCode::OK
    );
    // A second editor still holding version 1 loses.
    assert_eq!(
        call(&router, Method::PUT, &path, update(1), Some(&owner))
            .await
            .status(),
        StatusCode::PRECONDITION_FAILED
    );
    put_policy(&router, org.id, &owner, posture_policy()).await;
    let listed: serde_json::Value = body(
        call(
            &router,
            Method::GET,
            &format!("/v1/orgs/{}/posture-checks", org.id),
            serde_json::Value::Null,
            Some(&owner),
        )
        .await,
    )
    .await;
    assert_eq!(listed[0]["version"], 2);
    assert_eq!(listed[0]["referenced_by"][0], "rules[1]");
    assert_eq!(
        call(
            &router,
            Method::DELETE,
            &path,
            serde_json::Value::Null,
            Some(&owner)
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    // Posture can only gate allow rules.
    let response = call(
        &router,
        Method::PUT,
        &format!("/v1/orgs/{}/acl", org.id),
        serde_json::json!({"defaults":"deny","rules":[{"action":"deny","src_tags":["office"],"posture":["baseline"]}]}),
        Some(&owner),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    put_policy(
        &router,
        org.id,
        &owner,
        serde_json::json!({"defaults":"deny","rules":[]}),
    )
    .await;
    assert_eq!(
        call(
            &router,
            Method::DELETE,
            &path,
            serde_json::Value::Null,
            Some(&owner)
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    let audit: Vec<AuditEvent> = body(
        call(
            &router,
            Method::GET,
            &format!("/v1/orgs/{}/audit", org.id),
            serde_json::Value::Null,
            Some(&owner),
        )
        .await,
    )
    .await;
    for action in [
        "posture_check.created",
        "posture_check.updated",
        "posture_check.deleted",
    ] {
        assert!(audit.iter().any(|event| event.action == action), "{action}");
    }
}

#[tokio::test]
async fn explain_reports_rule_posture_ssh_and_enforcement_honestly() {
    let store = Store::memory().await.unwrap();
    let router = app(store, "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "explain-org").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let laptop = register_test_node(&router, org.id, &owner, "laptop", "laptop-key", &[]).await;
    let server = register_test_node(&router, org.id, &owner, "server", "server-key", &[]).await;
    create_check(
        &router,
        org.id,
        &owner,
        "baseline",
        serde_json::json!({"min_agent_version":"0.2.0"}),
    )
    .await;
    let mut policy = posture_policy();
    policy["rules"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"action":"deny","src_groups":["crew"],"dst_groups":["crew"],"dst_ports":["8080"],"protocols":["tcp"]}));
    policy["ssh"] = serde_json::json!([
        {"action":"allow","src_groups":["crew"],"dst_groups":["crew"],"users":["deploy"]}
    ]);
    put_policy(&router, org.id, &owner, policy).await;
    let explain = |body: serde_json::Value| {
        let router = router.clone();
        let owner = owner.clone();
        async move {
            let response = call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/policy/explain", org.id),
                body,
                Some(&owner),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            body_json(response).await
        }
    };
    let base = serde_json::json!({"source_node_id": laptop.id, "destination_node_id": server.id, "protocol":"tcp"});
    let with = |extra: serde_json::Value| {
        let mut value = base.clone();
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        value
    };

    let denied = explain(with(serde_json::json!({"port": 8080}))).await;
    assert_eq!(denied["decision"], "deny");
    assert_eq!(denied["basis"], "deny_rule");
    assert_eq!(denied["deny_precedence"], true);
    assert_eq!(denied["simulated"], true);
    assert_eq!(denied["policy"]["published"], true);
    assert_eq!(denied["source"]["groups"][0], "crew");

    let gated = explain(with(serde_json::json!({"port": 9000}))).await;
    assert_eq!(gated["decision"], "deny");
    assert!(gated["rules"]
        .as_array()
        .unwrap()
        .iter()
        .any(|rule| rule["outcome"] == "skipped_posture" && rule["index"] == 1));

    peers(&router, &laptop, "?agent_version=0.2.0").await;
    let allowed = explain(with(serde_json::json!({"port": 9000}))).await;
    assert_eq!(allowed["decision"], "allow");
    // Registered without capabilities and without an OS: not enforced there.
    assert_eq!(allowed["enforcement"]["state"], "not_enforced");

    let ssh = explain(serde_json::json!({"source_node_id": laptop.id, "destination_node_id": server.id, "ssh_user":"deploy"})).await;
    assert_eq!(ssh["decision"], "deny");
    assert_eq!(ssh["basis"], "ssh_closed");

    peers(&router, &server, "?capabilities=acl-filter,ssh-users").await;
    let ssh = explain(serde_json::json!({"source_node_id": laptop.id, "destination_node_id": server.id, "ssh_user":"deploy"})).await;
    assert_eq!(ssh["decision"], "allow");
    assert_eq!(ssh["enforcement"]["state"], "device_enforced");
    let root = explain(serde_json::json!({"source_node_id": laptop.id, "destination_node_id": server.id, "ssh_user":"root"})).await;
    assert_eq!(root["decision"], "deny");

    // A person with no device cannot pass posture.
    let person = explain(serde_json::json!({"source": {"user":"owner-1"}, "destination_node_id": server.id, "protocol":"tcp", "port": 9000})).await;
    assert_eq!(person["decision"], "deny");
    assert_eq!(person["source"]["kind"], "person");

    let bad = call(
        &router,
        Method::POST,
        &format!("/v1/orgs/{}/policy/explain", org.id),
        serde_json::json!({"destination_node_id": server.id}),
        Some(&owner),
    )
    .await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
}

async fn body_json(response: Response) -> serde_json::Value {
    body(response).await
}

#[tokio::test]
async fn lapsed_posture_deadline_bumps_the_control_revision_once() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "deadline-org").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let laptop = register_test_node(&router, org.id, &owner, "laptop", "laptop-key", &[]).await;
    let server = register_test_node(&router, org.id, &owner, "server", "server-key", &[]).await;
    create_check(
        &router,
        org.id,
        &owner,
        "baseline",
        serde_json::json!({"max_credential_age_secs":3600}),
    )
    .await;
    put_policy(&router, org.id, &owner, posture_policy()).await;
    let at_server = peers(&router, &server, "").await;
    assert_eq!(
        ingress_from(&at_server, laptop.id).tcp,
        vec!["8080", "9000"]
    );
    let deadline: Option<i64> =
        sqlx::query_scalar("SELECT posture_next_eval_at FROM orgs WHERE id=$1")
            .bind(org.id.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert!(deadline.is_some_and(|at| at > now() && at <= now() + 3600));

    // Age the credential past the limit and let the deadline fire.
    sqlx::query("UPDATE nodes SET credential_issued_at=$1 WHERE id=$2")
        .bind(now() - 7200)
        .bind(laptop.id.to_string())
        .execute(&store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE orgs SET posture_next_eval_at=$1 WHERE id=$2")
        .bind(now() - 1)
        .bind(org.id.to_string())
        .execute(&store.pool)
        .await
        .unwrap();
    let org_id = org.id.to_string();
    assert!(posture::due(&store.pool, &org_id).await.unwrap());
    assert!(!posture::due(&store.pool, &org_id).await.unwrap());
    let at_server = peers(&router, &server, "").await;
    assert_eq!(ingress_from(&at_server, laptop.id).tcp, vec!["8080"]);
}

#[test]
fn ssh_star_with_denied_user_and_lapsed_check_fail_closed() {
    let acl: Acl = serde_json::from_value(serde_json::json!({
        "defaults": "deny",
        "rules": [{"action":"allow","src_tags":["ranger"],"dst_tags":["store"]}],
        "ssh": [
            {"action":"allow","src_tags":["ranger"],"dst_tags":["store"],"users":["*"]},
            {"action":"deny","src_tags":["ranger"],"dst_tags":["store"],"users":["root"]},
            {"action":"check","src_tags":["office"],"dst_tags":["store"],"users":["deploy"],"check_period_secs":3600}
        ]
    }))
    .unwrap();
    let store = Subject::new(Role::Member, vec![DeviceTag::Store]);
    let ranger = Subject::new(Role::Member, vec![DeviceTag::Ranger]);
    let compiled = acl.peer_ingress_for(&ranger, &store, true);
    assert_eq!(compiled.ssh_users, vec!["*"]);
    assert_eq!(compiled.ssh_deny_users, vec!["root"]);
    assert!(compiled.all && compiled.deny_tcp.is_empty());
    // Without verified sshd limits the root deny cannot be expressed: close 22.
    let closed = acl.peer_ingress_for(&ranger, &store, false);
    assert!(closed.all);
    assert_eq!(closed.deny_tcp, vec!["22"]);
    assert!(!acl.allows_ssh(&ranger, &store, "root"));
    assert!(acl.allows_ssh(&ranger, &store, "ubuntu"));

    let mut office = Subject::new(Role::Member, vec![DeviceTag::Office]);
    office.authenticated_at = Some(now() - 60);
    assert!(acl.allows_ssh(&office, &store, "deploy"));
    assert_eq!(acl.peer_ingress_for(&office, &store, true).tcp, vec!["22"]);
    office.authenticated_at = Some(now() - 7200);
    assert!(!acl.allows_ssh(&office, &store, "deploy"));
    let lapsed = acl.peer_ingress_for(&office, &store, true);
    assert!(lapsed.tcp.is_empty());
    assert_eq!(lapsed.deny_tcp, vec!["22"]);
    // Unknown authentication time never satisfies a check rule.
    office.authenticated_at = None;
    assert!(!acl.allows_ssh(&office, &store, "deploy"));
}

#[test]
fn ssh_rules_govern_port_22_and_policy_tests_see_it() {
    let rejected = check_policy_document(
        &serde_json::json!({
            "defaults":"deny",
            "rules":[{"action":"allow","src_tags":["office"],"dst_tags":["store"],"dst_ports":["22"],"protocols":["tcp"]}],
            "ssh":[{"action":"allow","src_tags":["ranger"],"dst_tags":["store"],"users":["deploy"]}],
            "tests":[{"src_tags":["office"],"dst_tags":["store"],"dst_port":22,"protocol":"tcp","allow":true}]
        })
        .to_string(),
    );
    assert!(rejected.is_err());
    let posture_test = check_policy_document(
        &serde_json::json!({
            "defaults":"deny",
            "rules":[{"action":"allow","src_tags":["office"],"dst_tags":["store"],"posture":["baseline"]}],
            "tests":[
                {"src_tags":["office"],"dst_tags":["store"],"allow":false},
                {"src_tags":["office"],"dst_tags":["store"],"src_posture":["baseline"],"allow":true}
            ]
        })
        .to_string(),
    );
    assert!(posture_test.is_ok(), "{posture_test:?}");
}

#[tokio::test]
async fn capability_report_on_long_poll_returns_the_recompiled_grant() {
    let store = Store::memory().await.unwrap();
    let router = app(store, "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "caps-org").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let laptop = register_test_node(&router, org.id, &owner, "laptop", "laptop-key", &[]).await;
    let server = register_test_node(&router, org.id, &owner, "server", "server-key", &[]).await;
    put_policy(
        &router,
        org.id,
        &owner,
        serde_json::json!({
            "defaults":"deny",
            "groups":{"crew":["owner-1"]},
            "rules":[{"action":"allow","src_groups":["crew"],"dst_groups":["crew"],"dst_ports":["443"],"protocols":["tcp"]}],
            "ssh":[{"action":"allow","src_groups":["crew"],"dst_groups":["crew"],"users":["deploy"]}]
        }),
    )
    .await;
    let poll = |query: String| {
        let router = router.clone();
        let token = server.node_token.clone();
        let id = server.id;
        async move {
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{id}/updates?{query}"),
                serde_json::Value::Null,
                Some(&token),
            )
            .await
        }
    };
    let laptop_grant = |snapshot: &serde_json::Value| {
        snapshot["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|peer| peer["id"] == laptop.id.to_string())
            .unwrap()["ingress"]
            .clone()
    };
    let first: serde_json::Value = body(poll("since=0&capabilities=acl-filter".into()).await).await;
    assert_eq!(laptop_grant(&first)["deny_tcp"][0], "22");
    let current = first["revision"].as_i64().unwrap();
    // Unchanged capabilities: nothing new to send.
    assert_eq!(
        poll(format!("since={current}&wait=0&capabilities=acl-filter"))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let response = poll(format!(
        "since={current}&wait=0&capabilities=acl-filter,ssh-users"
    ))
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let opened: serde_json::Value = body(response).await;
    assert!(opened["revision"].as_i64().unwrap() > current);
    let grant = laptop_grant(&opened);
    assert_eq!(grant["tcp"], serde_json::json!(["22", "443"]));
    assert!(grant.get("deny_tcp").is_none());
}

#[tokio::test]
async fn concurrent_policy_puts_with_one_etag_publish_once() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "acl-race-org").await;
    let owner = || signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let before = load_acl_row(&store, org.id).await.unwrap();
    let etag = hash(&before.json);
    let put = |defaults: &'static str| {
        let request = Request::builder()
            .method(Method::PUT)
            .uri(format!("/v1/orgs/{}/acl", org.id))
            .header(
                AUTHORIZATION,
                format!("Bearer {}", sign_test_assertion(&owner())),
            )
            .header("content-type", "application/json")
            .header("if-match", format!("\"{etag}\""))
            .body(Body::from(
                serde_json::json!({"version":1,"defaults":defaults,"rules":[]}).to_string(),
            ))
            .unwrap();
        router.clone().oneshot(request)
    };
    let (first, second) = tokio::join!(put("deny"), put("same_tag"));
    let mut statuses = [first.unwrap().status(), second.unwrap().status()];
    statuses.sort();
    assert_eq!(
        statuses,
        [StatusCode::NO_CONTENT, StatusCode::PRECONDITION_FAILED]
    );
    let after = load_acl_row(&store, org.id).await.unwrap();
    assert_eq!(after.revision, before.revision + 1);
    assert_eq!(after.previous.as_deref(), Some(before.json.as_str()));

    // The publish itself is a compare-and-swap on the revision read, so a
    // writer that read before another committed (Postgres READ COMMITTED)
    // cannot overwrite it.
    let mut tx = store.pool.begin().await.unwrap();
    let stale = publish_acl_tx(&mut tx, org.id, &before.json, &before.json, before.revision).await;
    assert!(matches!(stale, Err(ApiError::PreconditionFailed)));
}
