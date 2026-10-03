//! IPv6 subnet routes and exit, staged renumbering, and pool growth
//! (NetBird-parity drafts 04, 05 and 26).

use super::*;
use crate::forwarding::ForwardFilter;

async fn poll(router: &Router, node: &RegisterResponse, query: &str) -> PeersResponse {
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

fn peer_ips(snapshot: &PeersResponse, peer: &RegisterResponse) -> Vec<String> {
    snapshot
        .peers
        .iter()
        .find(|candidate| candidate.id == peer.id)
        .map(|candidate| candidate.allowed_ips.clone())
        .unwrap_or_default()
}

async fn approve(
    router: &Router,
    org: Uuid,
    session: &str,
    node: Uuid,
    routes: &[&str],
) -> StatusCode {
    call(
        router,
        Method::PUT,
        &format!("/v1/orgs/{org}/nodes/{node}/routes"),
        serde_json::json!({ "approved_routes": routes }),
        Some(session),
    )
    .await
    .status()
}

async fn send(
    router: &Router,
    method: Method,
    uri: &str,
    value: serde_json::Value,
    session: &str,
    if_match: Option<&str>,
) -> Response {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header(
            "authorization",
            format!("Bearer {}", sign_test_assertion(session)),
        );
    if let Some(etag) = if_match {
        request = request.header("if-match", format!("\"{etag}\""));
    }
    router
        .clone()
        .oneshot(request.body(Body::from(value.to_string())).unwrap())
        .await
        .unwrap()
}

fn allow_destinations(filter: &ForwardFilter, client: &RegisterResponse) -> BTreeSet<String> {
    filter
        .allow
        .iter()
        .filter(|rule| rule.client == client.id)
        .map(|rule| rule.destination.clone())
        .collect()
}

#[test]
fn ipv6_advertisements_are_validated_and_kept_off_the_overlay() {
    assert_eq!(
        validate_advertised_routes(vec![
            "fd42:1::/64".into(),
            "10.2.0.0/16".into(),
            "2001:db8:5::/48".into(),
            "::/0".into(),
            "fd42:1::/64".into(),
        ])
        .unwrap(),
        vec!["10.2.0.0/16", "2001:db8:5::/48", "::/0", "fd42:1::/64"]
    );
    for invalid in [
        "fd42::1/64",
        "fe80::/64",
        "ff02::/16",
        "::1/128",
        "2000::/3",
        "fc00::/16",
        "64:ff9b::/96",
        "fd42::/129",
    ] {
        assert!(
            validate_advertised_routes(vec![invalid.into()]).is_err(),
            "{invalid}"
        );
    }
    assert!(
        validate_advertised_routes(vec!["fd42::/48".into(), "fd42:0:0:1::/64".into()]).is_err(),
        "overlapping IPv6 advertisements"
    );
    // IPv4 and IPv6 prefixes never overlap each other.
    assert!(validate_advertised_routes(vec!["10.0.0.0/8".into(), "fd0a::/16".into()]).is_ok());

    let org = Uuid::new_v4().to_string();
    let device_pool = crate::address_pool::org_ula_pool(&org);
    assert!(ensure_routes_outside_overlay(&org, std::slice::from_ref(&device_pool)).is_err());
    assert!(ensure_routes_outside_overlay(&org, &["fd00::/8".into()]).is_err());
    assert!(ensure_routes_outside_overlay(&org, &["::/0".into(), "fd42:1::/64".into()]).is_ok());
}

#[tokio::test]
async fn ipv6_subnet_routes_are_approved_distributed_and_forward_filtered() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "ipv6-routes-org").await;
    let owner = || signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let member = || signed_session(org.id, "member-1", Role::Member, now() + 60);
    let subnet_router = register_test_node(
        &router,
        org.id,
        &owner(),
        "v6-router",
        "v6-router-key",
        &["fd42:1::/64", "fd42:2::/64", "10.30.0.0/16"],
    )
    .await;
    let second_router = register_test_node(
        &router,
        org.id,
        &owner(),
        "v6-router-two",
        "v6-router-two-key",
        &["fd42:1:0:0::/56"],
    )
    .await;
    let client =
        register_test_node(&router, org.id, &owner(), "v6-client", "v6-client-key", &[]).await;

    // Advertised is not distributed until approved, and members cannot approve.
    assert!(
        !peer_ips(&poll(&router, &client, "?ipv6=true").await, &subnet_router)
            .contains(&"fd42:1::/64".to_owned())
    );
    assert_eq!(
        approve(
            &router,
            org.id,
            &member(),
            subnet_router.id,
            &["fd42:1::/64"]
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        approve(
            &router,
            org.id,
            &owner(),
            subnet_router.id,
            &["fd42:1::/64"]
        )
        .await,
        StatusCode::NO_CONTENT
    );
    let routed = poll(&router, &client, "?ipv6=true").await;
    assert!(peer_ips(&routed, &subnet_router).contains(&"fd42:1::/64".to_owned()));
    // Agents that do not ask for IPv6 never receive IPv6 routes.
    assert!(peer_ips(&poll(&router, &client, "").await, &subnet_router)
        .iter()
        .all(|route| !route.contains(':')));
    // A second router cannot claim an overlapping IPv6 prefix.
    assert_eq!(
        approve(
            &router,
            org.id,
            &owner(),
            second_router.id,
            &["fd42:1::/56"]
        )
        .await,
        StatusCode::CONFLICT
    );

    // The routing peer's forward allow-list names the client's overlay
    // addresses (IPv4 and IPv6) for the IPv6 prefix.
    let filter = poll(
        &router,
        &subnet_router,
        "?ipv6=true&capabilities=forward-filter",
    )
    .await
    .forward_filter
    .expect("allow-list for a forward-filter agent");
    let entry = filter
        .allow
        .iter()
        .find(|rule| rule.client == client.id && rule.destination == "fd42:1::/64")
        .expect("client allowed to the IPv6 subnet");
    assert!(entry.service.all);
    assert_eq!(
        entry.sources.iter().cloned().collect::<BTreeSet<_>>(),
        client.assigned_ips.iter().cloned().collect::<BTreeSet<_>>()
    );
    assert!(entry.sources.iter().any(|source| source.ends_with("/128")));

    // An IPv6 CIDR resource is now carriable by a router advertising it.
    let response = call(
        &router,
        Method::POST,
        &format!("/v1/orgs/{}/networks", org.id),
        serde_json::json!({
            "name": "Site B IPv6",
            "cidr": "fd42:2::/64",
            "routing_peers": [{"node_id": subnet_router.id, "metric": 10}],
            "access": {"roles": ["owner"]},
        }),
        Some(&owner()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created: serde_json::Value = body(response).await;
    assert_eq!(
        created["status"]["selected_routing_peer"],
        subnet_router.id.to_string()
    );
    assert!(
        peer_ips(&poll(&router, &client, "?ipv6=true").await, &subnet_router)
            .contains(&"fd42:2::/64".to_owned())
    );
    let filter = poll(
        &router,
        &subnet_router,
        "?ipv6=true&capabilities=forward-filter",
    )
    .await
    .forward_filter
    .unwrap();
    assert!(allow_destinations(&filter, &client).contains("fd42:2::/64"));
}

#[tokio::test]
async fn ipv6_exit_route_is_distributed_only_to_clients_that_select_it() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "ipv6-exit-org").await;
    let owner = || signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let exit = register_test_node(
        &router,
        org.id,
        &owner(),
        "dual-exit",
        "dual-exit-key",
        &["0.0.0.0/0", "::/0", "fd42:9::/64"],
    )
    .await;
    let client = register_test_node(
        &router,
        org.id,
        &owner(),
        "exit-client",
        "exit-client-key",
        &[],
    )
    .await;
    assert_eq!(
        approve(
            &router,
            org.id,
            &owner(),
            exit.id,
            &["0.0.0.0/0", "::/0", "fd42:9::/64"]
        )
        .await,
        StatusCode::NO_CONTENT
    );
    let plain = poll(&router, &client, "?ipv6=true").await;
    assert!(!plain.exit_node_active);
    let routes = peer_ips(&plain, &exit);
    assert!(!routes.contains(&"::/0".to_owned()));
    assert!(!routes.contains(&"0.0.0.0/0".to_owned()));
    assert!(routes.contains(&"fd42:9::/64".to_owned()));

    let selected = poll(&router, &client, "?ipv6=true&exit_node=dual-exit").await;
    assert!(selected.exit_node_active);
    let routes = peer_ips(&selected, &exit);
    assert!(routes.contains(&"::/0".to_owned()));
    assert!(routes.contains(&"0.0.0.0/0".to_owned()));
    // IPv4-only agents keep the IPv4 exit and never see ::/0.
    let v4_only = poll(&router, &client, "?exit_node=dual-exit").await;
    assert!(!peer_ips(&v4_only, &exit).contains(&"::/0".to_owned()));

    // The exit's allow-list admits the client to the IPv6 Internet except
    // the IPv6 subnet it also carries, which stays under its own grant.
    let filter = poll(&router, &exit, "?ipv6=true&capabilities=forward-filter")
        .await
        .forward_filter
        .unwrap();
    let allowed = allow_destinations(&filter, &client);
    assert!(allowed.contains("fd42:9::/64"));
    assert!(
        !allowed.contains("::/0"),
        "::/0 is split around carried prefixes"
    );
    assert!(allowed.contains("::/1"));
    assert!(crate::forwarding::permits(
        &ForwardFilter {
            deny: filter
                .deny
                .iter()
                .filter(|rule| rule.client == client.id)
                .cloned()
                .collect(),
            allow: filter
                .allow
                .iter()
                .filter(|rule| rule.client == client.id)
                .cloned()
                .collect(),
        },
        "2606:4700::1111/128",
        None,
        None
    ));
    // Once the client stops selecting it, the IPv6 exit grant disappears.
    poll(&router, &client, "?ipv6=true").await;
    let filter = poll(&router, &exit, "?ipv6=true&capabilities=forward-filter")
        .await
        .forward_filter
        .unwrap();
    assert!(!allow_destinations(&filter, &client).contains("::/1"));
}

async fn ipam_view(router: &Router, org: Uuid, session: &str) -> serde_json::Value {
    let response = call(
        router,
        Method::GET,
        &format!("/v1/orgs/{org}/ipam"),
        serde_json::Value::Null,
        Some(session),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    body(response).await
}

#[tokio::test]
async fn renumber_stage_then_complete_keeps_both_addresses_during_the_window() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "renumber-org").await;
    let other = create_test_org(&router, "renumber-other").await;
    let owner = || signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let member = || signed_session(org.id, "member-1", Role::Member, now() + 60);
    let stranger = || signed_session(other.id, "owner-2", Role::Owner, now() + 60);
    let moving = register_test_node(&router, org.id, &owner(), "moving", "moving-key", &[]).await;
    let peer = register_test_node(&router, org.id, &owner(), "watcher", "watcher-key", &[]).await;
    let subnet_router = register_test_node(
        &router,
        org.id,
        &owner(),
        "renumber-router",
        "renumber-router-key",
        &["10.40.0.0/24"],
    )
    .await;
    assert_eq!(
        approve(
            &router,
            org.id,
            &owner(),
            subnet_router.id,
            &["10.40.0.0/24"]
        )
        .await,
        StatusCode::NO_CONTENT
    );
    let old = moving.assigned_ips.clone();
    assert_eq!(old[0], "100.64.0.1/32");
    let uri = format!("/v1/orgs/{}/ipam/renumber", org.id);
    let plan_body = serde_json::json!({
        "devices": [{"node_id": moving.id, "address": "100.64.0.50"}],
        "window_seconds": 3600,
        "reason": "move off a clashing printer range",
    });

    // Role and organisation checks come first.
    for (session, expected) in [
        (member(), StatusCode::FORBIDDEN),
        (stranger(), StatusCode::FORBIDDEN),
    ] {
        let response = call(
            &router,
            Method::POST,
            &uri,
            plan_body.clone(),
            Some(&session),
        )
        .await;
        assert!(
            response.status() == expected || response.status() == StatusCode::UNAUTHORIZED,
            "{}",
            response.status()
        );
    }
    // Window bounds.
    let too_short = call(
        &router,
        Method::POST,
        &uri,
        serde_json::json!({"devices": [{"node_id": moving.id}], "window_seconds": 60}),
        Some(&owner()),
    )
    .await;
    assert_eq!(too_short.status(), StatusCode::BAD_REQUEST);

    // Preview names the move and the automatic updates.
    let response = call(
        &router,
        Method::POST,
        &format!("{uri}/preview"),
        plan_body.clone(),
        Some(&owner()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let preview: serde_json::Value = body(response).await;
    assert_eq!(preview["moves"][0]["new_addresses"][0], "100.64.0.50/32");
    assert_eq!(preview["peer_maps"], 2);
    assert_eq!(preview["forward_allow_lists"], 1);
    assert_eq!(preview["magic_dns_names"][0], moving.dns_name);
    assert!(preview["blockers"].as_array().unwrap().is_empty());

    let response = call(
        &router,
        Method::POST,
        &uri,
        plan_body.clone(),
        Some(&owner()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let staged: serde_json::Value = body(response).await;
    assert_eq!(staged["state"], "staged");
    let new_v6 = staged["moves"][0]["new_addresses"][1]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(new_v6.ends_with(":32/128"), "{new_v6}");

    // During the window peers route and accept both addresses, new first,
    // and MagicDNS is told the old ones are retiring.
    let seen = poll(&router, &peer, "?ipv6=true").await;
    let ips = peer_ips(&seen, &moving);
    assert_eq!(
        ips,
        vec![
            "100.64.0.50/32".to_owned(),
            new_v6.clone(),
            old[0].clone(),
            old[1].clone()
        ]
    );
    assert_eq!(seen.retiring_ips, old);
    let own = poll(&router, &moving, "?ipv6=true").await;
    assert_eq!(own.assigned_ips[0], "100.64.0.50/32");
    assert!(own.assigned_ips.contains(&old[0]));
    assert_eq!(own.retiring_ips, old);
    // IPv4-only agents see only the IPv4 retiring address.
    assert_eq!(
        poll(&router, &peer, "").await.retiring_ips,
        vec![old[0].clone()]
    );
    // The router's forward allow-list admits both source addresses.
    let filter = poll(
        &router,
        &subnet_router,
        "?ipv6=true&capabilities=forward-filter",
    )
    .await
    .forward_filter
    .unwrap();
    let sources: BTreeSet<_> = filter
        .allow
        .iter()
        .filter(|rule| rule.client == moving.id)
        .flat_map(|rule| rule.sources.iter().cloned())
        .collect();
    assert!(sources.contains("100.64.0.50/32") && sources.contains(&old[0]));
    let view = ipam_view(&router, org.id, &member()).await;
    assert_eq!(view["renumber"]["staged"]["id"], staged["id"]);
    assert!(view["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["address"] == "100.64.0.1" && entry["state"] == "retiring"));

    // Only one plan at a time; a new enrolment never takes either address.
    let second = call(
        &router,
        Method::POST,
        &uri,
        serde_json::json!({"devices": [{"node_id": peer.id}]}),
        Some(&owner()),
    )
    .await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
    let newcomer =
        register_test_node(&router, org.id, &owner(), "newcomer", "newcomer-key", &[]).await;
    assert_eq!(newcomer.assigned_ip, "100.64.0.4/32");

    // Completion needs the current etag and a manager.
    let plan_id = staged["id"].as_str().unwrap();
    let etag = staged["etag"].as_str().unwrap();
    let complete = format!("{uri}/{plan_id}/complete");
    let missing = send(
        &router,
        Method::POST,
        &complete,
        serde_json::Value::Null,
        &owner(),
        None,
    )
    .await;
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    let stale = send(
        &router,
        Method::POST,
        &complete,
        serde_json::Value::Null,
        &owner(),
        Some("stale"),
    )
    .await;
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    let by_member = send(
        &router,
        Method::POST,
        &complete,
        serde_json::Value::Null,
        &member(),
        Some(etag),
    )
    .await;
    assert_eq!(by_member.status(), StatusCode::FORBIDDEN);
    let done = send(
        &router,
        Method::POST,
        &complete,
        serde_json::Value::Null,
        &owner(),
        Some(etag),
    )
    .await;
    assert_eq!(done.status(), StatusCode::OK);
    let done: serde_json::Value = body(done).await;
    assert_eq!(done["state"], "completed");

    let after = poll(&router, &peer, "?ipv6=true").await;
    assert_eq!(
        peer_ips(&after, &moving),
        vec!["100.64.0.50/32".to_owned(), new_v6]
    );
    assert!(after.retiring_ips.is_empty());
    // The old address waits out the reuse grace period.
    let view = ipam_view(&router, org.id, &owner()).await;
    let old_entry = view["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["address"] == "100.64.0.1")
        .cloned()
        .unwrap();
    assert_eq!(old_entry["state"], "released");
    let later = register_test_node(&router, org.id, &owner(), "later", "later-key", &[]).await;
    assert_ne!(later.assigned_ip, "100.64.0.1/32");

    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE org_id=$1 AND action LIKE 'ipam.renumber%' ORDER BY action DESC",
    )
    .bind(org.id.to_string())
    .fetch_all(&store.pool)
    .await
    .unwrap();
    assert_eq!(actions, ["ipam.renumber_staged", "ipam.renumber_completed"]);
    // Finished plans cannot be finished again.
    let again = send(
        &router,
        Method::POST,
        &format!("{uri}/{plan_id}/rollback"),
        serde_json::Value::Null,
        &owner(),
        Some(done["etag"].as_str().unwrap()),
    )
    .await;
    assert_eq!(again.status(), StatusCode::CONFLICT);
    // The other organisation cannot see or finish this plan.
    let foreign = send(
        &router,
        Method::POST,
        &format!("/v1/orgs/{}/ipam/renumber/{plan_id}/complete", other.id),
        serde_json::Value::Null,
        &stranger(),
        Some(etag),
    )
    .await;
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn renumber_rollback_restores_the_old_address_and_window_end_completes() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "rollback-org").await;
    let owner = || signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let moving = register_test_node(&router, org.id, &owner(), "moving", "moving-key", &[]).await;
    let peer = register_test_node(&router, org.id, &owner(), "watcher", "watcher-key", &[]).await;
    let uri = format!("/v1/orgs/{}/ipam/renumber", org.id);
    let response = call(
        &router,
        Method::POST,
        &uri,
        serde_json::json!({"devices": [{"node_id": moving.id}], "window_seconds": 600}),
        Some(&owner()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let staged: serde_json::Value = body(response).await;
    let new_v4 = staged["moves"][0]["new_addresses"][0]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(new_v4, "100.64.0.3/32");
    assert_eq!(peer_ips(&poll(&router, &peer, "").await, &moving).len(), 2);

    let rolled = send(
        &router,
        Method::POST,
        &format!("{uri}/{}/rollback", staged["id"].as_str().unwrap()),
        serde_json::Value::Null,
        &owner(),
        Some(staged["etag"].as_str().unwrap()),
    )
    .await;
    assert_eq!(rolled.status(), StatusCode::OK);
    let rolled: serde_json::Value = body(rolled).await;
    assert_eq!(rolled["state"], "rolled_back");
    let after = poll(&router, &peer, "?ipv6=true").await;
    assert_eq!(peer_ips(&after, &moving), moving.assigned_ips);
    assert!(after.retiring_ips.is_empty());
    // The briefly published new address is not handed out at once.
    let newcomer =
        register_test_node(&router, org.id, &owner(), "newcomer", "newcomer-key", &[]).await;
    assert_eq!(newcomer.assigned_ip, "100.64.0.4/32");

    // A second plan whose window has ended completes on the next poll.
    let response = call(
        &router,
        Method::POST,
        &uri,
        serde_json::json!({"devices": [{"node_id": moving.id, "address": "100.64.0.20"}], "window_seconds": 600}),
        Some(&owner()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    sqlx::query("UPDATE ipam_renumber_plans SET window_ends_at=$1 WHERE state='staged'")
        .bind(now() - 1)
        .execute(&store.pool)
        .await
        .unwrap();
    let after = poll(&router, &peer, "?ipv6=true").await;
    assert_eq!(peer_ips(&after, &moving)[0], "100.64.0.20/32");
    assert_eq!(peer_ips(&after, &moving).len(), 2);
    let state: String = sqlx::query_scalar(
        "SELECT state FROM ipam_renumber_plans WHERE org_id=$1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(org.id.to_string())
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(state, "completed");
    let automatic: String = sqlx::query_scalar(
        "SELECT actor_user_id FROM audit_events WHERE org_id=$1 AND action='ipam.renumber_completed'",
    )
    .bind(org.id.to_string())
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(automatic, "system:ipam-renumber");
}

#[tokio::test]
async fn renumber_is_blocked_by_literal_policy_references_and_pool_moves_follow_the_window() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "pool-move-org").await;
    let owner = || signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let first = register_test_node(&router, org.id, &owner(), "first", "first-key", &[]).await;
    let second = register_test_node(&router, org.id, &owner(), "second", "second-key", &[]).await;
    let response = call(
        &router,
        Method::PUT,
        &format!("/v1/orgs/{}/acl", org.id),
        serde_json::json!({
            "version": 1,
            "defaults": "same_tag",
            "hosts": {"first-host": "100.64.0.1"},
            "rules": [{"action":"allow","src_roles":["owner"],"dst_hosts":["first-host"]}]
        }),
        Some(&owner()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let uri = format!("/v1/orgs/{}/ipam/renumber", org.id);
    let move_pool = serde_json::json!({"pool": "100.64.4.0/24", "window_seconds": 600});
    let preview: serde_json::Value = body(
        call(
            &router,
            Method::POST,
            &format!("{uri}/preview"),
            move_pool.clone(),
            Some(&owner()),
        )
        .await,
    )
    .await;
    assert_eq!(preview["moves"].as_array().unwrap().len(), 2);
    assert_eq!(preview["blockers"][0]["kind"], "access policy");
    let blocked = call(
        &router,
        Method::POST,
        &uri,
        move_pool.clone(),
        Some(&owner()),
    )
    .await;
    assert_eq!(blocked.status(), StatusCode::CONFLICT);
    assert!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ipam_renumber_plans")
            .fetch_one(&store.pool)
            .await
            .unwrap()
            == 0
    );

    let response = call(
        &router,
        Method::PUT,
        &format!("/v1/orgs/{}/acl", org.id),
        serde_json::json!({"version": 1, "defaults": "same_tag", "rules": []}),
        Some(&owner()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = call(&router, Method::POST, &uri, move_pool, Some(&owner())).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let staged: serde_json::Value = body(response).await;
    assert_eq!(staged["kind"], "pool");
    assert_eq!(staged["moves"][0]["new_addresses"][0], "100.64.4.1/32");
    assert_eq!(staged["moves"][1]["new_addresses"][0], "100.64.4.2/32");
    // New enrolments already come from the new pool.
    let third = register_test_node(&router, org.id, &owner(), "third", "third-key", &[]).await;
    assert_eq!(third.assigned_ip, "100.64.4.3/32");
    // Rolling back would strand the newcomer outside the old pool.
    let rollback = send(
        &router,
        Method::POST,
        &format!("{uri}/{}/rollback", staged["id"].as_str().unwrap()),
        serde_json::Value::Null,
        &owner(),
        Some(staged["etag"].as_str().unwrap()),
    )
    .await;
    assert_eq!(rollback.status(), StatusCode::CONFLICT);
    let complete = send(
        &router,
        Method::POST,
        &format!("{uri}/{}/complete", staged["id"].as_str().unwrap()),
        serde_json::Value::Null,
        &owner(),
        Some(staged["etag"].as_str().unwrap()),
    )
    .await;
    assert_eq!(complete.status(), StatusCode::OK);
    let view = ipam_view(&router, org.id, &owner()).await;
    assert_eq!(view["pools"][0]["cidr"], "100.64.4.0/24");
    assert!(view["conflicts"].as_array().unwrap().is_empty(), "{view}");
    let seen = poll(&router, &third, "").await;
    assert_eq!(peer_ips(&seen, &first), vec!["100.64.4.1/32".to_owned()]);
    assert_eq!(peer_ips(&seen, &second), vec!["100.64.4.2/32".to_owned()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_growth_beyond_254_keeps_addresses_and_allocates_uniquely() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "growth-org").await;
    let owner = || signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let existing =
        register_test_node(&router, org.id, &owner(), "existing", "existing-key", &[]).await;
    // Fill the rest of the /24 with held leases from other coordinators.
    for host in 2..=254 {
        sqlx::query(
            "INSERT INTO ipam_leases(org_id,address,node_id,allocated_at) VALUES($1,$2,$3,$4)",
        )
        .bind(org.id.to_string())
        .bind(format!("100.64.0.{host}/32"))
        .bind(Uuid::new_v4().to_string())
        .bind(now())
        .execute(&store.pool)
        .await
        .unwrap();
    }
    let key: JoinKeyResponse = body(
        call(
            &router,
            Method::POST,
            &format!("/v1/orgs/{}/join-keys", org.id),
            serde_json::json!({"expires_in_seconds":60}),
            Some(&owner()),
        )
        .await,
    )
    .await;
    let full = call(
        &router,
        Method::POST,
        "/v1/nodes/register",
        serde_json::json!({"join_key": key.key, "name": "overflow", "wg_public_key": "overflow-key"}),
        None,
    )
    .await;
    assert_eq!(full.status(), StatusCode::CONFLICT);

    // Shrinking or misaligned pools are refused; growth applies at once.
    for (pool, status) in [
        ("100.64.0.0/25", StatusCode::BAD_REQUEST),
        ("100.64.1.0/22", StatusCode::BAD_REQUEST),
        ("100.64.0.0/24", StatusCode::BAD_REQUEST),
    ] {
        let response = call(
            &router,
            Method::POST,
            &format!("/v1/orgs/{}/ipam/renumber", org.id),
            serde_json::json!({ "pool": pool }),
            Some(&owner()),
        )
        .await;
        assert_eq!(response.status(), status, "{pool}");
    }
    let response = call(
        &router,
        Method::POST,
        &format!("/v1/orgs/{}/ipam/renumber", org.id),
        serde_json::json!({"pool": "100.64.0.0/22", "reason": "growth"}),
        Some(&owner()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let grown: serde_json::Value = body(response).await;
    assert_eq!(grown["state"], "completed");
    assert!(grown["moves"].as_array().unwrap().is_empty());
    let view = ipam_view(&router, org.id, &owner()).await;
    assert_eq!(view["pools"][0]["cidr"], "100.64.0.0/22");
    assert_eq!(view["pools"][0]["usable"], 1022);

    let tasks = (0..20).map(|index| {
        let router = router.clone();
        let session = owner();
        tokio::spawn(async move {
            register_test_node(
                &router,
                org.id,
                &session,
                &format!("wide-{index}"),
                &format!("wide-{index}-key"),
                &[],
            )
            .await
        })
    });
    let mut v4 = BTreeSet::new();
    let mut v6 = BTreeSet::new();
    for task in tasks {
        let node = task.await.unwrap();
        assert!(v4.insert(node.assigned_ips[0].clone()));
        assert!(v6.insert(node.assigned_ips[1].clone()));
        let ip: std::net::Ipv4Addr = node.assigned_ips[0]
            .strip_suffix("/32")
            .unwrap()
            .parse()
            .unwrap();
        assert!(u32::from(ip) > u32::from(std::net::Ipv4Addr::new(100, 64, 0, 254)));
        assert_eq!(
            Some(node.assigned_ips[1].clone()),
            crate::address_pool::ipv6_twin(&org.id.to_string(), &node.assigned_ips[0])
        );
    }
    assert!(v4.contains("100.64.0.255/32") && v4.contains("100.64.1.0/32"));
    // The device enrolled before the growth keeps both addresses.
    let seen = poll(&router, &existing, "?ipv6=true").await;
    assert_eq!(seen.assigned_ips, existing.assigned_ips);
    assert_eq!(existing.assigned_ips[0], "100.64.0.1/32");
    assert!(existing.assigned_ips[1].ends_with("::1/128"));
}

/// Slot 39 adds the pool column and plan table without touching any device
/// address.
#[tokio::test]
async fn schema_38_upgrade_keeps_every_device_address() {
    install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    apply_sqlite_migrations_to(&pool, 38).await.unwrap();
    let org_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO orgs(id,name,acl_json,created_at,acl_revision,control_revision) VALUES($1,'Upgrade org','{\"version\":1,\"defaults\":\"same_tag\",\"rules\":[]}',$2,1,1)",
    )
    .bind(&org_id)
    .bind(now().to_string())
    .execute(&pool)
    .await
    .unwrap();
    let mut before = Vec::new();
    for host in [1_u32, 254, 7] {
        let addresses = vec![
            format!("100.64.0.{host}/32"),
            org_ula_address(&org_id, host),
        ];
        let json = serde_json::to_string(&addresses).unwrap();
        sqlx::query(
            "INSERT INTO nodes(id,org_id,name,wg_public_key,allowed_ips_json,token_hash,created_at,user_id,user_role,tags_json,dns_name,advertised_routes_json,approved_routes_json,credential_expires_at)
             VALUES($1,$2,$3,$4,$5,$6,$7,'u','owner','[]',$8,'[]','[]',$9)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&org_id)
        .bind(format!("node-{host}"))
        .bind(format!("key-{host}"))
        .bind(&json)
        .bind(format!("hash-{host}"))
        .bind(now().to_string())
        .bind(format!("node-{host}.upgrade.blaktail"))
        .bind(now() + 86_400)
        .execute(&pool)
        .await
        .unwrap();
        before.push(json);
    }
    apply_sqlite_migrations(&pool).await.unwrap();
    let after: Vec<String> =
        sqlx::query_scalar("SELECT allowed_ips_json FROM nodes WHERE org_id=$1 ORDER BY name")
            .bind(&org_id)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(after, before);
    let cidr: String = sqlx::query_scalar("SELECT ipv4_pool_cidr FROM orgs WHERE id=$1")
        .bind(&org_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(cidr, "100.64.0.0/24");
    // The new derivation reproduces every stored IPv6 address.
    for json in &after {
        let addresses: Vec<String> = serde_json::from_str(json).unwrap();
        assert_eq!(
            crate::address_pool::ipv6_twin(&org_id, &addresses[0]).as_deref(),
            Some(addresses[1].as_str())
        );
    }
    for sql in [
        include_str!("../../migrations/sqlite/0039_renumbering.sql"),
        include_str!("../../migrations/postgres/0039_renumbering.sql"),
    ] {
        assert!(!sql.contains("UPDATE"));
        assert!(!sql.contains("allowed_ips_json"));
    }
}
