//! Routing-peer forward allow-list tests (subnet forwarding enforcement).

use super::*;
use crate::forwarding::{ForwardFilter, ForwardRule, ForwardService};

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

/// The routing peer's allow-list, as a forward-filter-capable agent sees it.
async fn allow_list(router: &Router, node: &RegisterResponse) -> ForwardFilter {
    poll(router, node, "?capabilities=forward-filter")
        .await
        .forward_filter
        .expect("forward filter for a capable agent")
}

fn entries<'a>(rules: &'a [ForwardRule], client: &RegisterResponse) -> Vec<&'a ForwardRule> {
    rules
        .iter()
        .filter(|rule| rule.client == client.id)
        .collect()
}

/// Whether `client`'s entries in `filter` let it reach `host` on this service.
fn reaches(
    filter: &ForwardFilter,
    client: &RegisterResponse,
    host: &str,
    protocol: Option<AclProtocol>,
    port: Option<u16>,
) -> bool {
    let own = |rules: &[ForwardRule]| {
        rules
            .iter()
            .filter(|rule| rule.client == client.id)
            .cloned()
            .collect()
    };
    let filter = ForwardFilter {
        deny: own(&filter.deny),
        allow: own(&filter.allow),
    };
    crate::forwarding::permits(&filter, host, protocol, port)
}

fn sources_of(node: &RegisterResponse) -> BTreeSet<String> {
    node.assigned_ips.iter().cloned().collect()
}

async fn approve(router: &Router, org: Uuid, session: &str, node: Uuid, routes: &[&str]) {
    let response = call(
        router,
        Method::PUT,
        &format!("/v1/orgs/{org}/nodes/{node}/routes"),
        serde_json::json!({ "approved_routes": routes }),
        Some(session),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

async fn create_resource(
    router: &Router,
    org: Uuid,
    session: &str,
    body_json: serde_json::Value,
) -> serde_json::Value {
    let response = call(
        router,
        Method::POST,
        &format!("/v1/orgs/{org}/networks"),
        body_json,
        Some(session),
    )
    .await;
    assert!(response.status().is_success(), "{}", response.status());
    body(response).await
}

#[tokio::test]
async fn router_allow_list_names_only_authorised_clients_with_exact_ports() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "forward-org").await;
    let other = create_test_org(&router, "forward-other-org").await;
    let owner = || signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let alice = || signed_session(org.id, "alice", Role::Admin, now() + 60);
    let bob = || signed_session(org.id, "bob", Role::Admin, now() + 60);
    let stranger = || signed_session(other.id, "owner-1", Role::Owner, now() + 60);
    put_policy(
        &router,
        org.id,
        &owner(),
        serde_json::json!({
            "version": 1,
            "defaults": "same_tag",
            "groups": {"field": ["alice"]},
            "hosts": {"wiki": "10.20.1.10"},
            "rules": [
                {"action":"deny","src_groups":["field"],"dst_hosts":["wiki"],"dst_ports":["8080"],"protocols":["tcp"]},
                {"action":"allow","src_groups":["field"],"dst_hosts":["wiki"],"dst_ports":["53"],"protocols":["udp"]}
            ]
        }),
    )
    .await;
    let subnet_router = register_test_node(
        &router,
        org.id,
        &owner(),
        "router-one",
        "router-one-key",
        &["10.20.0.0/16"],
    )
    .await;
    let client_a =
        register_test_node(&router, org.id, &alice(), "alice-laptop", "alice-key", &[]).await;
    let client_b = register_test_node(&router, org.id, &bob(), "bob-laptop", "bob-key", &[]).await;
    let outsider = register_test_node(
        &router,
        other.id,
        &stranger(),
        "outsider",
        "outsider-key",
        &[],
    )
    .await;

    let created = create_resource(
        &router,
        org.id,
        &owner(),
        serde_json::json!({
            "name": "Field office",
            "cidr": "10.20.1.0/24",
            "ports": ["443", "8000-8080"],
            "protocols": ["tcp"],
            "routing_peers": [{"node_id": subnet_router.id, "metric": 10}],
            "access": {"groups": ["field"]},
        }),
    )
    .await;
    // The router has not reported forward-filter yet: visible, not hidden.
    assert_eq!(created["port_enforcement"], "not_enforced");
    assert_eq!(created["status"]["forwarding"], "not_enforced");
    assert!(created["status"]["forwarding_detail"]
        .as_str()
        .unwrap()
        .contains("upgrade its agent"));
    // Old agents get no allow-list field at all.
    assert!(poll(&router, &subnet_router, "")
        .await
        .forward_filter
        .is_none());

    let filter = allow_list(&router, &subnet_router).await;
    let alice_allow = entries(&filter.allow, &client_a);
    let resource_entry = alice_allow
        .iter()
        .find(|rule| rule.destination == "10.20.1.0/24")
        .expect("authorised client present");
    assert_eq!(
        resource_entry.service,
        ForwardService {
            all: false,
            tcp: vec!["443".into(), "8000-8080".into()],
            udp: vec![],
            icmp: false,
        }
    );
    assert_eq!(
        resource_entry
            .sources
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
        sources_of(&client_a)
    );
    // Named-host rules inside the prefix: deny carve-out and extra allow.
    let wiki_deny = entries(&filter.deny, &client_a);
    assert_eq!(wiki_deny.len(), 1);
    assert_eq!(wiki_deny[0].destination, "10.20.1.10/32");
    assert_eq!(wiki_deny[0].service.tcp, vec!["8080"]);
    assert!(alice_allow
        .iter()
        .any(|rule| rule.destination == "10.20.1.10/32"
            && rule.service.udp == vec!["53".to_owned()]
            && rule.service.tcp.is_empty()));
    // Unauthorised client and the other organisation are absent.
    assert!(entries(&filter.allow, &client_b).is_empty());
    assert!(entries(&filter.deny, &client_b).is_empty());
    assert!(filter
        .allow
        .iter()
        .chain(&filter.deny)
        .all(|rule| rule.client != outsider.id && rule.client != subnet_router.id));

    // Status follows the capability report.
    let detail: serde_json::Value = body(
        call(
            &router,
            Method::GET,
            &format!(
                "/v1/orgs/{}/networks/{}",
                org.id,
                created["id"].as_str().unwrap()
            ),
            serde_json::Value::Null,
            Some(&owner()),
        )
        .await,
    )
    .await;
    assert_eq!(detail["port_enforcement"], "enforced");
    assert_eq!(detail["status"]["forwarding"], "enforced");
    assert_eq!(
        detail["status"]["routing_peers"][0]["forwarding"],
        "enforced"
    );

    // Disabling the resource removes its entries (and the host entries that
    // depended on the route).
    let disable = serde_json::json!({
        "name": "Field office",
        "cidr": "10.20.1.0/24",
        "ports": ["443", "8000-8080"],
        "protocols": ["tcp"],
        "routing_peers": [{"node_id": subnet_router.id, "metric": 10}],
        "access": {"groups": ["field"]},
        "enabled": false,
        "etag": detail["etag"],
    });
    let response = call(
        &router,
        Method::PUT,
        &format!(
            "/v1/orgs/{}/networks/{}",
            org.id,
            created["id"].as_str().unwrap()
        ),
        disable,
        Some(&owner()),
    )
    .await;
    assert!(response.status().is_success());
    let filter = allow_list(&router, &subnet_router).await;
    assert!(
        filter.allow.is_empty() && filter.deny.is_empty(),
        "{filter:?}"
    );
}

#[tokio::test]
async fn exit_node_forwarding_only_for_clients_that_select_it() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "exit-forward-org").await;
    let owner = || signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let alice = || signed_session(org.id, "alice", Role::Admin, now() + 60);
    let bob = || signed_session(org.id, "bob", Role::Admin, now() + 60);
    put_policy(
        &router,
        org.id,
        &owner(),
        serde_json::json!({"version":1,"defaults":"same_tag","groups":{"field":["alice"]},"rules":[]}),
    )
    .await;
    let exit = register_test_node(
        &router,
        org.id,
        &owner(),
        "exit-one",
        "exit-one-key",
        &["0.0.0.0/0", "10.1.0.0/24", "10.1.9.0/24"],
    )
    .await;
    approve(
        &router,
        org.id,
        &owner(),
        exit.id,
        &["0.0.0.0/0", "10.1.0.0/24"],
    )
    .await;
    create_resource(
        &router,
        org.id,
        &owner(),
        serde_json::json!({
            "name": "Field only",
            "cidr": "10.1.9.0/24",
            "routing_peers": [{"node_id": exit.id}],
            "access": {"groups": ["field"]},
        }),
    )
    .await;
    let client_a =
        register_test_node(&router, org.id, &alice(), "alice-laptop", "alice-key", &[]).await;
    let client_b = register_test_node(&router, org.id, &bob(), "bob-laptop", "bob-key", &[]).await;

    // Nobody selected the exit node: approved subnet for both, no 0/0.
    poll(&router, &client_a, "").await;
    poll(&router, &client_b, "").await;
    let filter = allow_list(&router, &exit).await;
    assert!(filter
        .allow
        .iter()
        .all(|rule| rule.destination != "0.0.0.0/0"));
    assert!(entries(&filter.allow, &client_b)
        .iter()
        .any(|rule| rule.destination == "10.1.0.0/24" && rule.service.all));
    assert!(entries(&filter.allow, &client_a)
        .iter()
        .any(|rule| rule.destination == "10.1.9.0/24"));

    // Bob selects the exit node: the selection bumps the revision, his 0/0
    // appears, and the group-only resource stays denied to him.
    let revision = |store: Store| async move {
        sqlx::query_scalar::<_, i64>("SELECT control_revision FROM orgs WHERE id=$1")
            .bind(org.id.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap()
    };
    let before = revision(store.clone()).await;
    let selected = poll(&router, &client_b, "?exit_node=exit-one").await;
    assert!(selected.exit_node_active);
    assert!(revision(store.clone()).await > before);
    let filter = allow_list(&router, &exit).await;
    assert!(reaches(&filter, &client_b, "203.0.113.9/32", None, None));
    assert!(reaches(&filter, &client_b, "10.1.0.4/32", None, None));
    assert!(!reaches(&filter, &client_b, "10.1.9.4/32", None, None));
    // The exit route is allowed as its complement around carried prefixes.
    assert!(entries(&filter.allow, &client_b)
        .iter()
        .all(|rule| rule.destination != "0.0.0.0/0"));
    assert!(entries(&filter.deny, &client_b)
        .iter()
        .any(|rule| rule.destination == "10.1.9.0/24" && rule.service.all));
    assert!(entries(&filter.allow, &client_a)
        .iter()
        .all(|rule| rule.destination != "0.0.0.0/0"));

    // A restarted coordinator or another replica on the same database
    // compiles the same exit allow-list without Bob polling again.
    let replica = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let filter = allow_list(&replica, &exit).await;
    assert!(reaches(&filter, &client_b, "203.0.113.9/32", None, None));

    // Deselecting withdraws it again.
    poll(&router, &client_b, "").await;
    let filter = allow_list(&router, &exit).await;
    assert!(!reaches(&filter, &client_b, "203.0.113.9/32", None, None));
    assert!(entries(&filter.deny, &client_b).is_empty());
}

#[tokio::test]
async fn exit_route_never_widens_carried_prefixes_or_host_rules() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "exit-carried-org").await;
    let owner = || signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let alice = || signed_session(org.id, "alice", Role::Admin, now() + 60);
    // A general allow (no named hosts) must not open subnet hosts; only the
    // named-host rule does.
    put_policy(
        &router,
        org.id,
        &owner(),
        serde_json::json!({
            "version": 1,
            "defaults": "same_tag",
            "groups": {"field": ["alice"]},
            "hosts": {"nas": "10.1.0.10", "wiki": "10.1.0.20"},
            "rules": [
                {"action":"allow","src_groups":["field"]},
                {"action":"allow","src_groups":["field"],"dst_hosts":["wiki"],"dst_ports":["8080"],"protocols":["tcp"]}
            ]
        }),
    )
    .await;
    let exit = register_test_node(
        &router,
        org.id,
        &owner(),
        "exit-a",
        "exit-a-key",
        &["0.0.0.0/0", "192.168.50.0/24"],
    )
    .await;
    approve(&router, org.id, &owner(), exit.id, &["0.0.0.0/0"]).await;
    let standby_owner = register_test_node(
        &router,
        org.id,
        &owner(),
        "router-b",
        "router-b-key",
        &["10.2.0.0/24"],
    )
    .await;
    create_resource(
        &router,
        org.id,
        &owner(),
        serde_json::json!({
            "name": "Web only",
            "cidr": "10.1.0.0/24",
            "ports": ["443"],
            "protocols": ["tcp"],
            "routing_peers": [{"node_id": exit.id, "metric": 10}],
            "access": {"groups": ["field"]},
        }),
    )
    .await;
    // Exit-a is only a standby routing peer here: router-b is selected.
    create_resource(
        &router,
        org.id,
        &owner(),
        serde_json::json!({
            "name": "Standby",
            "cidr": "10.2.0.0/24",
            "routing_peers": [
                {"node_id": standby_owner.id, "metric": 10},
                {"node_id": exit.id, "metric": 100}
            ],
            "access": {"groups": ["field"]},
        }),
    )
    .await;
    let client = register_test_node(&router, org.id, &alice(), "alice", "alice-key", &[]).await;
    assert!(
        poll(&router, &client, "?exit_node=exit-a")
            .await
            .exit_node_active
    );
    let filter = allow_list(&router, &exit).await;
    let tcp = Some(AclProtocol::Tcp);
    // Internet traffic still exits.
    assert!(reaches(&filter, &client, "203.0.113.9/32", tcp, Some(22)));
    // The port-limited resource keeps its limit despite the exit route.
    assert!(reaches(&filter, &client, "10.1.0.5/32", tcp, Some(443)));
    assert!(!reaches(&filter, &client, "10.1.0.5/32", tcp, Some(22)));
    assert!(!reaches(
        &filter,
        &client,
        "10.1.0.5/32",
        Some(AclProtocol::Udp),
        Some(53)
    ));
    // A general rule does not open a named host; the named-host rule does.
    assert!(!reaches(&filter, &client, "10.1.0.10/32", tcp, Some(22)));
    assert!(reaches(&filter, &client, "10.1.0.20/32", tcp, Some(8080)));
    // Standby resource prefixes and advertised-but-unapproved routes are
    // closed to the exit client.
    assert!(!reaches(&filter, &client, "10.2.0.5/32", tcp, Some(443)));
    assert!(!reaches(
        &filter,
        &client,
        "192.168.50.5/32",
        tcp,
        Some(443)
    ));
}

#[tokio::test]
async fn policy_denied_client_and_device_routes_without_capability() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "forward-policy-org").await;
    let owner = || signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let alice = || signed_session(org.id, "alice", Role::Admin, now() + 60);
    let bob = || signed_session(org.id, "bob", Role::Admin, now() + 60);
    let subnet_router = register_test_node(
        &router,
        org.id,
        &owner(),
        "router-one",
        "router-one-key",
        &["10.5.0.0/24"],
    )
    .await;
    approve(
        &router,
        org.id,
        &owner(),
        subnet_router.id,
        &["10.5.0.0/24"],
    )
    .await;
    let client_a =
        register_test_node(&router, org.id, &alice(), "alice-laptop", "alice-key", &[]).await;
    let client_b = register_test_node(&router, org.id, &bob(), "bob-laptop", "bob-key", &[]).await;
    // Only alice may reach the router at all.
    put_policy(
        &router,
        org.id,
        &owner(),
        serde_json::json!({
            "version": 1,
            "defaults": "deny",
            "groups": {"field": ["alice"], "ops": ["owner-1"]},
            "hosts": {"printer": "10.5.0.20"},
            "rules": [
                {"action":"allow","src_groups":["field"],"dst_groups":["ops"]},
                {"action":"allow","src_groups":["ops"],"dst_groups":["field"]},
                {"action":"allow","src_groups":["ops"],"dst_groups":["ops"]}
            ]
        }),
    )
    .await;
    let filter = allow_list(&router, &subnet_router).await;
    assert!(entries(&filter.allow, &client_a)
        .iter()
        .any(|rule| rule.destination == "10.5.0.0/24" && rule.service.all));
    assert!(entries(&filter.allow, &client_b).is_empty());

    // Explain reports the router's real enforcement for a routed host.
    let explain = |router_handle: Router, port: u16| {
        let client_a = client_a.id;
        async move {
            let response = call(
                &router_handle,
                Method::POST,
                &format!("/v1/orgs/{}/policy/explain", org.id),
                serde_json::json!({"source_node_id": client_a, "dst_host": "printer", "protocol": "tcp", "port": port}),
                Some(&owner()),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            body::<serde_json::Value>(response).await
        }
    };
    let enforced = explain(router.clone(), 631).await;
    assert_eq!(enforced["enforcement"]["state"], "device_enforced");
    assert!(enforced["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason.as_str().unwrap().contains("would forward")));

    // The same router stops reporting the capability: not enforced.
    poll(&router, &subnet_router, "?capabilities=acl-filter").await;
    let unenforced = explain(router.clone(), 631).await;
    assert_eq!(unenforced["enforcement"]["state"], "not_enforced");
    assert!(unenforced["enforcement"]["detail"]
        .as_str()
        .unwrap()
        .contains("upgrade"));
    let overview: serde_json::Value = body(
        call(
            &router,
            Method::GET,
            &format!("/v1/orgs/{}/networks", org.id),
            serde_json::Value::Null,
            Some(&owner()),
        )
        .await,
    )
    .await;
    let device = overview["device_routes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["node_id"] == serde_json::json!(subnet_router.id))
        .unwrap();
    assert_eq!(device["forwarding"], "not_enforced");
}

#[test]
fn resource_constraints_map_to_services() {
    use crate::forwarding::resource_service;
    use crate::resources::ResourceProtocol;
    assert!(resource_service(&[], &[]).all);
    let tcp_udp = resource_service(&["443".into()], &[]);
    assert_eq!(tcp_udp.tcp, vec!["443"]);
    assert_eq!(tcp_udp.udp, vec!["443"]);
    assert!(!tcp_udp.icmp && !tcp_udp.all);
    let icmp = resource_service(&[], &[ResourceProtocol::Icmp]);
    assert!(icmp.icmp && icmp.tcp.is_empty() && icmp.udp.is_empty());
    let udp_all = resource_service(&[], &[ResourceProtocol::Udp]);
    assert_eq!(udp_all.udp, vec!["1-65535"]);
    assert!(udp_all.admits(Some(AclProtocol::Udp), Some(53)));
    assert!(!udp_all.admits(Some(AclProtocol::Tcp), Some(53)));
}

#[tokio::test]
async fn changed_advertisements_bump_the_control_revision_once() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "advertise-revision-org").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let node = register_test_node(
        &router,
        org.id,
        &owner,
        "router-one",
        "router-one-key",
        &["10.5.0.0/24"],
    )
    .await;
    let revision = || async {
        sqlx::query_scalar::<_, i64>("SELECT control_revision FROM orgs WHERE id=$1")
            .bind(org.id.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap()
    };
    let advertise = |routes: serde_json::Value| {
        let router = router.clone();
        let (id, token) = (node.id, node.node_token.clone());
        async move {
            call(
                &router,
                Method::PUT,
                &format!("/v1/nodes/{id}/routes"),
                serde_json::json!({ "advertised_routes": routes }),
                Some(&token),
            )
            .await
            .status()
        }
    };

    let before = revision().await;
    assert_eq!(
        advertise(serde_json::json!(["10.5.0.0/24"])).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(revision().await, before, "unchanged advertisement");
    assert_eq!(
        advertise(serde_json::json!(["10.5.0.0/24", "10.6.0.0/24"])).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(revision().await, before + 1, "changed advertisement");
}

#[tokio::test]
async fn exit_selection_on_a_long_poll_returns_a_fresh_snapshot() {
    // An agent resumed with a new `--exit-node` only long-polls `/updates`
    // with its current revision; the selection must still take effect.
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "exit-long-poll-org").await;
    let owner = || signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let exit = register_test_node(
        &router,
        org.id,
        &owner(),
        "exit-one",
        "exit-one-key",
        &["0.0.0.0/0"],
    )
    .await;
    approve(&router, org.id, &owner(), exit.id, &["0.0.0.0/0"]).await;
    let client =
        register_test_node(&router, org.id, &owner(), "client-one", "client-key", &[]).await;
    let updates = |since: i64, query: &'static str| {
        let router = router.clone();
        let (id, token) = (client.id, client.node_token.clone());
        async move {
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{id}/updates?since={since}&wait=0&version=2{query}"),
                serde_json::Value::Null,
                Some(&token),
            )
            .await
        }
    };
    let has_default = |snapshot: &serde_json::Value| {
        snapshot["peers"].as_array().unwrap().iter().any(|peer| {
            peer["allowed_ips"]
                .as_array()
                .unwrap()
                .iter()
                .any(|ip| ip == "0.0.0.0/0")
        })
    };

    // The exit node's first capability report bumps the revision; get it
    // out of the way so the client's long poll below starts idle.
    let filter = allow_list(&router, &exit).await;
    assert!(!reaches(&filter, &client, "203.0.113.9/32", None, None));
    let first: serde_json::Value = body(updates(0, "").await).await;
    assert!(!has_default(&first));
    let revision = first["revision"].as_i64().unwrap();
    assert_eq!(updates(revision, "").await.status(), StatusCode::NO_CONTENT);

    // Selecting the exit node on an otherwise idle organisation answers at
    // once with the default route.
    let response = updates(revision, "&exit_node=exit-one").await;
    assert_eq!(response.status(), StatusCode::OK);
    let selected: serde_json::Value = body(response).await;
    assert_eq!(selected["exit_node_active"], true);
    assert!(has_default(&selected));
    let revision = selected["revision"].as_i64().unwrap();
    let filter = allow_list(&router, &exit).await;
    assert!(reaches(&filter, &client, "203.0.113.9/32", None, None));
    // Repeating the same choice does not churn the revision.
    assert_eq!(
        updates(revision, "&exit_node=exit-one").await.status(),
        StatusCode::NO_CONTENT
    );
    // Dropping the choice withdraws it the same way.
    let response = updates(revision, "").await;
    assert_eq!(response.status(), StatusCode::OK);
    let dropped: serde_json::Value = body(response).await;
    assert_eq!(dropped["exit_node_active"], false);
    assert!(!has_default(&dropped));
}

#[tokio::test]
async fn routing_peer_failover_reaches_idle_long_polls() {
    // Liveness changes write nothing that bumps the revision; a client whose
    // long-poll is otherwise idle must still move to the standby router.
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "failover-poll-org").await;
    let owner = || signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let primary = register_test_node(
        &router,
        org.id,
        &owner(),
        "primary",
        "primary-key",
        &["10.30.0.0/24"],
    )
    .await;
    let standby = register_test_node(
        &router,
        org.id,
        &owner(),
        "standby",
        "standby-key",
        &["10.30.0.0/24"],
    )
    .await;
    create_resource(
        &router,
        org.id,
        &owner(),
        serde_json::json!({
            "name": "Site",
            "cidr": "10.30.0.0/24",
            "routing_peers": [
                {"node_id": primary.id, "metric": 10},
                {"node_id": standby.id, "metric": 20}
            ],
            "access": {"roles": ["owner"]},
        }),
    )
    .await;
    let client = register_test_node(&router, org.id, &owner(), "client", "client-key", &[]).await;
    let seen = |node: Uuid, at: i64| {
        let pool = store.pool.clone();
        async move {
            sqlx::query("UPDATE nodes SET last_seen_at=$1 WHERE id=$2")
                .bind(at)
                .bind(node.to_string())
                .execute(&pool)
                .await
                .unwrap();
        }
    };
    seen(primary.id, now()).await;
    seen(standby.id, now()).await;
    let updates = |since: i64| {
        let router = router.clone();
        let (id, token) = (client.id, client.node_token.clone());
        async move {
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{id}/updates?since={since}&wait=0&version=2"),
                serde_json::Value::Null,
                Some(&token),
            )
            .await
        }
    };
    let carrier = |snapshot: &serde_json::Value| {
        snapshot["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|peer| {
                peer["allowed_ips"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|ip| ip == "10.30.0.0/24")
            })
            .map(|peer| peer["id"].as_str().unwrap().to_owned())
    };

    let first: serde_json::Value = body(updates(0).await).await;
    assert_eq!(carrier(&first), Some(primary.id.to_string()));
    let revision = first["revision"].as_i64().unwrap();
    assert_eq!(updates(revision).await.status(), StatusCode::NO_CONTENT);

    // The primary goes quiet; after the next liveness check the idle poll
    // answers with the standby carrying the prefix.
    seen(primary.id, now() - NODE_ONLINE_SECS - 30).await;
    tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
    let response = updates(revision).await;
    assert_eq!(response.status(), StatusCode::OK);
    let failed_over: serde_json::Value = body(response).await;
    assert_eq!(carrier(&failed_over), Some(standby.id.to_string()));
    let revision = failed_over["revision"].as_i64().unwrap();
    assert_eq!(updates(revision).await.status(), StatusCode::NO_CONTENT);

    // And back again when the primary returns.
    seen(primary.id, now()).await;
    tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
    let back: serde_json::Value = body(updates(revision).await).await;
    assert_eq!(carrier(&back), Some(primary.id.to_string()));
}
