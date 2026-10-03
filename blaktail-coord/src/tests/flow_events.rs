//! Per-flow traffic events (draft 17): ingest, attribution, identities,
//! matched rule, grouping, filters, export and retention.

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

fn ip(node: &RegisterResponse) -> String {
    node.assigned_ip.split('/').next().unwrap().to_owned()
}

fn tcp(flow: &str, kind: &str, src: &str, sport: u16, dst: &str, dport: u16) -> serde_json::Value {
    serde_json::json!({
        "flow_id": flow,
        "type": kind,
        "at": now() - 20,
        "direction": "outbound",
        "protocol": "tcp",
        "src_ip": src,
        "src_port": sport,
        "dst_ip": dst,
        "dst_port": dport,
        "connection_type": "p2p",
    })
}

async fn send(
    router: &Router,
    node: &RegisterResponse,
    org: Uuid,
    events: Vec<serde_json::Value>,
) -> Response {
    call(
        router,
        Method::POST,
        &format!("/v1/nodes/{}/flow-events", node.id),
        serde_json::json!({
            "org_id": org,
            "window_start": now() - 30,
            "window_end": now(),
            "events": events,
        }),
        Some(&node.node_token),
    )
    .await
}

async fn flows(router: &Router, org: Uuid, session: &str, query: &str) -> serde_json::Value {
    let response = call(
        router,
        Method::GET,
        &format!("/v1/orgs/{org}/traffic/flows?{query}"),
        serde_json::Value::Null,
        Some(session),
    )
    .await;
    let status = response.status();
    let value: serde_json::Value = body(response).await;
    assert_eq!(status, StatusCode::OK, "{query}: {value}");
    value
}

#[tokio::test]
async fn flow_events_resolve_identities_rules_and_routers_and_stay_opt_in() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "flow-events").await;
    let other = create_test_org(&router, "flow-events-other").await;
    let owner = || signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let alice = || signed_session(org.id, "alice", Role::Admin, now() + 60);
    let member = signed_session(org.id, "member-1", Role::Member, now() + 60);
    let auditor = signed_session(org.id, "auditor-1", Role::Auditor, now() + 60);
    put_policy(
        &router,
        org.id,
        &owner(),
        serde_json::json!({
            "version": 1,
            "defaults": "deny",
            "groups": {"staff": ["alice"]},
            "rules": [
                {"action":"allow","src_groups":["staff"],"dst_roles":["owner"],"dst_ports":["22","443"],"protocols":["tcp"]},
                {"action":"allow","src_groups":["staff"],"dst_roles":["owner"],"protocols":["icmp"]},
                {"action":"deny","src_groups":["staff"],"dst_roles":["owner"],"dst_ports":["3389"],"protocols":["tcp"]},
                {"action":"allow","src_roles":["owner"],"dst_groups":["staff"],"protocols":["icmp"]}
            ]
        }),
    )
    .await;
    let laptop =
        register_test_node(&router, org.id, &alice(), "alice-laptop", "fe-alice", &[]).await;
    let server = register_test_node(&router, org.id, &owner(), "server", "fe-server", &[]).await;
    // Negative cases go through their own device: uploads are rate limited
    // per device.
    let probe = register_test_node(&router, org.id, &alice(), "probe", "fe-probe", &[]).await;
    let gateway = register_test_node(
        &router,
        org.id,
        &owner(),
        "router-1",
        "fe-router",
        &["10.30.0.0/16", "10.20.5.0/24"],
    )
    .await;
    let foreign = register_test_node(
        &router,
        other.id,
        &signed_session(other.id, "owner-2", Role::Owner, now() + 60),
        "foreign",
        "fe-foreign",
        &[],
    )
    .await;
    let response = call(
        &router,
        Method::PUT,
        &format!("/v1/orgs/{}/nodes/{}/routes", org.id, gateway.id),
        serde_json::json!({ "approved_routes": ["10.30.0.0/16"] }),
        Some(&owner()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = call(
        &router,
        Method::POST,
        &format!("/v1/orgs/{}/networks", org.id),
        serde_json::json!({
            "name": "Billing DB",
            "cidr": "10.20.5.0/24",
            "ports": ["5432"],
            "protocols": ["tcp"],
            "routing_peers": [{"node_id": gateway.id, "metric": 10}],
            "access": {"groups": ["staff"]},
        }),
        Some(&owner()),
    )
    .await;
    let status = response.status();
    let resource: serde_json::Value = body(response).await;
    assert!(status.is_success(), "{status} {resource}");

    let (a, s, g, p) = (ip(&laptop), ip(&server), ip(&gateway), ip(&probe));
    // Off: refused, nothing stored.
    let response = send(
        &router,
        &probe,
        org.id,
        vec![tcp("f1", "start", &a, 50_000, &s, 22)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    call(
        &router,
        Method::PUT,
        &format!("/v1/orgs/{}/traffic/settings", org.id),
        serde_json::json!({"enabled":true,"sampling_rate":1}),
        Some(&owner()),
    )
    .await;

    // Attribution: a device may not report someone else's connection, a
    // foreign organisation, a foreign peer, or a payload field.
    for (node, events, status) in [
        (
            &probe,
            vec![tcp("x", "start", &s, 50_000, &g, 22)],
            StatusCode::FORBIDDEN,
        ),
        (
            &probe,
            vec![{
                let mut e = tcp("x", "start", &p, 50_000, &s, 22);
                e["peer_id"] = serde_json::json!(foreign.id);
                e
            }],
            StatusCode::FORBIDDEN,
        ),
        (
            &probe,
            vec![{
                let mut e = tcp("x", "start", &p, 50_000, &s, 22);
                e["dns_query"] = serde_json::json!("bank.example");
                e
            }],
            StatusCode::BAD_REQUEST,
        ),
        (
            &probe,
            vec![{
                let mut e = tcp("x", "start", &p, 50_000, &s, 22);
                e["note"] = serde_json::json!("x");
                e
            }],
            StatusCode::BAD_REQUEST,
        ),
        // Only a routing peer reports forwarded connections.
        (
            &server,
            vec![{
                let mut e = tcp("x", "start", &a, 50_000, "10.20.5.7", 5432);
                e["connection_type"] = serde_json::json!("routed");
                e["direction"] = serde_json::json!("inbound");
                e
            }],
            StatusCode::FORBIDDEN,
        ),
    ] {
        assert_eq!(send(&router, node, org.id, events).await.status(), status);
    }
    let response = call(
        &router,
        Method::POST,
        &format!("/v1/nodes/{}/flow-events", probe.id),
        serde_json::json!({"org_id": other.id, "window_start": now()-30, "window_end": now(), "events": []}),
        Some(&probe.node_token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Laptop: allowed SSH start+end, denied RDP attempt, ping, and a
    // request to the resource carried by router-1.
    let mut end = tcp("ssh-1", "end", &a, 50_000, &s, 22);
    end["tx_bytes"] = serde_json::json!(4200);
    end["rx_bytes"] = serde_json::json!(9100);
    end["peer_id"] = serde_json::json!(server.id);
    let mut ping = serde_json::json!({
        "flow_id": "ping-1", "type": "start", "at": now() - 10, "direction": "outbound",
        "protocol": "icmp", "icmp_type": 8, "icmp_code": 0, "src_ip": a, "dst_ip": s,
        "connection_type": "relay",
    });
    ping["peer_id"] = serde_json::json!(server.id);
    let mut to_resource = tcp("db-1", "start", &a, 50_100, "10.20.5.7", 5432);
    to_resource["peer_id"] = serde_json::json!(gateway.id);
    let accepted: crate::flow_events::EventUploadResult = body(
        send(
            &router,
            &laptop,
            org.id,
            vec![
                tcp("ssh-1", "start", &a, 50_000, &s, 22),
                end,
                tcp("rdp-1", "start", &a, 50_001, &s, 3389),
                ping,
                to_resource,
            ],
        )
        .await,
    )
    .await;
    assert_eq!(accepted.accepted, 5);
    // Server: the RDP attempt dropped by its filter.
    let mut drop = tcp("rdp-in", "drop", &a, 50_001, &s, 3389);
    drop["direction"] = serde_json::json!("inbound");
    drop["rule_hint"] = serde_json::json!("acl:deny-port");
    drop["rx_packets"] = serde_json::json!(1);
    assert_eq!(
        send(&router, &server, org.id, vec![drop]).await.status(),
        StatusCode::ACCEPTED
    );
    // Router: forwarded connection to the resource, and one to an address
    // only an approved route covers.
    let mut forwarded = tcp("fwd-1", "start", &a, 50_100, "10.20.5.7", 5432);
    forwarded["direction"] = serde_json::json!("inbound");
    forwarded["connection_type"] = serde_json::json!("routed");
    let mut routed = tcp("fwd-2", "drop", &a, 50_200, "10.30.9.9", 80);
    routed["direction"] = serde_json::json!("inbound");
    routed["connection_type"] = serde_json::json!("routed");
    assert_eq!(
        send(&router, &gateway, org.id, vec![forwarded, routed])
            .await
            .status(),
        StatusCode::ACCEPTED
    );

    // Members may view (ViewAudit), grouped per reporter and flow.
    let page = flows(&router, org.id, &member, "limit=50").await;
    assert_eq!(page["state"], "current");
    let all = page["flows"].as_array().unwrap();
    assert_eq!(all.len(), 7, "{page}");
    let flow = |id: &str| {
        all.iter()
            .find(|flow| flow["flow_id"] == id)
            .unwrap_or_else(|| panic!("flow {id}"))
            .clone()
    };
    let ssh = flow("ssh-1");
    let events = ssh["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["event_type"], "start");
    assert_eq!(events[1]["event_type"], "end");
    assert_eq!(events[1]["tx_bytes"], 4200);
    assert_eq!(events[0]["source"]["kind"], "device");
    assert_eq!(events[0]["source"]["name"], "alice-laptop");
    assert_eq!(events[0]["source"]["port"], 50_000);
    assert_eq!(events[0]["destination"]["name"], "server");
    assert_eq!(events[0]["rule"]["basis"], "rule");
    assert_eq!(events[0]["rule"]["index"], 0);
    assert!(events[0]["rule"]["label"]
        .as_str()
        .unwrap()
        .starts_with("Rule 1: allow group:staff → role:owner"));
    let rdp = flow("rdp-in")["events"][0].clone();
    assert_eq!(rdp["event_type"], "drop");
    assert_eq!(rdp["reporter"]["name"], "server");
    assert_eq!(rdp["rule"]["basis"], "deny_rule");
    assert_eq!(rdp["rule"]["index"], 2);
    assert_eq!(rdp["rule"]["hint"], "acl:deny-port");
    let ping = flow("ping-1")["events"][0].clone();
    assert_eq!(ping["icmp_name"], "Echo");
    assert_eq!(ping["connection_type"], "relay");
    assert_eq!(ping["rule"]["index"], 1);
    let client_db = flow("db-1")["events"][0].clone();
    assert_eq!(client_db["destination"]["kind"], "resource");
    assert_eq!(client_db["destination"]["id"], resource["id"]);
    assert_eq!(client_db["destination"]["route"], "10.20.5.0/24");
    assert_eq!(client_db["router"]["name"], "router-1");
    assert_eq!(client_db["connection_type"], "routed");
    assert_eq!(client_db["rule"]["basis"], "resource");
    let forwarded = flow("fwd-1")["events"][0].clone();
    assert_eq!(forwarded["router"]["id"], gateway.id.to_string());
    assert_eq!(forwarded["reporter"]["name"], "router-1");
    assert_eq!(forwarded["destination"]["name"], "Billing DB");
    let routed = flow("fwd-2")["events"][0].clone();
    assert_eq!(routed["destination"]["kind"], "route");
    assert_eq!(routed["destination"]["route"], "10.30.0.0/16");
    assert_eq!(routed["rule"]["basis"], "default_deny");

    // Filters and search.
    let count = |page: serde_json::Value| page["flows"].as_array().unwrap().len();
    assert_eq!(
        count(flows(&router, org.id, &auditor, "event_type=drop").await),
        2
    );
    assert_eq!(
        count(flows(&router, org.id, &auditor, "protocol=icmp").await),
        1
    );
    assert_eq!(
        count(flows(&router, org.id, &auditor, "port=3389").await),
        2
    );
    assert_eq!(
        count(flows(&router, org.id, &auditor, "q=billing").await),
        2
    );
    assert_eq!(count(flows(&router, org.id, &auditor, "q=3389").await), 2);
    assert_eq!(
        count(
            flows(
                &router,
                org.id,
                &auditor,
                &format!("destination={}", resource["id"].as_str().unwrap())
            )
            .await
        ),
        2
    );
    assert_eq!(
        count(flows(&router, org.id, &auditor, &format!("source={}", laptop.id)).await),
        7
    );
    assert_eq!(
        count(flows(&router, org.id, &auditor, "connection_type=routed").await),
        3
    );
    assert_eq!(
        count(flows(&router, org.id, &auditor, "direction=inbound").await),
        3
    );
    assert_eq!(
        count(
            flows(
                &router,
                org.id,
                &auditor,
                &format!("from={}&to={}", now() - 7200, now() - 3600)
            )
            .await
        ),
        0
    );
    let bad = call(
        &router,
        Method::GET,
        &format!("/v1/orgs/{}/traffic/flows?protocol=gre", org.id),
        serde_json::Value::Null,
        Some(&auditor),
    )
    .await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

    // Cursor pagination visits every flow exactly once.
    let mut seen = BTreeSet::new();
    let mut cursor: Option<String> = None;
    loop {
        let query = match &cursor {
            Some(cursor) => format!("limit=3&cursor={cursor}"),
            None => "limit=3".into(),
        };
        let page = flows(&router, org.id, &auditor, &query).await;
        for flow in page["flows"].as_array().unwrap() {
            assert!(seen.insert(flow["key"].as_str().unwrap().to_owned()));
        }
        match page["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.replace('/', "%2F")),
            None => break,
        }
    }
    assert_eq!(seen.len(), 7);
    let flat: serde_json::Value = body(
        call(
            &router,
            Method::GET,
            &format!("/v1/orgs/{}/traffic/events?limit=4", org.id),
            serde_json::Value::Null,
            Some(&auditor),
        )
        .await,
    )
    .await;
    assert_eq!(flat["events"].as_array().unwrap().len(), 4);
    assert!(flat["next_cursor"].is_string());

    // Export needs export_audit and is itself audited.
    let export_uri = format!("/v1/orgs/{}/traffic/events/export?format=csv", org.id);
    let denied = call(
        &router,
        Method::GET,
        &export_uri,
        serde_json::Value::Null,
        Some(&member),
    )
    .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let csv = call(
        &router,
        Method::GET,
        &export_uri,
        serde_json::Value::Null,
        Some(&auditor),
    )
    .await;
    assert_eq!(csv.status(), StatusCode::OK);
    let text = String::from_utf8(
        to_bytes(csv.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(text.lines().count(), 9, "{text}");
    assert!(text.contains("Billing DB"));
    let audited: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE org_id=$1 AND action='traffic.events_exported'",
    )
    .bind(org.id.to_string())
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(audited, 1);

    // Retention purge and opt-out.
    sqlx::query("UPDATE flow_events SET created_at=created_at-$1 WHERE flow_id='ssh-1'")
        .bind(30 * 24 * 3600_i64)
        .execute(&store.pool)
        .await
        .unwrap();
    assert_eq!(crate::flow_events::purge_expired(&store).await.unwrap(), 2);
    call(
        &router,
        Method::PUT,
        &format!("/v1/orgs/{}/traffic/settings", org.id),
        serde_json::json!({"enabled":false}),
        Some(&owner()),
    )
    .await;
    let response = send(
        &router,
        &server,
        org.id,
        vec![tcp("late", "start", &s, 50_000, &a, 22)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let page = flows(&router, org.id, &auditor, "").await;
    assert_eq!(page["state"], "disabled");
    let deleted: serde_json::Value = body(
        call(
            &router,
            Method::DELETE,
            &format!("/v1/orgs/{}/traffic/records", org.id),
            serde_json::Value::Null,
            Some(&owner()),
        )
        .await,
    )
    .await;
    assert_eq!(deleted["deleted_events"], 6);
}

#[tokio::test]
async fn sampling_keeps_whole_flows() {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, "flow-sampling").await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let laptop = register_test_node(&router, org.id, &owner, "laptop", "fs-a", &[]).await;
    let server = register_test_node(&router, org.id, &owner, "server", "fs-b", &[]).await;
    call(
        &router,
        Method::PUT,
        &format!("/v1/orgs/{}/traffic/settings", org.id),
        serde_json::json!({"enabled":true,"sampling_rate":0.5}),
        Some(&owner),
    )
    .await;
    let (a, s) = (ip(&laptop), ip(&server));
    let mut events = Vec::new();
    for i in 0..100 {
        let flow = format!("f{i}");
        events.push(tcp(&flow, "start", &a, 40_000 + i, &s, 443));
        events.push(tcp(&flow, "end", &a, 40_000 + i, &s, 443));
    }
    let result: crate::flow_events::EventUploadResult =
        body(send(&router, &laptop, org.id, events).await).await;
    assert!(
        result.accepted > 40 && result.accepted < 160,
        "{}",
        result.accepted
    );
    assert_eq!(result.accepted % 2, 0);
    let odd: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM (SELECT flow_id FROM flow_events GROUP BY flow_id HAVING COUNT(*)<>2) t",
    )
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(odd, 0, "a sampled flow keeps both its events");
}
