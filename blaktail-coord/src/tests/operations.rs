//! Operator health view and relay directory integration tests (drafts 21, 23).

use super::*;

async fn relay_on_loopback() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let _ = blaktail_relay::serve(
            socket,
            blaktail_relay::RelayConfig {
                auth_secret: TEST_RELAY_SECRET.to_vec(),
                ..blaktail_relay::RelayConfig::default()
            },
        )
        .await;
    });
    (address, task)
}

fn closed_udp_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap().port()
}

async fn health(router: &Router, org_id: Uuid, session: Option<&str>) -> Response {
    call(
        router,
        Method::GET,
        &format!("/v1/orgs/{org_id}/operations/health"),
        serde_json::json!({}),
        session,
    )
    .await
}

async fn seed_webhooks(store: &Store, org_id: Uuid, prefix: &str) {
    let destination = format!("{prefix}-destination");
    // Disabled, so the background delivery loop never touches these rows.
    sqlx::query(
        "INSERT INTO webhook_destinations(id,org_id,name,url,signing_secret,secret_hash,secret_prefix,enabled,created_at) VALUES($1,$2,$3,$4,$5,'hash','whsec_',0,$6)",
    )
    .bind(&destination)
    .bind(org_id.to_string())
    .bind(prefix)
    .bind(format!("https://hooks.example.org.au/{prefix}?token=hook-url-secret"))
    .bind("whsec_signing-secret-never-returned")
    .bind(now())
    .execute(&store.pool)
    .await
    .unwrap();
    for (suffix, dead) in [("pending", None), ("dead", Some(now() - 10))] {
        sqlx::query(
            "INSERT INTO webhook_outbox(id,org_id,destination_id,event_id,event_type,payload_json,created_at,next_attempt_at,attempts,dead_lettered_at) VALUES($1,$2,$3,$4,'node.created','{}',$5,$5,0,$6)",
        )
        .bind(format!("{prefix}-{suffix}"))
        .bind(org_id.to_string())
        .bind(&destination)
        .bind(format!("{prefix}-event-{suffix}"))
        .bind(now() - 120)
        .bind(dead)
        .execute(&store.pool)
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn operator_health_is_owner_and_auditor_only_org_scoped_and_redacted() {
    let (relay, relay_task) = relay_on_loopback().await;
    let dead = format!("127.0.0.1:{}", closed_udp_port());
    let store = Store::memory().await.unwrap();
    let router = app_with_relays(
        store.clone(),
        "ap-southeast-2".into(),
        TEST_SECRET,
        TEST_RELAY_SECRET,
        vec![
            format!("{relay}#australiaeast"),
            "relay-offshore.example:3478#us-east-1".into(),
            dead.clone(),
        ],
    );
    let org = create_test_org(&router, "Ops").await;
    let other = create_test_org(&router, "Elsewhere").await;
    let exp = now() + 60;
    let owner = signed_session(org.id, "owner", Role::Owner, exp);
    let node = register_test_node(&router, org.id, &owner, "laptop", "laptop-key", &[]).await;
    sqlx::query("UPDATE nodes SET credential_expires_at=$1 WHERE id=$2")
        .bind(now() + 3_600)
        .bind(node.id.to_string())
        .execute(&store.pool)
        .await
        .unwrap();
    seed_webhooks(&store, org.id, "ops").await;
    seed_webhooks(&store, other.id, "elsewhere").await;

    let response = health(&router, org.id, Some(&owner)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let raw = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(raw.to_vec()).unwrap();
    let view: serde_json::Value = serde_json::from_str(&text).unwrap();

    assert_eq!(view["coordinator"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(view["coordinator"]["region"], "ap-southeast-2");
    assert_eq!(view["coordinator"]["database_backend"], "sqlite");
    assert_eq!(view["schema"]["applied_version"], CURRENT_SCHEMA_VERSION);
    assert_eq!(view["schema"]["status"], "current");
    let relays = view["relays"].as_array().unwrap();
    assert_eq!(
        relays.len(),
        2,
        "offshore relay must not be listed: {relays:?}"
    );
    assert_eq!(relays[0]["endpoint"], relay.to_string());
    assert_eq!(relays[0]["region"], "australiaeast");
    assert_eq!(relays[0]["status"], "reachable");
    assert_eq!(relays[1]["endpoint"], dead);
    assert_eq!(relays[1]["region"], "ap-southeast-2");
    assert_eq!(relays[1]["status"], "unreachable");
    // Only this organisation's outbox is counted.
    assert_eq!(view["webhooks"]["pending"], 1);
    assert_eq!(view["webhooks"]["dead_letters"], 1);
    assert!(
        view["webhooks"]["oldest_pending_age_seconds"]
            .as_i64()
            .unwrap()
            >= 120
    );
    assert_eq!(view["expiry"]["node_credentials_expiring_14_days"], 1);
    assert_eq!(view["expiry"]["node_credentials_expired"], 0);
    assert_eq!(view["backup"]["status"], "not_recorded");
    for secret in [
        std::str::from_utf8(TEST_RELAY_SECRET).unwrap(),
        std::str::from_utf8(TEST_SECRET).unwrap(),
        "whsec_signing-secret-never-returned",
        "hook-url-secret",
        "hooks.example.org.au",
        node.node_token.as_str(),
        "relay-offshore",
    ] {
        assert!(!text.contains(secret), "health view leaked {secret:?}");
    }

    let auditor = signed_session(org.id, "auditor", Role::Auditor, exp);
    assert_eq!(
        health(&router, org.id, Some(&auditor)).await.status(),
        StatusCode::OK
    );
    for role in [Role::Admin, Role::NetworkAdmin, Role::Member] {
        let session = signed_session(org.id, role.as_str(), role, exp);
        assert_eq!(
            health(&router, org.id, Some(&session)).await.status(),
            StatusCode::FORBIDDEN,
            "{} must not read operator health",
            role.as_str()
        );
    }
    assert_eq!(
        health(&router, org.id, None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    // Another organisation's owner assertion cannot read this organisation.
    let foreign_owner = signed_session(other.id, "owner", Role::Owner, exp);
    assert_eq!(
        health(&router, org.id, Some(&foreign_owner)).await.status(),
        StatusCode::UNAUTHORIZED
    );
    relay_task.abort();
}

#[tokio::test]
async fn agents_receive_only_australian_relays_in_configured_order() {
    let store = Store::memory().await.unwrap();
    let router = app_with_relays(
        store,
        "ap-southeast-2".into(),
        TEST_SECRET,
        TEST_RELAY_SECRET,
        vec![
            "relay-b.example.org.au:3478#australia-southeast1".into(),
            "relay-x.example:3478#ap-southeast-1".into(),
            "relay-a.example.org.au:3478".into(),
        ],
    );
    let org = create_test_org(&router, "Relays").await;
    let owner = signed_session(org.id, "owner", Role::Owner, now() + 60);
    let node = register_test_node(&router, org.id, &owner, "laptop", "laptop-key", &[]).await;
    assert_eq!(
        node.relays,
        vec!["relay-b.example.org.au:3478", "relay-a.example.org.au:3478"]
    );
    assert_eq!(
        node.relay_endpoints
            .iter()
            .map(|relay| relay.region.as_str())
            .collect::<Vec<_>>(),
        vec!["australia-southeast1", "ap-southeast-2"]
    );
}

/// Version N to N+1 safety: a database exactly as a schema-18 release left
/// it, with representative organisation state, migrates to the current
/// schema and still serves the same devices, ownership, tags, routes and
/// policy through the normal console API.
#[tokio::test]
async fn schema_18_database_upgrades_without_losing_devices_ownership_or_policy() {
    install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    apply_sqlite_migrations_to(&pool, 18).await.unwrap();
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(version, 18);
    let network_resources: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='network_resources'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(network_resources, 0, "helper must stop at schema 18");

    let org_id = Uuid::new_v4();
    let laptop = Uuid::new_v4();
    let router_node = Uuid::new_v4();
    let revoked = Uuid::new_v4();
    let created = now() - 86_400;
    let expires = now() + 30 * 86_400;
    let policy = serde_json::json!({
        "version": 1,
        "defaults": "same_tag",
        "groups": {"rangers": ["ranger-user"]},
        "rules": [{"action": "allow", "src_groups": ["rangers"], "dst_tags": ["store"]}]
    });
    sqlx::query(
        "INSERT INTO orgs(id,name,acl_json,created_at,acl_revision,control_revision) VALUES($1,'Upgrade org',$2,$3,7,9)",
    )
    .bind(org_id.to_string())
    .bind(policy.to_string())
    .bind(created.to_string())
    .execute(&pool)
    .await
    .unwrap();
    let nodes_at_18 = [
        (
            laptop,
            "laptop",
            "ranger-user",
            "member",
            r#"["ranger"]"#,
            "[]",
            None,
        ),
        (
            router_node,
            "store-router",
            "owner-user",
            "owner",
            r#"["store"]"#,
            r#"["10.20.0.0/16"]"#,
            None,
        ),
        (
            revoked,
            "old-phone",
            "ranger-user",
            "member",
            "[]",
            "[]",
            Some(created.to_string()),
        ),
    ];
    for (index, (id, name, user, role, tags, approved, revoked_at)) in
        nodes_at_18.into_iter().enumerate()
    {
        sqlx::query(
            "INSERT INTO nodes(id,org_id,name,display_name,wg_public_key,allowed_ips_json,token_hash,created_at,revoked_at,user_id,user_role,tags_json,dns_name,advertised_routes_json,approved_routes_json,credential_expires_at)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14,$15)",
        )
        .bind(id.to_string())
        .bind(org_id.to_string())
        .bind(name)
        .bind(format!("Friendly {name}"))
        .bind(format!("{name}-key"))
        .bind(format!("[\"100.64.0.{}/32\"]", index + 10))
        .bind(format!("{name}-token-hash"))
        .bind(created.to_string())
        .bind(revoked_at)
        .bind(user)
        .bind(role)
        .bind(tags)
        .bind(format!("{name}.upgrade.blaktail"))
        .bind(approved)
        .bind(expires)
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO join_keys(id,org_id,key_hash,expires_at,single_use,created_at,user_id,user_role,tags_json) VALUES('key-1',$1,'join-hash',$2,1,$3,'owner-user','owner','[\"store\"]')",
    )
    .bind(org_id.to_string())
    .bind((now() + 600).to_string())
    .bind(created.to_string())
    .execute(&pool)
    .await
    .unwrap();

    apply_sqlite_migrations(&pool).await.unwrap();
    configure_sqlite(&pool).await.unwrap();
    let store = Store {
        pool,
        backend: DatabaseBackend::Sqlite,
    };
    validate_schema_version(&store.pool, store.backend)
        .await
        .unwrap();
    let max_uses: Option<i64> =
        sqlx::query_scalar("SELECT max_uses FROM join_keys WHERE id='key-1'")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(max_uses, Some(1), "single-use join keys keep their limit");

    let router = app(store, "ap-southeast-2".into(), TEST_SECRET);
    let owner = signed_session(org_id, "owner-user", Role::Owner, now() + 60);
    let response = call(
        &router,
        Method::GET,
        &format!("/v1/orgs/{org_id}/nodes"),
        serde_json::json!({}),
        Some(&owner),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let nodes: Vec<serde_json::Value> = body(response).await;
    let by_name = |name: &str| {
        nodes
            .iter()
            .find(|node| node["name"] == name)
            .unwrap_or_else(|| panic!("{name} missing after upgrade: {nodes:?}"))
            .clone()
    };
    let laptop_row = by_name("laptop");
    assert_eq!(laptop_row["id"], laptop.to_string());
    assert_eq!(laptop_row["display_name"], "Friendly laptop");
    assert_eq!(laptop_row["user_id"], "ranger-user");
    assert_eq!(laptop_row["user_role"], "member");
    assert_eq!(laptop_row["tags"], serde_json::json!(["ranger"]));
    assert_eq!(laptop_row["dns_name"], "laptop.upgrade.blaktail");
    assert_eq!(laptop_row["credential_expires_at"], expires);
    assert_eq!(laptop_row["revoked"], false);
    let router_row = by_name("store-router");
    assert_eq!(router_row["user_role"], "owner");
    assert_eq!(
        router_row["approved_routes"],
        serde_json::json!(["10.20.0.0/16"])
    );
    if let Some(old_phone) = nodes.iter().find(|node| node["name"] == "old-phone") {
        assert_eq!(
            old_phone["revoked"], true,
            "revocation must survive the upgrade"
        );
    }

    let response = call(
        &router,
        Method::GET,
        &format!("/v1/orgs/{org_id}/acl"),
        serde_json::json!({}),
        Some(&owner),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let acl: serde_json::Value = body(response).await;
    let text = acl.to_string();
    assert!(
        text.contains("rangers") && text.contains("ranger-user"),
        "{text}"
    );
    assert!(text.contains("\"store\""), "{text}");
}
