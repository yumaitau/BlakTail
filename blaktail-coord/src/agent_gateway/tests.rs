use super::*;
use crate::private_services::test_support::{call, create_org, router, Auth};
use axum::{
    body::{to_bytes, Body},
    http::{Method, Request},
    Router as AxumRouter,
};
use serde_json::{json, Value};
use tower::ServiceExt;

const CREDENTIAL: &str = "sk-test-provider-credential-0000";

struct Node {
    id: Uuid,
    token: String,
    ip: String,
}

async fn enrol(router: &AxumRouter, org: Uuid, name: &str, capabilities: &[&str]) -> Node {
    let (status, key) = call(
        router,
        Method::POST,
        &format!("/v1/orgs/{org}/join-keys"),
        json!({"expires_in_seconds": 60, "tags": ["office"]}),
        Auth::Console(org, Role::Owner),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{key}");
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/nodes/register")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "join_key": key["key"],
                "name": name,
                "wg_public_key": format!("key-{}", Uuid::new_v4()),
                "capabilities": capabilities,
            })
            .to_string(),
        ))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    Node {
        id: body["id"].as_str().unwrap().parse().unwrap(),
        token: body["node_token"].as_str().unwrap().into(),
        ip: body["assigned_ip"]
            .as_str()
            .unwrap()
            .trim_end_matches("/32")
            .into(),
    }
}

async fn console(
    router: &AxumRouter,
    method: Method,
    org: Uuid,
    role: Role,
    suffix: &str,
    body: Value,
) -> (StatusCode, Value) {
    call(
        router,
        method,
        &format!("/v1/orgs/{org}/agents{suffix}"),
        body,
        Auth::Console(org, role),
    )
    .await
}

async fn provider(router: &AxumRouter, org: Uuid, body: Value) -> Value {
    let (status, view) = console(router, Method::POST, org, Role::Admin, "/providers", body).await;
    assert_eq!(status, StatusCode::CREATED, "{view}");
    view
}

fn local_provider(name: &str, models: &[&str]) -> Value {
    json!({
        "name": name,
        "base_url": "http://10.0.0.5:11434/v1",
        "data_location": "Australia (self-hosted)",
        "residency": "onshore",
        "credential": CREDENTIAL,
        "models": models,
    })
}

async fn key(router: &AxumRouter, org: Uuid, name: &str, policy: Value) -> (String, Value) {
    let (status, created) = console(
        router,
        Method::POST,
        org,
        Role::Admin,
        "/keys",
        json!({"name": name, "policy": policy}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    (
        created["secret"].as_str().unwrap().to_owned(),
        created["key"].clone(),
    )
}

async fn authorize(router: &AxumRouter, gateway: &Node, body: Value) -> Value {
    let (status, decision) = call(
        router,
        Method::POST,
        &format!("/v1/nodes/{}/agent-gateway/authorize", gateway.id),
        body,
        Auth::Node(&gateway.token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{decision}");
    decision
}

fn ask(secret: &str, model: &str) -> Value {
    json!({"api_key": secret, "model": model, "request_bytes": 100})
}

async fn record(router: &AxumRouter, gateway: &Node, body: Value) -> StatusCode {
    call(
        router,
        Method::POST,
        &format!("/v1/nodes/{}/agent-gateway/usage", gateway.id),
        body,
        Auth::Node(&gateway.token),
    )
    .await
    .0
}

struct Lab {
    router: AxumRouter,
    store: crate::Store,
    org: Uuid,
    gateway: Node,
    provider: Value,
}

async fn lab() -> Lab {
    let (router, store) = router().await;
    let org = create_org(&router, "agents-org").await;
    let gateway = enrol(&router, org, "gateway", &[CAP_AGENT_GATEWAY]).await;
    let provider = provider(
        &router,
        org,
        local_provider("ollama", &["llama3.2:1b", "qwen2.5:0.5b"]),
    )
    .await;
    Lab {
        router,
        store,
        org,
        gateway,
        provider,
    }
}

#[tokio::test]
async fn roles_are_enforced_server_side() {
    let lab = lab().await;
    let (router, org) = (&lab.router, lab.org);
    for role in [Role::Member, Role::NetworkAdmin] {
        let (status, _) = console(router, Method::GET, org, role, "", Value::Null).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{role:?} reads agents");
    }
    let (status, _) = console(router, Method::GET, org, Role::Auditor, "", Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = console(
        router,
        Method::GET,
        org,
        Role::Auditor,
        "/usage",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    for role in [Role::Member, Role::NetworkAdmin, Role::Auditor] {
        let (status, _) = console(
            router,
            Method::POST,
            org,
            role,
            "/providers",
            local_provider("second", &["m"]),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{role:?} creates providers");
        let (status, _) = console(
            router,
            Method::POST,
            org,
            role,
            "/keys",
            json!({"name": "k"}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{role:?} mints keys");
    }
    // Offshore policy is an owner decision.
    let (status, _) = console(
        router,
        Method::PUT,
        org,
        Role::Admin,
        "/settings",
        json!({"allow_offshore": true}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn organisations_are_isolated() {
    let lab = lab().await;
    let other = create_org(&lab.router, "other-org").await;
    let other_gateway = enrol(&lab.router, other, "other-gw", &[CAP_AGENT_GATEWAY]).await;
    let provider_id = lab.provider["id"].as_str().unwrap();
    let (secret, created) = key(
        &lab.router,
        lab.org,
        "agent",
        json!({"allowed_provider_ids": [provider_id]}),
    )
    .await;

    // Another org's owner cannot touch this org's provider or key by id.
    let (status, _) = console(
        &lab.router,
        Method::PATCH,
        other,
        Role::Owner,
        &format!("/providers/{provider_id}"),
        json!({"revision": 1, "enabled": false}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = console(
        &lab.router,
        Method::DELETE,
        other,
        Role::Owner,
        &format!("/keys/{}", created["id"].as_str().unwrap()),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // A console token for one org cannot address another org's path.
    let (status, _) = call(
        &lab.router,
        Method::GET,
        &format!("/v1/orgs/{}/agents", lab.org),
        Value::Null,
        Auth::Console(other, Role::Owner),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_, overview) = console(
        &lab.router,
        Method::GET,
        other,
        Role::Owner,
        "",
        Value::Null,
    )
    .await;
    assert!(overview["providers"].as_array().unwrap().is_empty());
    assert!(overview["keys"].as_array().unwrap().is_empty());

    // A key only works through a gateway in its own organisation.
    let decision = authorize(&lab.router, &other_gateway, ask(&secret, "llama3.2:1b")).await;
    assert_eq!(decision["allowed"], false);
    assert_eq!(decision["denial"]["code"], "invalid_api_key");
    let decision = authorize(&lab.router, &lab.gateway, ask(&secret, "llama3.2:1b")).await;
    assert_eq!(decision["allowed"], true, "{decision}");
}

#[tokio::test]
async fn gateway_needs_node_token_and_capability() {
    let lab = lab().await;
    let plain = enrol(&lab.router, lab.org, "laptop", &[]).await;
    let (status, _) = call(
        &lab.router,
        Method::POST,
        &format!("/v1/nodes/{}/agent-gateway/authorize", plain.id),
        ask("btak_x", "m"),
        Auth::Node(&plain.token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(
        &lab.router,
        Method::POST,
        &format!("/v1/nodes/{}/agent-gateway/authorize", lab.gateway.id),
        ask("btak_x", "m"),
        Auth::Node("not-the-token"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn key_auth_grant_and_revocation() {
    let lab = lab().await;
    let provider_id = lab.provider["id"].as_str().unwrap();
    let (secret, created) = key(
        &lab.router,
        lab.org,
        "agent",
        json!({"allowed_provider_ids": [provider_id]}),
    )
    .await;
    assert!(secret.starts_with("btak_"));
    assert_eq!(created["key_prefix"], &secret[..12]);
    let stored: String = sqlx::query_scalar("SELECT key_hash FROM agent_keys")
        .fetch_one(&lab.store.pool)
        .await
        .unwrap();
    assert_eq!(stored, hash(&secret));

    for wrong in [
        "",
        "btak_wrong",
        "sk-something",
        &secret[..secret.len() - 1],
    ] {
        let decision = authorize(&lab.router, &lab.gateway, ask(wrong, "llama3.2:1b")).await;
        assert_eq!(decision["denial"]["code"], "invalid_api_key", "{wrong}");
        assert!(decision.get("grant").is_none());
    }
    let decision = authorize(&lab.router, &lab.gateway, ask(&secret, "llama3.2:1b")).await;
    assert_eq!(decision["allowed"], true);
    let grant = &decision["grant"];
    assert_eq!(grant["provider"]["base_url"], "http://10.0.0.5:11434/v1");
    assert_eq!(grant["provider"]["credential"], CREDENTIAL);
    assert_eq!(
        grant["provider"]["data_location"],
        "Australia (self-hosted)"
    );
    assert_eq!(grant["logging_mode"], "off");

    let (status, _) = console(
        &lab.router,
        Method::DELETE,
        lab.org,
        Role::Admin,
        &format!("/keys/{}", created["id"].as_str().unwrap()),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let decision = authorize(&lab.router, &lab.gateway, ask(&secret, "llama3.2:1b")).await;
    assert_eq!(decision["denial"]["code"], "invalid_api_key");
}

#[tokio::test]
async fn provider_credential_is_never_returned_or_stored_in_clear() {
    let lab = lab().await;
    let text = lab.provider.to_string();
    assert!(!text.contains(CREDENTIAL));
    assert_eq!(lab.provider["has_credential"], true);
    let (_, overview) = console(
        &lab.router,
        Method::GET,
        lab.org,
        Role::Owner,
        "",
        Value::Null,
    )
    .await;
    assert!(!overview.to_string().contains(CREDENTIAL));
    let id = lab.provider["id"].as_str().unwrap();
    let (status, updated) = console(
        &lab.router,
        Method::PATCH,
        lab.org,
        Role::Admin,
        &format!("/providers/{id}"),
        json!({"revision": 1, "credential": "sk-rotated-credential-1111"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert!(!updated.to_string().contains("sk-rotated"));
    let sealed: String = sqlx::query_scalar("SELECT sealed_credential FROM agent_providers")
        .fetch_one(&lab.store.pool)
        .await
        .unwrap();
    assert!(sealed.starts_with("btca1.") && !sealed.contains("sk-"));
    let audit: Vec<String> = sqlx::query_scalar("SELECT details_json FROM audit_events")
        .fetch_all(&lab.store.pool)
        .await
        .unwrap();
    assert!(audit.iter().any(|d| d.contains("credential_replaced")));
    assert!(audit.iter().all(|d| !d.contains("sk-")));
    // Stale revision is a precondition failure.
    let (status, _) = console(
        &lab.router,
        Method::PATCH,
        lab.org,
        Role::Admin,
        &format!("/providers/{id}"),
        json!({"revision": 1, "enabled": false}),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn provider_validation() {
    let lab = lab().await;
    let cases = [
        json!({"name": "meta", "base_url": "http://169.254.169.254/v1", "data_location": "x", "residency": "onshore", "models": ["m"]}),
        json!({"name": "meta6", "base_url": "http://[fd00:ec2::254]/v1", "data_location": "x", "residency": "onshore", "models": ["m"]}),
        json!({"name": "gcp", "base_url": "http://metadata.google.internal/v1", "data_location": "x", "residency": "onshore", "models": ["m"]}),
        json!({"name": "plain", "base_url": "http://api.example.com/v1", "data_location": "US", "residency": "offshore", "models": ["m"]}),
        json!({"name": "leaky", "base_url": "http://api.example.com.au/v1", "data_location": "Sydney", "residency": "onshore", "credential": "sk-1", "models": ["m"]}),
        json!({"name": "userinfo", "base_url": "https://user:pw@api.example.com/v1", "data_location": "x", "residency": "offshore", "models": ["m"]}),
        json!({"name": "nomodels", "base_url": "https://api.example.com/v1", "data_location": "x", "residency": "offshore", "models": []}),
        json!({"name": "where", "base_url": "https://api.example.com/v1", "data_location": "", "residency": "offshore", "models": ["m"]}),
        json!({"name": "res", "base_url": "https://api.example.com/v1", "data_location": "x", "residency": "maybe", "models": ["m"]}),
        json!({"name": "kind", "kind": "anthropic", "base_url": "https://api.example.com/v1", "data_location": "x", "residency": "offshore", "models": ["m"]}),
        json!({"name": "Bad Name", "base_url": "https://api.example.com/v1", "data_location": "x", "residency": "offshore", "models": ["m"]}),
    ];
    for body in cases {
        let (status, error) = console(
            &lab.router,
            Method::POST,
            lab.org,
            Role::Owner,
            "/providers",
            body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body} -> {error}");
    }
    // Residency must be declared; there is no default.
    let (status, _) = console(
        &lab.router,
        Method::POST,
        lab.org,
        Role::Owner,
        "/providers",
        json!({"name": "silent", "base_url": "https://api.example.com/v1", "data_location": "x", "models": ["m"]}),
    )
    .await;
    assert!(status.is_client_error());
    let (status, _) = console(
        &lab.router,
        Method::POST,
        lab.org,
        Role::Owner,
        "/providers",
        local_provider("ollama", &["m"]),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn offshore_providers_are_forbidden_by_default() {
    let lab = lab().await;
    let offshore = provider(
        &lab.router,
        lab.org,
        json!({
            "name": "hosted",
            "base_url": "https://api.example.com/v1",
            "data_location": "United States (hosted)",
            "residency": "offshore",
            "credential": "sk-offshore",
            "models": ["gpt-hosted"],
        }),
    )
    .await;
    assert_eq!(offshore["blocked_by_policy"], true);
    let (secret, _) = key(
        &lab.router,
        lab.org,
        "agent",
        json!({"allowed_provider_ids": [offshore["id"], lab.provider["id"]]}),
    )
    .await;
    let decision = authorize(&lab.router, &lab.gateway, ask(&secret, "gpt-hosted")).await;
    assert_eq!(decision["denial"]["code"], "offshore_forbidden");
    let (status, models) = call(
        &lab.router,
        Method::POST,
        &format!("/v1/nodes/{}/agent-gateway/models", lab.gateway.id),
        json!({"api_key": secret}),
        Auth::Node(&lab.gateway.token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let ids: Vec<&str> = models["models"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["llama3.2:1b", "qwen2.5:0.5b"]);

    let (status, settings) = console(
        &lab.router,
        Method::PUT,
        lab.org,
        Role::Owner,
        "/settings",
        json!({"allow_offshore": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(settings["allow_offshore"], true);
    let decision = authorize(&lab.router, &lab.gateway, ask(&secret, "gpt-hosted")).await;
    assert_eq!(decision["allowed"], true, "{decision}");
    assert_eq!(decision["grant"]["provider"]["residency"], "offshore");
}

#[tokio::test]
async fn model_allowlist_and_request_size() {
    let lab = lab().await;
    let elsewhere = provider(
        &lab.router,
        lab.org,
        local_provider("vllm", &["mistral-7b"]),
    )
    .await;
    let (secret, _) = key(
        &lab.router,
        lab.org,
        "agent",
        json!({
            "allowed_provider_ids": [lab.provider["id"]],
            "allowed_models": ["llama3.2:1b"],
            "max_request_bytes": 1000,
        }),
    )
    .await;
    let decision = authorize(&lab.router, &lab.gateway, ask(&secret, "qwen2.5:0.5b")).await;
    assert_eq!(decision["denial"]["code"], "model_not_allowed");
    let decision = authorize(&lab.router, &lab.gateway, ask(&secret, "mistral-7b")).await;
    assert_eq!(decision["denial"]["code"], "model_not_allowed");
    let (secret_all, _) = key(
        &lab.router,
        lab.org,
        "agent-all",
        json!({"allowed_provider_ids": [lab.provider["id"]]}),
    )
    .await;
    let decision = authorize(&lab.router, &lab.gateway, ask(&secret_all, "mistral-7b")).await;
    assert_eq!(decision["denial"]["code"], "model_not_allowed");
    let decision = authorize(&lab.router, &lab.gateway, ask(&secret_all, "no-such-model")).await;
    assert_eq!(decision["denial"]["code"], "model_not_found");
    let decision = authorize(
        &lab.router,
        &lab.gateway,
        json!({"api_key": secret, "model": "llama3.2:1b", "request_bytes": 1001}),
    )
    .await;
    assert_eq!(decision["denial"]["status"], 413);
    let decision = authorize(&lab.router, &lab.gateway, ask(&secret, "llama3.2:1b")).await;
    assert_eq!(decision["allowed"], true);
    let _ = elsewhere;
}

#[tokio::test]
async fn daily_quotas_are_enforced() {
    let lab = lab().await;
    let (secret, created) = key(
        &lab.router,
        lab.org,
        "agent",
        json!({
            "allowed_provider_ids": [lab.provider["id"]],
            "daily_request_quota": 3,
            "daily_token_quota": 50,
        }),
    )
    .await;
    let first = authorize(&lab.router, &lab.gateway, ask(&secret, "llama3.2:1b")).await;
    let request_id = first["grant"]["request_id"].clone();
    // Recording 60 tokens exhausts the token quota.
    let status = record(
        &lab.router,
        &lab.gateway,
        json!({"request_id": request_id, "status": "ok", "prompt_tokens": 40, "completion_tokens": 20}),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let decision = authorize(&lab.router, &lab.gateway, ask(&secret, "llama3.2:1b")).await;
    assert_eq!(decision["denial"]["code"], "quota_exceeded");
    assert_eq!(decision["denial"]["status"], 429);
    // Usage and quota counters are visible to the console.
    let (_, overview) = console(
        &lab.router,
        Method::GET,
        lab.org,
        Role::Auditor,
        "",
        Value::Null,
    )
    .await;
    let view = &overview["keys"][0];
    assert_eq!(view["id"], created["id"]);
    assert_eq!(view["today"]["requests"], 1);
    assert_eq!(view["today"]["tokens"], 60);
    assert_eq!(view["today"]["denied"], 1);
    let (_, usage) = console(
        &lab.router,
        Method::GET,
        lab.org,
        Role::Auditor,
        "/usage",
        Value::Null,
    )
    .await;
    assert_eq!(usage["days"][0]["model"], "llama3.2:1b");
    assert_eq!(usage["days"][0]["prompt_tokens"], 40);
    assert_eq!(usage["days"][0]["completion_tokens"], 20);
    // Logging is off by default: no per-request record is kept.
    assert!(usage["recent"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn concurrent_requests_never_exceed_the_request_quota() {
    let lab = lab().await;
    let (secret, _) = key(
        &lab.router,
        lab.org,
        "agent",
        json!({"allowed_provider_ids": [lab.provider["id"]], "daily_request_quota": 5}),
    )
    .await;
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let router = lab.router.clone();
        let secret = secret.clone();
        let (id, token) = (lab.gateway.id, lab.gateway.token.clone());
        tasks.push(tokio::spawn(async move {
            let (status, body) = call(
                &router,
                Method::POST,
                &format!("/v1/nodes/{id}/agent-gateway/authorize"),
                ask(&secret, "llama3.2:1b"),
                Auth::Node(&token),
            )
            .await;
            (status, body["allowed"] == true)
        }));
    }
    let mut allowed = 0;
    for task in tasks {
        let (status, ok) = task.await.unwrap();
        if status == StatusCode::OK && ok {
            allowed += 1;
        }
    }
    assert_eq!(allowed, 5);
}

#[tokio::test]
async fn node_binding_uses_the_callers_overlay_address() {
    let lab = lab().await;
    let laptop = enrol(&lab.router, lab.org, "laptop", &[]).await;
    let other = enrol(&lab.router, lab.org, "other", &[]).await;
    let (secret, _) = key(
        &lab.router,
        lab.org,
        "bound",
        json!({"allowed_provider_ids": [lab.provider["id"]], "bound_node_id": laptop.id}),
    )
    .await;
    let with_ip = |ip: &str| json!({"api_key": secret, "model": "llama3.2:1b", "request_bytes": 10, "client_ip": ip});
    let decision = authorize(&lab.router, &lab.gateway, with_ip(&other.ip)).await;
    assert_eq!(decision["denial"]["code"], "node_binding");
    let decision = authorize(&lab.router, &lab.gateway, ask(&secret, "llama3.2:1b")).await;
    assert_eq!(decision["denial"]["code"], "node_binding");
    let decision = authorize(&lab.router, &lab.gateway, with_ip(&laptop.ip)).await;
    assert_eq!(decision["allowed"], true, "{decision}");
    // A key bound to another org's device cannot be created.
    let foreign_org = create_org(&lab.router, "foreign").await;
    let foreign = enrol(&lab.router, foreign_org, "foreign", &[]).await;
    let (status, _) = console(
        &lab.router,
        Method::POST,
        lab.org,
        Role::Owner,
        "/keys",
        json!({"name": "stolen", "policy": {"bound_node_id": foreign.id}}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn full_logging_needs_owner_icip_acknowledgement_and_short_retention() {
    let lab = lab().await;
    let (secret, created) = key(
        &lab.router,
        lab.org,
        "agent",
        json!({"allowed_provider_ids": [lab.provider["id"]], "logging_mode": "metadata"}),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_owned();
    let full = |revision: i64, days: i64, ack: bool| {
        json!({
            "revision": revision,
            "acknowledge_icip": ack,
            "policy": {
                "allowed_provider_ids": [lab.provider["id"]],
                "logging_mode": "full",
                "log_retention_days": days,
            },
        })
    };
    let path = format!("/keys/{id}");
    let (status, _) = console(
        &lab.router,
        Method::PUT,
        lab.org,
        Role::Admin,
        &path,
        full(1, 7, true),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = console(
        &lab.router,
        Method::PUT,
        lab.org,
        Role::Owner,
        &path,
        full(1, 7, false),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = console(
        &lab.router,
        Method::PUT,
        lab.org,
        Role::Owner,
        &path,
        full(1, 31, true),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, view) = console(
        &lab.router,
        Method::PUT,
        lab.org,
        Role::Owner,
        &path,
        full(1, 7, true),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{view}");
    let (status, _) = console(
        &lab.router,
        Method::PUT,
        lab.org,
        Role::Owner,
        &path,
        full(1, 7, true),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);

    let grant = authorize(&lab.router, &lab.gateway, ask(&secret, "llama3.2:1b")).await;
    assert_eq!(grant["grant"]["logging_mode"], "full");
    let request_id = grant["grant"]["request_id"].as_str().unwrap().to_owned();
    let status = record(
        &lab.router,
        &lab.gateway,
        json!({
            "request_id": request_id, "status": "ok", "prompt_tokens": 3, "completion_tokens": 4,
            "request_content": "tell me the story", "response_content": "once upon a time",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // Recording twice, or from another gateway, is refused.
    let status = record(
        &lab.router,
        &lab.gateway,
        json!({"request_id": request_id, "status": "ok"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let second_gateway = enrol(&lab.router, lab.org, "gateway-2", &[CAP_AGENT_GATEWAY]).await;
    let status = record(
        &lab.router,
        &second_gateway,
        json!({"request_id": request_id, "status": "ok"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let sealed: String = sqlx::query_scalar("SELECT sealed_content FROM agent_requests")
        .fetch_one(&lab.store.pool)
        .await
        .unwrap();
    assert!(!sealed.contains("story"));
    let (_, usage) = console(
        &lab.router,
        Method::GET,
        lab.org,
        Role::Auditor,
        "/usage",
        Value::Null,
    )
    .await;
    assert_eq!(usage["recent"][0]["has_content"], true);
    let content_path = format!("/requests/{request_id}/content");
    for role in [Role::Admin, Role::Auditor, Role::Member] {
        let (status, _) = console(
            &lab.router,
            Method::GET,
            lab.org,
            role,
            &content_path,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{role:?}");
    }
    let (status, content) = console(
        &lab.router,
        Method::GET,
        lab.org,
        Role::Owner,
        &content_path,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content["request"], "tell me the story");
    let viewed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE action='agent.request_content.viewed'",
    )
    .fetch_one(&lab.store.pool)
    .await
    .unwrap();
    assert_eq!(viewed, 1);

    // Turning full logging off drops stored content immediately.
    let (status, _) = console(
        &lab.router,
        Method::PUT,
        lab.org,
        Role::Admin,
        &path,
        json!({"revision": 2, "policy": {"allowed_provider_ids": [lab.provider["id"]], "logging_mode": "metadata"}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = console(
        &lab.router,
        Method::GET,
        lab.org,
        Role::Owner,
        &content_path,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn metadata_mode_ignores_content_and_patterns_are_validated() {
    let lab = lab().await;
    let (status, _) = console(
        &lab.router,
        Method::POST,
        lab.org,
        Role::Admin,
        "/keys",
        json!({"name": "bad", "policy": {"redact_patterns": ["("]}}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (secret, _) = key(
        &lab.router,
        lab.org,
        "agent",
        json!({
            "allowed_provider_ids": [lab.provider["id"]],
            "logging_mode": "metadata",
            "redact_patterns": ["\\b\\d{3}-\\d{3}-\\d{3}\\b"],
        }),
    )
    .await;
    let grant = authorize(&lab.router, &lab.gateway, ask(&secret, "llama3.2:1b")).await;
    assert_eq!(
        grant["grant"]["redact_patterns"][0],
        "\\b\\d{3}-\\d{3}-\\d{3}\\b"
    );
    let status = record(
        &lab.router,
        &lab.gateway,
        json!({"request_id": grant["grant"]["request_id"], "status": "ok", "request_content": "secret"}),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let stored: Option<String> = sqlx::query_scalar("SELECT sealed_content FROM agent_requests")
        .fetch_one(&lab.store.pool)
        .await
        .unwrap();
    assert!(stored.is_none());
}
