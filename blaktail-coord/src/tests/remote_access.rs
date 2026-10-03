//! Browser remote access and remote job tests (draft 13, ADR 0006).

use super::*;
use crate::remote_access::{AgentJobs, JobState, RedeemedSession, ReportDecision, SignedJob};
use base64::engine::general_purpose::STANDARD;

fn host_key(seed: u8) -> String {
    let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]));
    key.public_key().to_openssh().unwrap()
}

fn session_key() -> String {
    host_key(42)
}

struct Lab {
    router: Router,
    store: Store,
    org: OrgResponse,
    owner: String,
    gateway: RegisterResponse,
    target: RegisterResponse,
}

async fn send(
    router: &Router,
    method: Method,
    uri: &str,
    payload: serde_json::Value,
    token: &str,
) -> Response {
    call(router, method, uri, payload, Some(token)).await
}

async fn json(response: Response) -> serde_json::Value {
    body(response).await
}

async fn report_capabilities(router: &Router, node: &RegisterResponse, capabilities: &str) {
    let response = call(
        router,
        Method::GET,
        &format!("/v1/nodes/{}/peers?capabilities={capabilities}", node.id),
        serde_json::Value::Null,
        Some(&node.node_token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

async fn report_host_key(router: &Router, node: &RegisterResponse, key: &str) -> Response {
    call(
        router,
        Method::PUT,
        &format!("/v1/nodes/{}/ssh-host-key", node.id),
        serde_json::json!({ "public_key": key }),
        Some(&node.node_token),
    )
    .await
}

fn policy() -> serde_json::Value {
    serde_json::json!({
        "defaults": "deny",
        "groups": {"crew": ["owner-1"]},
        "rules": [
            {"action":"allow","src_groups":["crew"],"dst_groups":["crew"],"dst_ports":["22","3389"],"protocols":["tcp"]}
        ],
        "ssh": [
            {"action":"allow","src_groups":["crew"],"dst_groups":["crew"],"users":["deploy"]}
        ]
    })
}

async fn lab(name: &str) -> Lab {
    let store = Store::memory().await.unwrap();
    let router = app(store.clone(), "ap-southeast-2".into(), TEST_SECRET);
    let org = create_test_org(&router, name).await;
    let owner = signed_session(org.id, "owner-1", Role::Owner, now() + 60);
    let gateway = register_test_node(&router, org.id, &owner, "gateway", "gw-key", &[]).await;
    let target = register_test_node(&router, org.id, &owner, "server", "server-key", &[]).await;
    let response = send(
        &router,
        Method::PUT,
        &format!("/v1/orgs/{}/acl", org.id),
        policy(),
        &owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    report_capabilities(
        &router,
        &target,
        "acl-filter,ssh-users,remote-ssh-ca,remote-jobs",
    )
    .await;
    assert_eq!(
        report_host_key(&router, &target, &format!("{} target-a", host_key(1)))
            .await
            .status(),
        StatusCode::OK
    );
    let response = send(
        &router,
        Method::PUT,
        &format!("/v1/orgs/{}/remote-access/settings", org.id),
        serde_json::json!({"gateway_node_id": gateway.id, "gateway_url": "wss://gateway.example.au"}),
        &owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    Lab {
        router,
        store,
        org,
        owner,
        gateway,
        target,
    }
}

impl Lab {
    fn as_role(&self, user: &str, role: Role) -> String {
        signed_session(self.org.id, user, role, now() + 60)
    }

    async fn open(&self, token: &str, os_user: &str) -> Response {
        send(
            &self.router,
            Method::POST,
            &format!("/v1/orgs/{}/remote-access/sessions", self.org.id),
            serde_json::json!({
                "kind": "ssh",
                "target_node_id": self.target.id,
                "os_user": os_user,
                "reason": "restart the stock service",
            }),
            token,
        )
        .await
    }

    async fn ticket(&self) -> (Uuid, String) {
        let response = self.open(&self.owner, "deploy").await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let issued = json(response).await;
        (
            issued["session_id"].as_str().unwrap().parse().unwrap(),
            issued["ticket"].as_str().unwrap().to_owned(),
        )
    }

    async fn redeem_as(&self, node: &RegisterResponse, ticket: &str) -> Response {
        call(
            &self.router,
            Method::POST,
            &format!("/v1/nodes/{}/remote-sessions/redeem", node.id),
            serde_json::json!({"ticket": ticket, "public_key": session_key()}),
            Some(&node.node_token),
        )
        .await
    }

    async fn report(&self, session_id: Uuid, payload: serde_json::Value) -> ReportDecision {
        let response = call(
            &self.router,
            Method::POST,
            &format!(
                "/v1/nodes/{}/remote-sessions/{session_id}/report",
                self.gateway.id
            ),
            payload,
            Some(&self.gateway.node_token),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        body(response).await
    }

    async fn audit_actions(&self) -> Vec<String> {
        sqlx::query_scalar("SELECT action FROM audit_events WHERE org_id=$1 ORDER BY created_at")
            .bind(self.org.id.to_string())
            .fetch_all(&self.store.pool)
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn ticket_redeems_once_with_a_bound_certificate_and_pinned_host_key() {
    let lab = lab("remote-happy").await;
    let peers: PeersResponse = body(
        call(
            &lab.router,
            Method::GET,
            &format!("/v1/nodes/{}/peers", lab.target.id),
            serde_json::Value::Null,
            Some(&lab.target.node_token),
        )
        .await,
    )
    .await;
    let view = peers.remote_access.expect("remote access view");
    assert!(view.user_ca.starts_with("ssh-ed25519 "));
    assert!(view.gateway_addresses.contains(
        &lab.gateway
            .assigned_ip
            .split('/')
            .next()
            .unwrap()
            .to_owned()
    ));

    let admin = lab.as_role("admin-1", Role::Admin);
    let response = lab.open(&admin, "deploy").await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let issued = json(response).await;
    assert_eq!(issued["gateway_url"], "wss://gateway.example.au");
    assert!(issued["ticket_expires_at"].as_i64().unwrap() <= now() + 60);
    assert!(issued["max_end_at"].as_i64().unwrap() <= now() + 30 * 60);
    let ticket = issued["ticket"].as_str().unwrap();

    let response = lab.redeem_as(&lab.gateway, ticket).await;
    assert_eq!(response.status(), StatusCode::OK);
    let redeemed: RedeemedSession = body(response).await;
    assert_eq!(redeemed.os_user, "deploy");
    assert_eq!(redeemed.port, 22);
    assert_eq!(redeemed.host_key.as_deref(), Some(host_key(1).as_str()));
    let certificate =
        ssh_key::Certificate::from_openssh(redeemed.certificate.as_deref().unwrap()).unwrap();
    assert_eq!(certificate.valid_principals(), ["deploy".to_string()]);
    let ca = ssh_key::PublicKey::from_openssh(&view.user_ca).unwrap();
    certificate
        .validate([&ca.fingerprint(ssh_key::HashAlg::Sha256)])
        .unwrap();
    assert!(certificate.valid_before() as i64 <= now() + 30 * 60);

    // Single use: a second redeem, even by the right gateway, is gone.
    assert_eq!(
        lab.redeem_as(&lab.gateway, ticket).await.status(),
        StatusCode::GONE
    );
    // One live session per person and device.
    assert_eq!(
        lab.open(&admin, "deploy").await.status(),
        StatusCode::CONFLICT
    );

    let decision = lab
        .report(
            redeemed.session_id,
            serde_json::json!({"bytes_to_target": 10, "bytes_from_target": 20}),
        )
        .await;
    assert_eq!(decision.action, "continue");
    let decision = lab
        .report(
            redeemed.session_id,
            serde_json::json!({"bytes_to_target": 12, "bytes_from_target": 40, "ended": "user_closed"}),
        )
        .await;
    assert_eq!(decision.action, "terminate");
    let actions = lab.audit_actions().await;
    for action in [
        "remote_session.issued",
        "remote_session.started",
        "remote_session.ended",
    ] {
        assert!(actions.iter().any(|a| a == action), "{action} missing");
    }
    let details: String = sqlx::query_scalar(
        "SELECT details_json FROM audit_events WHERE org_id=$1 AND action='remote_session.ended'",
    )
    .bind(lab.org.id.to_string())
    .fetch_one(&lab.store.pool)
    .await
    .unwrap();
    let details: serde_json::Value = serde_json::from_str(&details).unwrap();
    assert_eq!(details["bytes_from_target"], 40);
    assert_eq!(details["end_reason"], "user_closed");
    let report: crate::audit_log::ChainReport = body(
        send(
            &lab.router,
            Method::GET,
            &format!("/v1/orgs/{}/audit/verify", lab.org.id),
            serde_json::Value::Null,
            &lab.owner,
        )
        .await,
    )
    .await;
    assert!(report.intact, "{:?}", report.problems);
}

#[tokio::test]
async fn expired_ticket_cannot_be_redeemed() {
    let lab = lab("remote-expiry").await;
    let (session_id, ticket) = lab.ticket().await;
    sqlx::query("UPDATE remote_sessions SET ticket_expires_at=$1 WHERE id=$2")
        .bind(now() - 1)
        .bind(session_id.to_string())
        .execute(&lab.store.pool)
        .await
        .unwrap();
    assert_eq!(
        lab.redeem_as(&lab.gateway, &ticket).await.status(),
        StatusCode::GONE
    );
    let sessions = json(
        send(
            &lab.router,
            Method::GET,
            &format!("/v1/orgs/{}/remote-access/sessions", lab.org.id),
            serde_json::Value::Null,
            &lab.owner,
        )
        .await,
    )
    .await;
    assert_eq!(sessions[0]["status"], "expired");
    // A new ticket is fine once the old one has lapsed.
    assert_eq!(
        lab.open(&lab.owner, "deploy").await.status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn members_and_auditors_cannot_open_or_list_sessions() {
    let lab = lab("remote-roles").await;
    for (user, role) in [("member-1", Role::Member), ("auditor-1", Role::Auditor)] {
        let token = lab.as_role(user, role);
        assert_eq!(
            lab.open(&token, "deploy").await.status(),
            StatusCode::FORBIDDEN
        );
        let token = lab.as_role(user, role);
        let listed = send(
            &lab.router,
            Method::GET,
            &format!("/v1/orgs/{}/remote-access/sessions", lab.org.id),
            serde_json::Value::Null,
            &token,
        )
        .await;
        assert_eq!(listed.status(), StatusCode::FORBIDDEN);
    }
    let network_admin = lab.as_role("netadmin-1", Role::NetworkAdmin);
    assert_eq!(
        lab.open(&network_admin, "deploy").await.status(),
        StatusCode::CREATED
    );
    // Only an owner sets the gateway.
    let admin = lab.as_role("admin-1", Role::Admin);
    let response = send(
        &lab.router,
        Method::PUT,
        &format!("/v1/orgs/{}/remote-access/settings", lab.org.id),
        serde_json::json!({"gateway_node_id": lab.target.id, "gateway_url": "wss://evil.example"}),
        &admin,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn other_organisations_cannot_reach_sessions_targets_or_tickets() {
    let lab = lab("remote-org-a").await;
    let other = create_test_org(&lab.router, "remote-org-b").await;
    let other_owner = signed_session(other.id, "owner-b", Role::Owner, now() + 60);
    let other_gateway =
        register_test_node(&lab.router, other.id, &other_owner, "gw-b", "gw-b-key", &[]).await;
    let response = send(
        &lab.router,
        Method::PUT,
        &format!("/v1/orgs/{}/remote-access/settings", other.id),
        serde_json::json!({"gateway_node_id": lab.gateway.id, "gateway_url": "wss://b.example"}),
        &other_owner,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "another organisation's node cannot become a gateway"
    );
    let response = send(
        &lab.router,
        Method::PUT,
        &format!("/v1/orgs/{}/remote-access/settings", other.id),
        serde_json::json!({"gateway_node_id": other_gateway.id, "gateway_url": "wss://b.example"}),
        &other_owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    // Org B cannot target org A's device.
    let response = send(
        &lab.router,
        Method::POST,
        &format!("/v1/orgs/{}/remote-access/sessions", other.id),
        serde_json::json!({"kind":"ssh","target_node_id": lab.target.id,"os_user":"deploy","reason":"cross org attempt"}),
        &other_owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    // Org B's gateway cannot redeem org A's ticket, and the ticket survives.
    let (session_id, ticket) = lab.ticket().await;
    assert_eq!(
        lab.redeem_as(&other_gateway, &ticket).await.status(),
        StatusCode::GONE
    );
    // Nor can a device that is not the configured gateway.
    assert_eq!(
        lab.redeem_as(&lab.target, &ticket).await.status(),
        StatusCode::GONE
    );
    let response = send(
        &lab.router,
        Method::POST,
        &format!(
            "/v1/orgs/{}/remote-access/sessions/{session_id}/revoke",
            other.id
        ),
        serde_json::json!({}),
        &other_owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = call(
        &lab.router,
        Method::POST,
        &format!(
            "/v1/nodes/{}/remote-sessions/{session_id}/report",
            other_gateway.id
        ),
        serde_json::json!({}),
        Some(&other_gateway.node_token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        lab.redeem_as(&lab.gateway, &ticket).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn suspended_or_revoked_devices_cannot_start_and_live_sessions_end() {
    let lab = lab("remote-lifecycle").await;
    let (session_id, ticket) = lab.ticket().await;
    assert_eq!(
        lab.redeem_as(&lab.gateway, &ticket).await.status(),
        StatusCode::OK
    );
    let admin = lab.as_role("admin-1", Role::Admin);
    let response = send(
        &lab.router,
        Method::POST,
        &format!("/v1/orgs/{}/nodes/{}/suspend", lab.org.id, lab.target.id),
        serde_json::json!({"reason":"lost tablet"}),
        &admin,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let decision = lab.report(session_id, serde_json::json!({})).await;
    assert_eq!(decision.action, "terminate");
    assert!(decision.reason.unwrap().contains("suspended"));
    let response = lab.open(&lab.owner, "deploy").await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(lab
        .audit_actions()
        .await
        .contains(&"remote_session.denied".to_string()));

    let admin = lab.as_role("admin-1", Role::Admin);
    send(
        &lab.router,
        Method::POST,
        &format!("/v1/orgs/{}/nodes/{}/resume", lab.org.id, lab.target.id),
        serde_json::json!({}),
        &admin,
    )
    .await;
    // Issued, then revoked by the console before the gateway redeems it.
    let (session_id, ticket) = lab.ticket().await;
    let response = send(
        &lab.router,
        Method::POST,
        &format!(
            "/v1/orgs/{}/remote-access/sessions/{session_id}/revoke",
            lab.org.id
        ),
        serde_json::json!({}),
        &lab.as_role("admin-1", Role::Admin),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        lab.redeem_as(&lab.gateway, &ticket).await.status(),
        StatusCode::GONE
    );

    // A live session ends when its person is suspended in the console.
    let (session_id, ticket) = lab.ticket().await;
    assert_eq!(
        lab.redeem_as(&lab.gateway, &ticket).await.status(),
        StatusCode::OK
    );
    let response = send(
        &lab.router,
        Method::POST,
        &format!("/v1/orgs/{}/remote-access/users/owner-1/revoke", lab.org.id),
        serde_json::json!({}),
        &lab.as_role("owner-2", Role::Owner),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let decision = lab.report(session_id, serde_json::json!({})).await;
    assert_eq!(decision.reason.as_deref(), Some("revoked"));

    // A revoked gateway can no longer redeem or report.
    let (_, ticket) = lab.ticket().await;
    sqlx::query("UPDATE nodes SET revoked_at=$1 WHERE id=$2")
        .bind(now())
        .bind(lab.gateway.id.to_string())
        .execute(&lab.store.pool)
        .await
        .unwrap();
    assert_eq!(
        lab.redeem_as(&lab.gateway, &ticket).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn changed_host_key_blocks_sessions_until_acknowledged() {
    let lab = lab("remote-host-key").await;
    let replacement = host_key(9);
    let response = report_host_key(&lab.router, &lab.target, &replacement).await;
    assert_eq!(json(response).await["state"], "pending_acknowledgement");
    let response = lab.open(&lab.owner, "deploy").await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(json(response).await["error"]
        .as_str()
        .unwrap()
        .contains("new SSH host key"));
    let keys = json(
        send(
            &lab.router,
            Method::GET,
            &format!("/v1/orgs/{}/remote-access/host-keys", lab.org.id),
            serde_json::Value::Null,
            &lab.owner,
        )
        .await,
    )
    .await;
    let pending = keys[0]["pending_fingerprint"].as_str().unwrap().to_owned();
    let wrong = send(
        &lab.router,
        Method::POST,
        &format!(
            "/v1/orgs/{}/remote-access/host-keys/{}/acknowledge",
            lab.org.id, lab.target.id
        ),
        serde_json::json!({"fingerprint": "SHA256:not-it"}),
        &lab.owner,
    )
    .await;
    assert_eq!(wrong.status(), StatusCode::CONFLICT);
    let member = lab.as_role("member-1", Role::Member);
    let forbidden = send(
        &lab.router,
        Method::POST,
        &format!(
            "/v1/orgs/{}/remote-access/host-keys/{}/acknowledge",
            lab.org.id, lab.target.id
        ),
        serde_json::json!({"fingerprint": pending}),
        &member,
    )
    .await;
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    let response = send(
        &lab.router,
        Method::POST,
        &format!(
            "/v1/orgs/{}/remote-access/host-keys/{}/acknowledge",
            lab.org.id, lab.target.id
        ),
        serde_json::json!({"fingerprint": pending}),
        &lab.as_role("admin-1", Role::Admin),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let (_, ticket) = lab.ticket().await;
    let redeemed: RedeemedSession = body(lab.redeem_as(&lab.gateway, &ticket).await).await;
    assert_eq!(redeemed.host_key.as_deref(), Some(replacement.as_str()));

    // The gateway reports a mismatch it found at connect time.
    let decision = lab
        .report(
            redeemed.session_id,
            serde_json::json!({"ended": "host_key_mismatch"}),
        )
        .await;
    assert_eq!(decision.action, "terminate");
    let actions = lab.audit_actions().await;
    assert!(actions.contains(&"remote_session.host_key_changed".to_string()));
    assert!(actions.contains(&"remote_session.host_key_mismatch".to_string()));
    // Non-Ed25519 or garbage keys are refused outright.
    assert_eq!(
        report_host_key(&lab.router, &lab.target, "ssh-rsa AAAA garbage")
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn sessions_follow_policy_and_device_opt_in() {
    let lab = lab("remote-policy").await;
    // No SSH rule names root.
    let response = lab.open(&lab.owner, "root").await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(json(response).await["error"]
        .as_str()
        .unwrap()
        .contains("no SSH rule"));
    // Without the target's sshd CA opt-in, nothing is issued.
    report_capabilities(&lab.router, &lab.target, "acl-filter,ssh-users").await;
    assert_eq!(
        lab.open(&lab.owner, "deploy").await.status(),
        StatusCode::CONFLICT
    );
    report_capabilities(
        &lab.router,
        &lab.target,
        "acl-filter,ssh-users,remote-ssh-ca",
    )
    .await;
    let (session_id, ticket) = lab.ticket().await;
    assert_eq!(
        lab.redeem_as(&lab.gateway, &ticket).await.status(),
        StatusCode::OK
    );
    // A policy change that drops the SSH rule ends the live session.
    let mut changed = policy();
    changed["ssh"] = serde_json::json!([]);
    let response = send(
        &lab.router,
        Method::PUT,
        &format!("/v1/orgs/{}/acl", lab.org.id),
        changed,
        &lab.owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let decision = lab.report(session_id, serde_json::json!({})).await;
    assert_eq!(decision.action, "terminate");
    assert!(decision.reason.unwrap().starts_with("policy"));
    // Shell-shaped or wildcard OS users are rejected before policy.
    for user in ["*", "deploy;id", "$(id)", ""] {
        assert_eq!(
            lab.open(&lab.owner, user).await.status(),
            StatusCode::BAD_REQUEST,
            "{user:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Remote jobs

async fn create_template(lab: &Lab, token: &str, body: serde_json::Value) -> Response {
    send(
        &lab.router,
        Method::POST,
        &format!("/v1/orgs/{}/remote-jobs/templates", lab.org.id),
        body,
        token,
    )
    .await
}

fn uptime_template(lab: &Lab) -> serde_json::Value {
    serde_json::json!({
        "name": "uptime",
        "argv": ["/usr/bin/uptime"],
        "timeout_secs": 30,
        "output_cap_bytes": 64,
        "target": {"node_ids": [lab.target.id]},
    })
}

async fn approved_run(lab: &Lab) -> Uuid {
    let template = json(create_template(lab, &lab.owner, uptime_template(lab)).await).await;
    let admin = lab.as_role("admin-1", Role::Admin);
    let response = send(
        &lab.router,
        Method::POST,
        &format!("/v1/orgs/{}/remote-jobs/runs", lab.org.id),
        serde_json::json!({"template_id": template["id"], "node_id": lab.target.id, "reason": "check load"}),
        &admin,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let run = json(response).await;
    assert_eq!(run["status"], "pending_approval");
    let run_id: Uuid = run["id"].as_str().unwrap().parse().unwrap();
    // Admins request; only an owner approves.
    let response = send(
        &lab.router,
        Method::POST,
        &format!("/v1/orgs/{}/remote-jobs/runs/{run_id}/approve", lab.org.id),
        serde_json::json!({}),
        &lab.as_role("admin-1", Role::Admin),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = send(
        &lab.router,
        Method::POST,
        &format!("/v1/orgs/{}/remote-jobs/runs/{run_id}/approve", lab.org.id),
        serde_json::json!({}),
        &lab.as_role("owner-1", Role::Owner),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    run_id
}

async fn agent_jobs(lab: &Lab, node: &RegisterResponse) -> AgentJobs {
    body(
        call(
            &lab.router,
            Method::GET,
            &format!("/v1/nodes/{}/remote-jobs", node.id),
            serde_json::Value::Null,
            Some(&node.node_token),
        )
        .await,
    )
    .await
}

async fn agent_post(lab: &Lab, path: &str, payload: serde_json::Value) -> Response {
    call(
        &lab.router,
        Method::POST,
        &format!("/v1/nodes/{}/remote-jobs/{path}", lab.target.id),
        payload,
        Some(&lab.target.node_token),
    )
    .await
}

#[tokio::test]
async fn job_templates_are_owner_only_fixed_argv() {
    let lab = lab("remote-job-templates").await;
    let admin = lab.as_role("admin-1", Role::Admin);
    assert_eq!(
        create_template(&lab, &admin, uptime_template(&lab))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    for (argv, timeout, cap) in [
        (serde_json::json!(["/bin/sh", "-c", "id"]), 30, 64),
        (serde_json::json!(["uptime"]), 30, 64),
        (serde_json::json!(["/usr/bin/uptime"]), 601, 64),
        (serde_json::json!(["/usr/bin/uptime"]), 30, 65_537),
        (serde_json::json!([]), 30, 64),
    ] {
        let response = create_template(
            &lab,
            &lab.owner,
            serde_json::json!({"name":"bad","argv":argv,"timeout_secs":timeout,"output_cap_bytes":cap,"target":{"node_ids":[lab.target.id]}}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{argv}");
    }
    let template = json(create_template(&lab, &lab.owner, uptime_template(&lab)).await).await;
    // A run request carries no command: extra fields are refused, so the
    // requester cannot add arguments to the owner's argv.
    let response = send(
        &lab.router,
        Method::POST,
        &format!("/v1/orgs/{}/remote-jobs/runs", lab.org.id),
        serde_json::json!({
            "template_id": template["id"],
            "node_id": lab.target.id,
            "reason": "inject",
            "argv": ["/bin/sh", "-c", "reboot"],
        }),
        &admin,
    )
    .await;
    assert!(response.status().is_client_error());
    let member = lab.as_role("member-1", Role::Member);
    let response = send(
        &lab.router,
        Method::POST,
        &format!("/v1/orgs/{}/remote-jobs/runs", lab.org.id),
        serde_json::json!({"template_id": template["id"], "node_id": lab.target.id, "reason": "member try"}),
        &member,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    // Devices outside the selector or without the agent opt-in are refused.
    let response = send(
        &lab.router,
        Method::POST,
        &format!("/v1/orgs/{}/remote-jobs/runs", lab.org.id),
        serde_json::json!({"template_id": template["id"], "node_id": lab.gateway.id, "reason": "wrong target"}),
        &admin,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    report_capabilities(&lab.router, &lab.target, "acl-filter").await;
    let response = send(
        &lab.router,
        Method::POST,
        &format!("/v1/orgs/{}/remote-jobs/runs", lab.org.id),
        serde_json::json!({"template_id": template["id"], "node_id": lab.target.id, "reason": "no opt in"}),
        &admin,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn approved_jobs_are_signed_claimed_once_capped_and_audited() {
    let lab = lab("remote-job-run").await;
    let run_id = approved_run(&lab).await;
    // Pending runs are never handed out before approval; this one is approved.
    let jobs = agent_jobs(&lab, &lab.target).await;
    assert_eq!(jobs.jobs.len(), 1);
    let job = &jobs.jobs[0];
    let peers: PeersResponse = body(
        call(
            &lab.router,
            Method::GET,
            &format!("/v1/nodes/{}/peers", lab.target.id),
            serde_json::Value::Null,
            Some(&lab.target.node_token),
        )
        .await,
    )
    .await;
    let key = ed25519_dalek::VerifyingKey::from_bytes(
        &STANDARD
            .decode(peers.remote_access.unwrap().job_signing_key)
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let signature =
        ed25519_dalek::Signature::from_slice(&STANDARD.decode(&job.signature).unwrap()).unwrap();
    key.verify_strict(
        format!(
            "{}{}",
            crate::remote_access::JOB_SIGNATURE_CONTEXT,
            job.payload
        )
        .as_bytes(),
        &signature,
    )
    .unwrap();
    let signed: SignedJob = serde_json::from_str(&job.payload).unwrap();
    assert_eq!(signed.argv, vec!["/usr/bin/uptime".to_string()]);
    assert_eq!(signed.node_id, lab.target.id);
    assert_eq!(signed.output_cap_bytes, 64);
    // Another device never sees it.
    assert!(agent_jobs(&lab, &lab.gateway).await.jobs.is_empty());

    assert_eq!(
        agent_post(&lab, &format!("{run_id}/claim"), serde_json::json!({}))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        agent_post(&lab, &format!("{run_id}/claim"), serde_json::json!({}))
            .await
            .status(),
        StatusCode::GONE
    );
    let oversized = agent_post(
        &lab,
        &format!("{run_id}/result"),
        serde_json::json!({"status":"succeeded","exit_code":0,"output":"x".repeat(65)}),
    )
    .await;
    assert_eq!(oversized.status(), StatusCode::BAD_REQUEST);
    let response = agent_post(
        &lab,
        &format!("{run_id}/result"),
        serde_json::json!({"status":"succeeded","exit_code":0,"output":" 10:00 up 1 day"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let runs = json(
        send(
            &lab.router,
            Method::GET,
            &format!("/v1/orgs/{}/remote-jobs/runs", lab.org.id),
            serde_json::Value::Null,
            &lab.owner,
        )
        .await,
    )
    .await;
    assert_eq!(runs[0]["status"], "succeeded");
    assert_eq!(runs[0]["output"], " 10:00 up 1 day");
    let actions = lab.audit_actions().await;
    for action in [
        "remote_job.template_created",
        "remote_job.requested",
        "remote_job.approved",
        "remote_job.started",
        "remote_job.finished",
    ] {
        assert!(actions.iter().any(|a| a == action), "{action} missing");
    }
    let report: crate::audit_log::ChainReport = body(
        send(
            &lab.router,
            Method::GET,
            &format!("/v1/orgs/{}/audit/verify", lab.org.id),
            serde_json::Value::Null,
            &lab.owner,
        )
        .await,
    )
    .await;
    assert!(report.intact, "{:?}", report.problems);
}

#[tokio::test]
async fn running_jobs_can_be_cancelled_and_queued_ones_never_run() {
    let lab = lab("remote-job-cancel").await;
    let run_id = approved_run(&lab).await;
    assert_eq!(
        agent_post(&lab, &format!("{run_id}/claim"), serde_json::json!({}))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let admin = lab.as_role("admin-1", Role::Admin);
    let response = send(
        &lab.router,
        Method::POST,
        &format!("/v1/orgs/{}/remote-jobs/runs/{run_id}/cancel", lab.org.id),
        serde_json::json!({}),
        &admin,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let state: JobState = body(
        call(
            &lab.router,
            Method::GET,
            &format!("/v1/nodes/{}/remote-jobs/{run_id}", lab.target.id),
            serde_json::Value::Null,
            Some(&lab.target.node_token),
        )
        .await,
    )
    .await;
    assert!(state.cancel);
    let response = agent_post(
        &lab,
        &format!("{run_id}/result"),
        serde_json::json!({"status":"cancelled","exit_code":null,"output":""}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Approved but cancelled before the agent claims it: never handed out.
    let template_id: String =
        sqlx::query_scalar("SELECT template_id FROM remote_job_runs WHERE id=$1")
            .bind(run_id.to_string())
            .fetch_one(&lab.store.pool)
            .await
            .unwrap();
    let response = send(
        &lab.router,
        Method::POST,
        &format!("/v1/orgs/{}/remote-jobs/runs", lab.org.id),
        serde_json::json!({"template_id": template_id, "node_id": lab.target.id, "reason": "second run"}),
        &admin,
    )
    .await;
    let second: Uuid = json(response).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    send(
        &lab.router,
        Method::POST,
        &format!("/v1/orgs/{}/remote-jobs/runs/{second}/approve", lab.org.id),
        serde_json::json!({}),
        &lab.owner,
    )
    .await;
    send(
        &lab.router,
        Method::POST,
        &format!("/v1/orgs/{}/remote-jobs/runs/{second}/cancel", lab.org.id),
        serde_json::json!({}),
        &lab.as_role("admin-1", Role::Admin),
    )
    .await;
    assert!(agent_jobs(&lab, &lab.target).await.jobs.is_empty());
    assert_eq!(
        agent_post(&lab, &format!("{second}/claim"), serde_json::json!({}))
            .await
            .status(),
        StatusCode::GONE
    );
}
