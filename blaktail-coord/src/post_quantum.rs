//! Opt-in hybrid post-quantum WireGuard PSKs (NetBird-parity draft 25,
//! ADR 0009): organisation policy, its delivery in peer maps, and the
//! per-peer state agents report.
//!
//! The coordinator never generates, relays, stores or sees a PSK. Agents run
//! the ML-KEM-768 + X25519 exchange inside their WireGuard tunnel; this module
//! only says which pairs should (`prefer`) or must (`require`) do so, whether
//! each peer advertises the `pq-psk` capability, and records what each agent
//! says it actually negotiated so the console can show it per peer. Request
//! bodies reject unknown fields, so a report cannot smuggle key material in.

use crate::{
    append_audit, bearer, bump_control_revision, console_session, now,
    permissions::{require, Permission},
    ApiError, AppState, DeviceTag, Peer,
};
use axum::{
    extract::{Path as UrlPath, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use tracing::info;
use uuid::Uuid;

pub(crate) const CAPABILITY: &str = "pq-psk";
/// The only algorithm string agents may report.
pub(crate) const ALGORITHM: &str = "ml-kem-768+x25519";
const STATES: [&str; 5] = [
    "classical",
    "negotiating",
    "established",
    "degraded",
    "required_not_established",
];
const MAX_RULES: usize = 32;
const MAX_REPORTED_PEERS: usize = 2_000;
const MAX_REASON_CHARS: usize = 64;
/// Reports older than this are shown as stale rather than current.
const REPORT_FRESH_SECS: i64 = 5 * 60;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/nodes/:node_id/pq-state", put(report_state))
        .route(
            "/v1/orgs/:org_id/post-quantum",
            get(get_overview).put(update_policy),
        )
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Mode {
    #[default]
    Off,
    Prefer,
    Require,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Prefer => "prefer",
            Self::Require => "require",
        }
    }
}

/// A rule for one unordered tag pair. Rules are symmetric so both agents of
/// a pair always resolve the same mode.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PairRule {
    pub(crate) tags: [DeviceTag; 2],
    pub(crate) mode: Mode,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct Policy {
    pub(crate) mode: Mode,
    /// Drop a pair's traffic (except the exchange) while `require` is unmet.
    pub(crate) block_unestablished: bool,
    pub(crate) rules: Vec<PairRule>,
    pub(crate) revision: i64,
    pub(crate) updated_by: String,
    pub(crate) updated_at: i64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            mode: Mode::Off,
            block_unestablished: true,
            rules: Vec::new(),
            revision: 0,
            updated_by: String::new(),
            updated_at: 0,
        }
    }
}

impl Policy {
    /// The pair's mode: the strongest matching tag-pair rule, otherwise the
    /// organisation default. A matching `off` rule can exempt a pair only
    /// when no stronger rule also matches it.
    pub(crate) fn mode_for(&self, a: &[DeviceTag], b: &[DeviceTag]) -> Mode {
        self.rules
            .iter()
            .filter(|rule| {
                let [x, y] = rule.tags;
                (a.contains(&x) && b.contains(&y)) || (a.contains(&y) && b.contains(&x))
            })
            .map(|rule| rule.mode)
            .max()
            .unwrap_or(self.mode)
    }

    fn is_inert(&self) -> bool {
        self.mode == Mode::Off && self.rules.iter().all(|rule| rule.mode == Mode::Off)
    }
}

/// Per-peer policy delivered in the peer map. Never carries key material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct PeerPq {
    pub(crate) mode: Mode,
    /// The peer advertises `pq-psk`.
    pub(crate) capable: bool,
    pub(crate) block: bool,
}

pub(crate) async fn load_policy(pool: &sqlx::AnyPool, org_id: &str) -> Result<Policy, ApiError> {
    let Some(row) = sqlx::query(
        "SELECT mode,block_unestablished,rules_json,revision,updated_by,updated_at FROM pq_policies WHERE org_id=$1",
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(Policy::default());
    };
    let mode: String = row.try_get(0)?;
    Ok(Policy {
        mode: serde_json::from_value(serde_json::Value::String(mode))
            .map_err(|_| ApiError::CorruptData)?,
        block_unestablished: row.try_get::<i64, _>(1)? != 0,
        rules: serde_json::from_str(&row.try_get::<String, _>(2)?)
            .map_err(|_| ApiError::CorruptData)?,
        revision: row.try_get(3)?,
        updated_by: row.try_get(4)?,
        updated_at: row.try_get(5)?,
    })
}

async fn capable_nodes(pool: &sqlx::AnyPool, org_id: &str) -> Result<HashSet<Uuid>, ApiError> {
    let rows = sqlx::query(
        "SELECT id,capabilities_json FROM nodes WHERE org_id=$1 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;
    let mut capable = HashSet::new();
    for row in rows {
        let capabilities: Vec<String> =
            serde_json::from_str(&row.try_get::<String, _>(1)?).unwrap_or_default();
        if capabilities.iter().any(|value| value == CAPABILITY) {
            let id: String = row.try_get(0)?;
            capable.insert(Uuid::parse_str(&id).map_err(|_| ApiError::CorruptData)?);
        }
    }
    Ok(capable)
}

/// Adds the pair policy to each peer of `source`'s map. A no-op while the
/// organisation has post-quantum PSKs off, so default peer maps are unchanged.
pub(crate) async fn annotate_peers(
    pool: &sqlx::AnyPool,
    org_id: &str,
    source_tags: &[DeviceTag],
    peers: &mut [Peer],
) -> Result<(), ApiError> {
    let policy = load_policy(pool, org_id).await?;
    if policy.is_inert() {
        return Ok(());
    }
    let capable = capable_nodes(pool, org_id).await?;
    for peer in peers {
        let mode = policy.mode_for(source_tags, &peer.tags);
        peer.pq = (mode != Mode::Off).then(|| PeerPq {
            mode,
            capable: capable.contains(&peer.id),
            block: policy.block_unestablished,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Agent reports

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateReport {
    #[serde(default)]
    #[allow(dead_code)]
    capable: bool,
    peers: Vec<PeerStateReport>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerStateReport {
    peer_id: Uuid,
    state: String,
    mode: Mode,
    #[serde(default)]
    algorithm: String,
    #[serde(default)]
    epoch: u64,
    #[serde(default)]
    last_rotation_at: Option<i64>,
    #[serde(default)]
    blocked: bool,
    #[serde(default)]
    reason: String,
}

impl PeerStateReport {
    fn validate(&self) -> Result<(), ApiError> {
        if !STATES.contains(&self.state.as_str()) {
            return Err(ApiError::BadRequest("unknown post-quantum state".into()));
        }
        if !self.algorithm.is_empty() && self.algorithm != ALGORITHM {
            return Err(ApiError::BadRequest(
                "unknown post-quantum algorithm".into(),
            ));
        }
        if self.reason.chars().count() > MAX_REASON_CHARS
            || !self
                .reason
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_')
        {
            return Err(ApiError::BadRequest(
                "reason must be a short lowercase code".into(),
            ));
        }
        if self.epoch > i64::MAX as u64 {
            return Err(ApiError::BadRequest("epoch is out of range".into()));
        }
        Ok(())
    }
}

async fn report_state(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<StateReport>,
) -> Result<StatusCode, ApiError> {
    if input.peers.len() > MAX_REPORTED_PEERS {
        return Err(ApiError::BadRequest("too many peers in one report".into()));
    }
    for peer in &input.peers {
        peer.validate()?;
    }
    let token = bearer(&headers)?;
    let row = sqlx::query(
        "SELECT org_id,credential_expires_at,CASE WHEN suspended_at IS NULL THEN 0 ELSE 1 END FROM nodes WHERE id=$1 AND token_hash=$2 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(node_id.to_string())
    .bind(token)
    .fetch_optional(&s.store.pool)
    .await?
    .ok_or(ApiError::Unauthorized)?;
    let org_id: String = row.try_get(0)?;
    if row.try_get::<i64, _>(2)? != 0 {
        return Err(ApiError::Suspended);
    }
    if row.try_get::<i64, _>(1)? <= now() {
        return Err(ApiError::CredentialExpired);
    }
    // Only peers in the reporter's own organisation are recorded.
    let org_nodes: HashSet<String> = sqlx::query_scalar("SELECT id FROM nodes WHERE org_id=$1")
        .bind(&org_id)
        .fetch_all(&s.store.pool)
        .await?
        .into_iter()
        .collect();
    let reported_at = now();
    let mut tx = s.store.pool.begin().await?;
    sqlx::query("DELETE FROM pq_peer_states WHERE node_id=$1")
        .bind(node_id.to_string())
        .execute(&mut *tx)
        .await?;
    let mut seen = HashSet::new();
    for peer in &input.peers {
        let peer_id = peer.peer_id.to_string();
        if peer.peer_id == node_id || !org_nodes.contains(&peer_id) || !seen.insert(peer.peer_id) {
            continue;
        }
        sqlx::query(
            "INSERT INTO pq_peer_states(org_id,node_id,peer_id,state,mode,algorithm,epoch,last_rotation_at,blocked,reason,reported_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(&org_id)
        .bind(node_id.to_string())
        .bind(peer_id)
        .bind(&peer.state)
        .bind(peer.mode.as_str())
        .bind(&peer.algorithm)
        .bind(peer.epoch as i64)
        .bind(peer.last_rotation_at)
        .bind(i64::from(peer.blocked))
        .bind(&peer.reason)
        .bind(reported_at)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Console

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct DeviceCapability {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) capable: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct PeerProtection {
    pub(crate) node_id: Uuid,
    pub(crate) peer_id: Uuid,
    pub(crate) peer_name: String,
    /// As the agent on `node_id` reported it.
    pub(crate) state: String,
    pub(crate) mode: Mode,
    pub(crate) algorithm: String,
    pub(crate) epoch: i64,
    pub(crate) last_rotation_at: Option<i64>,
    pub(crate) rotated_seconds_ago: Option<i64>,
    pub(crate) blocked: bool,
    pub(crate) reason: String,
    pub(crate) reported_at: i64,
    pub(crate) stale: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Overview {
    pub(crate) org_id: Uuid,
    pub(crate) server_time: i64,
    pub(crate) policy: Policy,
    pub(crate) devices: Vec<DeviceCapability>,
    pub(crate) peers: Vec<PeerProtection>,
}

#[derive(Default, Deserialize)]
struct OverviewQuery {
    #[serde(default)]
    node_id: Option<Uuid>,
}

async fn get_overview(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    Query(query): Query<OverviewQuery>,
    headers: HeaderMap,
) -> Result<Json<Overview>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewNetwork)?;
    let org = org_id.to_string();
    let policy = load_policy(&s.store.pool, &org).await?;
    let capable = capable_nodes(&s.store.pool, &org).await?;
    let rows = sqlx::query(
        "SELECT id,COALESCE(NULLIF(TRIM(display_name),''),name) FROM nodes WHERE org_id=$1 AND revoked_at IS NULL AND deleted_at IS NULL ORDER BY name",
    )
    .bind(&org)
    .fetch_all(&s.store.pool)
    .await?;
    let mut names = BTreeMap::new();
    let mut devices = Vec::new();
    for row in rows {
        let id =
            Uuid::parse_str(&row.try_get::<String, _>(0)?).map_err(|_| ApiError::CorruptData)?;
        let name: String = row.try_get(1)?;
        names.insert(id, name.clone());
        devices.push(DeviceCapability {
            id,
            name,
            capable: capable.contains(&id),
        });
    }
    let current = now();
    let rows = sqlx::query(
        "SELECT node_id,peer_id,state,mode,algorithm,epoch,last_rotation_at,blocked,reason,reported_at FROM pq_peer_states WHERE org_id=$1 ORDER BY node_id,peer_id",
    )
    .bind(&org)
    .fetch_all(&s.store.pool)
    .await?;
    let mut peers = Vec::new();
    for row in rows {
        let node_id =
            Uuid::parse_str(&row.try_get::<String, _>(0)?).map_err(|_| ApiError::CorruptData)?;
        let peer_id =
            Uuid::parse_str(&row.try_get::<String, _>(1)?).map_err(|_| ApiError::CorruptData)?;
        if query.node_id.is_some_and(|wanted| wanted != node_id) {
            continue;
        }
        // Rows for deleted or revoked devices are not shown.
        let (Some(_), Some(peer_name)) = (names.get(&node_id), names.get(&peer_id)) else {
            continue;
        };
        let mode: String = row.try_get(3)?;
        let last_rotation_at: Option<i64> = row.try_get(6)?;
        let reported_at: i64 = row.try_get(9)?;
        peers.push(PeerProtection {
            node_id,
            peer_id,
            peer_name: peer_name.clone(),
            state: row.try_get(2)?,
            mode: serde_json::from_value(serde_json::Value::String(mode))
                .map_err(|_| ApiError::CorruptData)?,
            algorithm: row.try_get(4)?,
            epoch: row.try_get(5)?,
            last_rotation_at,
            rotated_seconds_ago: last_rotation_at.map(|at| (current - at).max(0)),
            blocked: row.try_get::<i64, _>(7)? != 0,
            reason: row.try_get(8)?,
            reported_at,
            stale: current - reported_at > REPORT_FRESH_SECS,
        });
    }
    Ok(Json(Overview {
        org_id,
        server_time: current,
        policy,
        devices,
        peers,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyUpdate {
    mode: Mode,
    #[serde(default = "default_true")]
    block_unestablished: bool,
    #[serde(default)]
    rules: Vec<PairRule>,
    /// Optimistic concurrency: the revision the editor last saw.
    #[serde(default)]
    expected_revision: Option<i64>,
}

fn default_true() -> bool {
    true
}

async fn update_policy(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<PolicyUpdate>,
) -> Result<Json<Policy>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageSecurity)?;
    if input.rules.len() > MAX_RULES {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_RULES} tag-pair rules"
        )));
    }
    let mut rules = input.rules;
    for rule in &mut rules {
        rule.tags.sort();
    }
    let mut keys = BTreeSet::new();
    if !rules.iter().all(|rule| keys.insert(rule.tags)) {
        return Err(ApiError::BadRequest(
            "each tag pair may have only one rule".into(),
        ));
    }
    let org = org_id.to_string();
    let mut tx = s.store.pool.begin().await?;
    let previous = {
        let row = sqlx::query(
            "SELECT mode,block_unestablished,rules_json,revision FROM pq_policies WHERE org_id=$1",
        )
        .bind(&org)
        .fetch_optional(&mut *tx)
        .await?;
        match row {
            Some(row) => Some((
                row.try_get::<String, _>(0)?,
                row.try_get::<i64, _>(1)? != 0,
                row.try_get::<String, _>(2)?,
                row.try_get::<i64, _>(3)?,
            )),
            None => None,
        }
    };
    let revision = previous.as_ref().map_or(0, |row| row.3);
    if input
        .expected_revision
        .is_some_and(|expected| expected != revision)
    {
        return Err(ApiError::Conflict(
            "post-quantum policy changed since it was loaded; reload and try again".into(),
        ));
    }
    let rules_json = serde_json::to_string(&rules).map_err(|_| ApiError::CorruptData)?;
    let updated_at = now();
    let next = revision + 1;
    let updated_by = session.email.clone();
    let changed = sqlx::query(
        "UPDATE pq_policies SET mode=$1,block_unestablished=$2,rules_json=$3,revision=$4,updated_by=$5,updated_at=$6 WHERE org_id=$7 AND revision=$8",
    )
    .bind(input.mode.as_str())
    .bind(i64::from(input.block_unestablished))
    .bind(&rules_json)
    .bind(next)
    .bind(&updated_by)
    .bind(updated_at)
    .bind(&org)
    .bind(revision)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        if previous.is_some() {
            return Err(ApiError::Conflict(
                "post-quantum policy changed concurrently; reload and try again".into(),
            ));
        }
        sqlx::query(
            "INSERT INTO pq_policies(org_id,mode,block_unestablished,rules_json,revision,updated_by,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(&org)
        .bind(input.mode.as_str())
        .bind(i64::from(input.block_unestablished))
        .bind(&rules_json)
        .bind(next)
        .bind(&updated_by)
        .bind(updated_at)
        .execute(&mut *tx)
        .await?;
    }
    append_audit(
        &mut tx,
        org_id,
        &session,
        "post_quantum.policy_updated",
        "org",
        Some(&org),
        &serde_json::json!({
            "mode": input.mode.as_str(),
            "block_unestablished": input.block_unestablished,
            "rules": rules,
            "previous": previous.as_ref().map(|row| serde_json::json!({
                "mode": row.0,
                "block_unestablished": row.1,
                "rules": serde_json::from_str::<serde_json::Value>(&row.2).unwrap_or_default(),
            })),
            "revision": next,
        }),
    )
    .await?;
    bump_control_revision(&mut tx, &org).await?;
    tx.commit().await?;
    info!(%org_id, mode = input.mode.as_str(), "post-quantum policy updated");
    Ok(Json(Policy {
        mode: input.mode,
        block_unestablished: input.block_unestablished,
        rules,
        revision: next,
        updated_by,
        updated_at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app, AssertionClaims, JoinKeyResponse, OrgResponse, RegisterResponse, Role, Store,
        CONSOLE_ASSERTION_AUDIENCE, CONSOLE_ASSERTION_ISSUER, MAX_CONSOLE_ASSERTION_LIFETIME_SECS,
    };
    use axum::{
        body::{to_bytes, Body},
        http::{header::AUTHORIZATION, Method, Request},
        response::Response,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use tower::ServiceExt;

    const SECRET: &[u8] = b"post-quantum-test-secret-32-bytes!!!!";

    fn sign(claims: AssertionClaims) -> String {
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
        mac.update(payload.as_bytes());
        format!(
            "{payload}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        )
    }

    fn claims(org_id: Uuid, user: &str, role: &str, action: Option<&str>) -> AssertionClaims {
        let iat = now();
        AssertionClaims {
            user_id: user.into(),
            org_id,
            role: role.into(),
            name: user.into(),
            email: format!("{user}@example.org"),
            iss: CONSOLE_ASSERTION_ISSUER.into(),
            aud: CONSOLE_ASSERTION_AUDIENCE.into(),
            iat,
            exp: iat + MAX_CONSOLE_ASSERTION_LIFETIME_SECS,
            jti: Uuid::new_v4().to_string(),
            action: action.map(str::to_owned),
        }
    }

    fn console(org_id: Uuid, role: Role) -> Option<String> {
        Some(sign(claims(org_id, "user-1", role.as_str(), None)))
    }

    async fn call(
        router: &Router,
        method: Method,
        uri: &str,
        body: serde_json::Value,
        auth: Option<String>,
    ) -> Response {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(token) = auth {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        router
            .clone()
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }

    async fn text(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    async fn json<T: serde::de::DeserializeOwned>(response: Response) -> T {
        let status = response.status();
        let body = text(response).await;
        serde_json::from_str(&body).unwrap_or_else(|error| panic!("{status}: {error}: {body}"))
    }

    async fn router() -> Router {
        app(
            Store::memory().await.unwrap(),
            "ap-southeast-2".into(),
            SECRET,
        )
    }

    async fn org(router: &Router, name: &str) -> Uuid {
        let id = Uuid::new_v4();
        let prepared = call(
            router,
            Method::POST,
            "/v1/orgs",
            serde_json::json!({"id":id,"name":name,"acl":{"version":1,"defaults":"same_tag","rules":[]}}),
            Some(sign(claims(id, "operator", "service", Some("bootstrap.prepare")))),
        )
        .await;
        assert_eq!(prepared.status(), StatusCode::ACCEPTED);
        let committed = call(
            router,
            Method::POST,
            &format!("/v1/orgs/{id}/bootstrap-commit"),
            serde_json::json!({}),
            Some(sign(claims(
                id,
                "operator",
                "service",
                Some("bootstrap.commit"),
            ))),
        )
        .await;
        assert_eq!(committed.status(), StatusCode::CREATED);
        let created: OrgResponse = json(committed).await;
        created.id
    }

    async fn node(router: &Router, org_id: Uuid, name: &str) -> RegisterResponse {
        let minted = call(
            router,
            Method::POST,
            &format!("/v1/orgs/{org_id}/join-keys"),
            serde_json::json!({"expires_in_seconds":60}),
            console(org_id, Role::Owner),
        )
        .await;
        assert_eq!(minted.status(), StatusCode::CREATED);
        let key: JoinKeyResponse = json(minted).await;
        let registered = call(
            router,
            Method::POST,
            "/v1/nodes/register",
            serde_json::json!({"join_key":key.key,"name":name,"wg_public_key":format!("{name}-key")}),
            None,
        )
        .await;
        assert_eq!(registered.status(), StatusCode::CREATED);
        json(registered).await
    }

    async fn peer_map(router: &Router, node: &RegisterResponse, capabilities: &str) -> String {
        let response = call(
            router,
            Method::GET,
            &format!("/v1/nodes/{}/peers?capabilities={capabilities}", node.id),
            serde_json::json!({}),
            Some(node.node_token.clone()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        text(response).await
    }

    async fn set_policy(
        router: &Router,
        org_id: Uuid,
        role: Role,
        body: serde_json::Value,
    ) -> Response {
        call(
            router,
            Method::PUT,
            &format!("/v1/orgs/{org_id}/post-quantum"),
            body,
            console(org_id, role),
        )
        .await
    }

    async fn overview(router: &Router, org_id: Uuid, role: Role) -> Response {
        call(
            router,
            Method::GET,
            &format!("/v1/orgs/{org_id}/post-quantum"),
            serde_json::json!({}),
            console(org_id, role),
        )
        .await
    }

    fn assert_no_key_material(body: &str) {
        let lower = body.to_ascii_lowercase();
        for needle in ["psk", "preshared", "secret", "private", "shared_key"] {
            assert!(!lower.contains(needle), "{needle} leaked in {body}");
        }
    }

    #[test]
    fn tag_pair_rules_are_symmetric_and_strongest_wins() {
        let policy = Policy {
            mode: Mode::Prefer,
            rules: vec![
                PairRule {
                    tags: [DeviceTag::Office, DeviceTag::Store],
                    mode: Mode::Require,
                },
                PairRule {
                    tags: [DeviceTag::Ranger, DeviceTag::Ranger],
                    mode: Mode::Off,
                },
            ],
            ..Policy::default()
        };
        let office = [DeviceTag::Office];
        let store = [DeviceTag::Store];
        let ranger = [DeviceTag::Ranger];
        assert_eq!(policy.mode_for(&office, &store), Mode::Require);
        assert_eq!(policy.mode_for(&store, &office), Mode::Require);
        assert_eq!(policy.mode_for(&ranger, &ranger), Mode::Off);
        assert_eq!(policy.mode_for(&office, &ranger), Mode::Prefer);
        assert_eq!(policy.mode_for(&[], &[]), Mode::Prefer);
    }

    #[tokio::test]
    async fn policy_reaches_peer_maps_with_capabilities_but_no_keys() {
        let r = router().await;
        let org_id = org(&r, "pq-org").await;
        let a = node(&r, org_id, "alpha").await;
        let b = node(&r, org_id, "bravo").await;
        // Off by default: maps carry no post-quantum field at all.
        let map = peer_map(&r, &a, "wireguard,pq-psk").await;
        assert!(!map.contains("\"pq\""), "{map}");

        let updated = set_policy(
            &r,
            org_id,
            Role::Owner,
            serde_json::json!({"mode":"require"}),
        )
        .await;
        assert_eq!(updated.status(), StatusCode::OK);
        let policy: Policy = json(updated).await;
        assert_eq!((policy.mode, policy.revision), (Mode::Require, 1));
        assert!(policy.block_unestablished);

        // bravo has not advertised pq-psk: alpha learns it is not capable.
        let map: serde_json::Value =
            serde_json::from_str(&peer_map(&r, &a, "wireguard,pq-psk").await).unwrap();
        assert_eq!(
            map["peers"][0]["pq"],
            serde_json::json!({"mode":"require","capable":false,"block":true})
        );
        // Once bravo advertises it, alpha's map says so.
        let b_map = peer_map(&r, &b, "wireguard,pq-psk").await;
        assert_no_key_material(&b_map);
        let a_map = peer_map(&r, &a, "wireguard,pq-psk").await;
        assert_no_key_material(&a_map);
        let a_map: serde_json::Value = serde_json::from_str(&a_map).unwrap();
        assert_eq!(a_map["peers"][0]["pq"]["capable"], true);
        let b_map: serde_json::Value = serde_json::from_str(&b_map).unwrap();
        assert_eq!(b_map["peers"][0]["pq"]["capable"], true);

        // A stale editor revision is a conflict, not a silent overwrite.
        let stale = set_policy(
            &r,
            org_id,
            Role::Owner,
            serde_json::json!({"mode":"off","expected_revision":0}),
        )
        .await;
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        let ok = set_policy(
            &r,
            org_id,
            Role::Owner,
            serde_json::json!({"mode":"prefer","block_unestablished":false,"expected_revision":1}),
        )
        .await;
        assert_eq!(ok.status(), StatusCode::OK);
        let audit = text(
            call(
                &r,
                Method::GET,
                &format!("/v1/orgs/{org_id}/audit"),
                serde_json::json!({}),
                console(org_id, Role::Owner),
            )
            .await,
        )
        .await;
        assert!(audit.contains("post_quantum.policy_updated"), "{audit}");
    }

    #[tokio::test]
    async fn only_security_managers_change_policy_and_orgs_stay_isolated() {
        let r = router().await;
        let org_id = org(&r, "pq-roles").await;
        let other = org(&r, "pq-other").await;
        for role in [Role::Admin, Role::NetworkAdmin, Role::Auditor, Role::Member] {
            let response =
                set_policy(&r, org_id, role, serde_json::json!({"mode":"require"})).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{role:?}");
        }
        // A session for another organisation cannot read or change this one.
        let cross = call(
            &r,
            Method::PUT,
            &format!("/v1/orgs/{org_id}/post-quantum"),
            serde_json::json!({"mode":"require"}),
            console(other, Role::Owner),
        )
        .await;
        assert!(cross.status().is_client_error(), "{}", cross.status());
        let cross_read = call(
            &r,
            Method::GET,
            &format!("/v1/orgs/{org_id}/post-quantum"),
            serde_json::json!({}),
            console(other, Role::Owner),
        )
        .await;
        assert!(cross_read.status().is_client_error());
        let untouched: Overview = json(overview(&r, org_id, Role::Member).await).await;
        assert_eq!(untouched.policy.mode, Mode::Off);
        // Validation.
        let duplicate = set_policy(
            &r,
            org_id,
            Role::Owner,
            serde_json::json!({"mode":"prefer","rules":[
                {"tags":["office","store"],"mode":"require"},
                {"tags":["store","office"],"mode":"off"}
            ]}),
        )
        .await;
        assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
        let unknown = set_policy(
            &r,
            org_id,
            Role::Owner,
            serde_json::json!({"mode":"prefer","psk":"AAAA"}),
        )
        .await;
        assert!(unknown.status().is_client_error());
        let bad_mode = set_policy(
            &r,
            org_id,
            Role::Owner,
            serde_json::json!({"mode":"quantum-safe"}),
        )
        .await;
        assert!(bad_mode.status().is_client_error());
    }

    #[tokio::test]
    async fn agent_reports_are_validated_scoped_and_keyless() {
        let r = router().await;
        let org_id = org(&r, "pq-reports").await;
        let other = org(&r, "pq-elsewhere").await;
        let a = node(&r, org_id, "alpha").await;
        let b = node(&r, org_id, "bravo").await;
        let foreign = node(&r, other, "foreign").await;
        let uri = format!("/v1/nodes/{}/pq-state", a.id);
        let report =
            |peers: serde_json::Value| serde_json::json!({"capable": true, "peers": peers});
        let good = report(serde_json::json!([
            {"peer_id": b.id, "state":"established", "mode":"require", "algorithm": ALGORITHM,
             "epoch": 7, "last_rotation_at": now() - 30, "blocked": false, "reason": ""},
            {"peer_id": foreign.id, "state":"classical", "mode":"prefer"}
        ]));
        let wrong = call(&r, Method::PUT, &uri, good.clone(), Some("wrong".into())).await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        let ok = call(&r, Method::PUT, &uri, good, Some(a.node_token.clone())).await;
        assert_eq!(ok.status(), StatusCode::NO_CONTENT);
        // Key material has no field to land in: the whole report is refused.
        for rejected in [
            report(serde_json::json!([
                {"peer_id": b.id, "state":"established", "mode":"require", "psk":"c2VjcmV0"}
            ])),
            report(serde_json::json!([
                {"peer_id": b.id, "state":"quantum_safe", "mode":"require"}
            ])),
            report(serde_json::json!([
                {"peer_id": b.id, "state":"established", "mode":"require", "algorithm":"kyber-homebrew"}
            ])),
        ] {
            let response = call(&r, Method::PUT, &uri, rejected, Some(a.node_token.clone())).await;
            assert!(response.status().is_client_error(), "{}", response.status());
        }

        let response = overview(&r, org_id, Role::Auditor).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = text(response).await;
        assert_no_key_material(&body);
        let view: Overview = serde_json::from_str(&body).unwrap();
        // The cross-organisation peer id was dropped; the good row survived
        // the later rejected reports.
        assert_eq!(view.peers.len(), 1);
        let row = &view.peers[0];
        assert_eq!((row.node_id, row.peer_id), (a.id, b.id));
        assert_eq!(row.state, "established");
        assert_eq!(row.epoch, 7);
        assert_eq!(row.algorithm, ALGORITHM);
        assert!(row.rotated_seconds_ago.unwrap() >= 30);
        assert_eq!(row.peer_name, "bravo");
        // The other organisation sees none of it.
        let elsewhere: Overview = json(overview(&r, other, Role::Owner).await).await;
        assert!(elsewhere.peers.is_empty());
        assert!(elsewhere
            .devices
            .iter()
            .all(|device| device.id == foreign.id));
        // Per-device filter.
        let filtered: Overview = json(
            call(
                &r,
                Method::GET,
                &format!("/v1/orgs/{org_id}/post-quantum?node_id={}", b.id),
                serde_json::json!({}),
                console(org_id, Role::Member),
            )
            .await,
        )
        .await;
        assert!(filtered.peers.is_empty());
    }
}
