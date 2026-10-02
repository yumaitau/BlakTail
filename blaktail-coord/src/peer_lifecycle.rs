//! Peer detail, reversible suspension and the join-key (enrolment) inventory.
//!
//! Suspension is distinct from revoke and tombstone: a suspended node keeps its
//! identity, addresses, tags, routes and memberships, but is left out of every
//! peer map and cannot fetch updates or renew its credential until resumed.

use axum::{
    extract::{Path as UrlPath, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tracing::info;
use uuid::Uuid;

use crate::{
    append_audit, bump_control_revision, console_session, hash, load_audit_events, load_nodes, now,
    permissions::{require, Permission},
    webhooks, ApiError, AppState, AuditEvent, AuditQuery, NodeListQuery, NodeRow, Session,
    NODE_ONLINE_SECS,
};

/// Oldest agent release this coordinator is known to work with. Raise it in
/// the release that breaks compatibility and say so in docs/upgrades.md.
pub(crate) const MINIMUM_AGENT_VERSION: &str = "0.1.0";
const UPGRADE_GUIDE: &str = "docs/upgrades.md";
const MAX_JOIN_KEY_NAME_CHARS: usize = 64;
const MAX_JOIN_KEY_DESCRIPTION_CHARS: usize = 200;
const MAX_JOIN_KEY_USES: i64 = 10_000;
const MAX_SUSPEND_REASON_CHARS: usize = 200;
const TRANSPORTS: [&str; 3] = ["direct", "relay", "mixed"];

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/orgs/:org_id/nodes/:node_id", get(get_peer_detail))
        .route(
            "/v1/orgs/:org_id/nodes/:node_id/suspend",
            post(suspend_node),
        )
        .route("/v1/orgs/:org_id/nodes/:node_id/resume", post(resume_node))
        .route("/v1/orgs/:org_id/join-keys", get(list_join_keys))
        .route(
            "/v1/orgs/:org_id/join-keys/:key_id",
            delete(revoke_join_key),
        )
}

// ---------------------------------------------------------------------------
// Join keys

pub(crate) struct JoinKeyMetadata {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) max_uses: Option<i64>,
}

impl JoinKeyMetadata {
    pub(crate) fn validate(
        name: &str,
        description: &str,
        single_use: bool,
        max_uses: Option<i64>,
    ) -> Result<Self, ApiError> {
        let name = clean_text(name, "name", MAX_JOIN_KEY_NAME_CHARS)?;
        let description = clean_text(description, "description", MAX_JOIN_KEY_DESCRIPTION_CHARS)?;
        let max_uses = match (single_use, max_uses) {
            (true, None | Some(1)) => Some(1),
            (true, Some(_)) => {
                return Err(ApiError::BadRequest(
                    "a one-use key cannot set max_uses above 1".into(),
                ))
            }
            (false, Some(uses)) if !(1..=MAX_JOIN_KEY_USES).contains(&uses) => {
                return Err(ApiError::BadRequest(format!(
                    "max_uses must be between 1 and {MAX_JOIN_KEY_USES}"
                )))
            }
            (false, uses) => uses,
        };
        Ok(Self {
            name,
            description,
            max_uses,
        })
    }
}

fn clean_text(value: &str, field: &str, max_chars: usize) -> Result<String, ApiError> {
    let value = value.trim();
    if value.chars().count() > max_chars {
        return Err(ApiError::BadRequest(format!(
            "{field} must be at most {max_chars} characters"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field} cannot contain control characters"
        )));
    }
    Ok(value.to_owned())
}

/// Consumes one use of a join key. The limit check and the increment are one
/// conditional UPDATE, so concurrent enrolments cannot overspend a key on
/// either backend. Legacy one-use rows (no max_uses) are capped at one.
pub(crate) async fn claim_join_key(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    key_id: &str,
) -> Result<(), ApiError> {
    let current_time = now();
    let claimed = sqlx::query(
        "UPDATE join_keys SET use_count=use_count+1,used_at=COALESCE(used_at,$1),last_used_at=$1 \
         WHERE id=$2 AND revoked_at IS NULL AND expires_at>$1 \
         AND NOT (single_use=1 AND used_at IS NOT NULL) \
         AND (max_uses IS NULL OR use_count<max_uses) \
         AND (single_use=0 OR use_count<1)",
    )
    .bind(current_time)
    .bind(key_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if claimed != 1 {
        return Err(ApiError::Unauthorized);
    }
    Ok(())
}

/// Operator view of a join key. Deliberately has no secret or hash field.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct JoinKeySummary {
    id: Uuid,
    name: String,
    description: String,
    created_by: String,
    created_by_role: String,
    created_at: i64,
    expires_at: i64,
    single_use: bool,
    max_uses: Option<i64>,
    use_count: i64,
    remaining_uses: Option<i64>,
    last_used_at: Option<i64>,
    revoked_at: Option<i64>,
    tags: Vec<crate::DeviceTag>,
    state: String,
}

async fn list_join_keys(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<JoinKeySummary>>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    list_join_keys_as(&s, org_id, &session).await
}

/// Shared by the console route and `/api/v1/keys`.
pub(crate) async fn list_join_keys_as(
    s: &AppState,
    org_id: Uuid,
    session: &Session,
) -> Result<Json<Vec<JoinKeySummary>>, ApiError> {
    require(session, Permission::ManageJoinKeys)?;
    // Browser-approval grants share this table but are not operator keys. The
    // SQLite baseline declared the timestamp columns TEXT, hence the casts.
    let rows = sqlx::query(
        "SELECT k.id,k.name,k.description,k.user_id,k.user_role,CAST(k.created_at AS BIGINT),CAST(k.expires_at AS BIGINT),k.single_use,k.max_uses,k.use_count,k.last_used_at,CAST(k.revoked_at AS BIGINT),k.tags_json \
         FROM join_keys k WHERE k.org_id=$1 \
         AND NOT EXISTS(SELECT 1 FROM device_authorizations d WHERE d.device_code_hash=k.key_hash) \
         ORDER BY k.created_at DESC,k.id LIMIT 200",
    )
    .bind(org_id.to_string())
    .fetch_all(&s.store.pool)
    .await?;
    let current_time = now();
    let keys = rows
        .into_iter()
        .map(|row| {
            let id: String = row.try_get(0)?;
            let single_use = row.try_get::<i64, _>(7)? != 0;
            let max_uses: Option<i64> = row.try_get(8)?;
            let max_uses = if single_use { Some(1) } else { max_uses };
            let use_count: i64 = row.try_get(9)?;
            let expires_at: i64 = row.try_get(6)?;
            let revoked_at: Option<i64> = row.try_get(11)?;
            let remaining_uses = max_uses.map(|limit| (limit - use_count).max(0));
            let state = if revoked_at.is_some() {
                "revoked"
            } else if expires_at <= current_time {
                "expired"
            } else if remaining_uses == Some(0) {
                "used_up"
            } else {
                "active"
            };
            Ok::<_, ApiError>(JoinKeySummary {
                id: Uuid::parse_str(&id).map_err(|_| ApiError::CorruptData)?,
                name: row.try_get(1)?,
                description: row.try_get(2)?,
                created_by: row.try_get(3)?,
                created_by_role: row.try_get(4)?,
                created_at: row.try_get(5)?,
                expires_at,
                single_use,
                max_uses,
                use_count,
                remaining_uses,
                last_used_at: row.try_get(10)?,
                revoked_at,
                tags: serde_json::from_str(&row.try_get::<String, _>(12)?).unwrap_or_default(),
                state: state.into(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(keys))
}

async fn revoke_join_key(
    State(s): State<AppState>,
    UrlPath((org_id, key_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    revoke_join_key_as(&s, org_id, &session, key_id).await
}

/// Shared by the console route and `/api/v1/keys/{key_id}`.
pub(crate) async fn revoke_join_key_as(
    s: &AppState,
    org_id: Uuid,
    session: &Session,
    key_id: Uuid,
) -> Result<StatusCode, ApiError> {
    require(session, Permission::ManageJoinKeys)?;
    let mut tx = s.store.pool.begin().await?;
    let name: String = sqlx::query_scalar(
        "SELECT k.name FROM join_keys k WHERE k.id=$1 AND k.org_id=$2 \
         AND NOT EXISTS(SELECT 1 FROM device_authorizations d WHERE d.device_code_hash=k.key_hash)",
    )
    .bind(key_id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let changed = sqlx::query(
        "UPDATE join_keys SET revoked_at=$1 WHERE id=$2 AND org_id=$3 AND revoked_at IS NULL",
    )
    .bind(now())
    .bind(key_id.to_string())
    .bind(org_id.to_string())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        // Already revoked: idempotent, nothing new to audit.
        return Ok(StatusCode::NO_CONTENT);
    }
    append_audit(
        &mut tx,
        org_id,
        session,
        "join_key.revoked",
        "join_key",
        Some(&key_id.to_string()),
        &serde_json::json!({ "name": name }),
    )
    .await?;
    tx.commit().await?;
    info!(%key_id, %org_id, "join key revoked");
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Peer detail

/// Stores the agent's own summary of its WireGuard paths. Unknown values are
/// ignored so older or newer agents never fail a heartbeat over this field.
pub(crate) async fn record_transport(
    store: &crate::Store,
    node_id: Uuid,
    transport: Option<&str>,
) -> Result<(), ApiError> {
    let Some(transport) = transport.filter(|value| TRANSPORTS.contains(value)) else {
        return Ok(());
    };
    sqlx::query("UPDATE nodes SET transport=$1,transport_reported_at=$2 WHERE id=$3")
        .bind(transport)
        .bind(now())
        .bind(node_id.to_string())
        .execute(&store.pool)
        .await?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Heartbeat {
    /// `online`, `stale` or `never`, computed from coordinator time.
    state: String,
    last_seen_at: Option<i64>,
    age_seconds: Option<i64>,
    online_window_seconds: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Transport {
    /// `direct`, `relay`, `mixed` or `not_measured`.
    state: String,
    reported_at: Option<i64>,
    source: String,
    relay_endpoint: Option<String>,
    relay_endpoint_updated_at: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct VersionGuidance {
    agent_version: Option<String>,
    minimum_version: String,
    /// `supported`, `below_minimum` or `unknown`.
    status: String,
    upgrade_guide: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Lifecycle {
    /// `active`, `suspended`, `revoked` or `deleted`.
    state: String,
    suspended_at: Option<i64>,
    revoked_at: Option<i64>,
    deleted_at: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PeerDetail {
    node: NodeRow,
    server_time: i64,
    public_key_fingerprint: String,
    heartbeat: Heartbeat,
    transport: Transport,
    version: VersionGuidance,
    lifecycle: Lifecycle,
    audit: Vec<AuditEvent>,
}

async fn get_peer_detail(
    State(s): State<AppState>,
    UrlPath((org_id, node_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<PeerDetail>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewNetwork)?;
    let query = NodeListQuery {
        q: Some(node_id.to_string()),
        include_deleted: Some(true),
        ..NodeListQuery::default()
    };
    let node = load_nodes(&s.store, org_id, &query)
        .await?
        .into_iter()
        .find(|node| node.id == node_id)
        .ok_or(ApiError::NotFound)?;
    let row = sqlx::query(
        "SELECT suspended_at,revoked_at,deleted_at,transport,transport_reported_at,relay_endpoint,relay_endpoint_updated_at FROM nodes WHERE id=$1 AND org_id=$2",
    )
    .bind(node_id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&s.store.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let suspended_at: Option<i64> = row.try_get(0)?;
    let revoked_at: Option<i64> = row.try_get(1)?;
    let deleted_at: Option<i64> = row.try_get(2)?;
    let transport: Option<String> = row.try_get(3)?;
    let transport_reported_at: Option<i64> = row.try_get(4)?;
    let server_time = now();

    let audit = if session.role.can(Permission::ViewAudit) {
        load_audit_events(
            &s.store,
            org_id,
            &AuditQuery {
                limit: Some(20),
                target_id: Some(node_id.to_string()),
                ..AuditQuery::default()
            },
        )
        .await?
    } else {
        Vec::new()
    };

    Ok(Json(PeerDetail {
        public_key_fingerprint: hash(&node.wg_public_key)[..12].into(),
        heartbeat: heartbeat(node.last_seen_at, server_time),
        transport: Transport {
            state: transport
                .filter(|value| TRANSPORTS.contains(&value.as_str()))
                .unwrap_or_else(|| "not_measured".into()),
            reported_at: transport_reported_at,
            source: "agent".into(),
            relay_endpoint: row.try_get(5)?,
            relay_endpoint_updated_at: row.try_get(6)?,
        },
        version: version_guidance(node.agent_version.as_deref()),
        lifecycle: Lifecycle {
            state: if deleted_at.is_some() {
                "deleted"
            } else if revoked_at.is_some() {
                "revoked"
            } else if suspended_at.is_some() {
                "suspended"
            } else {
                "active"
            }
            .into(),
            suspended_at,
            revoked_at,
            deleted_at,
        },
        node,
        server_time,
        audit,
    }))
}

fn heartbeat(last_seen_at: Option<i64>, server_time: i64) -> Heartbeat {
    let age = last_seen_at.map(|seen| (server_time - seen).max(0));
    Heartbeat {
        state: match age {
            None => "never",
            Some(age) if age <= NODE_ONLINE_SECS => "online",
            Some(_) => "stale",
        }
        .into(),
        last_seen_at,
        age_seconds: age,
        online_window_seconds: NODE_ONLINE_SECS,
    }
}

fn parse_version(value: &str) -> Option<(u64, u64, u64)> {
    let core = value.trim().trim_start_matches('v');
    let core = core.split(['-', '+', ' ']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

fn version_guidance(agent_version: Option<&str>) -> VersionGuidance {
    let minimum = parse_version(MINIMUM_AGENT_VERSION).expect("valid minimum agent version");
    let status = match agent_version.and_then(parse_version) {
        Some(version) if version < minimum => "below_minimum",
        Some(_) => "supported",
        None => "unknown",
    };
    VersionGuidance {
        agent_version: agent_version.map(str::to_owned),
        minimum_version: MINIMUM_AGENT_VERSION.into(),
        status: status.into(),
        upgrade_guide: UPGRADE_GUIDE.into(),
    }
}

// ---------------------------------------------------------------------------
// Suspend / resume

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuspendRequest {
    #[serde(default)]
    reason: String,
}

async fn suspend_node(
    State(s): State<AppState>,
    UrlPath((org_id, node_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(body): Json<SuspendRequest>,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManagePeers)?;
    let reason = clean_text(&body.reason, "reason", MAX_SUSPEND_REASON_CHARS)?;
    set_suspended(&s, org_id, node_id, &session, Some(reason)).await
}

async fn resume_node(
    State(s): State<AppState>,
    UrlPath((org_id, node_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManagePeers)?;
    set_suspended(&s, org_id, node_id, &session, None).await
}

/// `reason` is `Some` to suspend and `None` to resume.
async fn set_suspended(
    s: &AppState,
    org_id: Uuid,
    node_id: Uuid,
    session: &crate::Session,
    reason: Option<String>,
) -> Result<StatusCode, ApiError> {
    let suspend = reason.is_some();
    let mut tx = s.store.pool.begin().await?;
    let current = sqlx::query(
        "SELECT name,CASE WHEN suspended_at IS NULL THEN 0 ELSE 1 END,CASE WHEN revoked_at IS NULL AND deleted_at IS NULL THEN 0 ELSE 1 END,approved_routes_json FROM nodes WHERE id=$1 AND org_id=$2",
    )
    .bind(node_id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let technical_name: String = current.try_get(0)?;
    let suspended = current.try_get::<i64, _>(1)? != 0;
    let ended = current.try_get::<i64, _>(2)? != 0;
    let approved_routes: Vec<String> =
        serde_json::from_str(&current.try_get::<String, _>(3)?).unwrap_or_default();
    if ended {
        return Err(ApiError::Conflict(
            "revoked or deleted devices cannot be suspended or resumed".into(),
        ));
    }
    if suspended == suspend {
        return Err(ApiError::Conflict(if suspend {
            "device is already suspended".into()
        } else {
            "device is not suspended".into()
        }));
    }
    let sql = if suspend {
        "UPDATE nodes SET suspended_at=$1 WHERE id=$2 AND org_id=$3 AND suspended_at IS NULL AND revoked_at IS NULL AND deleted_at IS NULL"
    } else {
        "UPDATE nodes SET suspended_at=NULL WHERE id=$2 AND org_id=$3 AND suspended_at IS NOT NULL AND revoked_at IS NULL AND deleted_at IS NULL AND $1>0"
    };
    let changed = sqlx::query(sql)
        .bind(now())
        .bind(node_id.to_string())
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if changed != 1 {
        return Err(ApiError::Conflict(
            "device state changed; reload and try again".into(),
        ));
    }
    bump_control_revision(&mut tx, org_id.to_string()).await?;
    let certificates_revoked = if suspend {
        crate::private_services::revoke_node_certificates(&mut tx, org_id, node_id).await?
    } else {
        0
    };
    let (action, event) = if suspend {
        ("node.suspended", "device.suspended")
    } else {
        ("node.resumed", "device.resumed")
    };
    let mut details = serde_json::json!({
        "technical_name": technical_name,
        "approved_routes": approved_routes,
    });
    if certificates_revoked > 0 {
        details["service_certificates_revoked"] = certificates_revoked.into();
    }
    if let Some(reason) = reason.filter(|reason| !reason.is_empty()) {
        details["reason"] = reason.into();
    }
    append_audit(
        &mut tx,
        org_id,
        session,
        action,
        "node",
        Some(&node_id.to_string()),
        &details,
    )
    .await?;
    webhooks::enqueue(
        &mut tx,
        org_id,
        event,
        &serde_json::json!({ "device_id": node_id }),
    )
    .await?;
    tx.commit().await?;
    info!(%node_id, %org_id, suspend, "node suspension changed");
    Ok(StatusCode::NO_CONTENT)
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

    const SECRET: &[u8] = b"peer-lifecycle-test-secret-32-bytes!!";

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
            email: String::new(),
            iss: CONSOLE_ASSERTION_ISSUER.into(),
            aud: CONSOLE_ASSERTION_AUDIENCE.into(),
            iat,
            exp: iat + MAX_CONSOLE_ASSERTION_LIFETIME_SECS,
            jti: Uuid::new_v4().to_string(),
            action: action.map(str::to_owned),
        }
    }

    /// Fresh single-use assertion per request (the coordinator rejects replays).
    #[derive(Clone, Copy)]
    struct As(Uuid, Role);

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

    fn console(who: As) -> Option<String> {
        Some(sign(claims(who.0, "user-1", who.1.as_str(), None)))
    }

    async fn json<T: serde::de::DeserializeOwned>(response: Response) -> T {
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!("{status}: {error}: {}", String::from_utf8_lossy(&bytes))
        })
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

    async fn mint(router: &Router, org_id: Uuid, body: serde_json::Value) -> JoinKeyResponse {
        let response = call(
            router,
            Method::POST,
            &format!("/v1/orgs/{org_id}/join-keys"),
            body,
            console(As(org_id, Role::Owner)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        json(response).await
    }

    async fn register(router: &Router, key: &str, name: &str) -> Response {
        call(
            router,
            Method::POST,
            "/v1/nodes/register",
            serde_json::json!({"join_key":key,"name":name,"wg_public_key":format!("{name}-key")}),
            None,
        )
        .await
    }

    async fn node(router: &Router, org_id: Uuid, name: &str) -> RegisterResponse {
        let key = mint(router, org_id, serde_json::json!({"expires_in_seconds":60})).await;
        let response = register(router, &key.key, name).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        json(response).await
    }

    async fn peers(router: &Router, node: &RegisterResponse) -> Response {
        call(
            router,
            Method::GET,
            &format!("/v1/nodes/{}/peers", node.id),
            serde_json::json!({}),
            Some(node.node_token.clone()),
        )
        .await
    }

    fn peer_ids(value: &serde_json::Value) -> Vec<String> {
        value["peers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|peer| peer["id"].as_str().unwrap().to_owned())
            .collect()
    }

    async fn router() -> Router {
        app(
            Store::memory().await.unwrap(),
            "ap-southeast-2".into(),
            SECRET,
        )
    }

    #[tokio::test]
    async fn suspended_peer_leaves_maps_and_resume_restores_it() {
        let r = router().await;
        let org_id = org(&r, "suspend-org").await;
        let a = node(&r, org_id, "alpha").await;
        let b = node(&r, org_id, "bravo").await;
        let seen: serde_json::Value = json(peers(&r, &a).await).await;
        assert_eq!(peer_ids(&seen), vec![b.id.to_string()]);

        let suspended = call(
            &r,
            Method::POST,
            &format!("/v1/orgs/{org_id}/nodes/{}/suspend", b.id),
            serde_json::json!({"reason":"lost tablet"}),
            console(As(org_id, Role::Admin)),
        )
        .await;
        assert_eq!(suspended.status(), StatusCode::NO_CONTENT);

        let seen: serde_json::Value = json(peers(&r, &a).await).await;
        assert!(peer_ids(&seen).is_empty(), "suspended peer must leave maps");
        let blocked = peers(&r, &b).await;
        assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
        let blocked: serde_json::Value = json(blocked).await;
        assert_eq!(blocked["code"], "suspended");
        let updates = call(
            &r,
            Method::GET,
            &format!("/v1/nodes/{}/updates?since=0", b.id),
            serde_json::json!({}),
            Some(b.node_token.clone()),
        )
        .await;
        assert_eq!(updates.status(), StatusCode::FORBIDDEN);
        let refresh_key = mint(&r, org_id, serde_json::json!({"expires_in_seconds":60})).await;
        let reauth = call(
            &r,
            Method::POST,
            &format!("/v1/nodes/{}/reauth", b.id),
            serde_json::json!({"join_key":refresh_key.key}),
            Some(b.node_token.clone()),
        )
        .await;
        assert_eq!(reauth.status(), StatusCode::FORBIDDEN);

        let detail: PeerDetail = json(
            call(
                &r,
                Method::GET,
                &format!("/v1/orgs/{org_id}/nodes/{}", b.id),
                serde_json::json!({}),
                console(As(org_id, Role::Member)),
            )
            .await,
        )
        .await;
        assert_eq!(detail.lifecycle.state, "suspended");
        assert!(detail.node.suspended);
        assert!(detail
            .audit
            .iter()
            .any(|event| event.action == "node.suspended"));

        let again = call(
            &r,
            Method::POST,
            &format!("/v1/orgs/{org_id}/nodes/{}/suspend", b.id),
            serde_json::json!({}),
            console(As(org_id, Role::Owner)),
        )
        .await;
        assert_eq!(again.status(), StatusCode::CONFLICT);

        let resumed = call(
            &r,
            Method::POST,
            &format!("/v1/orgs/{org_id}/nodes/{}/resume", b.id),
            serde_json::json!({}),
            console(As(org_id, Role::Owner)),
        )
        .await;
        assert_eq!(resumed.status(), StatusCode::NO_CONTENT);
        let seen: serde_json::Value = json(peers(&r, &a).await).await;
        assert_eq!(peer_ids(&seen), vec![b.id.to_string()]);
        let back: serde_json::Value = json(peers(&r, &b).await).await;
        assert_eq!(back["dns_name"], b.dns_name.as_str());
        assert_eq!(back["assigned_ips"][0], b.assigned_ip.as_str());
    }

    #[tokio::test]
    async fn suspended_or_expired_node_cannot_change_its_own_state() {
        let store = Store::memory().await.unwrap();
        let r = app(store.clone(), "ap-southeast-2".into(), SECRET);
        let org_id = org(&r, "suspend-writes-org").await;
        let a = node(&r, org_id, "alpha").await;
        let suspended = call(
            &r,
            Method::POST,
            &format!("/v1/orgs/{org_id}/nodes/{}/suspend", a.id),
            serde_json::json!({}),
            console(As(org_id, Role::Admin)),
        )
        .await;
        assert_eq!(suspended.status(), StatusCode::NO_CONTENT);
        for (path, body) in [
            (
                "routes",
                serde_json::json!({"advertised_routes": ["10.9.0.0/24"]}),
            ),
            ("shares", serde_json::json!({"shares": []})),
            (
                "relay-endpoint",
                serde_json::json!({"endpoint": "203.0.113.5:41641"}),
            ),
        ] {
            let response = call(
                &r,
                Method::PUT,
                &format!("/v1/nodes/{}/{path}", a.id),
                body,
                Some(a.node_token.clone()),
            )
            .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
            let error: serde_json::Value = json(response).await;
            assert_eq!(error["code"], "suspended", "{path}");
        }

        // An expired credential cannot refresh reported inventory through
        // the update stream.
        let b = node(&r, org_id, "bravo").await;
        let pool = &store.pool;
        sqlx::query("UPDATE nodes SET credential_expires_at=$1 WHERE id=$2")
            .bind(now() - 1)
            .bind(b.id.to_string())
            .execute(pool)
            .await
            .unwrap();
        let updates = call(
            &r,
            Method::GET,
            &format!(
                "/v1/nodes/{}/updates?since=0&capabilities=forward-filter&agent_version=9.9.9",
                b.id
            ),
            serde_json::json!({}),
            Some(b.node_token.clone()),
        )
        .await;
        assert!(updates.status().is_client_error(), "{}", updates.status());
        let agent: Option<String> =
            sqlx::query_scalar("SELECT agent_version FROM nodes WHERE id=$1")
                .bind(b.id.to_string())
                .fetch_one(pool)
                .await
                .unwrap();
        assert_ne!(agent.as_deref(), Some("9.9.9"));
    }

    #[tokio::test]
    async fn suspend_rejects_members_wrong_org_and_revoked_nodes() {
        let r = router().await;
        let org_id = org(&r, "home-org").await;
        let other = org(&r, "other-org").await;
        let device = node(&r, org_id, "charlie").await;
        let path = |org: Uuid| format!("/v1/orgs/{org}/nodes/{}/suspend", device.id);

        let member = call(
            &r,
            Method::POST,
            &path(org_id),
            serde_json::json!({}),
            console(As(org_id, Role::Member)),
        )
        .await;
        assert_eq!(member.status(), StatusCode::FORBIDDEN);
        let wrong_org = call(
            &r,
            Method::POST,
            &path(other),
            serde_json::json!({}),
            console(As(other, Role::Owner)),
        )
        .await;
        assert_eq!(wrong_org.status(), StatusCode::NOT_FOUND);
        let forged = call(
            &r,
            Method::POST,
            &path(org_id),
            serde_json::json!({}),
            console(As(other, Role::Owner)),
        )
        .await;
        assert_eq!(forged.status(), StatusCode::UNAUTHORIZED);
        let detail_wrong_org = call(
            &r,
            Method::GET,
            &format!("/v1/orgs/{other}/nodes/{}", device.id),
            serde_json::json!({}),
            console(As(other, Role::Owner)),
        )
        .await;
        assert_eq!(detail_wrong_org.status(), StatusCode::NOT_FOUND);
        let member_resume = call(
            &r,
            Method::POST,
            &format!("/v1/orgs/{org_id}/nodes/{}/resume", device.id),
            serde_json::json!({}),
            console(As(org_id, Role::Member)),
        )
        .await;
        assert_eq!(member_resume.status(), StatusCode::FORBIDDEN);

        let revoked = call(
            &r,
            Method::DELETE,
            &format!("/v1/orgs/{org_id}/nodes/{}", device.id),
            serde_json::json!({}),
            console(As(org_id, Role::Owner)),
        )
        .await;
        assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
        let after_revoke = call(
            &r,
            Method::POST,
            &path(org_id),
            serde_json::json!({}),
            console(As(org_id, Role::Owner)),
        )
        .await;
        assert_eq!(after_revoke.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn detail_reports_heartbeat_transport_and_version() {
        let r = router().await;
        let org_id = org(&r, "detail-org").await;
        let device = node(&r, org_id, "delta").await;
        let detail = |r: Router| async move {
            json::<PeerDetail>(
                call(
                    &r,
                    Method::GET,
                    &format!("/v1/orgs/{org_id}/nodes/{}", device.id),
                    serde_json::json!({}),
                    console(As(org_id, Role::Member)),
                )
                .await,
            )
            .await
        };
        let first = detail(r.clone()).await;
        assert_eq!(first.transport.state, "not_measured");
        assert_eq!(first.heartbeat.state, "online");
        assert_eq!(first.version.status, "unknown");
        assert_eq!(first.public_key_fingerprint.len(), 12);

        let reported = call(
            &r,
            Method::GET,
            &format!("/v1/nodes/{}/peers?transport=relay", device.id),
            serde_json::json!({}),
            Some(device.node_token.clone()),
        )
        .await;
        assert_eq!(reported.status(), StatusCode::OK);
        let bogus = call(
            &r,
            Method::GET,
            &format!("/v1/nodes/{}/peers?transport=teleport", device.id),
            serde_json::json!({}),
            Some(device.node_token.clone()),
        )
        .await;
        assert_eq!(bogus.status(), StatusCode::OK);
        let second = detail(r.clone()).await;
        assert_eq!(second.transport.state, "relay");
        assert!(second.transport.reported_at.is_some());
    }

    #[test]
    fn heartbeat_and_version_rules() {
        assert_eq!(heartbeat(None, 1_000).state, "never");
        assert_eq!(
            heartbeat(Some(1_000 - NODE_ONLINE_SECS), 1_000).state,
            "online"
        );
        assert_eq!(
            heartbeat(Some(1_000 - NODE_ONLINE_SECS - 1), 1_000).state,
            "stale"
        );
        assert_eq!(version_guidance(Some("0.0.9")).status, "below_minimum");
        assert_eq!(version_guidance(Some("v0.1.0-dev")).status, "supported");
        assert_eq!(version_guidance(Some("ios-build")).status, "unknown");
        assert_eq!(version_guidance(None).status, "unknown");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn one_use_and_reusable_keys_hold_their_limits_under_concurrency() {
        let r = router().await;
        let org_id = org(&r, "keys-org").await;
        let one_use = mint(
            &r,
            org_id,
            serde_json::json!({"expires_in_seconds":60,"name":"Office iMac"}),
        )
        .await;
        let (left, right) = tokio::join!(
            register(&r, &one_use.key, "race-a"),
            register(&r, &one_use.key, "race-b")
        );
        let created = [left.status(), right.status()]
            .iter()
            .filter(|status| **status == StatusCode::CREATED)
            .count();
        assert_eq!(created, 1, "one-use key must enrol exactly one node");

        let reusable = mint(
            &r,
            org_id,
            serde_json::json!({"expires_in_seconds":60,"single_use":false,"max_uses":3,"name":"Ranger fleet"}),
        )
        .await;
        assert_eq!(reusable.max_uses, Some(3));
        let attempts = (0..8).map(|index| {
            let r = r.clone();
            let key = reusable.key.clone();
            tokio::spawn(
                async move { register(&r, &key, &format!("fleet-{index}")).await.status() },
            )
        });
        let mut statuses = Vec::new();
        for attempt in attempts {
            statuses.push(attempt.await.unwrap());
        }
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::CREATED)
                .count(),
            3
        );
        assert!(statuses
            .iter()
            .all(|status| *status == StatusCode::CREATED || *status == StatusCode::UNAUTHORIZED));

        let keys: Vec<serde_json::Value> = json(
            call(
                &r,
                Method::GET,
                &format!("/v1/orgs/{org_id}/join-keys"),
                serde_json::json!({}),
                console(As(org_id, Role::Admin)),
            )
            .await,
        )
        .await;
        let fleet = keys
            .iter()
            .find(|key| key["name"] == "Ranger fleet")
            .unwrap();
        assert_eq!(fleet["use_count"], 3);
        assert_eq!(fleet["remaining_uses"], 0);
        assert_eq!(fleet["state"], "used_up");
        assert!(fleet["last_used_at"].is_i64());
        let office = keys
            .iter()
            .find(|key| key["name"] == "Office iMac")
            .unwrap();
        assert_eq!(office["max_uses"], 1);
        assert_eq!(office["use_count"], 1);
        // Inventory never exposes a secret or its hash.
        let text = serde_json::to_string(&keys).unwrap();
        assert!(!text.contains(&one_use.key) && !text.contains(&reusable.key));
        assert!(!text.contains(&hash(&one_use.key)) && !text.contains(&hash(&reusable.key)));
        assert!(keys.iter().all(|key| key.get("key").is_none()
            && key.get("key_hash").is_none()
            && key.get("hash").is_none()));
    }

    #[tokio::test]
    async fn key_validation_revocation_member_and_wrong_org() {
        let r = router().await;
        let org_id = org(&r, "revoke-org").await;
        let other = org(&r, "foreign-org").await;
        for invalid in [
            serde_json::json!({"single_use":true,"max_uses":5}),
            serde_json::json!({"single_use":false,"max_uses":0}),
            serde_json::json!({"name":"x".repeat(65)}),
            serde_json::json!({"name":"bad\nname"}),
        ] {
            let response = call(
                &r,
                Method::POST,
                &format!("/v1/orgs/{org_id}/join-keys"),
                invalid,
                console(As(org_id, Role::Owner)),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        let member_mint = call(
            &r,
            Method::POST,
            &format!("/v1/orgs/{org_id}/join-keys"),
            serde_json::json!({}),
            console(As(org_id, Role::Member)),
        )
        .await;
        assert_eq!(member_mint.status(), StatusCode::FORBIDDEN);
        let member_list = call(
            &r,
            Method::GET,
            &format!("/v1/orgs/{org_id}/join-keys"),
            serde_json::json!({}),
            console(As(org_id, Role::Member)),
        )
        .await;
        assert_eq!(member_list.status(), StatusCode::FORBIDDEN);

        let key = mint(&r, org_id, serde_json::json!({"single_use":false})).await;
        let wrong_org = call(
            &r,
            Method::DELETE,
            &format!("/v1/orgs/{other}/join-keys/{}", key.id),
            serde_json::json!({}),
            console(As(other, Role::Owner)),
        )
        .await;
        assert_eq!(wrong_org.status(), StatusCode::NOT_FOUND);
        let member_revoke = call(
            &r,
            Method::DELETE,
            &format!("/v1/orgs/{org_id}/join-keys/{}", key.id),
            serde_json::json!({}),
            console(As(org_id, Role::Member)),
        )
        .await;
        assert_eq!(member_revoke.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            register(&r, &key.key, "before-revoke").await.status(),
            StatusCode::CREATED
        );
        let revoked = call(
            &r,
            Method::DELETE,
            &format!("/v1/orgs/{org_id}/join-keys/{}", key.id),
            serde_json::json!({}),
            console(As(org_id, Role::Admin)),
        )
        .await;
        assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            register(&r, &key.key, "after-revoke").await.status(),
            StatusCode::UNAUTHORIZED
        );
        let foreign: Vec<serde_json::Value> = json(
            call(
                &r,
                Method::GET,
                &format!("/v1/orgs/{other}/join-keys"),
                serde_json::json!({}),
                console(As(other, Role::Owner)),
            )
            .await,
        )
        .await;
        assert!(foreign.is_empty(), "keys never leak across organisations");

        // A key from another organisation cannot renew this org's node.
        let device = node(&r, org_id, "home-node").await;
        let foreign_key = mint(&r, other, serde_json::json!({"single_use":false})).await;
        let reauth = call(
            &r,
            Method::POST,
            &format!("/v1/nodes/{}/reauth", device.id),
            serde_json::json!({"join_key":foreign_key.key}),
            Some(device.node_token.clone()),
        )
        .await;
        assert_eq!(reauth.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoked_and_expired_keys_stay_rejected_after_restart() {
        let path = std::env::temp_dir().join(format!("blaktail-keys-{}.db", Uuid::new_v4()));
        let (org_id, revoked_key, expiring_key) = {
            let store = Store::open(&path).await.unwrap();
            let r = app(store.clone(), "ap-southeast-2".into(), SECRET);
            let org_id = org(&r, "restart-org").await;
            let revoked_key = mint(&r, org_id, serde_json::json!({"single_use":false})).await;
            let expiring_key = mint(&r, org_id, serde_json::json!({"expires_in_seconds":1})).await;
            let revoked = call(
                &r,
                Method::DELETE,
                &format!("/v1/orgs/{org_id}/join-keys/{}", revoked_key.id),
                serde_json::json!({}),
                console(As(org_id, Role::Owner)),
            )
            .await;
            assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
            // Only the SHA-256 of a secret is ever stored.
            let stored: Vec<String> = sqlx::query_scalar("SELECT key_hash FROM join_keys")
                .fetch_all(&store.pool)
                .await
                .unwrap();
            assert!(stored.contains(&hash(&revoked_key.key)));
            assert!(!stored.contains(&revoked_key.key) && !stored.contains(&expiring_key.key));
            store.pool.close().await;
            (org_id, revoked_key, expiring_key)
        };
        tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
        let store = Store::open_existing(&path).await.unwrap();
        let r = app(store.clone(), "ap-southeast-2".into(), SECRET);
        assert_eq!(
            register(&r, &revoked_key.key, "zombie").await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            register(&r, &expiring_key.key, "late").await.status(),
            StatusCode::UNAUTHORIZED
        );
        let keys: Vec<serde_json::Value> = json(
            call(
                &r,
                Method::GET,
                &format!("/v1/orgs/{org_id}/join-keys"),
                serde_json::json!({}),
                console(As(org_id, Role::Owner)),
            )
            .await,
        )
        .await;
        let states: Vec<_> = keys
            .iter()
            .map(|key| key["state"].as_str().unwrap())
            .collect();
        assert!(states.contains(&"revoked") && states.contains(&"expired"));
        store.pool.close().await;
        let _ = std::fs::remove_file(&path);
    }
}
