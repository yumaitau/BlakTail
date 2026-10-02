use crate::{
    append_audit, bump_control_revision, canonical_ipv4_route, conflict, console_session,
    ipv4_route_is_within, ipv4_routes_overlap, now, ApiError, AppState, DeviceTag, Session,
};
use axum::{
    extract::{Path as UrlPath, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use uuid::Uuid;

pub(crate) const KIND: &str = "wireguard_only";
const MAX_ALLOWED_IPS: usize = 8;
const MAX_NAME_CHARS: usize = 64;
const MIN_OVERLAP_SECS: i64 = 15;
const MAX_OVERLAP_SECS: i64 = 86_400;
const DEFAULT_OVERLAP_SECS: i64 = 300;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateWireGuardOnlyPeer {
    name: String,
    kind: String,
    wg_public_key: String,
    endpoint: String,
    allowed_ips: Vec<String>,
    #[serde(default)]
    tags: Vec<DeviceTag>,
    #[serde(default)]
    expires_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RotateWireGuardOnlyPeer {
    wg_public_key: String,
    #[serde(default)]
    overlap_seconds: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WireGuardOnlyPeer {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub wg_public_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub tags: Vec<DeviceTag>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub revision: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_wg_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlap_until: Option<i64>,
}

pub(crate) async fn list_console(
    State(state): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<WireGuardOnlyPeer>>, ApiError> {
    let _session = console_session(&state, &headers, org_id).await?;
    Ok(Json(list_peers(&state, org_id).await?))
}

pub(crate) async fn create_console(
    State(state): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<CreateWireGuardOnlyPeer>,
) -> Result<(StatusCode, Json<WireGuardOnlyPeer>), ApiError> {
    let session = console_session(&state, &headers, org_id).await?;
    require_writer(&session)?;
    let peer = insert_peer(&state, org_id, &session, input).await?;
    Ok((StatusCode::CREATED, Json(peer)))
}

pub(crate) async fn get_console(
    State(state): State<AppState>,
    UrlPath((org_id, peer_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<WireGuardOnlyPeer>, ApiError> {
    let _session = console_session(&state, &headers, org_id).await?;
    Ok(Json(load_peer(&state, org_id, peer_id).await?))
}

pub(crate) async fn revoke_console(
    State(state): State<AppState>,
    UrlPath((org_id, peer_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&state, &headers, org_id).await?;
    require_writer(&session)?;
    revoke_peer(&state, org_id, peer_id, &session).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn rotate_console(
    State(state): State<AppState>,
    UrlPath((org_id, peer_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<RotateWireGuardOnlyPeer>,
) -> Result<Json<WireGuardOnlyPeer>, ApiError> {
    let session = console_session(&state, &headers, org_id).await?;
    require_writer(&session)?;
    Ok(Json(
        rotate_peer(&state, org_id, peer_id, &session, input).await?,
    ))
}

pub(crate) async fn list_for_org(
    state: &AppState,
    org_id: Uuid,
) -> Result<Vec<WireGuardOnlyPeer>, ApiError> {
    list_peers(state, org_id).await
}

pub(crate) async fn create_for_org(
    state: &AppState,
    org_id: Uuid,
    session: &Session,
    input: CreateWireGuardOnlyPeer,
) -> Result<WireGuardOnlyPeer, ApiError> {
    insert_peer(state, org_id, session, input).await
}

pub(crate) async fn get_for_org(
    state: &AppState,
    org_id: Uuid,
    peer_id: Uuid,
) -> Result<WireGuardOnlyPeer, ApiError> {
    load_peer(state, org_id, peer_id).await
}

pub(crate) async fn revoke_for_org(
    state: &AppState,
    org_id: Uuid,
    peer_id: Uuid,
    session: &Session,
) -> Result<(), ApiError> {
    revoke_peer(state, org_id, peer_id, session).await
}

pub(crate) async fn rotate_for_org(
    state: &AppState,
    org_id: Uuid,
    peer_id: Uuid,
    session: &Session,
    input: RotateWireGuardOnlyPeer,
) -> Result<WireGuardOnlyPeer, ApiError> {
    rotate_peer(state, org_id, peer_id, session, input).await
}

fn require_writer(session: &Session) -> Result<(), ApiError> {
    crate::permissions::require(session, crate::permissions::Permission::ManagePeers)
}

async fn insert_peer(
    state: &AppState,
    org_id: Uuid,
    session: &Session,
    input: CreateWireGuardOnlyPeer,
) -> Result<WireGuardOnlyPeer, ApiError> {
    if input.kind != KIND {
        return Err(ApiError::BadRequest(
            "kind must be stored as wireguard_only".into(),
        ));
    }
    let name = validate_name(&input.name)?;
    let wg_public_key = validate_public_key(&input.wg_public_key)?;
    let endpoint = validate_endpoint(&input.endpoint)?;
    let allowed_ips = validate_allowed_ips(input.allowed_ips)?;
    let tags = crate::canonical_tags(input.tags);
    if input.expires_at.is_some_and(|expires| expires <= now()) {
        return Err(ApiError::BadRequest(
            "expires_at must be in the future".into(),
        ));
    }
    let mut tx = state.store.pool.begin().await?;
    let org_exists: Option<String> = sqlx::query_scalar("SELECT id FROM orgs WHERE id=$1")
        .bind(org_id.to_string())
        .fetch_optional(&mut *tx)
        .await?;
    if org_exists.is_none() {
        return Err(ApiError::NotFound);
    }
    let node_name_taken: Option<String> = sqlx::query_scalar(
        "SELECT id FROM nodes WHERE org_id=$1 AND name=$2 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(org_id.to_string())
    .bind(&name)
    .fetch_optional(&mut *tx)
    .await?;
    if node_name_taken.is_some() {
        return Err(ApiError::Conflict(
            "a managed node already uses that name".into(),
        ));
    }
    let node_key_taken: Option<String> = sqlx::query_scalar(
        "SELECT id FROM nodes WHERE org_id=$1 AND wg_public_key=$2 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(org_id.to_string())
    .bind(&wg_public_key)
    .fetch_optional(&mut *tx)
    .await?;
    if node_key_taken.is_some() {
        return Err(ApiError::Conflict(
            "a managed node already uses that public key".into(),
        ));
    }
    let id = Uuid::new_v4();
    let created_at = now();
    sqlx::query(
        "INSERT INTO wireguard_only_peers(id,org_id,name,kind,wg_public_key,endpoint,allowed_ips_json,tags_json,created_at,expires_at,revision)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1)",
    )
    .bind(id.to_string())
    .bind(org_id.to_string())
    .bind(&name)
    .bind(KIND)
    .bind(&wg_public_key)
    .bind(&endpoint)
    .bind(serde_json::to_string(&allowed_ips).unwrap())
    .bind(serde_json::to_string(&tags).unwrap())
    .bind(created_at)
    .bind(input.expires_at)
    .execute(&mut *tx)
    .await
    .map_err(conflict("wireguard-only peer name or public key already exists"))?;
    bump_control_revision(&mut tx, org_id.to_string()).await?;
    append_audit(
        &mut tx,
        org_id,
        session,
        "wireguard_only.created",
        "wireguard_only_peer",
        Some(&id.to_string()),
        &serde_json::json!({
            "name": name,
            "kind": KIND,
            "endpoint": endpoint,
            "allowed_ips": allowed_ips,
            "tags": tags,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(WireGuardOnlyPeer {
        id,
        name,
        kind: KIND.into(),
        wg_public_key,
        endpoint,
        allowed_ips,
        tags,
        created_at,
        expires_at: input.expires_at,
        revoked_at: None,
        revision: 1,
        previous_wg_public_key: None,
        overlap_until: None,
    })
}

async fn list_peers(state: &AppState, org_id: Uuid) -> Result<Vec<WireGuardOnlyPeer>, ApiError> {
    let rows = sqlx::query(
        "SELECT id,name,kind,wg_public_key,endpoint,allowed_ips_json,tags_json,created_at,expires_at,revoked_at,revision,previous_wg_public_key,overlap_until
         FROM wireguard_only_peers WHERE org_id=$1 ORDER BY name",
    )
    .bind(org_id.to_string())
    .fetch_all(&state.store.pool)
    .await?;
    rows.into_iter().map(row_to_peer).collect()
}

async fn load_peer(
    state: &AppState,
    org_id: Uuid,
    peer_id: Uuid,
) -> Result<WireGuardOnlyPeer, ApiError> {
    let row = sqlx::query(
        "SELECT id,name,kind,wg_public_key,endpoint,allowed_ips_json,tags_json,created_at,expires_at,revoked_at,revision,previous_wg_public_key,overlap_until
         FROM wireguard_only_peers WHERE id=$1 AND org_id=$2",
    )
    .bind(peer_id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&state.store.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    row_to_peer(row)
}

async fn revoke_peer(
    state: &AppState,
    org_id: Uuid,
    peer_id: Uuid,
    session: &Session,
) -> Result<(), ApiError> {
    let mut tx = state.store.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE wireguard_only_peers SET revoked_at=$1, revision=revision+1
         WHERE id=$2 AND org_id=$3 AND revoked_at IS NULL",
    )
    .bind(now())
    .bind(peer_id.to_string())
    .bind(org_id.to_string())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        let exists: Option<String> =
            sqlx::query_scalar("SELECT id FROM wireguard_only_peers WHERE id=$1 AND org_id=$2")
                .bind(peer_id.to_string())
                .bind(org_id.to_string())
                .fetch_optional(&mut *tx)
                .await?;
        return Err(if exists.is_none() {
            ApiError::NotFound
        } else {
            ApiError::Conflict("wireguard-only peer is already revoked".into())
        });
    }
    bump_control_revision(&mut tx, org_id.to_string()).await?;
    append_audit(
        &mut tx,
        org_id,
        session,
        "wireguard_only.revoked",
        "wireguard_only_peer",
        Some(&peer_id.to_string()),
        &serde_json::json!({"kind": KIND}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn rotate_peer(
    state: &AppState,
    org_id: Uuid,
    peer_id: Uuid,
    session: &Session,
    input: RotateWireGuardOnlyPeer,
) -> Result<WireGuardOnlyPeer, ApiError> {
    let next_key = validate_public_key(&input.wg_public_key)?;
    let overlap_seconds = input.overlap_seconds.unwrap_or(DEFAULT_OVERLAP_SECS);
    if !(MIN_OVERLAP_SECS..=MAX_OVERLAP_SECS).contains(&overlap_seconds) {
        return Err(ApiError::BadRequest(format!(
            "overlap_seconds must be between {MIN_OVERLAP_SECS} and {MAX_OVERLAP_SECS}"
        )));
    }
    let current = load_peer(state, org_id, peer_id).await?;
    if current.revoked_at.is_some() {
        return Err(ApiError::Conflict(
            "wireguard-only peer is already revoked".into(),
        ));
    }
    if next_key == current.wg_public_key {
        return Err(ApiError::BadRequest(
            "rotated public key must differ from the current key".into(),
        ));
    }
    let now = now();
    let overlap_until = now + overlap_seconds;
    let overlap_peer_id = Uuid::new_v4();
    let mut tx = state.store.pool.begin().await?;
    let node_key_taken: Option<String> = sqlx::query_scalar(
        "SELECT id FROM nodes WHERE org_id=$1 AND wg_public_key=$2 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(org_id.to_string())
    .bind(&next_key)
    .fetch_optional(&mut *tx)
    .await?;
    if node_key_taken.is_some() {
        return Err(ApiError::Conflict(
            "a managed node already uses that public key".into(),
        ));
    }
    let peer_key_taken: Option<String> = sqlx::query_scalar(
        "SELECT id FROM wireguard_only_peers
         WHERE org_id=$1 AND id<>$2 AND revoked_at IS NULL
           AND (wg_public_key=$3 OR (previous_wg_public_key=$3 AND overlap_until IS NOT NULL AND overlap_until>$4))",
    )
    .bind(org_id.to_string())
    .bind(peer_id.to_string())
    .bind(&next_key)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;
    if peer_key_taken.is_some() {
        return Err(ApiError::Conflict(
            "wireguard-only peer name or public key already exists".into(),
        ));
    }
    let changed = sqlx::query(
        "UPDATE wireguard_only_peers
         SET wg_public_key=$1, previous_wg_public_key=$2, overlap_until=$3, overlap_peer_id=$4, revision=revision+1
         WHERE id=$5 AND org_id=$6 AND revoked_at IS NULL",
    )
    .bind(&next_key)
    .bind(&current.wg_public_key)
    .bind(overlap_until)
    .bind(overlap_peer_id.to_string())
    .bind(peer_id.to_string())
    .bind(org_id.to_string())
    .execute(&mut *tx)
    .await
    .map_err(conflict("wireguard-only peer name or public key already exists"))?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::NotFound);
    }
    bump_control_revision(&mut tx, org_id.to_string()).await?;
    append_audit(
        &mut tx,
        org_id,
        session,
        "wireguard_only.rotated",
        "wireguard_only_peer",
        Some(&peer_id.to_string()),
        &serde_json::json!({
            "kind": KIND,
            "overlap_until": overlap_until,
        }),
    )
    .await?;
    tx.commit().await?;
    load_peer(state, org_id, peer_id).await
}

fn row_to_peer(row: sqlx::any::AnyRow) -> Result<WireGuardOnlyPeer, ApiError> {
    let id: String = row.try_get(0)?;
    let previous: Option<String> = row.try_get(11)?;
    let overlap_until: Option<i64> = row.try_get(12)?;
    Ok(WireGuardOnlyPeer {
        id: Uuid::parse_str(&id).map_err(|_| ApiError::CorruptData)?,
        name: row.try_get(1)?,
        kind: row.try_get(2)?,
        wg_public_key: row.try_get(3)?,
        endpoint: row.try_get(4)?,
        allowed_ips: serde_json::from_str(&row.try_get::<String, _>(5)?)
            .map_err(|_| ApiError::CorruptData)?,
        tags: serde_json::from_str(&row.try_get::<String, _>(6)?).unwrap_or_default(),
        created_at: row.try_get(7)?,
        expires_at: row.try_get(8)?,
        revoked_at: row.try_get(9)?,
        revision: row.try_get(10)?,
        previous_wg_public_key: previous.filter(|key| !key.is_empty()),
        overlap_until,
    })
}

fn validate_name(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }
    if value.chars().count() > MAX_NAME_CHARS {
        return Err(ApiError::BadRequest(format!(
            "name must be at most {MAX_NAME_CHARS} characters"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "name cannot contain control characters".into(),
        ));
    }
    Ok(value.to_owned())
}

fn validate_public_key(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 88 {
        return Err(ApiError::BadRequest(
            "wg_public_key must be a WireGuard public key".into(),
        ));
    }
    if value.to_ascii_uppercase().contains("PRIVATE") {
        return Err(ApiError::BadRequest("private keys are not accepted".into()));
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || byte == b'+'
            || byte == b'/'
            || byte == b'='
            || byte == b'-'
            || byte == b'_'
    }) {
        return Err(ApiError::BadRequest(
            "wg_public_key must be a WireGuard public key".into(),
        ));
    }
    Ok(value.to_owned())
}

fn validate_endpoint(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if let Ok(address) = value.parse::<SocketAddr>() {
        if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
            return Err(ApiError::BadRequest(
                "endpoint must use a unicast host and non-zero port".into(),
            ));
        }
        return Ok(address.to_string());
    }
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| ApiError::BadRequest("endpoint must be host:port".into()))?;
    let port: u16 = port
        .parse()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| ApiError::BadRequest("endpoint must use a non-zero port".into()))?;
    if host.is_empty() || host.contains('/') || host.contains(' ') {
        return Err(ApiError::BadRequest("endpoint must be host:port".into()));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_unspecified() || ip.is_multicast() {
            return Err(ApiError::BadRequest(
                "endpoint must use a unicast host and non-zero port".into(),
            ));
        }
    }
    Ok(format!("{host}:{port}"))
}

fn validate_allowed_ips(routes: Vec<String>) -> Result<Vec<String>, ApiError> {
    if routes.is_empty() || routes.len() > MAX_ALLOWED_IPS {
        return Err(ApiError::BadRequest(format!(
            "wireguard-only peers require 1 to {MAX_ALLOWED_IPS} AllowedIPs"
        )));
    }
    let mut canonical = routes
        .into_iter()
        .map(|route| canonical_allowed_ip(&route))
        .collect::<Result<Vec<_>, _>>()?;
    canonical.sort();
    canonical.dedup();
    for (index, route) in canonical.iter().enumerate() {
        if canonical[index + 1..]
            .iter()
            .any(|other| prefixes_overlap(route, other))
        {
            return Err(ApiError::BadRequest(format!(
                "allowed IP {route} overlaps another prefix"
            )));
        }
    }
    Ok(canonical)
}

fn canonical_allowed_ip(route: &str) -> Result<String, ApiError> {
    if route.contains(':') {
        return canonical_ipv6_ula(route);
    }
    let canonical = canonical_ipv4_route(route)?;
    if canonical == "0.0.0.0/0" {
        return Err(ApiError::BadRequest(
            "default routes are not allowed for wireguard-only peers".into(),
        ));
    }
    if !["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        .iter()
        .any(|private| ipv4_route_is_within(&canonical, private))
    {
        return Err(ApiError::BadRequest(format!(
            "allowed IP {canonical} must be an RFC1918 private subnet"
        )));
    }
    if ipv4_routes_overlap(&canonical, "100.64.0.0/10") {
        return Err(ApiError::BadRequest(format!(
            "allowed IP {canonical} overlaps the BlakTail address pool"
        )));
    }
    Ok(canonical)
}

fn canonical_ipv6_ula(route: &str) -> Result<String, ApiError> {
    let route = route.trim();
    let (address, prefix) = route
        .split_once('/')
        .ok_or_else(|| ApiError::BadRequest(format!("route {route} must use CIDR notation")))?;
    let address: Ipv6Addr = address
        .parse()
        .map_err(|_| ApiError::BadRequest(format!("route {route} must be IPv6 CIDR")))?;
    let prefix: u8 = prefix
        .parse()
        .ok()
        .filter(|prefix| *prefix <= 128)
        .ok_or_else(|| ApiError::BadRequest(format!("route {route} has an invalid prefix")))?;
    if prefix == 0 {
        return Err(ApiError::BadRequest(
            "default routes are not allowed for wireguard-only peers".into(),
        ));
    }
    let mask = ipv6_mask(prefix);
    if u128::from(address) & !mask != 0 {
        return Err(ApiError::BadRequest(format!(
            "route {route} is not a network address"
        )));
    }
    if !address.is_unique_local() || address.is_multicast() {
        return Err(ApiError::BadRequest(format!(
            "allowed IP {address}/{prefix} must be a unique-local prefix"
        )));
    }
    Ok(format!("{address}/{prefix}"))
}

fn prefixes_overlap(left: &str, right: &str) -> bool {
    match (left.contains(':'), right.contains(':')) {
        (false, false) => ipv4_routes_overlap(left, right),
        (true, true) => ipv6_routes_overlap(left, right),
        _ => false,
    }
}

fn ipv6_routes_overlap(left: &str, right: &str) -> bool {
    let parse = |route: &str| {
        let (address, prefix) = route.split_once('/').expect("validated CIDR");
        (
            u128::from(address.parse::<Ipv6Addr>().expect("validated IPv6")),
            prefix.parse::<u8>().expect("validated prefix"),
        )
    };
    let (left_address, left_prefix) = parse(left);
    let (right_address, right_prefix) = parse(right);
    let mask = ipv6_mask(left_prefix.min(right_prefix));
    left_address & mask == right_address & mask
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

pub(crate) async fn expire_overlaps(pool: &sqlx::AnyPool, org_id: &str) -> Result<bool, ApiError> {
    let expired = sqlx::query(
        "UPDATE wireguard_only_peers
         SET previous_wg_public_key=NULL, overlap_until=NULL, overlap_peer_id=NULL, revision=revision+1
         WHERE org_id=$1 AND overlap_until IS NOT NULL AND overlap_until<=$2",
    )
    .bind(org_id)
    .bind(now())
    .execute(pool)
    .await?
    .rows_affected();
    if expired == 0 {
        return Ok(false);
    }
    sqlx::query("UPDATE orgs SET control_revision=control_revision+1 WHERE id=$1")
        .bind(org_id)
        .execute(pool)
        .await?;
    Ok(true)
}

pub(crate) async fn active_export_rows(
    pool: &sqlx::AnyPool,
    org_id: &str,
) -> Result<Vec<(Uuid, String, String, String, Vec<String>, Vec<DeviceTag>)>, ApiError> {
    let observed = now();
    let rows = sqlx::query(
        "SELECT id,name,wg_public_key,endpoint,allowed_ips_json,tags_json,previous_wg_public_key,overlap_until,overlap_peer_id
         FROM wireguard_only_peers
         WHERE org_id=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>$2)
         ORDER BY name",
    )
    .bind(org_id)
    .bind(observed)
    .fetch_all(pool)
    .await?;
    let mut exported = Vec::new();
    for row in rows {
        let id: String = row.try_get(0)?;
        let name: String = row.try_get(1)?;
        let wg_public_key: String = row.try_get(2)?;
        let endpoint: String = row.try_get(3)?;
        let allowed_ips: Vec<String> = serde_json::from_str(&row.try_get::<String, _>(4)?)
            .map_err(|_| ApiError::CorruptData)?;
        let tags: Vec<DeviceTag> =
            serde_json::from_str(&row.try_get::<String, _>(5)?).unwrap_or_default();
        exported.push((
            Uuid::parse_str(&id).map_err(|_| ApiError::CorruptData)?,
            name.clone(),
            wg_public_key,
            endpoint.clone(),
            allowed_ips.clone(),
            tags.clone(),
        ));
        let previous: Option<String> = row.try_get(6)?;
        let overlap_until: Option<i64> = row.try_get(7)?;
        let overlap_peer_id: Option<String> = row.try_get(8)?;
        if let (Some(previous), Some(until), Some(overlap_id)) =
            (previous, overlap_until, overlap_peer_id)
        {
            if until > observed && !previous.is_empty() {
                exported.push((
                    Uuid::parse_str(&overlap_id).map_err(|_| ApiError::CorruptData)?,
                    name,
                    previous,
                    endpoint,
                    allowed_ips,
                    tags,
                ));
            }
        }
    }
    Ok(exported)
}
