//! Overlay address management (NetBird-parity draft 26).
//!
//! Every device gets one IPv4 host from the organisation pool
//! `100.64.0.0/24` (inside the CGNAT supernet `100.64.0.0/10`) and the
//! matching host in the organisation's ULA `/64`, derived from the IPv4 host
//! number. `ipam_leases` has one row per handed-out IPv4 address and its
//! primary key is the concurrency guard: two enrolments racing on PostgreSQL
//! both try to insert the same row and the loser moves to the next address.
//! Operator reservations are never auto-allocated; a reservation bound to a
//! device name or WireGuard key is handed to that device when it enrols.

use crate::{
    append_audit, console_session, hash, ipam, now, org_ula_address,
    permissions::{require, Permission},
    ApiError, AppState, Session,
};
use axum::{
    extract::{Path as UrlPath, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::{AnyConnection, Row};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use uuid::Uuid;

/// How long an address stays out of circulation after its device was
/// revoked, deleted or purged. Matches the tombstone retention so a deleted
/// device's address is never handed to a different device while the
/// tombstone (and any cached peer map or DNS answer naming it) can still exist.
pub(crate) const ADDRESS_REUSE_GRACE_SECS: i64 = 7 * 24 * 60 * 60;
const POOL_V4: &str = "100.64.0.0/24";
const SUPERNET_V4: &str = "100.64.0.0/10";
const FIRST_HOST: u8 = 1;
const LAST_HOST: u8 = 254;
const MAX_RESERVATIONS: usize = 128;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/orgs/:org_id/ipam", get(view_console))
        .route(
            "/v1/orgs/:org_id/ipam/reservations",
            axum::routing::post(reserve_console),
        )
        .route(
            "/v1/orgs/:org_id/ipam/reservations/:reservation_id",
            delete(release_console),
        )
}

fn pool_address(host: u8) -> String {
    format!("100.64.0.{host}/32")
}

fn pool_host(address: &str) -> Option<u8> {
    let ip: Ipv4Addr = address.strip_suffix("/32")?.parse().ok()?;
    let octets = ip.octets();
    (octets[..3] == [100, 64, 0] && (FIRST_HOST..=LAST_HOST).contains(&octets[3]))
        .then_some(octets[3])
}

fn bare(address: &str) -> String {
    address
        .split_once('/')
        .map_or(address, |(ip, _)| ip)
        .to_owned()
}

fn org_ula_pool(org_id: &str) -> String {
    format!("{}/64", bare(&org_ula_address(org_id, 0)))
}

fn reservation_etag(id: &str, revision: i64) -> String {
    hash(&format!("ipam-reservation:{id}:{revision}"))[..32].to_owned()
}

/// WireGuard keys are public, but the console only needs enough to tell
/// bindings apart.
fn key_fingerprint(key: &str) -> String {
    format!("{}…", key.chars().take(8).collect::<String>())
}

struct NodeRow {
    id: String,
    name: String,
    label: String,
    wg_public_key: String,
    addresses: Vec<String>,
    revoked_at: Option<i64>,
    deleted_at: Option<i64>,
}

impl NodeRow {
    fn active(&self) -> bool {
        self.revoked_at.is_none() && self.deleted_at.is_none()
    }
    fn pool_address(&self) -> Option<&String> {
        self.addresses.iter().find(|a| pool_host(a).is_some())
    }
}

struct LeaseRow {
    address: String,
    node_id: Option<String>,
    released_at: Option<i64>,
}

struct ReservationRow {
    id: String,
    address: String,
    bound_name: Option<String>,
    bound_wg_public_key: Option<String>,
    reason: String,
    created_by: String,
    created_at: i64,
    revision: i64,
}

impl ReservationRow {
    fn binds(&self, name: &str, wg_public_key: &str) -> bool {
        self.bound_name.as_deref() == Some(name)
            || self.bound_wg_public_key.as_deref() == Some(wg_public_key)
    }
}

async fn load_nodes(conn: &mut AnyConnection, org_id: &str) -> Result<Vec<NodeRow>, ApiError> {
    let rows = sqlx::query(
        "SELECT id,name,COALESCE(NULLIF(TRIM(display_name),''),name),wg_public_key,allowed_ips_json,CAST(revoked_at AS BIGINT),CAST(deleted_at AS BIGINT) FROM nodes WHERE org_id=$1 ORDER BY name",
    )
    .bind(org_id)
    .fetch_all(&mut *conn)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(NodeRow {
                id: row.try_get(0)?,
                name: row.try_get(1)?,
                label: row.try_get(2)?,
                wg_public_key: row.try_get(3)?,
                addresses: serde_json::from_str(&row.try_get::<String, _>(4)?).unwrap_or_default(),
                revoked_at: row.try_get(5)?,
                deleted_at: row.try_get(6)?,
            })
        })
        .collect()
}

async fn load_leases(conn: &mut AnyConnection, org_id: &str) -> Result<Vec<LeaseRow>, ApiError> {
    let rows = sqlx::query(
        "SELECT address,node_id,released_at FROM ipam_leases WHERE org_id=$1 ORDER BY address",
    )
    .bind(org_id)
    .fetch_all(&mut *conn)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(LeaseRow {
                address: row.try_get(0)?,
                node_id: row.try_get(1)?,
                released_at: row.try_get(2)?,
            })
        })
        .collect()
}

async fn load_reservations(
    conn: &mut AnyConnection,
    org_id: &str,
) -> Result<Vec<ReservationRow>, ApiError> {
    let rows = sqlx::query(
        "SELECT id,address,bound_name,bound_wg_public_key,reason,created_by,created_at,revision FROM ipam_address_reservations WHERE org_id=$1 ORDER BY address",
    )
    .bind(org_id)
    .fetch_all(&mut *conn)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(ReservationRow {
                id: row.try_get(0)?,
                address: row.try_get(1)?,
                bound_name: row.try_get(2)?,
                bound_wg_public_key: row.try_get(3)?,
                reason: row.try_get(4)?,
                created_by: row.try_get(5)?,
                created_at: row.try_get(6)?,
                revision: row.try_get(7)?,
            })
        })
        .collect()
}

/// Starts the reuse grace period for leases whose device is revoked,
/// deleted or already purged. Purged rows are stamped when first noticed,
/// which is never earlier than the deletion itself.
async fn stamp_releases(conn: &mut AnyConnection, org_id: &str, at: i64) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE ipam_leases SET released_at=(SELECT CAST(COALESCE(n.deleted_at,n.revoked_at) AS BIGINT) FROM nodes n WHERE n.id=ipam_leases.node_id) WHERE org_id=$1 AND released_at IS NULL AND node_id IN (SELECT id FROM nodes WHERE org_id=$1 AND (deleted_at IS NOT NULL OR revoked_at IS NOT NULL))",
    )
    .bind(org_id)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE ipam_leases SET released_at=$2 WHERE org_id=$1 AND released_at IS NULL AND (node_id IS NULL OR node_id NOT IN (SELECT id FROM nodes WHERE org_id=$1))",
    )
    .bind(org_id)
    .bind(at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

fn lease_held(lease: &LeaseRow, at: i64) -> bool {
    lease
        .released_at
        .is_none_or(|released| released > at - ADDRESS_REUSE_GRACE_SECS)
}

/// Picks and leases the overlay addresses for a device being registered in
/// `tx`. A reservation bound to `name` or `wg_public_key` wins; otherwise
/// the lowest free host that no device row, held lease or reservation uses.
pub(crate) async fn allocate(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: &str,
    node_id: Uuid,
    name: &str,
    wg_public_key: &str,
) -> Result<Vec<String>, ApiError> {
    let at = now();
    stamp_releases(tx, org_id, at).await?;
    let nodes = load_nodes(tx, org_id).await?;
    let leases = load_leases(tx, org_id).await?;
    let reservations = load_reservations(tx, org_id).await?;

    if let Some(reservation) = reservations
        .iter()
        .find(|reservation| reservation.binds(name, wg_public_key))
    {
        let host = pool_host(&reservation.address).ok_or(ApiError::CorruptData)?;
        if let Some(holder) = nodes
            .iter()
            .find(|node| node.active() && node.addresses.contains(&reservation.address))
        {
            return Err(ApiError::Conflict(format!(
                "address {} is reserved for this device but active device {} still uses it; revoke or delete that device first",
                bare(&reservation.address),
                holder.label
            )));
        }
        // An explicit reservation may take over a released address during
        // its grace period: the operator chose this device for it.
        let taken = sqlx::query(
            "INSERT INTO ipam_leases(org_id,address,node_id,allocated_at,released_at) VALUES($1,$2,$3,$4,NULL) ON CONFLICT (org_id,address) DO UPDATE SET node_id=excluded.node_id,allocated_at=excluded.allocated_at,released_at=NULL WHERE ipam_leases.released_at IS NOT NULL",
        )
        .bind(org_id)
        .bind(&reservation.address)
        .bind(node_id.to_string())
        .bind(at)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        if taken == 0 {
            return Err(ApiError::Conflict(format!(
                "reserved address {} is being assigned to another enrolment",
                bare(&reservation.address)
            )));
        }
        return Ok(vec![
            reservation.address.clone(),
            org_ula_address(org_id, host),
        ]);
    }

    let mut blocked = BTreeSet::new();
    blocked.extend(
        nodes
            .iter()
            .flat_map(|node| node.addresses.iter())
            .filter_map(|address| pool_host(address)),
    );
    blocked.extend(
        leases
            .iter()
            .filter(|lease| lease_held(lease, at))
            .filter_map(|lease| pool_host(&lease.address)),
    );
    blocked.extend(
        reservations
            .iter()
            .filter_map(|reservation| pool_host(&reservation.address)),
    );
    let grace_cutoff = at - ADDRESS_REUSE_GRACE_SECS;
    for host in (FIRST_HOST..=LAST_HOST).filter(|host| !blocked.contains(host)) {
        let address = pool_address(host);
        // Zero rows means a concurrent enrolment holds this address (on
        // PostgreSQL the insert waits for it to commit); try the next one.
        let inserted = sqlx::query(
            "INSERT INTO ipam_leases(org_id,address,node_id,allocated_at,released_at) VALUES($1,$2,$3,$4,NULL) ON CONFLICT (org_id,address) DO UPDATE SET node_id=excluded.node_id,allocated_at=excluded.allocated_at,released_at=NULL WHERE ipam_leases.released_at IS NOT NULL AND ipam_leases.released_at<=$5",
        )
        .bind(org_id)
        .bind(&address)
        .bind(node_id.to_string())
        .bind(at)
        .bind(grace_cutoff)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        if inserted > 0 {
            return Ok(vec![address, org_ula_address(org_id, host)]);
        }
    }
    let in_grace = leases
        .iter()
        .filter(|lease| lease.released_at.is_some() && lease_held(lease, at))
        .count();
    Err(ApiError::Conflict(format!(
        "tailnet address pool exhausted ({} of {} addresses are reserved or in the {}-day reuse grace period)",
        in_grace + reservations.len(),
        LAST_HOST,
        ADDRESS_REUSE_GRACE_SECS / 86_400
    )))
}

// ---------- operator view ----------

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct PoolSummary {
    family: String,
    cidr: String,
    supernet: String,
    usable: u32,
    used: u32,
    reserved: u32,
    in_grace: u32,
    available: u32,
    note: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct AddressEntry {
    address: String,
    ipv6: String,
    /// active, revoked, tombstoned or released.
    state: String,
    node_id: Option<String>,
    node_name: Option<String>,
    released_at: Option<i64>,
    /// Earliest time automatic allocation may hand the address out again.
    reusable_at: Option<i64>,
    reservation_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ReservationView {
    id: String,
    address: String,
    ipv6: String,
    bound_name: Option<String>,
    bound_key_fingerprint: Option<String>,
    reason: String,
    created_by: String,
    created_at: i64,
    revision: i64,
    etag: String,
    /// held, waiting, assigned, pending_reenrolment or conflict.
    state: String,
    detail: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct AddressConflict {
    address: String,
    kind: String,
    detail: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct IpamView {
    pools: Vec<PoolSummary>,
    addresses: Vec<AddressEntry>,
    reservations: Vec<ReservationView>,
    conflicts: Vec<AddressConflict>,
    reuse_grace_seconds: i64,
    next_free: Option<String>,
}

async fn load_wg_only_allowed(
    conn: &mut AnyConnection,
    org_id: &str,
) -> Result<Vec<(String, Vec<String>)>, ApiError> {
    let rows = sqlx::query(
        "SELECT name,allowed_ips_json FROM wireguard_only_peers WHERE org_id=$1 AND revoked_at IS NULL",
    )
    .bind(org_id)
    .fetch_all(&mut *conn)
    .await?;
    rows.iter()
        .map(|row| {
            Ok((
                row.try_get(0)?,
                serde_json::from_str(&row.try_get::<String, _>(1)?).unwrap_or_default(),
            ))
        })
        .collect()
}

async fn view(conn: &mut AnyConnection, org_id: &str) -> Result<IpamView, ApiError> {
    let at = now();
    let nodes = load_nodes(conn, org_id).await?;
    let leases = load_leases(conn, org_id).await?;
    let reservations = load_reservations(conn, org_id).await?;
    let ula = org_ula_pool(org_id);
    let ipv6_of = |address: &str| {
        pool_host(address)
            .map(|host| bare(&org_ula_address(org_id, host)))
            .unwrap_or_default()
    };
    let reservation_for = |address: &str| {
        reservations
            .iter()
            .find(|reservation| reservation.address == address)
            .map(|reservation| reservation.id.clone())
    };

    let mut conflicts = Vec::new();
    let mut addresses = Vec::new();
    let mut active_by_address: BTreeMap<&str, Vec<&NodeRow>> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut used = BTreeSet::new();
    let mut in_grace = BTreeSet::new();
    for node in &nodes {
        let Some(address) = node.pool_address() else {
            if node.active() {
                for address in node.addresses.iter().filter(|a| !a.contains(':')) {
                    conflicts.push(AddressConflict {
                        address: bare(address),
                        kind: "outside_pool".into(),
                        detail: format!(
                            "{} uses an address outside {POOL_V4}; it was not assigned by this pool",
                            node.label
                        ),
                    });
                }
            }
            continue;
        };
        let (state, released_at, reusable_at) = match (node.deleted_at, node.revoked_at) {
            (Some(deleted), _) => (
                "tombstoned",
                Some(deleted),
                Some(deleted + ADDRESS_REUSE_GRACE_SECS),
            ),
            (None, Some(revoked)) => ("revoked", Some(revoked), None),
            (None, None) => ("active", None, None),
        };
        if node.active() {
            active_by_address.entry(address).or_default().push(node);
            used.insert(address.clone());
        } else if node.deleted_at.is_some() {
            in_grace.insert(address.clone());
        } else {
            used.insert(address.clone());
        }
        seen.insert(address.clone());
        addresses.push(AddressEntry {
            address: bare(address),
            ipv6: ipv6_of(address),
            state: state.into(),
            node_id: Some(node.id.clone()),
            node_name: Some(node.label.clone()),
            released_at,
            reusable_at,
            reservation_id: reservation_for(address),
        });
    }
    for lease in leases
        .iter()
        .filter(|lease| !seen.contains(&lease.address) && lease_held(lease, at))
    {
        // A lease with no device row: the tombstone was purged.
        if lease
            .node_id
            .as_ref()
            .is_some_and(|id| nodes.iter().any(|n| &n.id == id))
        {
            continue;
        }
        in_grace.insert(lease.address.clone());
        addresses.push(AddressEntry {
            address: bare(&lease.address),
            ipv6: ipv6_of(&lease.address),
            state: "released".into(),
            node_id: lease.node_id.clone(),
            node_name: None,
            released_at: lease.released_at,
            reusable_at: lease
                .released_at
                .map(|released| released + ADDRESS_REUSE_GRACE_SECS),
            reservation_id: reservation_for(&lease.address),
        });
    }
    addresses.sort_by_key(|entry| {
        entry
            .address
            .parse::<Ipv4Addr>()
            .map(u32::from)
            .unwrap_or(u32::MAX)
    });
    for (address, holders) in &active_by_address {
        if holders.len() > 1 {
            conflicts.push(AddressConflict {
                address: bare(address),
                kind: "duplicate".into(),
                detail: format!(
                    "assigned to {} active devices: {}",
                    holders.len(),
                    holders
                        .iter()
                        .map(|node| node.label.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }
    }

    let mut reservation_views = Vec::new();
    for reservation in &reservations {
        let holder = active_by_address
            .get(reservation.address.as_str())
            .and_then(|holders| holders.first());
        let bound = reservation.bound_name.is_some() || reservation.bound_wg_public_key.is_some();
        let bound_node = nodes
            .iter()
            .find(|node| node.active() && reservation.binds(&node.name, &node.wg_public_key));
        let (state, detail) = match (holder, bound_node) {
            (Some(holder), _) if reservation.binds(&holder.name, &holder.wg_public_key) => (
                "assigned",
                format!("in use by {}, as reserved", holder.label),
            ),
            (Some(holder), _) => {
                conflicts.push(AddressConflict {
                    address: bare(&reservation.address),
                    kind: "reserved_in_use".into(),
                    detail: format!(
                        "reserved but assigned to {}; that device keeps it until it is revoked or deleted",
                        holder.label
                    ),
                });
                ("conflict", format!("in use by {}", holder.label))
            }
            (None, Some(node)) => (
                "pending_reenrolment",
                format!(
                    "{} currently uses {}; it receives this address only when it enrols again",
                    node.label,
                    node.pool_address().map(|a| bare(a)).unwrap_or_default()
                ),
            ),
            (None, None) if bound => (
                "waiting",
                "handed to the device with this name or key when it enrols".into(),
            ),
            (None, None) => ("held", "never handed out automatically".into()),
        };
        reservation_views.push(ReservationView {
            id: reservation.id.clone(),
            address: bare(&reservation.address),
            ipv6: ipv6_of(&reservation.address),
            bound_name: reservation.bound_name.clone(),
            bound_key_fingerprint: reservation
                .bound_wg_public_key
                .as_deref()
                .map(key_fingerprint),
            reason: reservation.reason.clone(),
            created_by: reservation.created_by.clone(),
            created_at: reservation.created_at,
            revision: reservation.revision,
            etag: reservation_etag(&reservation.id, reservation.revision),
            state: state.into(),
            detail,
        });
    }

    for (peer, allowed) in load_wg_only_allowed(conn, org_id).await? {
        for prefix in allowed.iter().filter(|prefix| prefix.contains(':')) {
            if ipam::pools_overlap(prefix, &ula).unwrap_or(false) {
                conflicts.push(AddressConflict {
                    address: prefix.clone(),
                    kind: "overlaps_device_pool".into(),
                    detail: format!(
                        "WireGuard-only peer {peer} claims part of the device IPv6 pool {ula}"
                    ),
                });
            }
        }
    }

    let reserved: BTreeSet<_> = reservations
        .iter()
        .map(|reservation| reservation.address.clone())
        .filter(|address| !used.contains(address))
        .collect();
    let taken: BTreeSet<_> = used
        .union(&in_grace)
        .chain(reserved.iter())
        .cloned()
        .collect();
    let usable = u32::from(LAST_HOST - FIRST_HOST + 1);
    let available = usable.saturating_sub(taken.len() as u32);
    let next_free = (FIRST_HOST..=LAST_HOST)
        .map(pool_address)
        .find(|address| !taken.contains(address))
        .map(|address| bare(&address));
    let summary = |family: &str, cidr: String, supernet: &str, note: &str| PoolSummary {
        family: family.into(),
        cidr,
        supernet: supernet.into(),
        usable,
        used: used.len() as u32,
        reserved: reserved.len() as u32,
        in_grace: in_grace.len() as u32,
        available,
        note: note.into(),
    };
    Ok(IpamView {
        pools: vec![
            summary(
                "ipv4",
                POOL_V4.into(),
                SUPERNET_V4,
                "Shared CGNAT range; each organisation's peer map is separate, so the same address in another organisation never reaches your devices.",
            ),
            summary(
                "ipv6",
                ula.clone(),
                "fd00::/8",
                "Unique local /64 derived from this organisation's ID. Each device's IPv6 host number mirrors its IPv4 host number.",
            ),
        ],
        addresses,
        reservations: reservation_views,
        conflicts,
        reuse_grace_seconds: ADDRESS_REUSE_GRACE_SECS,
        next_free,
    })
}

// ---------- reservations ----------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReserveInput {
    address: String,
    #[serde(default)]
    bound_name: Option<String>,
    #[serde(default)]
    bound_wg_public_key: Option<String>,
    #[serde(default)]
    reason: String,
}

fn optional_text(value: Option<&str>, label: &str) -> Result<Option<String>, ApiError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.chars().count() > 64 || value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(ApiError::BadRequest(format!(
            "{label} must be at most 64 characters without spaces"
        )));
    }
    Ok(Some(value.to_owned()))
}

fn canonical_pool_address(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    let ip = value.strip_suffix("/32").unwrap_or(value);
    let pool = [ipam::IpamPool {
        name: "devices".into(),
        cidr: POOL_V4.into(),
        exclusions: Vec::new(),
    }];
    ipam::validate_reservation(&pool, ip).map_err(|error| {
        ApiError::BadRequest(format!(
            "{error}; reserve a host address in {POOL_V4} (100.64.0.1 to 100.64.0.254)"
        ))
    })?;
    let parsed: Ipv4Addr = ip
        .parse()
        .map_err(|_| ApiError::BadRequest(format!("{value} is not an IPv4 address")))?;
    Ok(format!("{parsed}/32"))
}

async fn reserve(
    state: &AppState,
    org_id: Uuid,
    session: &Session,
    input: ReserveInput,
) -> Result<(StatusCode, ReservationView), ApiError> {
    let org = org_id.to_string();
    let address = canonical_pool_address(&input.address)?;
    let bound_name = optional_text(input.bound_name.as_deref(), "device name")?;
    let bound_wg_public_key =
        optional_text(input.bound_wg_public_key.as_deref(), "WireGuard public key")?;
    let reason = input.reason.trim().to_owned();
    if reason.chars().count() > 256 || reason.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "reason must be at most 256 characters without control characters".into(),
        ));
    }
    let mut tx = state.store.pool.begin().await?;
    let at = now();
    stamp_releases(&mut tx, &org, at).await?;
    let reservations = load_reservations(&mut tx, &org).await?;
    if let Some(existing) = reservations.iter().find(|r| r.address == address) {
        // Replaying the same reservation is a no-op so retries are safe.
        if existing.bound_name == bound_name
            && existing.bound_wg_public_key == bound_wg_public_key
            && existing.reason == reason
        {
            drop(tx);
            let view = reservation_view(state, &org, &existing.id).await?;
            return Ok((StatusCode::OK, view));
        }
        return Err(ApiError::Conflict(format!(
            "{} is already reserved; release that reservation first",
            bare(&address)
        )));
    }
    if reservations.len() >= MAX_RESERVATIONS {
        return Err(ApiError::Conflict(format!(
            "an organisation may hold at most {MAX_RESERVATIONS} address reservations"
        )));
    }
    if let Some(other) = reservations.iter().find(|r| {
        (bound_name.is_some() && r.bound_name == bound_name)
            || (bound_wg_public_key.is_some() && r.bound_wg_public_key == bound_wg_public_key)
    }) {
        return Err(ApiError::Conflict(format!(
            "that device is already bound to reserved address {}",
            bare(&other.address)
        )));
    }
    let nodes = load_nodes(&mut tx, &org).await?;
    if let Some(holder) = nodes
        .iter()
        .find(|node| node.active() && node.addresses.contains(&address))
    {
        let pins_holder = bound_name.as_deref() == Some(holder.name.as_str())
            || bound_wg_public_key.as_deref() == Some(holder.wg_public_key.as_str());
        if !pins_holder {
            return Err(ApiError::Conflict(format!(
                "{} is assigned to {}; bind the reservation to that device's name to pin it, or choose a free address",
                bare(&address),
                holder.label
            )));
        }
    }
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO ipam_address_reservations(id,org_id,address,bound_name,bound_wg_public_key,reason,created_by,created_at,revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8,1)",
    )
    .bind(&id)
    .bind(&org)
    .bind(&address)
    .bind(&bound_name)
    .bind(&bound_wg_public_key)
    .bind(&reason)
    .bind(&session.user_id)
    .bind(at)
    .execute(&mut *tx)
    .await
    .map_err(crate::conflict("that address was reserved concurrently"))?;
    append_audit(
        &mut tx,
        org_id,
        session,
        "ipam.reservation_created",
        "ipam_reservation",
        Some(&id),
        &serde_json::json!({
            "address": bare(&address),
            "bound_name": bound_name,
            "bound_key_fingerprint": bound_wg_public_key.as_deref().map(key_fingerprint),
            "reason": reason,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        reservation_view(state, &org, &id).await?,
    ))
}

async fn reservation_view(
    state: &AppState,
    org: &str,
    id: &str,
) -> Result<ReservationView, ApiError> {
    let mut conn = state.store.pool.acquire().await?;
    view(&mut conn, org)
        .await?
        .reservations
        .into_iter()
        .find(|reservation| reservation.id == id)
        .ok_or(ApiError::NotFound)
}

fn if_match(headers: &HeaderMap) -> Option<String> {
    headers
        .get("if-match")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .trim()
                .trim_start_matches("W/")
                .trim_matches('"')
                .to_owned()
        })
}

async fn release(
    state: &AppState,
    org_id: Uuid,
    reservation_id: &str,
    session: &Session,
    headers: &HeaderMap,
) -> Result<StatusCode, ApiError> {
    let expected = if_match(headers).ok_or_else(|| {
        ApiError::BadRequest("If-Match with the reservation etag is required".into())
    })?;
    let org = org_id.to_string();
    let mut tx = state.store.pool.begin().await?;
    let current = load_reservations(&mut tx, &org)
        .await?
        .into_iter()
        .find(|reservation| reservation.id == reservation_id);
    // Already released (or never in this organisation): releasing is idempotent.
    let Some(current) = current else {
        return Ok(StatusCode::NO_CONTENT);
    };
    if reservation_etag(&current.id, current.revision) != expected {
        return Err(ApiError::PreconditionFailed);
    }
    let deleted = sqlx::query(
        "DELETE FROM ipam_address_reservations WHERE id=$1 AND org_id=$2 AND revision=$3",
    )
    .bind(&current.id)
    .bind(&org)
    .bind(current.revision)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if deleted == 0 {
        return Err(ApiError::PreconditionFailed);
    }
    append_audit(
        &mut tx,
        org_id,
        session,
        "ipam.reservation_released",
        "ipam_reservation",
        Some(&current.id),
        &serde_json::json!({
            "address": bare(&current.address),
            "bound_name": current.bound_name,
            "bound_key_fingerprint": current.bound_wg_public_key.as_deref().map(key_fingerprint),
            "reason": current.reason,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- console routes ----------

async fn view_console(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<IpamView>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewNetwork)?;
    let mut conn = s.store.pool.acquire().await?;
    Ok(Json(view(&mut conn, &org_id.to_string()).await?))
}

async fn reserve_console(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(value): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<ReservationView>), ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageNetworks)?;
    let input: ReserveInput = serde_json::from_value(value)
        .map_err(|error| ApiError::BadRequest(format!("invalid reservation: {error}")))?;
    let (status, view) = reserve(&s, org_id, &session, input).await?;
    Ok((status, Json(view)))
}

async fn release_console(
    State(s): State<AppState>,
    UrlPath((org_id, reservation_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageNetworks)?;
    release(&s, org_id, &reservation_id.to_string(), &session, &headers).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_connectors::integration::{
        call, create_org, error_text, json, register, try_register, Who, SECRET,
    };
    use crate::{app, connect_postgres, Store};
    use axum::http::Method;

    async fn view_as(router: &Router, who: &Who) -> IpamView {
        let response = call(
            router,
            Method::GET,
            &format!("/v1/orgs/{}/ipam", who.org),
            serde_json::Value::Null,
            Some(who.token()),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        json(response).await
    }

    async fn reserve_as(
        router: &Router,
        who: &Who,
        body: serde_json::Value,
    ) -> axum::response::Response {
        call(
            router,
            Method::POST,
            &format!("/v1/orgs/{}/ipam/reservations", who.org),
            body,
            Some(who.token()),
            &[],
        )
        .await
    }

    #[test]
    fn pool_hosts_are_parsed_strictly() {
        assert_eq!(pool_host("100.64.0.1/32"), Some(1));
        assert_eq!(pool_host("100.64.0.254/32"), Some(254));
        assert_eq!(pool_host("100.64.0.0/32"), None);
        assert_eq!(pool_host("100.64.0.255/32"), None);
        assert_eq!(pool_host("100.64.1.5/32"), None);
        assert_eq!(pool_host("100.64.0.5"), None);
        assert!(canonical_pool_address("100.64.0.0").is_err());
        assert!(canonical_pool_address("100.64.0.255").is_err());
        assert!(canonical_pool_address("10.0.0.1").is_err());
        assert_eq!(
            canonical_pool_address(" 100.64.0.9/32 ").unwrap(),
            "100.64.0.9/32"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_enrolment_never_duplicates_and_respects_racing_leases() {
        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), SECRET);
        let org = create_org(&router, "ipam-race-org").await;
        let owner = Who::person(org.id, "owner-1", "owner");
        // A lease committed by another coordinator whose device row is not
        // visible (or already purged) still blocks its address.
        sqlx::query("INSERT INTO ipam_leases(org_id,address,node_id,allocated_at) VALUES($1,'100.64.0.1/32',$2,$3)")
            .bind(org.id.to_string())
            .bind(Uuid::new_v4().to_string())
            .bind(now())
            .execute(&store.pool)
            .await
            .unwrap();
        let tasks = (0..24).map(|index| {
            let router = router.clone();
            let owner = owner.clone();
            tokio::spawn(
                async move { register(&router, &owner, &format!("device-{index}"), &[]).await },
            )
        });
        let mut addresses = BTreeSet::new();
        let mut ipv6 = BTreeSet::new();
        for task in tasks {
            let registered = task.await.unwrap();
            assert_ne!(registered.assigned_ip, "100.64.0.1/32");
            assert!(addresses.insert(registered.assigned_ip.clone()));
            assert!(ipv6.insert(registered.assigned_ips[1].clone()));
        }
        assert_eq!(addresses.len(), 24);
        let leases: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ipam_leases WHERE org_id=$1")
            .bind(org.id.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(leases, 25);
    }

    #[tokio::test]
    async fn reservations_are_honoured_audited_and_role_checked() {
        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), SECRET);
        let org = create_org(&router, "ipam-org").await;
        let other = create_org(&router, "ipam-other").await;
        let owner = Who::person(org.id, "owner-1", "owner");
        let admin = Who::person(org.id, "admin-1", "admin");
        let member = Who::person(org.id, "member-1", "member");
        let outsider = Who::person(other.id, "owner-2", "owner");

        let held = serde_json::json!({"address":"100.64.0.1","reason":"printer VLAN gateway"});
        assert_eq!(
            reserve_as(&router, &member, held.clone()).await.status(),
            StatusCode::FORBIDDEN
        );
        let response = call(
            &router,
            Method::POST,
            &format!("/v1/orgs/{}/ipam/reservations", org.id),
            held.clone(),
            Some(outsider.token()),
            &[],
        )
        .await;
        assert!(response.status().is_client_error());
        let response = reserve_as(&router, &admin, held.clone()).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let first: ReservationView = json(response).await;
        assert_eq!(first.state, "held");
        // Replaying the same reservation is a no-op; a different one conflicts.
        let replay = reserve_as(&router, &admin, held.clone()).await;
        assert_eq!(replay.status(), StatusCode::OK);
        assert_eq!(json::<ReservationView>(replay).await.id, first.id);
        let clash = reserve_as(
            &router,
            &admin,
            serde_json::json!({"address":"100.64.0.1","bound_name":"other"}),
        )
        .await;
        assert_eq!(clash.status(), StatusCode::CONFLICT);
        for address in [
            "100.64.0.0",
            "100.64.0.255",
            "100.64.1.4",
            "10.0.0.1",
            "nope",
        ] {
            assert_eq!(
                reserve_as(&router, &admin, serde_json::json!({"address": address}))
                    .await
                    .status(),
                StatusCode::BAD_REQUEST,
                "{address}"
            );
        }

        let bound: ReservationView = json(
            reserve_as(
                &router,
                &owner,
                serde_json::json!({"address":"100.64.0.50","bound_name":"printer"}),
            )
            .await,
        )
        .await;
        assert_eq!(bound.state, "waiting");

        // Held addresses are skipped; the bound one goes to its device.
        let laptop = register(&router, &owner, "laptop", &[]).await;
        assert_eq!(laptop.assigned_ip, "100.64.0.2/32");
        let printer = register(&router, &owner, "printer", &[]).await;
        assert_eq!(printer.assigned_ip, "100.64.0.50/32");
        assert!(
            printer.assigned_ips[1].ends_with(":32/128"),
            "{:?}",
            printer.assigned_ips
        );
        let tablet = register(&router, &owner, "tablet", &[]).await;
        assert_eq!(tablet.assigned_ip, "100.64.0.3/32");

        // Unbound reservations cannot steal an address in use.
        let response =
            reserve_as(&router, &admin, serde_json::json!({"address":"100.64.0.2"})).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(error_text(response).await.contains("laptop"));
        // Pinning a device's current address is allowed.
        let pinned: ReservationView = json(
            reserve_as(
                &router,
                &admin,
                serde_json::json!({"address":"100.64.0.2","bound_name":"laptop"}),
            )
            .await,
        )
        .await;
        assert_eq!(pinned.state, "assigned");

        let view = view_as(&router, &member).await;
        assert_eq!(view.pools.len(), 2);
        let v4 = &view.pools[0];
        assert_eq!((v4.used, v4.reserved, v4.available), (3, 1, 250));
        assert_eq!(view.pools[1].family, "ipv6");
        assert!(view.pools[1].cidr.ends_with("::/64"));
        assert_eq!(view.next_free.as_deref(), Some("100.64.0.4"));
        let printer_row = view
            .addresses
            .iter()
            .find(|entry| entry.address == "100.64.0.50")
            .unwrap();
        assert_eq!(printer_row.node_name.as_deref(), Some("printer"));
        assert_eq!(printer_row.state, "active");
        assert!(view.conflicts.is_empty(), "{:?}", view.conflicts);

        // Release needs the current etag, is audited, and is idempotent.
        let release_uri = format!("/v1/orgs/{}/ipam/reservations/{}", org.id, first.id);
        let missing = call(
            &router,
            Method::DELETE,
            &release_uri,
            serde_json::Value::Null,
            Some(admin.token()),
            &[],
        )
        .await;
        assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
        let stale = call(
            &router,
            Method::DELETE,
            &release_uri,
            serde_json::Value::Null,
            Some(admin.token()),
            &[("if-match", "\"stale\"".into())],
        )
        .await;
        assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
        let by_member = call(
            &router,
            Method::DELETE,
            &release_uri,
            serde_json::Value::Null,
            Some(member.token()),
            &[("if-match", format!("\"{}\"", first.etag))],
        )
        .await;
        assert_eq!(by_member.status(), StatusCode::FORBIDDEN);
        for _ in 0..2 {
            let response = call(
                &router,
                Method::DELETE,
                &release_uri,
                serde_json::Value::Null,
                Some(admin.token()),
                &[("if-match", format!("\"{}\"", first.etag))],
            )
            .await;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }
        let next = register(&router, &owner, "phone", &[]).await;
        assert_eq!(next.assigned_ip, "100.64.0.1/32");

        let actions: Vec<String> = sqlx::query_scalar(
            "SELECT action FROM audit_events WHERE org_id=$1 AND action LIKE 'ipam.%' ORDER BY created_at,action",
        )
        .bind(org.id.to_string())
        .fetch_all(&store.pool)
        .await
        .unwrap();
        assert_eq!(
            actions,
            [
                "ipam.reservation_created",
                "ipam.reservation_created",
                "ipam.reservation_created",
                "ipam.reservation_released"
            ]
        );
        // The other organisation's pool is untouched and starts at .1.
        let outsider_device = register(&router, &outsider, "laptop", &[]).await;
        assert_eq!(outsider_device.assigned_ip, "100.64.0.1/32");
        assert!(view_as(&router, &outsider).await.reservations.is_empty());
    }

    #[tokio::test]
    async fn tombstoned_addresses_wait_out_the_grace_period() {
        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), SECRET);
        let org = create_org(&router, "ipam-grace-org").await;
        let owner = Who::person(org.id, "owner-1", "owner");
        let old = register(&router, &owner, "old", &[]).await;
        assert_eq!(old.assigned_ip, "100.64.0.1/32");
        let response = call(
            &router,
            Method::POST,
            &format!("/v1/orgs/{}/nodes/{}/tombstone", org.id, old.id),
            serde_json::Value::Null,
            Some(owner.token()),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let second = register(&router, &owner, "second", &[]).await;
        assert_eq!(second.assigned_ip, "100.64.0.2/32");
        let view = view_as(&router, &owner).await;
        let entry = view
            .addresses
            .iter()
            .find(|e| e.address == "100.64.0.1")
            .unwrap();
        assert_eq!(entry.state, "tombstoned");
        assert!(entry.reusable_at.unwrap() > now() + ADDRESS_REUSE_GRACE_SECS - 60);
        assert_eq!(view.pools[0].in_grace, 1);

        // Purging the tombstone row does not free the address early.
        sqlx::query("DELETE FROM nodes WHERE id=$1")
            .bind(old.id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        let third = register(&router, &owner, "third", &[]).await;
        assert_eq!(third.assigned_ip, "100.64.0.3/32");
        let view = view_as(&router, &owner).await;
        assert_eq!(
            view.addresses
                .iter()
                .find(|e| e.address == "100.64.0.1")
                .unwrap()
                .state,
            "released"
        );

        // Once the grace period has passed, the address is reused.
        sqlx::query("UPDATE ipam_leases SET released_at=$1 WHERE address='100.64.0.1/32'")
            .bind(now() - ADDRESS_REUSE_GRACE_SECS - 1)
            .execute(&store.pool)
            .await
            .unwrap();
        let fourth = register(&router, &owner, "fourth", &[]).await;
        assert_eq!(fourth.assigned_ip, "100.64.0.1/32");

        // A bound reservation reclaims a tombstoned address immediately, but
        // never one an active device still uses.
        let response = reserve_as(
            &router,
            &owner,
            serde_json::json!({"address":"100.64.0.3","bound_name":"replacement"}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let reserved: ReservationView = json(
            reserve_as(
                &router,
                &owner,
                serde_json::json!({"address":"100.64.0.3","bound_name":"third"}),
            )
            .await,
        )
        .await;
        assert_eq!(reserved.state, "assigned");
        let response = call(
            &router,
            Method::POST,
            &format!("/v1/orgs/{}/nodes/{}/tombstone", org.id, third.id),
            serde_json::Value::Null,
            Some(owner.token()),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let again = register(&router, &owner, "third", &[]).await;
        assert_eq!(again.assigned_ip, "100.64.0.3/32");
        // A device bound to an address another active device holds is refused.
        reserve_as(
            &router,
            &owner,
            serde_json::json!({"address":"100.64.0.2","bound_name":"second"}),
        )
        .await;
        sqlx::query("UPDATE ipam_address_reservations SET bound_name='usurper' WHERE address='100.64.0.2/32'")
            .execute(&store.pool)
            .await
            .unwrap();
        let response = try_register(&router, &owner, "usurper", &[]).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let view = view_as(&router, &owner).await;
        assert!(view
            .conflicts
            .iter()
            .any(|conflict| conflict.kind == "reserved_in_use"));
    }

    /// Real parallel enrolment against PostgreSQL through two coordinator
    /// pools. Needs `BLAKTAIL_COORD_IPAM_TEST_DATABASE_URL` pointing at a
    /// throwaway database whose name contains `blaktail_ipam_test`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn postgres_concurrent_enrolment_allocates_unique_addresses() {
        let Ok(database_url) = std::env::var("BLAKTAIL_COORD_IPAM_TEST_DATABASE_URL") else {
            return;
        };
        assert!(database_url.contains("blaktail_ipam_test"));
        let cleanup = connect_postgres(&database_url).await.unwrap();
        sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
            .execute(&cleanup)
            .await
            .unwrap();
        cleanup.close().await;
        Store::migrate_postgres(&database_url)
            .await
            .unwrap()
            .pool
            .close()
            .await;
        let first = Store::open_existing_postgres(&database_url).await.unwrap();
        let second = Store::open_existing_postgres(&database_url).await.unwrap();
        let routers = [
            app(first, "ap-southeast-2".into(), SECRET),
            app(second, "ap-southeast-2".into(), SECRET),
        ];
        let org = create_org(&routers[0], "pg-ipam-org").await;
        let owner = Who::person(org.id, "owner-1", "owner");
        reserve_as(
            &routers[0],
            &owner,
            serde_json::json!({"address":"100.64.0.3","reason":"held"}),
        )
        .await;
        let tasks = (0..40).map(|index| {
            let router = routers[index % 2].clone();
            let owner = owner.clone();
            tokio::spawn(
                async move { register(&router, &owner, &format!("pg-{index}"), &[]).await },
            )
        });
        let mut addresses = BTreeSet::new();
        for task in tasks {
            let registered = task.await.unwrap();
            assert_ne!(registered.assigned_ip, "100.64.0.3/32");
            assert!(
                addresses.insert(registered.assigned_ip),
                "duplicate address"
            );
        }
        assert_eq!(addresses.len(), 40);
    }
}
