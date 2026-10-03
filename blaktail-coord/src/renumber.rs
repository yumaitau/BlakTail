//! Staged, reversible overlay renumbering and pool growth (NetBird-parity
//! draft 26, `docs/ipam.md`).
//!
//! A device's identity (node ID, WireGuard key, MagicDNS name) never changes;
//! only its overlay address does, in three steps:
//!
//! 1. **Stage.** The new IPv4 address is leased and the device's AllowedIPs
//!    become `new + old`, so peers route and accept both, ACL ingress and
//!    forward allow-lists include both, and the device adds the new interface
//!    address. Peer maps list the old addresses as `retiring_ips`, so
//!    MagicDNS answers only the new ones.
//! 2. **Complete** (explicitly, or when the window ends): AllowedIPs become
//!    `new` only and the old IPv4 lease enters the normal reuse grace period.
//! 3. **Roll back** (only while staged): AllowedIPs return to `old` and the
//!    new lease enters the grace period instead.
//!
//! Growing the pool (a `/24` to a `/22`, say) moves nobody and completes at
//! once. Moving to a pool that no longer covers a device's address renumbers
//! those devices through the same window.

use crate::{
    address_pool::{self, Pool},
    append_audit, bump_control_revision, console_session, hash, now,
    permissions::{require, Permission},
    ApiError, AppState, Role, Session,
};
use axum::{
    extract::{Path as UrlPath, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::{any::AnyRow, AnyConnection, AnyPool, Row};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use uuid::Uuid;

pub(crate) const DEFAULT_WINDOW_SECS: i64 = 24 * 60 * 60;
pub(crate) const MIN_WINDOW_SECS: i64 = 10 * 60;
pub(crate) const MAX_WINDOW_SECS: i64 = 30 * 24 * 60 * 60;
const MAX_DEVICE_MOVES: usize = 64;
const HISTORY: i64 = 10;
const COLUMNS: &str = "id,kind,state,previous_pool_cidr,target_pool_cidr,moves_json,window_seconds,window_ends_at,reason,created_by,created_at,finished_by,finished_at,revision";

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/orgs/:org_id/ipam/renumber", post(create_console))
        .route(
            "/v1/orgs/:org_id/ipam/renumber/preview",
            post(preview_console),
        )
        .route(
            "/v1/orgs/:org_id/ipam/renumber/:plan_id/complete",
            post(complete_console),
        )
        .route(
            "/v1/orgs/:org_id/ipam/renumber/:plan_id/rollback",
            post(rollback_console),
        )
}

// ---------- model ----------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlanInput {
    /// Target IPv4 pool, for a pool change.
    #[serde(default)]
    pool: Option<String>,
    /// Devices to move, for a per-device renumber.
    #[serde(default)]
    devices: Vec<DeviceInput>,
    #[serde(default)]
    window_seconds: Option<i64>,
    #[serde(default)]
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceInput {
    node_id: Uuid,
    /// Exact new IPv4 address; omitted means a bound reservation, else the
    /// lowest free host.
    #[serde(default)]
    address: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct Move {
    pub(crate) node_id: String,
    pub(crate) name: String,
    pub(crate) old_addresses: Vec<String>,
    pub(crate) new_addresses: Vec<String>,
}

impl Move {
    fn retiring(&self) -> impl Iterator<Item = &String> {
        self.old_addresses
            .iter()
            .filter(|address| !self.new_addresses.contains(address))
    }
    fn new_v4(&self) -> Option<&String> {
        self.new_addresses.iter().find(|a| !a.contains(':'))
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Blocker {
    kind: String,
    detail: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Preview {
    kind: String,
    current_pool: String,
    target_pool: String,
    window_seconds: i64,
    moves: Vec<Move>,
    /// Active devices whose address does not change.
    unchanged_devices: usize,
    /// Other active devices whose peer maps carry both addresses during the
    /// window (policy may hide some of them from each other).
    peer_maps: usize,
    /// Routing peers whose forward allow-lists list both addresses.
    forward_allow_lists: usize,
    /// MagicDNS names that switch to the new address at once.
    magic_dns_names: Vec<String>,
    /// Literal references to an old address; the plan cannot start until
    /// they are edited.
    blockers: Vec<Blocker>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct PlanView {
    pub(crate) id: String,
    kind: String,
    /// staged, completed or rolled_back.
    pub(crate) state: String,
    previous_pool: String,
    target_pool: String,
    pub(crate) moves: Vec<Move>,
    window_seconds: i64,
    window_ends_at: i64,
    reason: String,
    created_by: String,
    created_at: i64,
    finished_by: Option<String>,
    finished_at: Option<i64>,
    revision: i64,
    pub(crate) etag: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub(crate) struct RenumberSummary {
    pub(crate) staged: Option<PlanView>,
    pub(crate) history: Vec<PlanView>,
    default_window_seconds: i64,
    min_window_seconds: i64,
}

fn etag(id: &str, revision: i64) -> String {
    hash(&format!("ipam-renumber:{id}:{revision}"))[..32].to_owned()
}

fn plan_from_row(row: &AnyRow) -> Result<PlanView, ApiError> {
    let id: String = row.try_get(0)?;
    let revision: i64 = row.try_get(13)?;
    Ok(PlanView {
        etag: etag(&id, revision),
        id,
        kind: row.try_get(1)?,
        state: row.try_get(2)?,
        previous_pool: row.try_get(3)?,
        target_pool: row.try_get(4)?,
        moves: serde_json::from_str(&row.try_get::<String, _>(5)?)
            .map_err(|_| ApiError::CorruptData)?,
        window_seconds: row.try_get(6)?,
        window_ends_at: row.try_get(7)?,
        reason: row.try_get(8)?,
        created_by: row.try_get(9)?,
        created_at: row.try_get(10)?,
        finished_by: row.try_get(11)?,
        finished_at: row.try_get(12)?,
        revision,
    })
}

async fn load_plan(
    conn: &mut AnyConnection,
    org_id: &str,
    plan_id: &str,
) -> Result<Option<PlanView>, ApiError> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM ipam_renumber_plans WHERE id=$1 AND org_id=$2"
    )))
    .bind(plan_id)
    .bind(org_id)
    .fetch_optional(&mut *conn)
    .await?
    .as_ref()
    .map(plan_from_row)
    .transpose()
}

pub(crate) async fn summary(
    conn: &mut AnyConnection,
    org_id: &str,
) -> Result<RenumberSummary, ApiError> {
    let staged = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM ipam_renumber_plans WHERE org_id=$1 AND state='staged'"
    )))
    .bind(org_id)
    .fetch_optional(&mut *conn)
    .await?
    .as_ref()
    .map(plan_from_row)
    .transpose()?;
    let history = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM ipam_renumber_plans WHERE org_id=$1 AND state<>'staged' ORDER BY created_at DESC,id LIMIT {HISTORY}")
    ))
    .bind(org_id)
    .fetch_all(&mut *conn)
    .await?
    .iter()
    .map(plan_from_row)
    .collect::<Result<_, _>>()?;
    Ok(RenumberSummary {
        staged,
        history,
        default_window_seconds: DEFAULT_WINDOW_SECS,
        min_window_seconds: MIN_WINDOW_SECS,
    })
}

/// Retiring overlay addresses per device in the organisation's staged plan.
pub(crate) async fn retiring(
    pool: &AnyPool,
    org_id: &str,
) -> Result<BTreeMap<Uuid, Vec<String>>, ApiError> {
    let moves: Option<String> = sqlx::query_scalar(
        "SELECT moves_json FROM ipam_renumber_plans WHERE org_id=$1 AND state='staged'",
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await?;
    let moves: Vec<Move> = match moves {
        Some(json) => serde_json::from_str(&json).map_err(|_| ApiError::CorruptData)?,
        None => return Ok(BTreeMap::new()),
    };
    Ok(moves
        .iter()
        .filter_map(|change| {
            let id = Uuid::parse_str(&change.node_id).ok()?;
            Some((id, change.retiring().cloned().collect()))
        })
        .collect())
}

// ---------- planning ----------

struct Planned {
    kind: &'static str,
    current: Pool,
    target: Pool,
    window_seconds: i64,
    moves: Vec<Move>,
    preview: Preview,
}

fn window(input: Option<i64>) -> Result<i64, ApiError> {
    let seconds = input.unwrap_or(DEFAULT_WINDOW_SECS);
    if !(MIN_WINDOW_SECS..=MAX_WINDOW_SECS).contains(&seconds) {
        return Err(ApiError::BadRequest(format!(
            "the dual-address window must be between {} minutes and {} days",
            MIN_WINDOW_SECS / 60,
            MAX_WINDOW_SECS / 86_400
        )));
    }
    Ok(seconds)
}

fn host_ip(address: &str) -> Option<IpAddr> {
    address
        .split_once('/')
        .map_or(address, |(ip, _)| ip)
        .parse()
        .ok()
}

/// Literal mentions of an old address in policy or DNS settings. A host
/// mention, or a CIDR that covers the old address but not its replacement,
/// would silently change meaning after the move.
fn literal_references(source: &str, text: &str, moves: &[Move], out: &mut Vec<Blocker>) {
    let tokens: BTreeSet<&str> = text
        .split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':' || c == '/'))
        .filter(|token| token.len() >= 3)
        .collect();
    for change in moves {
        for old in change.retiring() {
            let Some(old_ip) = host_ip(old) else { continue };
            let replacement = change
                .new_addresses
                .iter()
                .filter_map(|address| host_ip(address))
                .find(|ip| ip.is_ipv4() == old_ip.is_ipv4());
            for token in &tokens {
                let hit = match token.split_once('/') {
                    None => token.parse::<IpAddr>().ok() == Some(old_ip),
                    Some(_) => match crate::ipam::parse_cidr(token) {
                        Ok((network, prefix)) => {
                            let host = if network.is_ipv4() { 32 } else { 128 };
                            let covers = |ip: IpAddr| {
                                crate::ipam::pools_overlap(token, &format!("{ip}/{host}"))
                                    .unwrap_or(false)
                            };
                            if prefix == host {
                                network == old_ip
                            } else {
                                covers(old_ip) && !replacement.is_some_and(covers)
                            }
                        }
                        Err(_) => false,
                    },
                };
                if hit {
                    out.push(Blocker {
                        kind: source.into(),
                        detail: format!(
                            "{source} names {token}, which covers {}'s current address {old_ip}; edit it before renumbering",
                            change.name
                        ),
                    });
                }
            }
        }
    }
}

async fn plan(
    conn: &mut AnyConnection,
    org_id: &str,
    input: &PlanInput,
) -> Result<Planned, ApiError> {
    let at = now();
    let window_seconds = window(input.window_seconds)?;
    let current = address_pool::load_pool(conn, org_id).await?;
    let nodes = address_pool::load_nodes(conn, org_id).await?;
    let reservations = address_pool::load_reservations(conn, org_id).await?;
    let mut blocked = address_pool::blocked_hosts(conn, org_id, at).await?;
    let mut blockers = Vec::new();

    let (kind, target, wanted): (
        &'static str,
        Pool,
        Vec<(&address_pool::NodeRow, Option<String>)>,
    ) = match (input.pool.as_deref(), input.devices.is_empty()) {
        (Some(cidr), true) => {
            let target = Pool::parse(cidr).map_err(ApiError::BadRequest)?;
            if target == current {
                return Err(ApiError::BadRequest(format!(
                    "the device pool is already {}",
                    target.cidr()
                )));
            }
            for reservation in reservations
                .iter()
                .filter(|reservation| !target.contains(&reservation.address))
            {
                blockers.push(Blocker {
                    kind: "reservation".into(),
                    detail: format!(
                        "reservation {} is outside {}; release it first",
                        address_pool::bare(&reservation.address),
                        target.cidr()
                    ),
                });
            }
            let movers = nodes
                .iter()
                .filter(|node| node.active())
                .filter(|node| {
                    node.addresses
                        .iter()
                        .any(|a| !a.contains(':') && !target.contains(a))
                })
                .map(|node| (node, None))
                .collect();
            ("pool", target, movers)
        }
        (None, false) => {
            if input.devices.len() > MAX_DEVICE_MOVES {
                return Err(ApiError::BadRequest(format!(
                    "renumber at most {MAX_DEVICE_MOVES} devices at a time"
                )));
            }
            let mut movers = Vec::new();
            let mut seen = BTreeSet::new();
            for device in &input.devices {
                if !seen.insert(device.node_id) {
                    return Err(ApiError::BadRequest(
                        "each device may appear once in a renumber plan".into(),
                    ));
                }
                let node = nodes
                    .iter()
                    .find(|node| node.id == device.node_id.to_string() && node.active())
                    .ok_or(ApiError::NotFound)?;
                let address = device
                    .address
                    .as_deref()
                    .map(|value| address_pool::canonical_pool_address(value, &current))
                    .transpose()?;
                movers.push((node, address));
            }
            ("devices", current, movers)
        }
        _ => {
            return Err(ApiError::BadRequest(
                "give either a target pool or a list of devices".into(),
            ))
        }
    };

    let mut moves = Vec::new();
    for (node, requested) in wanted {
        let bound = reservations
            .iter()
            .find(|reservation| {
                reservation.binds_node(node)
                    && target.contains(&reservation.address)
                    && !node.addresses.contains(&reservation.address)
            })
            .map(|reservation| reservation.address.clone());
        let new_v4 = match requested.or_else(|| bound.clone()) {
            Some(address) => {
                let ip = address_pool::v4_host(&address).ok_or(ApiError::CorruptData)?;
                if node.addresses.contains(&address) {
                    return Err(ApiError::BadRequest(format!(
                        "{} already uses {}",
                        node.label,
                        address_pool::bare(&address)
                    )));
                }
                let reserved_for_it = bound.as_deref() == Some(address.as_str());
                if blocked.contains(&ip) && !reserved_for_it {
                    return Err(ApiError::Conflict(format!(
                        "{} is in use, reserved or in its reuse grace period",
                        address_pool::bare(&address)
                    )));
                }
                address
            }
            None => {
                let ip = target
                    .hosts()
                    .find(|ip| !blocked.contains(ip))
                    .ok_or_else(|| {
                        ApiError::Conflict(format!("no free address left in {}", target.cidr()))
                    })?;
                address_pool::host_address(ip)
            }
        };
        if let Some(ip) = address_pool::v4_host(&new_v4) {
            blocked.insert(ip);
        }
        let new_v6 = address_pool::ipv6_twin(org_id, &new_v4).ok_or(ApiError::CorruptData)?;
        moves.push(Move {
            node_id: node.id.clone(),
            name: node.label.clone(),
            old_addresses: node.addresses.clone(),
            new_addresses: vec![new_v4, new_v6],
        });
    }

    let org = sqlx::query("SELECT acl_json,COALESCE(dns_json,'') FROM orgs WHERE id=$1")
        .bind(org_id)
        .fetch_one(&mut *conn)
        .await?;
    literal_references(
        "access policy",
        &org.try_get::<String, _>(0)?,
        &moves,
        &mut blockers,
    );
    literal_references(
        "DNS settings",
        &org.try_get::<String, _>(1)?,
        &moves,
        &mut blockers,
    );

    let active: Vec<_> = nodes.iter().filter(|node| node.active()).collect();
    let moving: BTreeSet<&str> = moves.iter().map(|m| m.node_id.as_str()).collect();
    // Any device that advertises routes may forward for the moved devices.
    let routers: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM nodes WHERE org_id=$1 AND revoked_at IS NULL AND deleted_at IS NULL AND advertised_routes_json<>'[]'",
    )
    .bind(org_id)
    .fetch_one(&mut *conn)
    .await?;
    let mut magic_dns_names = Vec::new();
    for change in &moves {
        let name: Option<String> = sqlx::query_scalar("SELECT dns_name FROM nodes WHERE id=$1")
            .bind(&change.node_id)
            .fetch_optional(&mut *conn)
            .await?;
        magic_dns_names.extend(name);
    }
    let preview = Preview {
        kind: kind.into(),
        current_pool: current.cidr(),
        target_pool: target.cidr(),
        window_seconds,
        moves: moves.clone(),
        unchanged_devices: active.len() - moving.len(),
        peer_maps: if moves.is_empty() {
            0
        } else {
            active.len().saturating_sub(1)
        },
        forward_allow_lists: if moves.is_empty() {
            0
        } else {
            usize::try_from(routers).unwrap_or(0)
        },
        magic_dns_names,
        blockers,
    };
    Ok(Planned {
        kind,
        current,
        target,
        window_seconds,
        moves,
        preview,
    })
}

// ---------- stage, complete, roll back ----------

fn system_session() -> Session {
    Session {
        user_id: "system:ipam-renumber".into(),
        role: Role::Member,
        name: "Renumber window".into(),
        email: String::new(),
    }
}

async fn set_addresses(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    node_id: &str,
    addresses: &[String],
) -> Result<(), ApiError> {
    sqlx::query("UPDATE nodes SET allowed_ips_json=$1 WHERE id=$2")
        .bind(serde_json::to_string(addresses).map_err(|_| ApiError::CorruptData)?)
        .bind(node_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Starts the reuse grace period for one device's lease on `address`.
async fn release_lease(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: &str,
    node_id: &str,
    address: &str,
    at: i64,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE ipam_leases SET released_at=$4 WHERE org_id=$1 AND address=$2 AND node_id=$3 AND released_at IS NULL",
    )
    .bind(org_id)
    .bind(address)
    .bind(node_id)
    .bind(at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn create(
    state: &AppState,
    org_id: Uuid,
    session: &Session,
    input: PlanInput,
) -> Result<(StatusCode, PlanView), ApiError> {
    let org = org_id.to_string();
    let reason = input.reason.trim().to_owned();
    if reason.chars().count() > 256 || reason.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "reason must be at most 256 characters without control characters".into(),
        ));
    }
    let at = now();
    let mut tx = state.store.pool.begin().await?;
    // Serialise renumber plans per organisation (on PostgreSQL a concurrent
    // plan waits here for the first to commit) before planning.
    sqlx::query("UPDATE orgs SET ipv4_pool_cidr=ipv4_pool_cidr WHERE id=$1")
        .bind(&org)
        .execute(&mut *tx)
        .await?;
    if let Some(staged) = summary(&mut tx, &org).await?.staged {
        return Err(ApiError::Conflict(format!(
            "renumber plan {} is still in its dual-address window; complete or roll it back first",
            staged.id
        )));
    }
    address_pool::stamp_releases(&mut tx, &org, at).await?;
    let planned = plan(&mut tx, &org, &input).await?;
    if !planned.preview.blockers.is_empty() {
        return Err(ApiError::Conflict(format!(
            "renumbering is blocked: {}",
            planned
                .preview
                .blockers
                .iter()
                .map(|blocker| blocker.detail.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        )));
    }
    for change in &planned.moves {
        let new_v4 = change.new_v4().ok_or(ApiError::CorruptData)?;
        if !address_pool::take_lease(&mut tx, &org, new_v4, &change.node_id, at).await? {
            return Err(ApiError::Conflict(format!(
                "{} was taken by a concurrent enrolment; preview the plan again",
                address_pool::bare(new_v4)
            )));
        }
        // New addresses first: agents use the first IPv4 as their primary.
        let mut both = change.new_addresses.clone();
        both.extend(change.old_addresses.iter().cloned());
        set_addresses(&mut tx, &change.node_id, &both).await?;
    }
    if planned.target != planned.current {
        sqlx::query("UPDATE orgs SET ipv4_pool_cidr=$1 WHERE id=$2")
            .bind(planned.target.cidr())
            .bind(&org)
            .execute(&mut *tx)
            .await?;
    }
    // Growing the pool moves nobody, so there is no window to wait out.
    let immediate = planned.moves.is_empty();
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO ipam_renumber_plans(id,org_id,kind,state,previous_pool_cidr,target_pool_cidr,moves_json,window_seconds,window_ends_at,reason,created_by,created_at,finished_by,finished_at,revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,1)",
    )
    .bind(&id)
    .bind(&org)
    .bind(planned.kind)
    .bind(if immediate { "completed" } else { "staged" })
    .bind(planned.current.cidr())
    .bind(planned.target.cidr())
    .bind(serde_json::to_string(&planned.moves).map_err(|_| ApiError::CorruptData)?)
    .bind(planned.window_seconds)
    .bind(at + planned.window_seconds)
    .bind(&reason)
    .bind(&session.user_id)
    .bind(at)
    .bind(immediate.then(|| session.user_id.clone()))
    .bind(immediate.then_some(at))
    .execute(&mut *tx)
    .await
    .map_err(crate::conflict("another renumber plan was staged concurrently"))?;
    append_audit(
        &mut tx,
        org_id,
        session,
        if immediate {
            "ipam.pool_resized"
        } else {
            "ipam.renumber_staged"
        },
        "ipam_renumber_plan",
        Some(&id),
        &serde_json::json!({
            "kind": planned.kind,
            "previous_pool": planned.current.cidr(),
            "target_pool": planned.target.cidr(),
            "moves": planned.moves,
            "window_seconds": planned.window_seconds,
            "reason": reason,
        }),
    )
    .await?;
    bump_control_revision(&mut tx, &org).await?;
    let view = load_plan(&mut tx, &org, &id)
        .await?
        .ok_or(ApiError::CorruptData)?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, view))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Finish {
    Complete,
    Rollback,
}

/// Completes or rolls back a staged plan. `expected` is the caller's etag;
/// `None` is the window-end completion, which needs none.
async fn finish(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: Uuid,
    plan_id: &str,
    expected: Option<&str>,
    how: Finish,
    session: &Session,
) -> Result<PlanView, ApiError> {
    let org = org_id.to_string();
    let at = now();
    let plan = load_plan(tx, &org, plan_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if expected.is_some_and(|expected| expected != plan.etag) {
        return Err(ApiError::PreconditionFailed);
    }
    if plan.state != "staged" {
        return Err(ApiError::Conflict(format!(
            "this renumber plan is already {}",
            plan.state.replace('_', " ")
        )));
    }
    if how == Finish::Rollback && plan.previous_pool != plan.target_pool {
        let previous = Pool::parse(&plan.previous_pool).map_err(|_| ApiError::CorruptData)?;
        let moved: BTreeSet<&str> = plan.moves.iter().map(|m| m.node_id.as_str()).collect();
        if let Some(node) = address_pool::load_nodes(tx, &org)
            .await?
            .iter()
            .filter(|node| node.active() && !moved.contains(node.id.as_str()))
            .find(|node| {
                node.addresses
                    .iter()
                    .any(|a| !a.contains(':') && !previous.contains(a))
            })
        {
            return Err(ApiError::Conflict(format!(
                "{} enrolled from the new pool during the window; rolling back would leave it outside {}. Complete the plan, or renumber that device first",
                node.label, plan.previous_pool
            )));
        }
    }
    let state = match how {
        Finish::Complete => "completed",
        Finish::Rollback => "rolled_back",
    };
    let changed = sqlx::query(
        "UPDATE ipam_renumber_plans SET state=$1,finished_by=$2,finished_at=$3,revision=revision+1 WHERE id=$4 AND org_id=$5 AND state='staged' AND revision=$6",
    )
    .bind(state)
    .bind(&session.user_id)
    .bind(at)
    .bind(&plan.id)
    .bind(&org)
    .bind(plan.revision)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::PreconditionFailed);
    }
    for change in &plan.moves {
        let (keep, drop) = match how {
            Finish::Complete => (&change.new_addresses, &change.old_addresses),
            Finish::Rollback => (&change.old_addresses, &change.new_addresses),
        };
        set_addresses(tx, &change.node_id, keep).await?;
        // The dropped address waits out the normal reuse grace period.
        for address in drop
            .iter()
            .filter(|address| !address.contains(':') && !keep.contains(address))
        {
            release_lease(tx, &org, &change.node_id, address, at).await?;
        }
    }
    if how == Finish::Rollback && plan.previous_pool != plan.target_pool {
        sqlx::query("UPDATE orgs SET ipv4_pool_cidr=$1 WHERE id=$2")
            .bind(&plan.previous_pool)
            .bind(&org)
            .execute(&mut **tx)
            .await?;
    }
    append_audit(
        tx,
        org_id,
        session,
        match how {
            Finish::Complete => "ipam.renumber_completed",
            Finish::Rollback => "ipam.renumber_rolled_back",
        },
        "ipam_renumber_plan",
        Some(&plan.id),
        &serde_json::json!({
            "moves": plan.moves,
            "automatic": expected.is_none(),
        }),
    )
    .await?;
    bump_control_revision(tx, &org).await?;
    load_plan(tx, &org, &plan.id)
        .await?
        .ok_or(ApiError::CorruptData)
}

/// Completes the organisation's staged plan once its window has ended.
/// Cheap when nothing is due: one indexed lookup.
pub(crate) async fn complete_due(pool: &AnyPool, org_id: &str) -> Result<(), ApiError> {
    let due: Option<String> = sqlx::query_scalar(
        "SELECT id FROM ipam_renumber_plans WHERE org_id=$1 AND state='staged' AND window_ends_at<=$2",
    )
    .bind(org_id)
    .bind(now())
    .fetch_optional(pool)
    .await?;
    let (Some(plan_id), Ok(org)) = (due, Uuid::parse_str(org_id)) else {
        return Ok(());
    };
    let mut tx = pool.begin().await?;
    match finish(
        &mut tx,
        org,
        &plan_id,
        None,
        Finish::Complete,
        &system_session(),
    )
    .await
    {
        Ok(_) => {
            tx.commit().await?;
            Ok(())
        }
        // Another request finished it first.
        Err(ApiError::PreconditionFailed | ApiError::Conflict(_)) => Ok(()),
        Err(error) => Err(error),
    }
}

// ---------- console routes ----------

fn parse_input(value: serde_json::Value) -> Result<PlanInput, ApiError> {
    serde_json::from_value(value)
        .map_err(|error| ApiError::BadRequest(format!("invalid renumber plan: {error}")))
}

fn if_match(headers: &HeaderMap) -> Result<String, ApiError> {
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
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::BadRequest("If-Match with the plan etag is required".into()))
}

async fn preview_console(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(value): Json<serde_json::Value>,
) -> Result<Json<Preview>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageNetworks)?;
    let input = parse_input(value)?;
    let mut conn = s.store.pool.acquire().await?;
    Ok(Json(
        plan(&mut conn, &org_id.to_string(), &input).await?.preview,
    ))
}

async fn create_console(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(value): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<PlanView>), ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageNetworks)?;
    let input = parse_input(value)?;
    let (status, view) = create(&s, org_id, &session, input).await?;
    Ok((status, Json(view)))
}

async fn finish_console(
    s: AppState,
    org_id: Uuid,
    plan_id: Uuid,
    headers: HeaderMap,
    how: Finish,
) -> Result<Json<PlanView>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageNetworks)?;
    let expected = if_match(&headers)?;
    let mut tx = s.store.pool.begin().await?;
    let view = finish(
        &mut tx,
        org_id,
        &plan_id.to_string(),
        Some(&expected),
        how,
        &session,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(view))
}

async fn complete_console(
    State(s): State<AppState>,
    UrlPath((org_id, plan_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<PlanView>, ApiError> {
    finish_console(s, org_id, plan_id, headers, Finish::Complete).await
}

async fn rollback_console(
    State(s): State<AppState>,
    UrlPath((org_id, plan_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<PlanView>, ApiError> {
    finish_console(s, org_id, plan_id, headers, Finish::Rollback).await
}
