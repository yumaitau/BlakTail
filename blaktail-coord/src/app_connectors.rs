//! Domain app connectors (NetBird-parity draft 06).
//!
//! A DNS-target network resource becomes routable when one of its routing
//! peers runs blaktaild with the `app-connector` capability. That connector
//! resolves the exact FQDN from its own resolver, reports the A/AAAA answers
//! and TTLs here, and the coordinator turns accepted answers into host-route
//! leases (`/32`, `/128`). `resources::load_distribution` hands the leases of
//! the selected connector to authorised clients exactly like a CIDR resource.
//!
//! Reports are untrusted: any answer in a forbidden range (loopback,
//! link-local, cloud metadata, multicast, unspecified, the overlay pools or
//! a device's WireGuard endpoint) rejects the whole report and withdraws
//! every lease for that resource, so DNS rebinding fails closed.

use crate::{
    append_audit, bearer, bump_control_revision, now, org_ula_address, ApiError, AppState, Role,
    Session,
};
use axum::{
    extract::{Path as UrlPath, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::{AnyConnection, Row};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use uuid::Uuid;

pub(crate) const CAP_APP_CONNECTOR: &str = "app-connector";
/// Lease lifetime is the reported TTL clamped to this window. The floor stops
/// a zero or tiny TTL flapping routes between connector polls; the cap bounds
/// how long a stale answer can outlive a silent connector.
pub(crate) const MIN_LEASE_SECS: i64 = 30;
pub(crate) const MAX_LEASE_SECS: i64 = 300;
const MAX_ANSWERS: usize = 32;
const RESOLVE_INTERVAL_SECS: i64 = 30;
const MAX_REASON_CHARS: usize = 200;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/nodes/:node_id/connector/assignments", get(assignments))
        .route(
            "/v1/nodes/:node_id/connector/resolutions",
            post(report_resolution),
        )
}

// ---------- address safety ----------

fn ipv4_in(ip: Ipv4Addr, network: [u8; 4], prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(ip) & mask == u32::from(Ipv4Addr::from(network)) & mask
}

fn ipv6_in(ip: Ipv6Addr, network: Ipv6Addr, prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    u128::from(ip) & mask == u128::from(network) & mask
}

fn ipv4_forbidden(ip: Ipv4Addr) -> Option<&'static str> {
    const RANGES: [([u8; 4], u32, &str); 8] = [
        ([169, 254, 169, 254], 32, "cloud metadata endpoint"),
        ([100, 100, 100, 200], 32, "cloud metadata endpoint"),
        ([0, 0, 0, 0], 8, "unspecified or this-network"),
        ([127, 0, 0, 0], 8, "loopback"),
        ([169, 254, 0, 0], 16, "link-local"),
        ([100, 64, 0, 0], 10, "BlakTail overlay pool"),
        ([224, 0, 0, 0], 4, "multicast"),
        ([240, 0, 0, 0], 4, "reserved or broadcast"),
    ];
    RANGES
        .iter()
        .find(|(network, prefix, _)| ipv4_in(ip, *network, *prefix))
        .map(|(_, _, reason)| *reason)
}

/// Why `ip` may never become a connector host route, if it may not.
pub(crate) fn forbidden_reason(ip: IpAddr, org_id: &str) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => ipv4_forbidden(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ipv4_forbidden(v4).or(Some("IPv4-mapped address"));
            }
            // NAT64 can smuggle a forbidden IPv4 target inside an AAAA answer.
            if ipv6_in(v6, Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96) {
                let embedded = Ipv4Addr::from((u128::from(v6) & 0xffff_ffff) as u32);
                if let Some(reason) = ipv4_forbidden(embedded) {
                    return Some(reason);
                }
            }
            let org_pool: Ipv6Addr = org_ula_address(org_id, 0)
                .split_once('/')
                .and_then(|(address, _)| address.parse().ok())
                .unwrap_or(Ipv6Addr::UNSPECIFIED);
            let ranges: [(Ipv6Addr, u32, &str); 6] = [
                (
                    Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254),
                    128,
                    "cloud metadata endpoint",
                ),
                (Ipv6Addr::UNSPECIFIED, 128, "unspecified"),
                (Ipv6Addr::LOCALHOST, 128, "loopback"),
                (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10, "link-local"),
                (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8, "multicast"),
                (org_pool, 64, "BlakTail overlay pool"),
            ];
            ranges
                .iter()
                .find(|(network, prefix, _)| ipv6_in(v6, *network, *prefix))
                .map(|(_, _, reason)| *reason)
        }
    }
}

/// Parses an answer that must be a single host. Prefixes other than /32 and
/// /128 are broad routes and are refused outright.
fn host_ip(raw: &str) -> Result<IpAddr, String> {
    let text = raw.trim();
    let (address, prefix) = match text.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (text, None),
    };
    let ip: IpAddr = address
        .parse()
        .map_err(|_| format!("{raw:?} is not an IP address"))?;
    let host = if ip.is_ipv4() { "32" } else { "128" };
    if prefix.is_some_and(|prefix| prefix != host) {
        return Err(format!(
            "{raw} is a prefix; connectors only lease host routes (/32 or /128)"
        ));
    }
    Ok(ip)
}

fn host_route(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(_) => format!("{ip}/32"),
        IpAddr::V6(_) => format!("{ip}/128"),
    }
}

fn lease_seconds(ttl: u32) -> i64 {
    i64::from(ttl).clamp(MIN_LEASE_SECS, MAX_LEASE_SECS)
}

fn clean_reason(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(MAX_REASON_CHARS)
        .collect()
}

// ---------- node authentication ----------

struct ConnectorNode {
    id: Uuid,
    org_id: String,
}

async fn authenticate(
    s: &AppState,
    node_id: Uuid,
    headers: &HeaderMap,
) -> Result<ConnectorNode, ApiError> {
    let token = bearer(headers)?;
    let row = sqlx::query(
        "SELECT org_id,credential_expires_at,capabilities_json,CASE WHEN suspended_at IS NULL THEN 0 ELSE 1 END FROM nodes WHERE id=$1 AND token_hash=$2 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(node_id.to_string())
    .bind(token)
    .fetch_optional(&s.store.pool)
    .await?
    .ok_or(ApiError::Unauthorized)?;
    if row.try_get::<i64, _>(3)? != 0 {
        return Err(ApiError::Suspended);
    }
    if row.try_get::<i64, _>(1)? <= now() {
        return Err(ApiError::CredentialExpired);
    }
    let capabilities: Vec<String> =
        serde_json::from_str(&row.try_get::<String, _>(2)?).unwrap_or_default();
    if !capabilities.iter().any(|c| c == CAP_APP_CONNECTOR) {
        return Err(ApiError::Forbidden);
    }
    Ok(ConnectorNode {
        id: node_id,
        org_id: row.try_get(0)?,
    })
}

#[derive(Deserialize)]
struct PeerRef {
    node_id: Uuid,
}

struct DnsResource {
    id: Uuid,
    name: String,
    fqdn: String,
    enabled: bool,
    routing_peers: Vec<Uuid>,
}

async fn load_dns_resources(
    conn: &mut AnyConnection,
    org_id: &str,
) -> Result<Vec<DnsResource>, ApiError> {
    let rows = sqlx::query(
        "SELECT id,name,dns_target,enabled,routing_peers_json FROM network_resources WHERE org_id=$1 AND kind='dns' ORDER BY id",
    )
    .bind(org_id)
    .fetch_all(&mut *conn)
    .await?;
    rows.iter()
        .map(|row| {
            let peers: Vec<PeerRef> = serde_json::from_str(&row.try_get::<String, _>(4)?)
                .map_err(|_| ApiError::CorruptData)?;
            Ok(DnsResource {
                id: Uuid::parse_str(&row.try_get::<String, _>(0)?)
                    .map_err(|_| ApiError::CorruptData)?,
                name: row.try_get(1)?,
                fqdn: row
                    .try_get::<Option<String>, _>(2)?
                    .ok_or(ApiError::CorruptData)?,
                enabled: row.try_get::<i64, _>(3)? != 0,
                routing_peers: peers.into_iter().map(|peer| peer.node_id).collect(),
            })
        })
        .collect()
}

// ---------- agent endpoints ----------

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Assignment {
    pub(crate) resource_id: Uuid,
    pub(crate) fqdn: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Assignments {
    pub(crate) interval_seconds: i64,
    pub(crate) resources: Vec<Assignment>,
}

async fn assignments(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Assignments>, ApiError> {
    let node = authenticate(&s, node_id, &headers).await?;
    let mut conn = s.store.pool.acquire().await?;
    let resources = load_dns_resources(&mut conn, &node.org_id)
        .await?
        .into_iter()
        .filter(|resource| resource.enabled && resource.routing_peers.contains(&node.id))
        .map(|resource| Assignment {
            resource_id: resource.id,
            fqdn: resource.fqdn,
        })
        .collect();
    Ok(Json(Assignments {
        interval_seconds: RESOLVE_INTERVAL_SECS,
        resources,
    }))
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Answer {
    pub(crate) address: String,
    pub(crate) ttl: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolutionReport {
    pub(crate) resource_id: Uuid,
    pub(crate) fqdn: String,
    #[serde(default)]
    pub(crate) answers: Vec<Answer>,
    /// Set when the connector could not resolve at all (timeout, SERVFAIL).
    #[serde(default)]
    pub(crate) error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ResolutionOutcome {
    /// resolved, empty or error. Blocked reports are rejected with 409.
    pub(crate) state: String,
    /// Host routes this connector must forward for the resource.
    pub(crate) routes: Vec<String>,
    pub(crate) lease_expires_at: Option<i64>,
}

fn connector_session(node_id: Uuid) -> Session {
    Session {
        user_id: format!("node:{node_id}"),
        role: Role::Member,
        name: "App connector".into(),
        email: String::new(),
    }
}

async fn record_report(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: &str,
    resource_id: Uuid,
    node_id: Uuid,
    state: &str,
    reason: &str,
    at: i64,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO connector_reports(resource_id,node_id,org_id,state,reason,reported_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (resource_id,node_id) DO UPDATE SET state=excluded.state,reason=excluded.reason,reported_at=excluded.reported_at",
    )
    .bind(resource_id.to_string())
    .bind(node_id.to_string())
    .bind(org_id)
    .bind(state)
    .bind(reason)
    .bind(at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn active_leases(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    resource_id: Uuid,
    node_id: Uuid,
    at: i64,
) -> Result<BTreeSet<String>, ApiError> {
    Ok(sqlx::query_scalar::<_, String>(
        "SELECT route FROM connector_leases WHERE resource_id=$1 AND node_id=$2 AND expires_at>$3",
    )
    .bind(resource_id.to_string())
    .bind(node_id.to_string())
    .bind(at)
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .collect())
}

async fn withdraw_all(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    resource_id: Uuid,
    node_id: Uuid,
) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM connector_leases WHERE resource_id=$1 AND node_id=$2")
        .bind(resource_id.to_string())
        .bind(node_id.to_string())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn device_endpoints(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: &str,
) -> Result<BTreeSet<IpAddr>, ApiError> {
    Ok(sqlx::query_scalar::<_, Option<String>>(
        "SELECT endpoint FROM nodes WHERE org_id=$1 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(org_id)
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .flatten()
    .filter_map(|endpoint| endpoint.parse::<SocketAddr>().ok())
    .map(|endpoint| endpoint.ip())
    .collect())
}

async fn report_resolution(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(report): Json<ResolutionReport>,
) -> Result<Json<ResolutionOutcome>, ApiError> {
    let node = authenticate(&s, node_id, &headers).await?;
    let org = node.org_id.clone();
    let org_uuid = Uuid::parse_str(&org).map_err(|_| ApiError::CorruptData)?;
    let at = now();
    let mut tx = s.store.pool.begin().await?;
    // Resource lookup is scoped to the node's own organisation, so a report
    // naming another organisation's resource is simply not found.
    let resource = load_dns_resources(&mut tx, &org)
        .await?
        .into_iter()
        .find(|resource| resource.id == report.resource_id)
        .ok_or(ApiError::NotFound)?;
    if !resource.routing_peers.contains(&node.id) {
        return Err(ApiError::Forbidden);
    }
    let fqdn = report
        .fqdn
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if fqdn != resource.fqdn {
        return Err(ApiError::BadRequest(format!(
            "report is for {fqdn:?} but the resource names {}",
            resource.fqdn
        )));
    }
    if report.answers.len() > MAX_ANSWERS {
        return Err(ApiError::BadRequest(format!(
            "a resolution may carry at most {MAX_ANSWERS} answers"
        )));
    }
    sqlx::query("DELETE FROM connector_leases WHERE org_id=$1 AND expires_at<=$2")
        .bind(&org)
        .bind(at)
        .execute(&mut *tx)
        .await?;
    let previous = active_leases(&mut tx, resource.id, node.id, at).await?;
    let session = connector_session(node.id);

    if !resource.enabled {
        withdraw_all(&mut tx, resource.id, node.id).await?;
        if !previous.is_empty() {
            bump_control_revision(&mut tx, &org).await?;
        }
        tx.commit().await?;
        return Err(ApiError::Conflict(
            "this resource is disabled; nothing is routed".into(),
        ));
    }

    if let Some(error) = report.error.as_deref() {
        // Keep existing leases: they still expire on their own TTL.
        let reason = clean_reason(error);
        record_report(&mut tx, &org, resource.id, node.id, "error", &reason, at).await?;
        tx.commit().await?;
        return Ok(Json(ResolutionOutcome {
            state: "error".into(),
            routes: previous.into_iter().collect(),
            lease_expires_at: None,
        }));
    }

    let endpoints = device_endpoints(&mut tx, &org).await?;
    let mut accepted: BTreeMap<String, u32> = BTreeMap::new();
    let mut blocked: Option<String> = None;
    for answer in &report.answers {
        let ip = match host_ip(&answer.address) {
            Ok(ip) => ip,
            Err(reason) => {
                blocked = Some(reason);
                break;
            }
        };
        let why = forbidden_reason(ip, &org).or_else(|| {
            endpoints
                .contains(&ip)
                .then_some("a device's WireGuard endpoint")
        });
        if let Some(why) = why {
            blocked = Some(format!("{fqdn} resolved to {ip} ({why})"));
            break;
        }
        let route = host_route(ip);
        let ttl = accepted
            .get(&route)
            .map_or(answer.ttl, |t| (*t).min(answer.ttl));
        accepted.insert(route, ttl);
    }

    if let Some(reason) = blocked {
        let reason = clean_reason(&if previous.is_empty() {
            reason
        } else {
            format!("possible DNS rebinding: {reason}")
        });
        withdraw_all(&mut tx, resource.id, node.id).await?;
        record_report(&mut tx, &org, resource.id, node.id, "blocked", &reason, at).await?;
        bump_control_revision(&mut tx, &org).await?;
        append_audit(
            &mut tx,
            org_uuid,
            &session,
            "connector.resolution_blocked",
            "network_resource",
            Some(&resource.id.to_string()),
            &serde_json::json!({
                "resource": resource.name,
                "fqdn": fqdn,
                "connector": node.id,
                "reason": reason,
                "withdrawn": previous,
            }),
        )
        .await?;
        tx.commit().await?;
        return Err(ApiError::Conflict(format!(
            "{reason}; every route for this resource was withdrawn"
        )));
    }

    let current: BTreeSet<String> = accepted.keys().cloned().collect();
    sqlx::query("DELETE FROM connector_leases WHERE resource_id=$1 AND node_id=$2")
        .bind(resource.id.to_string())
        .bind(node.id.to_string())
        .execute(&mut *tx)
        .await?;
    let mut earliest = None::<i64>;
    for (route, ttl) in &accepted {
        let expires_at = at + lease_seconds(*ttl);
        earliest = Some(earliest.map_or(expires_at, |e| e.min(expires_at)));
        sqlx::query(
            "INSERT INTO connector_leases(org_id,resource_id,node_id,route,ttl,resolved_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(&org)
        .bind(resource.id.to_string())
        .bind(node.id.to_string())
        .bind(route)
        .bind(i64::from(*ttl))
        .bind(at)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;
    }
    let state = if accepted.is_empty() {
        "empty"
    } else {
        "resolved"
    };
    record_report(&mut tx, &org, resource.id, node.id, state, "", at).await?;
    if current != previous {
        bump_control_revision(&mut tx, &org).await?;
        append_audit(
            &mut tx,
            org_uuid,
            &session,
            "connector.routes_changed",
            "network_resource",
            Some(&resource.id.to_string()),
            &serde_json::json!({
                "resource": resource.name,
                "fqdn": fqdn,
                "connector": node.id,
                "added": current.difference(&previous).collect::<Vec<_>>(),
                "removed": previous.difference(&current).collect::<Vec<_>>(),
            }),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Json(ResolutionOutcome {
        state: state.into(),
        routes: current.into_iter().collect(),
        lease_expires_at: earliest,
    }))
}

// ---------- read side for resources.rs ----------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct LeaseView {
    pub(crate) route: String,
    pub(crate) ttl: i64,
    pub(crate) resolved_at: i64,
    pub(crate) expires_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ConnectorReport {
    pub(crate) node_id: Uuid,
    /// resolved, empty, blocked or error.
    pub(crate) state: String,
    pub(crate) reason: String,
    pub(crate) reported_at: i64,
}

/// Unexpired leases and the latest report from every connector, per resource.
#[derive(Default)]
pub(crate) struct OrgLeases {
    leases: BTreeMap<(Uuid, Uuid), Vec<LeaseView>>,
    reports: BTreeMap<Uuid, Vec<ConnectorReport>>,
}

impl OrgLeases {
    pub(crate) async fn load(conn: &mut AnyConnection, org_id: &str) -> Result<Self, ApiError> {
        let at = now();
        let mut leases: BTreeMap<(Uuid, Uuid), Vec<LeaseView>> = BTreeMap::new();
        for row in sqlx::query(
            "SELECT resource_id,node_id,route,ttl,resolved_at,expires_at FROM connector_leases WHERE org_id=$1 AND expires_at>$2 ORDER BY route",
        )
        .bind(org_id)
        .bind(at)
        .fetch_all(&mut *conn)
        .await?
        {
            let resource = Uuid::parse_str(&row.try_get::<String, _>(0)?)
                .map_err(|_| ApiError::CorruptData)?;
            let node = Uuid::parse_str(&row.try_get::<String, _>(1)?)
                .map_err(|_| ApiError::CorruptData)?;
            leases.entry((resource, node)).or_default().push(LeaseView {
                route: row.try_get(2)?,
                ttl: row.try_get(3)?,
                resolved_at: row.try_get(4)?,
                expires_at: row.try_get(5)?,
            });
        }
        let mut reports: BTreeMap<Uuid, Vec<ConnectorReport>> = BTreeMap::new();
        for row in sqlx::query(
            "SELECT resource_id,node_id,state,reason,reported_at FROM connector_reports WHERE org_id=$1 ORDER BY node_id",
        )
        .bind(org_id)
        .fetch_all(&mut *conn)
        .await?
        {
            let resource = Uuid::parse_str(&row.try_get::<String, _>(0)?)
                .map_err(|_| ApiError::CorruptData)?;
            reports.entry(resource).or_default().push(ConnectorReport {
                node_id: Uuid::parse_str(&row.try_get::<String, _>(1)?)
                    .map_err(|_| ApiError::CorruptData)?,
                state: row.try_get(2)?,
                reason: row.try_get(3)?,
                reported_at: row.try_get(4)?,
            });
        }
        Ok(Self { leases, reports })
    }

    pub(crate) fn leases(&self, resource: Uuid, node: Uuid) -> &[LeaseView] {
        self.leases
            .get(&(resource, node))
            .map_or(&[], Vec::as_slice)
    }

    pub(crate) fn report(&self, resource: Uuid, node: Uuid) -> Option<&ConnectorReport> {
        self.reports
            .get(&resource)
            .and_then(|reports| reports.iter().find(|report| report.node_id == node))
    }

    pub(crate) fn reports(&self, resource: Uuid) -> Vec<ConnectorReport> {
        self.reports.get(&resource).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_ranges_cover_metadata_overlay_and_smuggled_ipv4() {
        let org = Uuid::new_v4().to_string();
        let overlay_v6 = org_ula_address(&org, 9);
        let overlay_v6 = overlay_v6.split_once('/').unwrap().0;
        for address in [
            "169.254.169.254",
            "100.100.100.200",
            "127.0.0.1",
            "0.0.0.0",
            "169.254.10.1",
            "100.64.0.7",
            "100.127.255.1",
            "224.0.0.251",
            "255.255.255.255",
            "::",
            "::1",
            "fe80::1",
            "ff02::1",
            "fd00:ec2::254",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a9fe:a9fe",
            overlay_v6,
        ] {
            let ip: IpAddr = address.parse().unwrap();
            assert!(forbidden_reason(ip, &org).is_some(), "{address}");
        }
        for address in [
            "10.20.0.5",
            "192.168.1.10",
            "203.0.113.9",
            "fd12::5",
            "2001:db8::1",
        ] {
            let ip: IpAddr = address.parse().unwrap();
            assert_eq!(forbidden_reason(ip, &org), None, "{address}");
        }
    }

    #[test]
    fn only_host_routes_are_accepted_and_ttl_is_clamped() {
        assert!(host_ip("10.0.0.5/32").is_ok());
        assert!(host_ip("fd12::5/128").is_ok());
        assert!(host_ip("10.0.0.0/24").is_err());
        assert!(host_ip("fd12::/64").is_err());
        assert!(host_ip("files.example.org").is_err());
        assert_eq!(lease_seconds(0), MIN_LEASE_SECS);
        assert_eq!(lease_seconds(120), 120);
        assert_eq!(lease_seconds(86_400), MAX_LEASE_SECS);
    }
}

#[cfg(test)]
pub(crate) mod integration {
    use super::*;
    use crate::resources::ResourceDetail;
    use crate::{
        app, AssertionClaims, JoinKeyResponse, OrgResponse, PeersResponse, RegisterResponse, Store,
        CONSOLE_ASSERTION_AUDIENCE, CONSOLE_ASSERTION_ISSUER,
    };
    use axum::{
        body::{to_bytes, Body},
        http::{Method, Request, StatusCode},
        response::Response,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use tower::ServiceExt;

    pub(crate) const SECRET: &[u8] = b"test-only-hmac-secret-at-least-32-bytes";

    #[derive(Clone)]
    pub(crate) struct Who {
        pub(crate) org: Uuid,
        user: String,
        role: &'static str,
        action: Option<&'static str>,
    }

    impl Who {
        pub(crate) fn person(org: Uuid, user: &str, role: &'static str) -> Self {
            Self {
                org,
                user: user.into(),
                role,
                action: None,
            }
        }
        /// Console assertions are single-use, so sign a fresh one per call.
        pub(crate) fn token(&self) -> String {
            let at = now();
            let claims = AssertionClaims {
                user_id: self.user.clone(),
                org_id: self.org,
                role: self.role.into(),
                name: self.user.clone(),
                email: format!("{}@example.com", self.user),
                iss: CONSOLE_ASSERTION_ISSUER.into(),
                aud: CONSOLE_ASSERTION_AUDIENCE.into(),
                iat: at,
                exp: at + 60,
                jti: Uuid::new_v4().to_string(),
                action: self.action.map(Into::into),
            };
            let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
            let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
            mac.update(payload.as_bytes());
            format!(
                "{payload}.{}",
                URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
            )
        }
    }

    pub(crate) async fn call(
        router: &Router,
        method: Method,
        uri: &str,
        body: serde_json::Value,
        token: Option<String>,
        extra: &[(&str, String)],
    ) -> Response {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        for (name, value) in extra {
            request = request.header(*name, value);
        }
        router
            .clone()
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }

    pub(crate) async fn json<T: serde::de::DeserializeOwned>(response: Response) -> T {
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
    }

    pub(crate) async fn error_text(response: Response) -> String {
        let value: serde_json::Value = json(response).await;
        value["error"].as_str().unwrap_or_default().to_owned()
    }

    pub(crate) async fn create_org(router: &Router, name: &str) -> OrgResponse {
        let id = Uuid::new_v4();
        let service = |action| Who {
            org: id,
            user: "operator-cli".into(),
            role: "service",
            action: Some(action),
        };
        let response = call(
            router,
            Method::POST,
            "/v1/orgs",
            serde_json::json!({"id":id,"name":name,"acl":{"version":1,"defaults":"same_tag","rules":[]}}),
            Some(service("bootstrap.prepare").token()),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let response = call(
            router,
            Method::POST,
            &format!("/v1/orgs/{id}/bootstrap-commit"),
            serde_json::json!({}),
            Some(service("bootstrap.commit").token()),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        json(response).await
    }

    pub(crate) async fn try_register(
        router: &Router,
        who: &Who,
        name: &str,
        capabilities: &[&str],
    ) -> Response {
        let key: JoinKeyResponse = json(
            call(
                router,
                Method::POST,
                &format!("/v1/orgs/{}/join-keys", who.org),
                serde_json::json!({"expires_in_seconds":60}),
                Some(who.token()),
                &[],
            )
            .await,
        )
        .await;
        call(
            router,
            Method::POST,
            "/v1/nodes/register",
            serde_json::json!({
                "join_key": key.key,
                "name": name,
                "wg_public_key": format!("{name}-key"),
                "capabilities": capabilities,
            }),
            None,
            &[],
        )
        .await
    }

    pub(crate) async fn register(
        router: &Router,
        who: &Who,
        name: &str,
        capabilities: &[&str],
    ) -> RegisterResponse {
        let response = try_register(router, who, name, capabilities).await;
        assert_eq!(response.status(), StatusCode::CREATED, "{name}");
        json(response).await
    }

    async fn peers(router: &Router, node: &RegisterResponse) -> PeersResponse {
        let response = call(
            router,
            Method::GET,
            &format!("/v1/nodes/{}/peers?ipv6=true", node.id),
            serde_json::Value::Null,
            Some(node.node_token.clone()),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        json(response).await
    }

    async fn routes_via(
        router: &Router,
        client: &RegisterResponse,
        via: &RegisterResponse,
    ) -> Vec<String> {
        peers(router, client)
            .await
            .peers
            .iter()
            .find(|peer| peer.id == via.id)
            .map(|peer| peer.allowed_ips.clone())
            .unwrap_or_default()
    }

    async fn create_dns_resource(
        router: &Router,
        who: &Who,
        fqdn: &str,
        connector: &RegisterResponse,
    ) -> ResourceDetail {
        let response = call(
            router,
            Method::POST,
            &format!("/v1/orgs/{}/networks", who.org),
            serde_json::json!({
                "name": format!("App {fqdn}"),
                "dns_target": fqdn,
                "ports": ["443"],
                "protocols": ["tcp"],
                "routing_peers": [{"node_id": connector.id}],
                "access": {"roles":["owner","admin","member"]},
            }),
            Some(who.token()),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        json(response).await
    }

    async fn report_as(
        router: &Router,
        node_id: Uuid,
        token: &str,
        resource: Uuid,
        fqdn: &str,
        answers: &[(&str, u32)],
    ) -> Response {
        call(
            router,
            Method::POST,
            &format!("/v1/nodes/{node_id}/connector/resolutions"),
            serde_json::json!({
                "resource_id": resource,
                "fqdn": fqdn,
                "answers": answers
                    .iter()
                    .map(|(address, ttl)| serde_json::json!({"address": address, "ttl": ttl}))
                    .collect::<Vec<_>>(),
            }),
            Some(token.to_owned()),
            &[],
        )
        .await
    }

    async fn report(
        router: &Router,
        node: &RegisterResponse,
        resource: Uuid,
        fqdn: &str,
        answers: &[(&str, u32)],
    ) -> Response {
        report_as(router, node.id, &node.node_token, resource, fqdn, answers).await
    }

    async fn detail(router: &Router, who: &Who, id: Uuid) -> ResourceDetail {
        json(detail_response(router, who, id).await).await
    }

    async fn detail_response(router: &Router, who: &Who, id: Uuid) -> Response {
        call(
            router,
            Method::GET,
            &format!("/v1/orgs/{}/networks/{id}", who.org),
            serde_json::Value::Null,
            Some(who.token()),
            &[],
        )
        .await
    }

    #[tokio::test]
    async fn forward_filter_connector_limits_leases_to_resource_ports() {
        let store = Store::memory().await.unwrap();
        let router = app(store, "ap-southeast-2".into(), SECRET);
        let org = create_org(&router, "connector-filter-org").await;
        let owner = Who::person(org.id, "owner-1", "owner");
        let connector = register(
            &router,
            &owner,
            "connector",
            &[CAP_APP_CONNECTOR, "forward-filter"],
        )
        .await;
        let laptop = register(&router, &owner, "laptop", &[]).await;
        let fqdn = "files.example.org.au";
        let resource = create_dns_resource(&router, &owner, fqdn, &connector).await;
        let response = report(
            &router,
            &connector,
            resource.resource.id,
            fqdn,
            &[("10.20.0.5", 120)],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let filter = peers(&router, &connector)
            .await
            .forward_filter
            .expect("forward filter for a capable connector");
        let lease_rules: Vec<_> = filter
            .allow
            .iter()
            .filter(|rule| rule.client == laptop.id && rule.destination == "10.20.0.5/32")
            .collect();
        assert_eq!(lease_rules.len(), 1, "{filter:?}");
        assert!(!lease_rules[0].service.all);
        assert_eq!(lease_rules[0].service.tcp, ["443"]);
        assert!(lease_rules[0].service.udp.is_empty());
    }

    #[tokio::test]
    async fn connector_leases_reach_authorised_clients_and_expire() {
        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), SECRET);
        let org = create_org(&router, "connector-org").await;
        let owner = Who::person(org.id, "owner-1", "owner");
        let connector = register(&router, &owner, "connector", &[CAP_APP_CONNECTOR]).await;
        let laptop = register(&router, &owner, "laptop", &[]).await;
        let fqdn = "files.example.org.au";
        let resource = create_dns_resource(&router, &owner, fqdn, &connector).await;
        assert_eq!(resource.status.state, "dns_not_resolved");

        let assigned: Assignments = json(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/connector/assignments", connector.id),
                serde_json::Value::Null,
                Some(connector.node_token.clone()),
                &[],
            )
            .await,
        )
        .await;
        assert_eq!(assigned.resources.len(), 1);
        assert_eq!(assigned.resources[0].fqdn, fqdn);

        let response = report(
            &router,
            &connector,
            resource.resource.id,
            "FILES.example.org.au.",
            &[("10.20.0.5", 120), ("fd12::5", 5), ("10.20.0.5", 60)],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let outcome: ResolutionOutcome = json(response).await;
        assert_eq!(outcome.routes, ["10.20.0.5/32", "fd12::5/128"]);
        let routes = routes_via(&router, &laptop, &connector).await;
        assert!(routes.contains(&"10.20.0.5/32".to_owned()), "{routes:?}");
        assert!(routes.contains(&"fd12::5/128".to_owned()), "{routes:?}");
        // The connector never routes its own answers back through a peer.
        assert!(peers(&router, &connector)
            .await
            .peers
            .iter()
            .all(|peer| peer.allowed_ips.iter().all(|r| !r.starts_with("10.20."))));
        let view = detail(&router, &owner, resource.resource.id).await;
        assert_eq!(view.status.state, "distributing");
        let state = view.connector.expect("connector state");
        assert_eq!(state.selected, Some(connector.id));
        let lifetimes: BTreeMap<_, _> = state
            .answers
            .iter()
            .map(|lease| {
                (
                    lease.route.clone(),
                    (lease.ttl, lease.expires_at - lease.resolved_at),
                )
            })
            .collect();
        assert_eq!(lifetimes["10.20.0.5/32"], (60, 60));
        assert_eq!(lifetimes["fd12::5/128"], (5, MIN_LEASE_SECS));

        // A changed answer withdraws the old addresses atomically.
        let response = report(
            &router,
            &connector,
            resource.resource.id,
            fqdn,
            &[("10.20.0.6", 900)],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let routes = routes_via(&router, &laptop, &connector).await;
        assert!(routes.contains(&"10.20.0.6/32".to_owned()));
        assert!(!routes.contains(&"10.20.0.5/32".to_owned()));
        assert!(!routes.contains(&"fd12::5/128".to_owned()));
        let view = detail(&router, &owner, resource.resource.id).await;
        let lease = &view.connector.unwrap().answers[0];
        assert_eq!(lease.expires_at - lease.resolved_at, MAX_LEASE_SECS);

        // TTL expiry withdraws the host route without any new report.
        sqlx::query("UPDATE connector_leases SET expires_at=$1")
            .bind(now() - 1)
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(!routes_via(&router, &laptop, &connector)
            .await
            .contains(&"10.20.0.6/32".to_owned()));
        let view = detail(&router, &owner, resource.resource.id).await;
        assert_eq!(view.status.state, "dns_not_resolved");
        assert!(view.status.clients.iter().all(|client| !client.receives));

        // An empty answer (NXDOMAIN) withdraws everything immediately.
        assert_eq!(
            report(
                &router,
                &connector,
                resource.resource.id,
                fqdn,
                &[("10.20.0.7", 60)]
            )
            .await
            .status(),
            StatusCode::OK
        );
        let outcome: ResolutionOutcome =
            json(report(&router, &connector, resource.resource.id, fqdn, &[]).await).await;
        assert_eq!(outcome.state, "empty");
        assert!(!routes_via(&router, &laptop, &connector)
            .await
            .contains(&"10.20.0.7/32".to_owned()));

        let actions: Vec<String> = sqlx::query_scalar(
            "SELECT action FROM audit_events WHERE org_id=$1 AND action LIKE 'connector.%'",
        )
        .bind(org.id.to_string())
        .fetch_all(&store.pool)
        .await
        .unwrap();
        assert!(actions
            .iter()
            .all(|action| action == "connector.routes_changed"));
        assert_eq!(actions.len(), 4, "only real route changes are audited");
    }

    #[tokio::test]
    async fn rebinding_and_unsafe_answers_fail_closed() {
        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), SECRET);
        let org = create_org(&router, "rebind-org").await;
        let owner = Who::person(org.id, "owner-1", "owner");
        let connector = register(&router, &owner, "connector", &[CAP_APP_CONNECTOR]).await;
        let laptop = register(&router, &owner, "laptop", &[]).await;
        let fqdn = "intranet.example.org.au";
        let resource = create_dns_resource(&router, &owner, fqdn, &connector).await;
        let id = resource.resource.id;
        assert_eq!(
            report(&router, &connector, id, fqdn, &[("10.30.0.5", 60)])
                .await
                .status(),
            StatusCode::OK
        );

        let response = report(
            &router,
            &connector,
            id,
            fqdn,
            &[("10.30.0.5", 60), ("169.254.169.254", 60)],
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let message = error_text(response).await;
        assert!(message.contains("rebinding"), "{message}");
        assert!(message.contains("metadata"), "{message}");
        assert!(!routes_via(&router, &laptop, &connector)
            .await
            .contains(&"10.30.0.5/32".to_owned()));
        let raw: serde_json::Value = json(detail_response(&router, &owner, id).await).await;
        assert_eq!(raw["status"]["state"], "dns_blocked");
        assert_eq!(raw["dns_resolution"], "blocked");
        assert!(raw["connector"]["blocked_reason"]
            .as_str()
            .unwrap()
            .contains("169.254.169.254"));
        assert!(raw["status"]["clients"]
            .as_array()
            .unwrap()
            .iter()
            .any(|client| client["reason"].as_str().unwrap().starts_with("blocked:")));
        let blocked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE org_id=$1 AND action='connector.resolution_blocked'",
        )
        .bind(org.id.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(blocked, 1);

        for answer in [
            "127.0.0.1",
            "fe80::1",
            "fd00:ec2::254",
            "224.0.0.251",
            "0.0.0.0",
            "::",
            "100.64.0.1",
            "::ffff:169.254.169.254",
            "10.30.0.0/24",
            "fd12::/64",
        ] {
            let response = report(&router, &connector, id, fqdn, &[(answer, 60)]).await;
            assert_eq!(response.status(), StatusCode::CONFLICT, "{answer}");
        }
        let leases: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM connector_leases")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(leases, 0);

        // A clean answer later resumes routing; the block stays in audit.
        assert_eq!(
            report(&router, &connector, id, fqdn, &[("10.30.0.9", 60)])
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            detail(&router, &owner, id).await.status.state,
            "distributing"
        );
    }

    #[tokio::test]
    async fn two_orgs_resolving_the_same_name_stay_isolated() {
        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), SECRET);
        let fqdn = "files.example.org.au";
        let mut sides = Vec::new();
        for (name, answer) in [("org-a", "10.1.0.5"), ("org-b", "10.2.0.5")] {
            let org = create_org(&router, name).await;
            let owner = Who::person(org.id, &format!("{name}-owner"), "owner");
            let connector = register(&router, &owner, "connector", &[CAP_APP_CONNECTOR]).await;
            let laptop = register(&router, &owner, "laptop", &[]).await;
            let resource = create_dns_resource(&router, &owner, fqdn, &connector).await;
            assert_eq!(
                report(
                    &router,
                    &connector,
                    resource.resource.id,
                    fqdn,
                    &[(answer, 60)]
                )
                .await
                .status(),
                StatusCode::OK
            );
            sides.push((owner, connector, laptop, resource, answer));
        }
        for (index, (_, connector, laptop, _, answer)) in sides.iter().enumerate() {
            let other = sides[1 - index].4;
            let routes = routes_via(&router, laptop, connector).await;
            assert!(routes.contains(&format!("{answer}/32")), "{routes:?}");
            assert!(!routes.contains(&format!("{other}/32")), "{routes:?}");
        }

        // Org A's connector cannot report for org B's resource, even with
        // the right name.
        let connector_a = &sides[0].1;
        let (owner_b, _, _, resource_b, _) = &sides[1];
        let response = report(
            &router,
            connector_a,
            resource_b.resource.id,
            fqdn,
            &[("10.9.9.9", 60)],
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let view = detail(&router, owner_b, resource_b.resource.id).await;
        let answers: Vec<_> = view
            .connector
            .unwrap()
            .answers
            .into_iter()
            .map(|lease| lease.route)
            .collect();
        assert_eq!(answers, ["10.2.0.5/32"]);
        // And org A's people cannot read org B's resource.
        let owner_a = &sides[0].0;
        let cross = call(
            &router,
            Method::GET,
            &format!(
                "/v1/orgs/{}/networks/{}",
                owner_b.org, resource_b.resource.id
            ),
            serde_json::Value::Null,
            Some(owner_a.token()),
            &[],
        )
        .await;
        assert!(cross.status().is_client_error());
    }

    #[tokio::test]
    async fn only_assigned_connectors_may_report() {
        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), SECRET);
        let org = create_org(&router, "auth-org").await;
        let owner = Who::person(org.id, "owner-1", "owner");
        let member = Who::person(org.id, "member-1", "member");
        let connector = register(&router, &owner, "connector", &[CAP_APP_CONNECTOR]).await;
        let plain = register(&router, &owner, "plain", &[]).await;
        let spare = register(&router, &owner, "spare-connector", &[CAP_APP_CONNECTOR]).await;
        let fqdn = "files.example.org.au";
        let resource = create_dns_resource(&router, &owner, fqdn, &connector).await;
        let id = resource.resource.id;

        // Members cannot create resources that drive connectors.
        let response = call(
            &router,
            Method::POST,
            &format!("/v1/orgs/{}/networks", org.id),
            serde_json::json!({"name":"Sneaky","dns_target":"x.example.org","access":{"roles":["member"]}}),
            Some(member.token()),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // A node without the capability cannot use either endpoint.
        assert_eq!(
            report(&router, &plain, id, fqdn, &[("10.40.0.5", 60)])
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{}/connector/assignments", plain.id),
                serde_json::Value::Null,
                Some(plain.node_token.clone()),
                &[],
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        // A connector that is not a routing peer of this resource is refused.
        assert_eq!(
            report(&router, &spare, id, fqdn, &[("10.40.0.5", 60)])
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        // Another node's token, and a mismatched name, are refused.
        assert_eq!(
            report_as(
                &router,
                connector.id,
                &plain.node_token,
                id,
                fqdn,
                &[("10.40.0.5", 60)]
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            report(
                &router,
                &connector,
                id,
                "other.example.org.au",
                &[("10.40.0.5", 60)]
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let leases: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM connector_leases")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(leases, 0);

        // A routing peer without the capability is listed but never selected.
        let response = call(
            &router,
            Method::POST,
            &format!("/v1/orgs/{}/networks", org.id),
            serde_json::json!({
                "name":"Plain only",
                "dns_target":"plain.example.org.au",
                "routing_peers":[{"node_id": plain.id}],
                "access":{"roles":["owner"]},
            }),
            Some(owner.token()),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let raw: serde_json::Value = json(response).await;
        assert_eq!(raw["status"]["state"], "no_routing_peer");
        assert_eq!(raw["status"]["routing_peers"][0]["state"], "not_connector");
    }
}
