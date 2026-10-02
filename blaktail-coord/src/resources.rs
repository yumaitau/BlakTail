//! Organisation-scoped network resources (NetBird-parity drafts 04 and 05).
//!
//! A resource names one private prefix (or an exact DNS target), the routing
//! peers that may carry it, and the clients allowed to receive it. Creating
//! or enabling a resource is the approval act: a node advertising a prefix
//! never makes it a resource route by itself. Distribution reuses the
//! existing peer map in `list_peers`: the selected routing peer's
//! `allowed_ips` gain the exact resource prefix for authorised clients only.
//! Device-level `approved_routes_json` keeps working unchanged alongside.

use crate::{
    admin::{authenticate_org_header, idempotency_key, require_scope, Envelope, Scope},
    append_audit, bump_control_revision, console_session, hash, ipam, now, org_ula_address,
    parse_acl_port_spec,
    permissions::{require, Permission},
    subject_in_group, Acl, ApiError, AppState, DeviceTag, Role, Session, Subject, NODE_ONLINE_SECS,
};
use axum::{
    extract::{Path as UrlPath, State},
    http::{HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::{any::AnyRow, AnyConnection, AnyPool, Row};
use std::collections::BTreeMap;
use std::net::IpAddr;
use uuid::Uuid;

const MAX_RESOURCES_PER_ORG: i64 = 256;
const MAX_ROUTING_PEERS: usize = 8;
const MAX_SELECTORS: usize = 16;
const DEFAULT_METRIC: u16 = 100;
const COLUMNS: &str = "id,name,description,kind,cidr,dns_target,ports_json,protocols_json,routing_peers_json,access_json,enabled,allow_nested_overlap,public_route_confirmed_by,revision,created_at,updated_at";
const RFC1918: [&str; 3] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
const IPV4_OVERLAY: &str = "100.64.0.0/10";
const IPV4_SPECIAL: [&str; 5] = [
    "0.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
];
const IPV6_SPECIAL: [&str; 5] = [
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "fe80::/10",
    "ff00::/8",
];

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/orgs/:org_id/networks",
            get(list_console).post(create_console),
        )
        .route(
            "/v1/orgs/:org_id/networks/:resource_id",
            get(get_console).put(update_console).delete(delete_console),
        )
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ResourceProtocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ResourceKind {
    Cidr,
    Dns,
}

/// Clients receive the resource when they match ANY selected role, device
/// tag or policy group. A group later removed from policy matches nobody.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResourceAccess {
    #[serde(default)]
    roles: Vec<Role>,
    #[serde(default)]
    tags: Vec<DeviceTag>,
    #[serde(default)]
    groups: Vec<String>,
}

impl ResourceAccess {
    fn matches(&self, subject: &Subject, groups: &BTreeMap<String, Vec<String>>) -> bool {
        self.roles.contains(&subject.role)
            || self.tags.iter().any(|tag| subject.tags.contains(tag))
            || self.groups.iter().any(|name| {
                groups
                    .get(name)
                    .is_some_and(|members| subject_in_group(subject, members))
            })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RoutingPeer {
    node_id: Uuid,
    /// Lower metric wins; ties break on node ID so selection is deterministic.
    #[serde(default = "default_metric")]
    metric: u16,
}

fn default_metric() -> u16 {
    DEFAULT_METRIC
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResourceInput {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    cidr: Option<String>,
    #[serde(default)]
    dns_target: Option<String>,
    #[serde(default)]
    ports: Vec<String>,
    #[serde(default)]
    protocols: Vec<ResourceProtocol>,
    #[serde(default)]
    routing_peers: Vec<RoutingPeer>,
    access: ResourceAccess,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    allow_nested_overlap: bool,
    #[serde(default)]
    confirm_public_route: bool,
    /// Only `true` (or omitted) is accepted: blaktaild always masquerades.
    #[serde(default)]
    masquerade: Option<bool>,
    #[serde(default)]
    etag: Option<String>,
    #[serde(default)]
    dry_run: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct NetworkResource {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    description: String,
    kind: ResourceKind,
    pub(crate) cidr: Option<String>,
    pub(crate) dns_target: Option<String>,
    /// `ipv4` or `ipv6` for CIDR resources.
    family: Option<String>,
    /// DNS targets are modelled only; resolution belongs to connectors.
    dns_resolution: Option<String>,
    ports: Vec<String>,
    protocols: Vec<ResourceProtocol>,
    /// Ports and protocols are recorded but the routing peer still forwards
    /// the whole prefix; see docs/network-resources.md.
    port_enforcement: String,
    routing_peers: Vec<RoutingPeer>,
    access: ResourceAccess,
    pub(crate) enabled: bool,
    allow_nested_overlap: bool,
    public_route_confirmed_by: Option<String>,
    /// Linux routing peers always masquerade overlay sources today.
    masquerade: String,
    pub(crate) revision: i64,
    pub(crate) etag: String,
    created_at: i64,
    updated_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RoutingPeerHealth {
    pub(crate) node_id: Uuid,
    pub(crate) name: Option<String>,
    metric: u16,
    /// primary, standby, offline, not_advertising, expired or missing.
    pub(crate) state: String,
    online: bool,
    last_seen_at: Option<i64>,
    covering_route: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ClientDistribution {
    pub(crate) node_id: Uuid,
    name: String,
    pub(crate) receives: bool,
    pub(crate) reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ResourceStatus {
    /// distributing, stale, no_routing_peer, dns_not_resolved or disabled.
    pub(crate) state: String,
    pub(crate) selected_routing_peer: Option<Uuid>,
    pub(crate) routing_peers: Vec<RoutingPeerHealth>,
    pub(crate) clients: Vec<ClientDistribution>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ResourceDetail {
    #[serde(flatten)]
    pub(crate) resource: NetworkResource,
    pub(crate) status: ResourceStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct DeviceRoutes {
    node_id: Uuid,
    name: String,
    display_name: Option<String>,
    online: bool,
    last_seen_at: Option<i64>,
    credential_expired: bool,
    advertised_routes: Vec<String>,
    approved_routes: Vec<String>,
    /// Advertised but never approved: these are not distributed.
    unapproved_routes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct NetworksOverview {
    pub(crate) resources: Vec<ResourceDetail>,
    pub(crate) device_routes: Vec<DeviceRoutes>,
}

struct OrgNode {
    id: Uuid,
    name: String,
    display_name: Option<String>,
    advertised: Vec<String>,
    approved: Vec<String>,
    last_seen_at: Option<i64>,
    credential_expires_at: i64,
    subject: Subject,
}

impl OrgNode {
    fn online(&self, at: i64) -> bool {
        self.last_seen_at
            .is_some_and(|seen| at - seen <= NODE_ONLINE_SECS)
    }
    fn label(&self) -> String {
        self.display_name
            .clone()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| self.name.clone())
    }
}

// ---------- CIDR helpers ----------

fn is_default_route(cidr: &str) -> bool {
    cidr == "0.0.0.0/0" || cidr == "::/0"
}

fn cidrs_overlap(left: &str, right: &str) -> bool {
    ipam::pools_overlap(left, right).unwrap_or(false)
}

fn cidr_within(inner: &str, outer: &str) -> bool {
    match (ipam::parse_cidr(inner), ipam::parse_cidr(outer)) {
        (Ok((inner_net, inner_prefix)), Ok((outer_net, outer_prefix))) => {
            inner_net.is_ipv4() == outer_net.is_ipv4()
                && inner_prefix >= outer_prefix
                && cidrs_overlap(inner, outer)
        }
        _ => false,
    }
}

fn org_overlay_ipv6(org_id: &str) -> String {
    let host_zero = org_ula_address(org_id, 0);
    let address = host_zero
        .split_once('/')
        .map_or(host_zero.as_str(), |(a, _)| a);
    format!("{address}/64")
}

struct CanonicalCidr {
    cidr: String,
    public: bool,
}

fn canonical_cidr(value: &str, org_id: &str) -> Result<CanonicalCidr, ApiError> {
    let value = value.trim();
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| ApiError::BadRequest(format!("{value} must use CIDR notation")))?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| ApiError::BadRequest(format!("{value} is not an IPv4 or IPv6 CIDR")))?;
    let prefix: u8 = prefix
        .parse()
        .ok()
        .filter(|prefix| *prefix <= if address.is_ipv4() { 32 } else { 128 })
        .ok_or_else(|| ApiError::BadRequest(format!("{value} has an invalid prefix")))?;
    let (network, _) = ipam::parse_cidr(&format!("{address}/{prefix}"))
        .map_err(|_| ApiError::BadRequest(format!("{value} is not a valid CIDR")))?;
    if network != address {
        return Err(ApiError::BadRequest(format!(
            "{value} is not a network address; use {network}/{prefix}"
        )));
    }
    let cidr = format!("{network}/{prefix}");
    let ipv6 = network.is_ipv6();
    if is_default_route(&cidr) {
        return Ok(CanonicalCidr { cidr, public: true });
    }
    let special: &[&str] = if ipv6 { &IPV6_SPECIAL } else { &IPV4_SPECIAL };
    if let Some(range) = special.iter().find(|range| cidrs_overlap(&cidr, range)) {
        return Err(ApiError::BadRequest(format!(
            "{cidr} overlaps reserved range {range} and cannot be routed"
        )));
    }
    let overlay = if ipv6 {
        org_overlay_ipv6(org_id)
    } else {
        IPV4_OVERLAY.to_owned()
    };
    if cidrs_overlap(&cidr, &overlay) {
        return Err(ApiError::Conflict(format!(
            "{cidr} overlaps the BlakTail overlay pool {overlay}"
        )));
    }
    let public = if ipv6 {
        !cidr_within(&cidr, "fc00::/7")
    } else {
        !RFC1918.iter().any(|private| cidr_within(&cidr, private))
    };
    Ok(CanonicalCidr { cidr, public })
}

fn canonical_dns_target(value: &str) -> Result<String, ApiError> {
    let target = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let invalid = || {
        ApiError::BadRequest(format!(
            "DNS target {value:?} must be an exact host name such as files.example.org.au"
        ))
    };
    if target.is_empty() || target.len() > 253 || target.parse::<IpAddr>().is_ok() {
        return Err(invalid());
    }
    let labels: Vec<&str> = target.split('.').collect();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
        || labels
            .last()
            .is_some_and(|tld| tld.chars().all(|c| c.is_ascii_digit()))
    {
        return Err(invalid());
    }
    if target.ends_with(".blaktail") || target == "localhost" || target.ends_with(".localhost") {
        return Err(ApiError::BadRequest(format!(
            "DNS target {target} is reserved for BlakTail device names or loopback"
        )));
    }
    Ok(target)
}

fn normalise_name(name: &str) -> Result<String, ApiError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "name must be 1-64 characters without control characters".into(),
        ));
    }
    Ok(name.to_owned())
}

fn etag(id: Uuid, revision: i64) -> String {
    hash(&format!("network-resource:{id}:{revision}"))[..32].to_owned()
}

// ---------- persistence ----------

fn json_column<T: serde::de::DeserializeOwned>(row: &AnyRow, index: usize) -> Result<T, ApiError> {
    serde_json::from_str(&row.try_get::<String, _>(index)?).map_err(|_| ApiError::CorruptData)
}

fn resource_from_row(row: &AnyRow) -> Result<NetworkResource, ApiError> {
    let id = Uuid::parse_str(&row.try_get::<String, _>(0)?).map_err(|_| ApiError::CorruptData)?;
    let kind = match row.try_get::<String, _>(3)?.as_str() {
        "cidr" => ResourceKind::Cidr,
        "dns" => ResourceKind::Dns,
        _ => return Err(ApiError::CorruptData),
    };
    let cidr: Option<String> = row.try_get(4)?;
    let revision: i64 = row.try_get(13)?;
    Ok(NetworkResource {
        id,
        name: row.try_get(1)?,
        description: row.try_get(2)?,
        kind,
        family: cidr
            .as_deref()
            .map(|cidr| if cidr.contains(':') { "ipv6" } else { "ipv4" }.to_owned()),
        cidr,
        dns_target: row.try_get(5)?,
        dns_resolution: (kind == ResourceKind::Dns).then(|| "not_resolved".to_owned()),
        ports: json_column(row, 6)?,
        protocols: json_column(row, 7)?,
        port_enforcement: "not_enforced".into(),
        routing_peers: json_column(row, 8)?,
        access: json_column(row, 9)?,
        enabled: row.try_get::<i64, _>(10)? != 0,
        allow_nested_overlap: row.try_get::<i64, _>(11)? != 0,
        public_route_confirmed_by: row.try_get(12)?,
        masquerade: "always".into(),
        revision,
        etag: etag(id, revision),
        created_at: row.try_get(14)?,
        updated_at: row.try_get(15)?,
    })
}

async fn load_resources(
    conn: &mut AnyConnection,
    org_id: &str,
) -> Result<Vec<NetworkResource>, ApiError> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM network_resources WHERE org_id=$1 ORDER BY LOWER(name),id"
    )))
    .bind(org_id)
    .fetch_all(&mut *conn)
    .await?;
    rows.iter().map(resource_from_row).collect()
}

async fn load_resource(
    conn: &mut AnyConnection,
    org_id: &str,
    id: Uuid,
) -> Result<NetworkResource, ApiError> {
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM network_resources WHERE org_id=$1 AND id=$2"
    )))
    .bind(org_id)
    .bind(id.to_string())
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(ApiError::NotFound)?;
    resource_from_row(&row)
}

async fn load_org_nodes(conn: &mut AnyConnection, org_id: &str) -> Result<Vec<OrgNode>, ApiError> {
    let rows = sqlx::query(
        "SELECT id,name,display_name,advertised_routes_json,approved_routes_json,last_seen_at,credential_expires_at,user_id,user_role,tags_json FROM nodes WHERE org_id=$1 AND revoked_at IS NULL AND deleted_at IS NULL ORDER BY name",
    )
    .bind(org_id)
    .fetch_all(&mut *conn)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(OrgNode {
                id: Uuid::parse_str(&row.try_get::<String, _>(0)?)
                    .map_err(|_| ApiError::CorruptData)?,
                name: row.try_get(1)?,
                display_name: row.try_get(2)?,
                advertised: json_column(row, 3).unwrap_or_default(),
                approved: json_column(row, 4).unwrap_or_default(),
                last_seen_at: row.try_get(5)?,
                credential_expires_at: row.try_get(6)?,
                subject: Subject::new(
                    row.try_get::<String, _>(8)?
                        .parse()
                        .map_err(|_| ApiError::CorruptData)?,
                    json_column(row, 9).unwrap_or_default(),
                )
                .with_user(row.try_get::<String, _>(7)?),
            })
        })
        .collect()
}

async fn load_acl(conn: &mut AnyConnection, org_id: &str) -> Result<Acl, ApiError> {
    let acl: String = sqlx::query_scalar("SELECT acl_json FROM orgs WHERE id=$1")
        .bind(org_id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(ApiError::NotFound)?;
    serde_json::from_str(&acl).map_err(|_| ApiError::CorruptData)
}

// ---------- evaluation ----------

/// Picks the routing peer that carries a CIDR resource: the lowest-metric
/// peer that is active, unexpired and advertises a covering prefix,
/// preferring online peers so an offline primary fails over to a standby.
fn evaluate_peers(
    resource: &NetworkResource,
    nodes: &[OrgNode],
    at: i64,
) -> (Option<Uuid>, Vec<RoutingPeerHealth>) {
    let mut ordered = resource.routing_peers.clone();
    ordered.sort_by_key(|peer| (peer.metric, peer.node_id));
    let mut health = Vec::new();
    let mut candidates = Vec::new();
    for peer in &ordered {
        let node = nodes.iter().find(|node| node.id == peer.node_id);
        let covering = match (node, resource.cidr.as_deref()) {
            (Some(node), Some(cidr)) => node
                .advertised
                .iter()
                .find(|route| {
                    if is_default_route(cidr) {
                        route.as_str() == cidr
                    } else {
                        cidr_within(cidr, route)
                    }
                })
                .cloned(),
            _ => None,
        };
        let online = node.is_some_and(|node| node.online(at));
        let state = match node {
            None => "missing",
            Some(node) if node.credential_expires_at <= at => "expired",
            Some(_) if resource.kind == ResourceKind::Cidr && covering.is_none() => {
                "not_advertising"
            }
            Some(_) => {
                candidates.push((peer.node_id, online));
                if online {
                    "standby"
                } else {
                    "offline"
                }
            }
        };
        health.push(RoutingPeerHealth {
            node_id: peer.node_id,
            name: node.map(OrgNode::label),
            metric: peer.metric,
            state: state.into(),
            online,
            last_seen_at: node.and_then(|node| node.last_seen_at),
            covering_route: covering,
        });
    }
    let selected = candidates
        .iter()
        .find(|(_, online)| *online)
        .or_else(|| candidates.first())
        .map(|(id, _)| *id);
    if resource.kind == ResourceKind::Cidr {
        if let Some(entry) = health
            .iter_mut()
            .find(|entry| Some(entry.node_id) == selected)
        {
            entry.state = "primary".into();
        }
    }
    (
        selected.filter(|_| resource.kind == ResourceKind::Cidr),
        health,
    )
}

fn evaluate(resource: NetworkResource, nodes: &[OrgNode], acl: &Acl, at: i64) -> ResourceDetail {
    let (selected, routing_peers) = evaluate_peers(&resource, nodes, at);
    let state = if !resource.enabled {
        "disabled"
    } else if resource.kind == ResourceKind::Dns {
        "dns_not_resolved"
    } else {
        match selected.and_then(|id| nodes.iter().find(|node| node.id == id)) {
            None => "no_routing_peer",
            Some(node) if node.online(at) => "distributing",
            Some(_) => "stale",
        }
    };
    let router = selected.and_then(|id| nodes.iter().find(|node| node.id == id));
    let default_route = resource.cidr.as_deref().is_some_and(is_default_route);
    let clients = nodes
        .iter()
        .filter(|node| Some(node.id) != selected)
        .map(|node| {
            let (receives, reason) = if resource.routing_peers.iter().any(|p| p.node_id == node.id)
            {
                (false, "routing peer for this resource".to_owned())
            } else if !resource.enabled {
                (false, "resource is disabled".to_owned())
            } else if !resource.access.matches(&node.subject, &acl.groups) {
                (false, "outside the resource's access selection".to_owned())
            } else if let Some(router) = router {
                if node.credential_expires_at <= at {
                    (false, "device credential expired".to_owned())
                } else if !acl.allows(&node.subject, &router.subject) {
                    (
                        false,
                        "access policy does not let it reach the routing peer".to_owned(),
                    )
                } else if default_route {
                    (
                        false,
                        format!("only when it selects {} as its exit node", router.label()),
                    )
                } else {
                    (true, format!("via {}", router.label()))
                }
            } else if resource.kind == ResourceKind::Dns {
                (false, "DNS target is not resolved yet".to_owned())
            } else {
                (false, "no routing peer can carry it".to_owned())
            };
            ClientDistribution {
                node_id: node.id,
                name: node.label(),
                receives,
                reason,
            }
        })
        .collect();
    ResourceDetail {
        status: ResourceStatus {
            state: state.into(),
            selected_routing_peer: selected,
            routing_peers,
            clients,
        },
        resource,
    }
}

/// The enabled CIDR resources an organisation currently distributes, each
/// pinned to its selected routing peer. Built once per peer-map request.
pub(crate) struct Distribution {
    routes: Vec<ActiveRoute>,
}

struct ActiveRoute {
    cidr: String,
    router: Uuid,
    routing_peers: Vec<Uuid>,
    access: ResourceAccess,
}

pub(crate) async fn load_distribution(
    pool: &AnyPool,
    org_id: &str,
) -> Result<Distribution, ApiError> {
    let mut conn = pool.acquire().await?;
    let resources = load_resources(&mut conn, org_id).await?;
    if !resources.iter().any(|resource| resource.enabled) {
        return Ok(Distribution { routes: Vec::new() });
    }
    let nodes = load_org_nodes(&mut conn, org_id).await?;
    let at = now();
    let routes = resources
        .into_iter()
        .filter(|resource| resource.enabled && resource.kind == ResourceKind::Cidr)
        .filter_map(|resource| {
            let (selected, _) = evaluate_peers(&resource, &nodes, at);
            Some(ActiveRoute {
                cidr: resource.cidr?,
                router: selected?,
                routing_peers: resource.routing_peers.iter().map(|p| p.node_id).collect(),
                access: resource.access,
            })
        })
        .collect();
    Ok(Distribution { routes })
}

impl Distribution {
    /// Exact resource prefixes `source` should route through `router`. The
    /// caller has already checked that policy lets `source` reach `router`.
    pub(crate) fn routes_via(
        &self,
        router: Uuid,
        source_id: Uuid,
        source: &Subject,
        acl: &Acl,
        exit_selected: bool,
    ) -> Vec<String> {
        self.routes
            .iter()
            .filter(|route| {
                route.router == router
                    && !route.routing_peers.contains(&source_id)
                    && (!is_default_route(&route.cidr) || exit_selected)
                    && route.access.matches(source, &acl.groups)
            })
            .map(|route| route.cidr.clone())
            .collect()
    }
}

/// Device-level approvals must not overlap a network resource prefix.
pub(crate) async fn ensure_routes_free(
    conn: &mut AnyConnection,
    org_id: Uuid,
    approved: &[String],
) -> Result<(), ApiError> {
    let resources = load_resources(conn, &org_id.to_string()).await?;
    for route in approved.iter().filter(|route| !is_default_route(route)) {
        if let Some(resource) = resources.iter().find(|resource| {
            resource
                .cidr
                .as_deref()
                .is_some_and(|cidr| !is_default_route(cidr) && cidrs_overlap(route, cidr))
        }) {
            return Err(ApiError::Conflict(format!(
                "route {route} overlaps network resource \"{}\" ({}); manage it from Networks",
                resource.name,
                resource.cidr.as_deref().unwrap_or_default()
            )));
        }
    }
    Ok(())
}

// ---------- validation ----------

struct Prepared {
    name: String,
    description: String,
    kind: ResourceKind,
    cidr: Option<CanonicalCidr>,
    dns_target: Option<String>,
    ports: Vec<String>,
    protocols: Vec<ResourceProtocol>,
    routing_peers: Vec<RoutingPeer>,
    access: ResourceAccess,
    enabled: bool,
    allow_nested_overlap: bool,
    public_route_confirmed_by: Option<String>,
}

fn prepare(
    input: &ResourceInput,
    org_id: &str,
    session: &Session,
    acl: &Acl,
    nodes: &[OrgNode],
    existing: Option<&NetworkResource>,
) -> Result<Prepared, ApiError> {
    let name = normalise_name(&input.name)?;
    let description = input.description.trim().to_owned();
    if description.chars().count() > 256 || description.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "description must be at most 256 characters without control characters".into(),
        ));
    }
    if input.masquerade == Some(false) {
        return Err(ApiError::BadRequest(
            "routing peers always masquerade overlay traffic; forwarding without NAT is not supported by blaktaild yet".into(),
        ));
    }
    let (kind, cidr, dns_target) = match (&input.cidr, &input.dns_target) {
        (Some(cidr), None) => (
            ResourceKind::Cidr,
            Some(canonical_cidr(cidr, org_id)?),
            None,
        ),
        (None, Some(target)) => (ResourceKind::Dns, None, Some(canonical_dns_target(target)?)),
        _ => {
            return Err(ApiError::BadRequest(
                "set exactly one of cidr or dns_target".into(),
            ))
        }
    };

    let mut ports = Vec::new();
    if input.ports.len() > MAX_SELECTORS {
        return Err(ApiError::BadRequest(
            "a resource may list at most 16 port ranges".into(),
        ));
    }
    for spec in &input.ports {
        let (start, end) = parse_acl_port_spec(spec).map_err(|_| {
            ApiError::BadRequest(format!(
                "port {spec:?} must be 1-65535 or a start-end range"
            ))
        })?;
        ports.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
    }
    ports.sort();
    ports.dedup();
    let mut protocols = input.protocols.clone();
    protocols.sort();
    protocols.dedup();
    if protocols.contains(&ResourceProtocol::Icmp) && !ports.is_empty() {
        return Err(ApiError::BadRequest(
            "ICMP constraints cannot name destination ports".into(),
        ));
    }

    let mut access = input.access.clone();
    access.roles.sort_by_key(|role| role.as_str());
    access.roles.dedup();
    access.tags.sort();
    access.tags.dedup();
    access.groups = access
        .groups
        .iter()
        .map(|group| group.trim().to_owned())
        .collect();
    access.groups.sort();
    access.groups.dedup();
    if access.roles.is_empty() && access.tags.is_empty() && access.groups.is_empty() {
        return Err(ApiError::BadRequest(
            "select at least one role, device tag or policy group that may use this resource"
                .into(),
        ));
    }
    if access.tags.len() > MAX_SELECTORS || access.groups.len() > MAX_SELECTORS {
        return Err(ApiError::BadRequest(
            "access is limited to 16 tags and 16 groups".into(),
        ));
    }
    if let Some(group) = access
        .groups
        .iter()
        .find(|group| !acl.groups.contains_key(group.as_str()))
    {
        return Err(ApiError::BadRequest(format!(
            "policy group {group} does not exist; define it in Access policy first"
        )));
    }

    if input.routing_peers.len() > MAX_ROUTING_PEERS {
        return Err(ApiError::BadRequest(
            "a resource may have at most 8 routing peers".into(),
        ));
    }
    let mut routing_peers = input.routing_peers.clone();
    routing_peers.sort_by_key(|peer| (peer.metric, peer.node_id));
    for (index, peer) in routing_peers.iter().enumerate() {
        if !(1..=9999).contains(&peer.metric) {
            return Err(ApiError::BadRequest(
                "routing peer metric must be 1-9999".into(),
            ));
        }
        if routing_peers[..index]
            .iter()
            .any(|other| other.node_id == peer.node_id)
        {
            return Err(ApiError::BadRequest(format!(
                "routing peer {} is listed twice",
                peer.node_id
            )));
        }
        let already = existing.is_some_and(|resource| {
            resource
                .routing_peers
                .iter()
                .any(|other| other.node_id == peer.node_id)
        });
        if !already && !nodes.iter().any(|node| node.id == peer.node_id) {
            return Err(ApiError::BadRequest(format!(
                "routing peer {} is not an active device in this organisation",
                peer.node_id
            )));
        }
    }

    let mut public_route_confirmed_by = None;
    if let Some(cidr) = cidr.as_ref().filter(|cidr| cidr.public) {
        let unchanged = existing.and_then(|resource| {
            (resource.cidr.as_deref() == Some(cidr.cidr.as_str()))
                .then(|| resource.public_route_confirmed_by.clone())
                .flatten()
        });
        public_route_confirmed_by = match unchanged {
            Some(confirmed) => Some(confirmed),
            None => {
                if !input.confirm_public_route {
                    return Err(ApiError::BadRequest(format!(
                        "{} is a default or public route; an organisation owner must confirm it explicitly",
                        cidr.cidr
                    )));
                }
                if session.role != Role::Owner {
                    return Err(ApiError::Forbidden);
                }
                Some(session.user_id.clone())
            }
        };
    }

    Ok(Prepared {
        name,
        description,
        kind,
        cidr,
        dns_target,
        ports,
        protocols,
        routing_peers,
        access,
        enabled: input.enabled,
        allow_nested_overlap: input.allow_nested_overlap,
        public_route_confirmed_by,
    })
}

/// Rejects overlap with the overlay (already done in `canonical_cidr`),
/// other resources and device-approved routes in the same organisation only.
/// Nested (strictly more- or less-specific) resource prefixes are allowed
/// when explicitly requested: WireGuard then picks the longest match.
async fn check_overlaps(
    conn: &mut AnyConnection,
    org_id: &str,
    prepared: &Prepared,
    nodes: &[OrgNode],
    exclude: Option<Uuid>,
) -> Result<(), ApiError> {
    let Some(cidr) = prepared.cidr.as_ref().map(|cidr| cidr.cidr.as_str()) else {
        return Ok(());
    };
    if is_default_route(cidr) {
        return Ok(());
    }
    let mut conflicts = Vec::new();
    for other in load_resources(conn, org_id).await? {
        if Some(other.id) == exclude {
            continue;
        }
        let Some(other_cidr) = other.cidr.as_deref() else {
            continue;
        };
        if is_default_route(other_cidr) || !cidrs_overlap(cidr, other_cidr) {
            continue;
        }
        if other_cidr == cidr || !prepared.allow_nested_overlap {
            conflicts.push(format!(
                "overlaps network resource \"{}\" ({other_cidr})",
                other.name
            ));
        }
    }
    for node in nodes {
        for route in node
            .approved
            .iter()
            .filter(|route| !is_default_route(route) && cidrs_overlap(cidr, route))
        {
            conflicts.push(format!(
                "overlaps route {route} approved on device {}; withdraw that approval first",
                node.label()
            ));
        }
    }
    if conflicts.is_empty() {
        Ok(())
    } else {
        Err(ApiError::Conflict(format!(
            "{cidr} {}",
            conflicts.join("; ")
        )))
    }
}

// ---------- mutations ----------

fn audit_details(resource: &NetworkResource, via: &str) -> serde_json::Value {
    serde_json::json!({
        "name": resource.name,
        "cidr": resource.cidr,
        "dns_target": resource.dns_target,
        "enabled": resource.enabled,
        "routing_peers": resource.routing_peers,
        "access": resource.access,
        "ports": resource.ports,
        "protocols": resource.protocols,
        "public_route_confirmed_by": resource.public_route_confirmed_by,
        "revision": resource.revision,
        "via": via,
    })
}

async fn create_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: Uuid,
    session: &Session,
    input: &ResourceInput,
    via: &str,
) -> Result<ResourceDetail, ApiError> {
    let org = org_id.to_string();
    let acl = load_acl(tx, &org).await?;
    let nodes = load_org_nodes(tx, &org).await?;
    let prepared = prepare(input, &org, session, &acl, &nodes, None)?;
    check_overlaps(tx, &org, &prepared, &nodes, None).await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM network_resources WHERE org_id=$1")
        .bind(&org)
        .fetch_one(&mut **tx)
        .await?;
    if count >= MAX_RESOURCES_PER_ORG {
        return Err(ApiError::Conflict(
            "an organisation may define at most 256 network resources".into(),
        ));
    }
    let id = Uuid::new_v4();
    let at = now();
    write_resource(tx, &org, id, &prepared, at, None).await?;
    let resource = load_resource(tx, &org, id).await?;
    append_audit(
        tx,
        org_id,
        session,
        "network_resource.created",
        "network_resource",
        Some(&id.to_string()),
        &audit_details(&resource, via),
    )
    .await?;
    Ok(evaluate(resource, &nodes, &acl, at))
}

async fn update_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: Uuid,
    id: Uuid,
    session: &Session,
    input: &ResourceInput,
    via: &str,
) -> Result<ResourceDetail, ApiError> {
    let org = org_id.to_string();
    let expected = input
        .etag
        .as_deref()
        .ok_or_else(|| ApiError::BadRequest("etag is required".into()))?;
    let current = load_resource(tx, &org, id).await?;
    if current.etag != expected {
        return Err(ApiError::PreconditionFailed);
    }
    let acl = load_acl(tx, &org).await?;
    let nodes = load_org_nodes(tx, &org).await?;
    let prepared = prepare(input, &org, session, &acl, &nodes, Some(&current))?;
    check_overlaps(tx, &org, &prepared, &nodes, Some(id)).await?;
    let at = now();
    write_resource(tx, &org, id, &prepared, at, Some(current.revision)).await?;
    let resource = load_resource(tx, &org, id).await?;
    let mut details = audit_details(&resource, via);
    details["previous_revision"] = serde_json::json!(current.revision);
    details["previous_cidr"] = serde_json::json!(current.cidr);
    details["previous_enabled"] = serde_json::json!(current.enabled);
    append_audit(
        tx,
        org_id,
        session,
        "network_resource.updated",
        "network_resource",
        Some(&id.to_string()),
        &details,
    )
    .await?;
    Ok(evaluate(resource, &nodes, &acl, at))
}

async fn write_resource(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org: &str,
    id: Uuid,
    prepared: &Prepared,
    at: i64,
    previous_revision: Option<i64>,
) -> Result<(), ApiError> {
    let kind = match prepared.kind {
        ResourceKind::Cidr => "cidr",
        ResourceKind::Dns => "dns",
    };
    let cidr = prepared.cidr.as_ref().map(|cidr| cidr.cidr.clone());
    let query = match previous_revision {
        None => sqlx::query(
            "INSERT INTO network_resources(name,description,kind,cidr,dns_target,ports_json,protocols_json,routing_peers_json,access_json,enabled,allow_nested_overlap,public_route_confirmed_by,updated_at,id,org_id,revision,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,1,$13)",
        ),
        Some(_) => sqlx::query(
            "UPDATE network_resources SET name=$1,description=$2,kind=$3,cidr=$4,dns_target=$5,ports_json=$6,protocols_json=$7,routing_peers_json=$8,access_json=$9,enabled=$10,allow_nested_overlap=$11,public_route_confirmed_by=$12,updated_at=$13,revision=revision+1 WHERE id=$14 AND org_id=$15 AND revision=$16",
        ),
    };
    let result = query
        .bind(&prepared.name)
        .bind(&prepared.description)
        .bind(kind)
        .bind(cidr)
        .bind(&prepared.dns_target)
        .bind(serde_json::to_string(&prepared.ports).unwrap())
        .bind(serde_json::to_string(&prepared.protocols).unwrap())
        .bind(serde_json::to_string(&prepared.routing_peers).unwrap())
        .bind(serde_json::to_string(&prepared.access).unwrap())
        .bind(i64::from(prepared.enabled))
        .bind(i64::from(prepared.allow_nested_overlap))
        .bind(&prepared.public_route_confirmed_by)
        .bind(at)
        .bind(id.to_string())
        .bind(org);
    let result = match previous_revision {
        Some(revision) => result.bind(revision),
        None => result,
    }
    .execute(&mut **tx)
    .await
    .map_err(crate::conflict(
        "a network resource with that name already exists",
    ))?;
    if previous_revision.is_some() && result.rows_affected() == 0 {
        return Err(ApiError::PreconditionFailed);
    }
    Ok(())
}

async fn delete_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: Uuid,
    id: Uuid,
    session: &Session,
    if_match: Option<&str>,
    via: &str,
) -> Result<(), ApiError> {
    let org = org_id.to_string();
    let current = load_resource(tx, &org, id).await?;
    if if_match.is_some_and(|expected| expected != current.etag) {
        return Err(ApiError::PreconditionFailed);
    }
    sqlx::query("DELETE FROM network_resources WHERE id=$1 AND org_id=$2")
        .bind(id.to_string())
        .bind(&org)
        .execute(&mut **tx)
        .await?;
    append_audit(
        tx,
        org_id,
        session,
        "network_resource.deleted",
        "network_resource",
        Some(&id.to_string()),
        &audit_details(&current, via),
    )
    .await
}

async fn overview(state: &AppState, org_id: Uuid) -> Result<NetworksOverview, ApiError> {
    let mut conn = state.store.pool.acquire().await?;
    overview_conn(&mut conn, org_id).await
}

pub(crate) async fn overview_conn(
    conn: &mut AnyConnection,
    org_id: Uuid,
) -> Result<NetworksOverview, ApiError> {
    let org = org_id.to_string();
    let acl = load_acl(conn, &org).await?;
    let nodes = load_org_nodes(conn, &org).await?;
    let at = now();
    let resources = load_resources(conn, &org)
        .await?
        .into_iter()
        .map(|resource| evaluate(resource, &nodes, &acl, at))
        .collect();
    let device_routes = nodes
        .iter()
        .filter(|node| !node.advertised.is_empty() || !node.approved.is_empty())
        .map(|node| DeviceRoutes {
            node_id: node.id,
            name: node.name.clone(),
            display_name: node.display_name.clone(),
            online: node.online(at),
            last_seen_at: node.last_seen_at,
            credential_expired: node.credential_expires_at <= at,
            advertised_routes: node.advertised.clone(),
            approved_routes: node.approved.clone(),
            unapproved_routes: node
                .advertised
                .iter()
                .filter(|route| !node.approved.contains(route))
                .cloned()
                .collect(),
        })
        .collect();
    Ok(NetworksOverview {
        resources,
        device_routes,
    })
}

async fn detail(state: &AppState, org_id: Uuid, id: Uuid) -> Result<ResourceDetail, ApiError> {
    let org = org_id.to_string();
    let mut conn = state.store.pool.acquire().await?;
    let resource = load_resource(&mut conn, &org, id).await?;
    let acl = load_acl(&mut conn, &org).await?;
    let nodes = load_org_nodes(&mut conn, &org).await?;
    Ok(evaluate(resource, &nodes, &acl, now()))
}

/// Runs a mutation; `dry_run` validates everything then rolls back.
async fn create(
    state: &AppState,
    org_id: Uuid,
    session: &Session,
    input: &ResourceInput,
    via: &str,
) -> Result<(StatusCode, ResourceDetail), ApiError> {
    let mut tx = state.store.pool.begin().await?;
    // Bumping first takes the org row lock on PostgreSQL, serialising
    // concurrent resource writers before the overlap check.
    bump_control_revision(&mut tx, org_id.to_string()).await?;
    let created = create_in_tx(&mut tx, org_id, session, input, via).await?;
    if input.dry_run {
        return Ok((StatusCode::OK, created));
    }
    tx.commit().await?;
    Ok((StatusCode::CREATED, created))
}

async fn update(
    state: &AppState,
    org_id: Uuid,
    id: Uuid,
    session: &Session,
    input: &ResourceInput,
    via: &str,
) -> Result<ResourceDetail, ApiError> {
    let mut tx = state.store.pool.begin().await?;
    bump_control_revision(&mut tx, org_id.to_string()).await?;
    let updated = update_in_tx(&mut tx, org_id, id, session, input, via).await?;
    if !input.dry_run {
        tx.commit().await?;
    }
    Ok(updated)
}

async fn delete(
    state: &AppState,
    org_id: Uuid,
    id: Uuid,
    session: &Session,
    headers: &HeaderMap,
    via: &str,
) -> Result<StatusCode, ApiError> {
    let if_match = headers
        .get("if-match")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .trim()
                .trim_start_matches("W/")
                .trim_matches('"')
                .to_owned()
        });
    let mut tx = state.store.pool.begin().await?;
    bump_control_revision(&mut tx, org_id.to_string()).await?;
    delete_in_tx(&mut tx, org_id, id, session, if_match.as_deref(), via).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

fn parse_input(value: serde_json::Value) -> Result<ResourceInput, ApiError> {
    serde_json::from_value(value)
        .map_err(|error| ApiError::BadRequest(format!("invalid network resource: {error}")))
}

// ---------- change drafts ----------

/// One live resource as an editable draft item: the create/update body plus
/// its id. Server-managed fields (revision, etag, status) are left out.
fn draft_item(resource: &NetworkResource) -> serde_json::Value {
    let mut item = serde_json::json!({
        "id": resource.id,
        "name": resource.name,
        "description": resource.description,
        "ports": resource.ports,
        "protocols": resource.protocols,
        "routing_peers": resource.routing_peers,
        "access": resource.access,
        "enabled": resource.enabled,
        "allow_nested_overlap": resource.allow_nested_overlap,
    });
    match (&resource.cidr, &resource.dns_target) {
        (Some(cidr), _) => item["cidr"] = serde_json::json!(cidr),
        (None, Some(target)) => item["dns_target"] = serde_json::json!(target),
        _ => {}
    }
    item
}

/// Changes when any resource in the organisation is created, edited or
/// deleted; a draft records it as its resources base.
fn set_etag(resources: &[NetworkResource]) -> String {
    let mut parts: Vec<String> = resources
        .iter()
        .map(|resource| format!("{}:{}", resource.id, resource.revision))
        .collect();
    parts.sort();
    hash(&format!("network-resources:{}", parts.join(",")))[..32].to_owned()
}

pub(crate) async fn draft_snapshot(
    conn: &mut AnyConnection,
    org_id: Uuid,
) -> Result<(Vec<serde_json::Value>, String), ApiError> {
    let resources = load_resources(conn, &org_id.to_string()).await?;
    Ok((
        resources.iter().map(draft_item).collect(),
        set_etag(&resources),
    ))
}

#[derive(Debug, Serialize)]
pub(crate) struct ResourceChange {
    pub(crate) op: &'static str,
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) before: Option<serde_json::Value>,
    pub(crate) after: Option<serde_json::Value>,
}

/// Canonical form used to decide whether a draft item changes a resource.
fn comparable(input: &ResourceInput) -> serde_json::Value {
    serde_json::json!([
        input.name.trim(),
        input.description.trim(),
        input.cidr,
        input.dns_target,
        input.ports,
        input.protocols,
        input.routing_peers,
        input.access,
        input.enabled,
        input.allow_nested_overlap,
    ])
}

/// Makes the organisation's resources match `desired` (the full set) through
/// the ordinary create/update/delete validators and writers, inside the
/// caller's transaction. The caller bumps the control revision.
pub(crate) async fn apply_draft_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: Uuid,
    session: &Session,
    desired: &[serde_json::Value],
    via: &str,
) -> Result<Vec<ResourceChange>, ApiError> {
    let org = org_id.to_string();
    let live = load_resources(tx, &org).await?;
    let mut wanted: Vec<(Option<Uuid>, ResourceInput)> = Vec::new();
    for (index, item) in desired.iter().enumerate() {
        let mut object = item
            .as_object()
            .cloned()
            .ok_or_else(|| ApiError::BadRequest(format!("resources[{index}] must be an object")))?;
        let id = match object.remove("id") {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => Some(
                value
                    .as_str()
                    .and_then(|v| Uuid::parse_str(v).ok())
                    .ok_or_else(|| {
                        ApiError::BadRequest(format!("resources[{index}].id is not a UUID"))
                    })?,
            ),
        };
        if object.contains_key("etag") || object.contains_key("dry_run") {
            return Err(ApiError::BadRequest(format!(
                "resources[{index}] may not set etag or dry_run; the draft tracks them"
            )));
        }
        if let Some(id) = id {
            if !live.iter().any(|resource| resource.id == id) {
                return Err(ApiError::BadRequest(format!(
                    "resources[{index}] names resource {id}, which does not exist in this organisation"
                )));
            }
            if wanted.iter().any(|(other, _)| *other == Some(id)) {
                return Err(ApiError::BadRequest(format!(
                    "resource {id} appears twice in the draft"
                )));
            }
        }
        let input: ResourceInput = serde_json::from_value(serde_json::Value::Object(object))
            .map_err(|error| ApiError::BadRequest(format!("resources[{index}]: {error}")))?;
        wanted.push((id, input));
    }
    let mut changes = Vec::new();
    // Deletions first so a replacement can reuse a name or prefix.
    for resource in &live {
        if wanted.iter().any(|(id, _)| *id == Some(resource.id)) {
            continue;
        }
        delete_in_tx(tx, org_id, resource.id, session, Some(&resource.etag), via).await?;
        changes.push(ResourceChange {
            op: "delete",
            id: resource.id,
            name: resource.name.clone(),
            before: Some(draft_item(resource)),
            after: None,
        });
    }
    for (id, input) in wanted.iter_mut() {
        let Some(id) = *id else { continue };
        let current = live
            .iter()
            .find(|resource| resource.id == id)
            .expect("checked above");
        let before: ResourceInput = serde_json::from_value({
            let mut item = draft_item(current);
            item.as_object_mut().map(|o| o.remove("id"));
            item
        })
        .map_err(|_| ApiError::CorruptData)?;
        if comparable(&before) == comparable(input) {
            continue;
        }
        input.etag = Some(current.etag.clone());
        let updated = update_in_tx(tx, org_id, id, session, input, via).await?;
        changes.push(ResourceChange {
            op: "update",
            id,
            name: updated.resource.name.clone(),
            before: Some(draft_item(current)),
            after: Some(draft_item(&updated.resource)),
        });
    }
    for (id, input) in &wanted {
        if id.is_some() {
            continue;
        }
        let created = create_in_tx(tx, org_id, session, input, via).await?;
        changes.push(ResourceChange {
            op: "create",
            id: created.resource.id,
            name: created.resource.name.clone(),
            before: None,
            after: Some(draft_item(&created.resource)),
        });
    }
    Ok(changes)
}

// ---------- console routes ----------

async fn list_console(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<NetworksOverview>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewNetwork)?;
    Ok(Json(overview(&s, org_id).await?))
}

async fn get_console(
    State(s): State<AppState>,
    UrlPath((org_id, resource_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<ResourceDetail>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewNetwork)?;
    Ok(Json(detail(&s, org_id, resource_id).await?))
}

async fn create_console(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(value): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<ResourceDetail>), ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageNetworks)?;
    let input = parse_input(value)?;
    let (status, created) = create(&s, org_id, &session, &input, "console").await?;
    Ok((status, Json(created)))
}

async fn update_console(
    State(s): State<AppState>,
    UrlPath((org_id, resource_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(value): Json<serde_json::Value>,
) -> Result<Json<ResourceDetail>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageNetworks)?;
    let input = parse_input(value)?;
    Ok(Json(
        update(&s, org_id, resource_id, &session, &input, "console").await?,
    ))
}

async fn delete_console(
    State(s): State<AppState>,
    UrlPath((org_id, resource_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageNetworks)?;
    delete(&s, org_id, resource_id, &session, &headers, "console").await
}

// ---------- /api/v1 automation routes ----------

pub(crate) async fn api_list(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Envelope<Vec<ResourceDetail>>>, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::DevicesRead)?;
    require(&caller.session, Permission::ViewNetwork)?;
    Ok(Json(Envelope {
        data: overview(&s, org_id).await?.resources,
        next_cursor: None,
    }))
}

pub(crate) async fn api_get(
    State(s): State<AppState>,
    UrlPath(resource_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Envelope<ResourceDetail>>, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::DevicesRead)?;
    require(&caller.session, Permission::ViewNetwork)?;
    Ok(Json(Envelope {
        data: detail(&s, org_id, resource_id).await?,
        next_cursor: None,
    }))
}

pub(crate) async fn api_create(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(value): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::RoutesWrite)?;
    require(&caller.session, Permission::ManageNetworks)?;
    let request_hash = hash(&value.to_string());
    let input = parse_input(value)?;
    let actor = caller.session.user_id.clone();
    let idempotency = idempotency_key(&headers)?.filter(|_| !input.dry_run);
    if let Some(key) = &idempotency {
        if let Some(row) = sqlx::query(
            "SELECT request_hash,status,body_json FROM api_idempotency WHERE org_id=$1 AND client_id=$2 AND key_hash=$3",
        )
        .bind(org_id.to_string())
        .bind(&actor)
        .bind(hash(key))
        .fetch_optional(&s.store.pool)
        .await?
        {
            if row.try_get::<String, _>(0)? != request_hash {
                return Err(ApiError::Conflict(
                    "Idempotency-Key was reused with a different request".into(),
                ));
            }
            let status = u16::try_from(row.try_get::<i64, _>(1)?).unwrap_or(201);
            let body: String = row.try_get(2)?;
            return Ok((
                StatusCode::from_u16(status).unwrap_or(StatusCode::CREATED),
                Json(serde_json::from_str(&body).map_err(|_| ApiError::CorruptData)?),
            ));
        }
    }
    let mut tx = s.store.pool.begin().await?;
    bump_control_revision(&mut tx, org_id.to_string()).await?;
    let created = create_in_tx(&mut tx, org_id, &caller.session, &input, "admin_api").await?;
    let body = serde_json::to_value(Envelope {
        data: created,
        next_cursor: None,
    })
    .map_err(|_| ApiError::CorruptData)?;
    if input.dry_run {
        return Ok((StatusCode::OK, Json(body)));
    }
    if let Some(key) = &idempotency {
        sqlx::query(
            "INSERT INTO api_idempotency(org_id,client_id,key_hash,method,path,request_hash,status,body_json,created_at) VALUES($1,$2,$3,'POST','/api/v1/network-resources',$4,201,$5,$6)",
        )
        .bind(org_id.to_string())
        .bind(&actor)
        .bind(hash(key))
        .bind(&request_hash)
        .bind(body.to_string())
        .bind(now())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(body)))
}

pub(crate) async fn api_update(
    State(s): State<AppState>,
    UrlPath(resource_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(value): Json<serde_json::Value>,
) -> Result<Json<Envelope<ResourceDetail>>, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::RoutesWrite)?;
    require(&caller.session, Permission::ManageNetworks)?;
    let input = parse_input(value)?;
    Ok(Json(Envelope {
        data: update(
            &s,
            org_id,
            resource_id,
            &caller.session,
            &input,
            "admin_api",
        )
        .await?,
        next_cursor: None,
    }))
}

pub(crate) async fn api_delete(
    State(s): State<AppState>,
    UrlPath(resource_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::RoutesWrite)?;
    require(&caller.session, Permission::ManageNetworks)?;
    delete(
        &s,
        org_id,
        resource_id,
        &caller.session,
        &headers,
        "admin_api",
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app, AssertionClaims, JoinKeyResponse, OrgResponse, PeersResponse, RegisterResponse, Store,
        CONSOLE_ASSERTION_AUDIENCE, CONSOLE_ASSERTION_ISSUER,
    };
    use axum::{
        body::{to_bytes, Body},
        http::{Method, Request},
        response::Response,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use tower::ServiceExt;

    const SECRET: &[u8] = b"test-only-hmac-secret-at-least-32-bytes";

    #[derive(Clone)]
    struct Who {
        org: Uuid,
        user: String,
        role: &'static str,
        action: Option<&'static str>,
    }

    impl Who {
        fn person(org: Uuid, user: &str, role: &'static str) -> Self {
            Self {
                org,
                user: user.into(),
                role,
                action: None,
            }
        }
        /// Console assertions are single-use, so sign a fresh one per call.
        fn token(&self) -> String {
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

    async fn call(
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

    async fn json<T: serde::de::DeserializeOwned>(response: Response) -> T {
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
    }

    async fn error_text(response: Response) -> String {
        let value: serde_json::Value = json(response).await;
        value["error"].as_str().unwrap_or_default().to_owned()
    }

    async fn create_org(router: &Router, name: &str) -> OrgResponse {
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

    async fn register(router: &Router, who: &Who, name: &str, routes: &[&str]) -> RegisterResponse {
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
        let response = call(
            router,
            Method::POST,
            "/v1/nodes/register",
            serde_json::json!({
                "join_key": key.key,
                "name": name,
                "wg_public_key": format!("{name}-key"),
                "advertised_routes": routes,
            }),
            None,
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        json(response).await
    }

    async fn peers(router: &Router, node: &RegisterResponse, query: &str) -> PeersResponse {
        let response = call(
            router,
            Method::GET,
            &format!("/v1/nodes/{}/peers{query}", node.id),
            serde_json::Value::Null,
            Some(node.node_token.clone()),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        json(response).await
    }

    fn routes_via(snapshot: &PeersResponse, router: &RegisterResponse) -> Vec<String> {
        snapshot
            .peers
            .iter()
            .find(|peer| peer.id == router.id)
            .map(|peer| peer.allowed_ips.clone())
            .unwrap_or_default()
    }

    async fn create_resource(router: &Router, who: &Who, body: serde_json::Value) -> Response {
        call(
            router,
            Method::POST,
            &format!("/v1/orgs/{}/networks", who.org),
            body,
            Some(who.token()),
            &[],
        )
        .await
    }

    #[tokio::test]
    async fn dual_stack_overlap_and_public_route_rules() {
        let store = Store::memory().await.unwrap();
        let router = app(store, "ap-southeast-2".into(), SECRET);
        let org = create_org(&router, "overlap-org").await;
        let owner = Who::person(org.id, "owner-1", "owner");
        let admin = Who::person(org.id, "admin-1", "admin");
        let everyone = serde_json::json!({"roles":["owner","admin","member"]});
        let make =
            |name: &str, cidr: &str| serde_json::json!({"name":name,"cidr":cidr,"access":everyone});

        for (name, cidr) in [
            ("Office v4", "10.10.0.0/16"),
            ("Office v6", "fd12:3456::/48"),
            ("Depot v4", "192.168.50.0/24"),
            ("Depot v6", "fd99:1::/48"),
        ] {
            let response = create_resource(&router, &admin, make(name, cidr)).await;
            assert_eq!(response.status(), StatusCode::CREATED, "{name}");
        }
        for (name, cidr) in [
            ("Nested v4", "10.10.1.0/24"),
            ("Nested v6", "fd12:3456:0:1::/64"),
            ("Duplicate v4", "10.10.0.0/16"),
        ] {
            let response = create_resource(&router, &admin, make(name, cidr)).await;
            assert_eq!(response.status(), StatusCode::CONFLICT, "{name}");
            assert!(error_text(response)
                .await
                .contains("overlaps network resource"));
        }
        let mut nested = make("Nested v4", "10.10.1.0/24");
        nested["allow_nested_overlap"] = serde_json::json!(true);
        assert_eq!(
            create_resource(&router, &admin, nested).await.status(),
            StatusCode::CREATED
        );
        let mut duplicate = make("Duplicate v4", "10.10.0.0/16");
        duplicate["allow_nested_overlap"] = serde_json::json!(true);
        assert_eq!(
            create_resource(&router, &admin, duplicate).await.status(),
            StatusCode::CONFLICT
        );

        let overlay_v6 = org_overlay_ipv6(&org.id.to_string());
        for cidr in ["100.64.1.0/24", overlay_v6.as_str()] {
            let response = create_resource(&router, &admin, make("Overlay", cidr)).await;
            assert_eq!(response.status(), StatusCode::CONFLICT, "{cidr}");
            assert!(error_text(response).await.contains("overlay pool"));
        }
        for cidr in [
            "10.0.0.1/8",
            "127.0.0.0/8",
            "fe80::/64",
            "not-a-cidr",
            "10.0.0.0/33",
        ] {
            assert_eq!(
                create_resource(&router, &admin, make("Invalid", cidr))
                    .await
                    .status(),
                StatusCode::BAD_REQUEST,
                "{cidr}"
            );
        }

        for cidr in ["0.0.0.0/0", "::/0", "203.0.113.0/24", "2001:db8::/32"] {
            assert_eq!(
                create_resource(&router, &owner, make("Public", cidr))
                    .await
                    .status(),
                StatusCode::BAD_REQUEST,
                "{cidr} needs explicit confirmation"
            );
            let mut confirmed = make("Public", cidr);
            confirmed["confirm_public_route"] = serde_json::json!(true);
            assert_eq!(
                create_resource(&router, &admin, confirmed.clone())
                    .await
                    .status(),
                StatusCode::FORBIDDEN,
                "{cidr} needs an owner"
            );
        }
        let mut default_route = make("Internet", "0.0.0.0/0");
        default_route["confirm_public_route"] = serde_json::json!(true);
        let created: ResourceDetail =
            json(create_resource(&router, &owner, default_route).await).await;
        assert_eq!(
            created.resource.public_route_confirmed_by.as_deref(),
            Some("owner-1")
        );

        let dns: ResourceDetail = json(
            create_resource(
                &router,
                &admin,
                serde_json::json!({"name":"Files","dns_target":"Files.Example.org.au.","access":everyone}),
            )
            .await,
        )
        .await;
        assert_eq!(
            dns.resource.dns_target.as_deref(),
            Some("files.example.org.au")
        );
        assert_eq!(dns.resource.dns_resolution.as_deref(), Some("not_resolved"));
        assert_eq!(dns.status.state, "dns_not_resolved");
        for body in [
            serde_json::json!({"name":"Wild","dns_target":"*.example.org","access":everyone}),
            serde_json::json!({"name":"Both","cidr":"10.99.0.0/24","dns_target":"a.example.org","access":everyone}),
            serde_json::json!({"name":"Nobody","cidr":"10.99.0.0/24","access":{}}),
            serde_json::json!({"name":"Ghost group","cidr":"10.99.0.0/24","access":{"groups":["ghost"]}}),
            serde_json::json!({"name":"No NAT","cidr":"10.99.0.0/24","access":everyone,"masquerade":false}),
            serde_json::json!({"name":"ICMP port","cidr":"10.99.0.0/24","access":everyone,"protocols":["icmp"],"ports":["22"]}),
        ] {
            assert_eq!(
                create_resource(&router, &admin, body.clone())
                    .await
                    .status(),
                StatusCode::BAD_REQUEST,
                "{body}"
            );
        }

        // Device-approved routes and resources cannot overlap in either direction.
        let legacy = register(&router, &owner, "legacy-router", &["172.16.5.0/24"]).await;
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &format!("/v1/orgs/{}/nodes/{}/routes", org.id, legacy.id),
                serde_json::json!({"approved_routes":["172.16.5.0/24"]}),
                Some(owner.token()),
                &[],
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        let response = create_resource(&router, &admin, make("Wider", "172.16.0.0/16")).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(error_text(response)
            .await
            .contains("approved on device legacy-router"));
        let depot_router = register(&router, &owner, "depot-router", &["192.168.50.0/25"]).await;
        for (uri, extra) in [
            (
                format!("/v1/orgs/{}/nodes/{}/routes", org.id, depot_router.id),
                vec![],
            ),
            (
                format!("/api/v1/devices/{}/routes", depot_router.id),
                vec![("x-blaktail-organisation", org.id.to_string())],
            ),
        ] {
            let response = call(
                &router,
                Method::PUT,
                &uri,
                serde_json::json!({"approved_routes":["192.168.50.0/25"]}),
                Some(owner.token()),
                &extra,
            )
            .await;
            assert_eq!(response.status(), StatusCode::CONFLICT, "{uri}");
            assert!(error_text(response).await.contains("Depot v4"));
        }

        let dry: ResourceDetail = json(
            create_resource(
                &router,
                &admin,
                serde_json::json!({"name":"Preview","cidr":"10.77.0.0/24","access":everyone,"dry_run":true}),
            )
            .await,
        )
        .await;
        assert_eq!(dry.resource.cidr.as_deref(), Some("10.77.0.0/24"));
        let overview: NetworksOverview = json(
            call(
                &router,
                Method::GET,
                &format!("/v1/orgs/{}/networks", org.id),
                serde_json::Value::Null,
                Some(Who::person(org.id, "member-1", "member").token()),
                &[],
            )
            .await,
        )
        .await;
        assert!(!overview
            .resources
            .iter()
            .any(|item| item.resource.name == "Preview"));
        assert!(overview
            .device_routes
            .iter()
            .any(|device| device.unapproved_routes == vec!["192.168.50.0/25".to_owned()]));
    }

    #[tokio::test]
    async fn resource_routes_reach_only_authorised_clients_and_withdraw() {
        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), SECRET);
        let org = create_org(&router, "routing-org").await;
        let owner = Who::person(org.id, "owner-1", "owner");
        let alice = Who::person(org.id, "alice", "admin");
        let bob = Who::person(org.id, "bob", "admin");
        let member = Who::person(org.id, "member-1", "member");
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &format!("/v1/orgs/{}/acl", org.id),
                serde_json::json!({"version":1,"defaults":"same_tag","groups":{"field":["alice"]},"rules":[]}),
                Some(owner.token()),
                &[],
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        let subnet_router = register(&router, &owner, "router-one", &["10.20.0.0/16"]).await;
        let client_a = register(&router, &alice, "alice-laptop", &[]).await;
        let client_b = register(&router, &bob, "bob-laptop", &[]).await;

        // Advertised but unapproved: never distributed.
        assert_eq!(
            routes_via(&peers(&router, &client_a, "").await, &subnet_router),
            vec!["100.64.0.1/32"]
        );

        let body = serde_json::json!({
            "name": "Field office",
            "cidr": "10.20.1.0/24",
            "ports": ["443", "8000-8080"],
            "protocols": ["tcp"],
            "routing_peers": [{"node_id": subnet_router.id, "metric": 10}],
            "access": {"groups": ["field"]},
        });
        assert_eq!(
            create_resource(&router, &member, body.clone())
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let revision_before: i64 =
            sqlx::query_scalar("SELECT control_revision FROM orgs WHERE id=$1")
                .bind(org.id.to_string())
                .fetch_one(&store.pool)
                .await
                .unwrap();
        let created: ResourceDetail =
            json(create_resource(&router, &owner, body.clone()).await).await;
        assert_eq!(created.status.state, "distributing");
        assert_eq!(created.status.selected_routing_peer, Some(subnet_router.id));
        assert_eq!(created.resource.port_enforcement, "not_enforced");
        assert_eq!(created.resource.masquerade, "always");
        let alice_view = created
            .status
            .clients
            .iter()
            .find(|client| client.node_id == client_a.id)
            .unwrap();
        assert!(alice_view.receives);
        assert!(
            !created
                .status
                .clients
                .iter()
                .find(|client| client.node_id == client_b.id)
                .unwrap()
                .receives
        );
        let revision_after: i64 =
            sqlx::query_scalar("SELECT control_revision FROM orgs WHERE id=$1")
                .bind(org.id.to_string())
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert!(revision_after > revision_before);

        // Exactly the resource prefix, not the router's wider advertisement.
        assert_eq!(
            routes_via(&peers(&router, &client_a, "").await, &subnet_router),
            vec!["100.64.0.1/32", "10.20.1.0/24"]
        );
        assert_eq!(
            routes_via(&peers(&router, &client_b, "").await, &subnet_router),
            vec!["100.64.0.1/32"]
        );
        assert!(peers(&router, &subnet_router, "")
            .await
            .peers
            .iter()
            .all(|peer| !peer.allowed_ips.contains(&"10.20.1.0/24".to_owned())));

        let path = format!("/v1/orgs/{}/networks/{}", org.id, created.resource.id);
        let mut disable = body.clone();
        disable["enabled"] = serde_json::json!(false);
        disable["etag"] = serde_json::json!("stale");
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &path,
                disable.clone(),
                Some(owner.token()),
                &[]
            )
            .await
            .status(),
            StatusCode::PRECONDITION_FAILED
        );
        disable["etag"] = serde_json::json!(created.resource.etag);
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &path,
                disable.clone(),
                Some(member.token()),
                &[]
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let disabled: ResourceDetail = json(
            call(
                &router,
                Method::PUT,
                &path,
                disable,
                Some(owner.token()),
                &[],
            )
            .await,
        )
        .await;
        assert_eq!(disabled.status.state, "disabled");
        assert_eq!(disabled.resource.revision, 2);
        assert_eq!(
            routes_via(&peers(&router, &client_a, "").await, &subnet_router),
            vec!["100.64.0.1/32"]
        );
        let mut enable = body.clone();
        enable["etag"] = serde_json::json!(disabled.resource.etag);
        let enabled: ResourceDetail = json(
            call(
                &router,
                Method::PUT,
                &path,
                enable,
                Some(owner.token()),
                &[],
            )
            .await,
        )
        .await;
        assert!(
            routes_via(&peers(&router, &client_a, "").await, &subnet_router)
                .contains(&"10.20.1.0/24".to_owned())
        );

        assert_eq!(
            call(
                &router,
                Method::DELETE,
                &path,
                serde_json::Value::Null,
                Some(member.token()),
                &[]
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &router,
                Method::DELETE,
                &path,
                serde_json::Value::Null,
                Some(owner.token()),
                &[("if-match", format!("\"{}\"", enabled.resource.etag))],
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            routes_via(&peers(&router, &client_a, "").await, &subnet_router),
            vec!["100.64.0.1/32"]
        );
        assert_eq!(
            call(
                &router,
                Method::GET,
                &path,
                serde_json::Value::Null,
                Some(owner.token()),
                &[]
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        let actions: Vec<String> = sqlx::query_scalar(
            "SELECT action FROM audit_events WHERE org_id=$1 AND target_type='network_resource' ORDER BY created_at,action",
        )
        .bind(org.id.to_string())
        .fetch_all(&store.pool)
        .await
        .unwrap();
        assert!(actions.contains(&"network_resource.created".to_owned()));
        assert!(actions.contains(&"network_resource.updated".to_owned()));
        assert!(actions.contains(&"network_resource.deleted".to_owned()));
    }

    #[tokio::test]
    async fn unadvertised_prefixes_and_default_routes_stay_opt_in() {
        let store = Store::memory().await.unwrap();
        let router = app(store, "ap-southeast-2".into(), SECRET);
        let org = create_org(&router, "exit-org").await;
        let owner = Who::person(org.id, "owner-1", "owner");
        let exit_router = register(&router, &owner, "exit-one", &["0.0.0.0/0"]).await;
        let lan_router = register(&router, &owner, "lan-one", &["10.60.0.0/24"]).await;
        let client = register(&router, &owner, "client-one", &[]).await;
        let everyone = serde_json::json!({"roles":["owner","admin","member"]});

        // The routing peer does not advertise this prefix, so nothing flows.
        let orphan: ResourceDetail = json(
            create_resource(
                &router,
                &owner,
                serde_json::json!({"name":"Orphan","cidr":"10.61.0.0/24","access":everyone,
                    "routing_peers":[{"node_id":lan_router.id}]}),
            )
            .await,
        )
        .await;
        assert_eq!(orphan.status.state, "no_routing_peer");
        assert_eq!(orphan.status.routing_peers[0].state, "not_advertising");
        let snapshot = peers(&router, &client, "").await;
        assert_eq!(routes_via(&snapshot, &lan_router), vec!["100.64.0.2/32"]);

        let internet: ResourceDetail = json(
            create_resource(
                &router,
                &owner,
                serde_json::json!({"name":"Internet","cidr":"0.0.0.0/0","access":everyone,
                    "confirm_public_route":true,
                    "routing_peers":[{"node_id":exit_router.id}]}),
            )
            .await,
        )
        .await;
        assert_eq!(internet.status.state, "distributing");
        let without_exit = peers(&router, &client, "").await;
        assert!(!without_exit.exit_node_active);
        assert!(!routes_via(&without_exit, &exit_router).contains(&"0.0.0.0/0".to_owned()));
        let with_exit = peers(&router, &client, "?exit_node=exit-one").await;
        assert!(with_exit.exit_node_active);
        assert!(routes_via(&with_exit, &exit_router).contains(&"0.0.0.0/0".to_owned()));
    }

    #[tokio::test]
    async fn failover_prefers_online_lowest_metric_routing_peer() {
        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), SECRET);
        let org = create_org(&router, "failover-org").await;
        let owner = Who::person(org.id, "owner-1", "owner");
        let primary = register(&router, &owner, "router-a", &["10.30.0.0/24"]).await;
        let standby = register(&router, &owner, "router-b", &["10.30.0.0/16"]).await;
        let client = register(&router, &owner, "client", &[]).await;
        let created: ResourceDetail = json(
            create_resource(
                &router,
                &owner,
                serde_json::json!({"name":"Site","cidr":"10.30.0.0/24",
                    "access":{"roles":["owner"]},
                    "routing_peers":[{"node_id":standby.id,"metric":20},{"node_id":primary.id,"metric":10}]}),
            )
            .await,
        )
        .await;
        assert_eq!(created.status.selected_routing_peer, Some(primary.id));
        let snapshot = peers(&router, &client, "").await;
        assert!(routes_via(&snapshot, &primary).contains(&"10.30.0.0/24".to_owned()));
        assert!(!routes_via(&snapshot, &standby).contains(&"10.30.0.0/24".to_owned()));
        // A standby routing peer never routes its own resource via the primary.
        assert!(!routes_via(&peers(&router, &standby, "").await, &primary)
            .contains(&"10.30.0.0/24".to_owned()));

        sqlx::query("UPDATE nodes SET last_seen_at=$1 WHERE id=$2")
            .bind(now() - 3600)
            .bind(primary.id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        let snapshot = peers(&router, &client, "").await;
        assert!(!routes_via(&snapshot, &primary).contains(&"10.30.0.0/24".to_owned()));
        assert!(routes_via(&snapshot, &standby).contains(&"10.30.0.0/24".to_owned()));
        let detail: ResourceDetail = json(
            call(
                &router,
                Method::GET,
                &format!("/v1/orgs/{}/networks/{}", org.id, created.resource.id),
                serde_json::Value::Null,
                Some(owner.token()),
                &[],
            )
            .await,
        )
        .await;
        assert_eq!(detail.status.selected_routing_peer, Some(standby.id));
        let states: Vec<_> = detail
            .status
            .routing_peers
            .iter()
            .map(|peer| (peer.node_id, peer.state.as_str()))
            .collect();
        assert_eq!(
            states,
            vec![(primary.id, "offline"), (standby.id, "primary")]
        );
    }

    #[tokio::test]
    async fn organisations_with_the_same_cidr_stay_isolated() {
        let store = Store::memory().await.unwrap();
        let router = app(store, "ap-southeast-2".into(), SECRET);
        let first = create_org(&router, "first-org").await;
        let second = create_org(&router, "second-org").await;
        let first_owner = Who::person(first.id, "owner-a", "owner");
        let second_owner = Who::person(second.id, "owner-b", "owner");
        let first_router = register(&router, &first_owner, "router-a", &["10.40.0.0/24"]).await;
        let second_router = register(&router, &second_owner, "router-b", &["10.40.0.0/24"]).await;
        let second_client = register(&router, &second_owner, "client-b", &[]).await;
        let resource = |peer: Uuid| {
            serde_json::json!({"name":"Shared plan","cidr":"10.40.0.0/24",
                "access":{"roles":["owner"]},"routing_peers":[{"node_id":peer}]})
        };
        let first_resource: ResourceDetail =
            json(create_resource(&router, &first_owner, resource(first_router.id)).await).await;
        assert_eq!(
            create_resource(&router, &second_owner, resource(first_router.id))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            create_resource(&router, &second_owner, resource(second_router.id))
                .await
                .status(),
            StatusCode::CREATED
        );
        let snapshot = peers(&router, &second_client, "").await;
        assert!(snapshot.peers.iter().all(|peer| peer.id != first_router.id));
        assert!(routes_via(&snapshot, &second_router).contains(&"10.40.0.0/24".to_owned()));

        let foreign = format!(
            "/v1/orgs/{}/networks/{}",
            second.id, first_resource.resource.id
        );
        assert_eq!(
            call(
                &router,
                Method::GET,
                &foreign,
                serde_json::Value::Null,
                Some(second_owner.token()),
                &[]
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call(
                &router,
                Method::DELETE,
                &foreign,
                serde_json::Value::Null,
                Some(second_owner.token()),
                &[]
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        let cross = format!("/v1/orgs/{}/networks", first.id);
        assert_eq!(
            call(
                &router,
                Method::GET,
                &cross,
                serde_json::Value::Null,
                Some(second_owner.token()),
                &[]
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        let api = format!("/api/v1/network-resources/{}", first_resource.resource.id);
        assert_eq!(
            call(
                &router,
                Method::GET,
                &api,
                serde_json::Value::Null,
                Some(second_owner.token()),
                &[("x-blaktail-organisation", second.id.to_string())],
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn admin_api_is_idempotent_and_etag_guarded() {
        let store = Store::memory().await.unwrap();
        let router = app(store, "ap-southeast-2".into(), SECRET);
        let org = create_org(&router, "api-org").await;
        let owner = Who::person(org.id, "owner-1", "owner");
        let member = Who::person(org.id, "member-1", "member");
        let header = ("x-blaktail-organisation", org.id.to_string());
        let body =
            serde_json::json!({"name":"Plant","cidr":"10.70.0.0/24","access":{"roles":["admin"]}});
        let key = ("idempotency-key", "create-plant-0001".to_owned());
        assert_eq!(
            call(
                &router,
                Method::POST,
                "/api/v1/network-resources",
                body.clone(),
                Some(member.token()),
                std::slice::from_ref(&header),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let first = call(
            &router,
            Method::POST,
            "/api/v1/network-resources",
            body.clone(),
            Some(owner.token()),
            &[header.clone(), key.clone()],
        )
        .await;
        assert_eq!(first.status(), StatusCode::CREATED);
        let first: serde_json::Value = json(first).await;
        let replay = call(
            &router,
            Method::POST,
            "/api/v1/network-resources",
            body.clone(),
            Some(owner.token()),
            &[header.clone(), key.clone()],
        )
        .await;
        assert_eq!(replay.status(), StatusCode::CREATED);
        let replay: serde_json::Value = json(replay).await;
        assert_eq!(first["data"]["id"], replay["data"]["id"]);
        let mut changed = body.clone();
        changed["name"] = serde_json::json!("Other");
        assert_eq!(
            call(
                &router,
                Method::POST,
                "/api/v1/network-resources",
                changed,
                Some(owner.token()),
                &[header.clone(), key],
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        let listed: serde_json::Value = json(
            call(
                &router,
                Method::GET,
                "/api/v1/network-resources",
                serde_json::Value::Null,
                Some(member.token()),
                std::slice::from_ref(&header),
            )
            .await,
        )
        .await;
        assert_eq!(listed["data"].as_array().unwrap().len(), 1);

        let path = format!(
            "/api/v1/network-resources/{}",
            first["data"]["id"].as_str().unwrap()
        );
        let mut update = body.clone();
        update["description"] = serde_json::json!("Pump controllers");
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &path,
                update.clone(),
                Some(owner.token()),
                std::slice::from_ref(&header)
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        update["etag"] = serde_json::json!("0000");
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &path,
                update.clone(),
                Some(owner.token()),
                std::slice::from_ref(&header)
            )
            .await
            .status(),
            StatusCode::PRECONDITION_FAILED
        );
        update["etag"] = first["data"]["etag"].clone();
        let updated: serde_json::Value = json(
            call(
                &router,
                Method::PUT,
                &path,
                update.clone(),
                Some(owner.token()),
                std::slice::from_ref(&header),
            )
            .await,
        )
        .await;
        assert_eq!(updated["data"]["revision"], 2);
        // Replaying the same etag after a successful write must fail.
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &path,
                update,
                Some(owner.token()),
                std::slice::from_ref(&header)
            )
            .await
            .status(),
            StatusCode::PRECONDITION_FAILED
        );
        assert_eq!(
            call(
                &router,
                Method::DELETE,
                &path,
                serde_json::Value::Null,
                Some(owner.token()),
                &[
                    header.clone(),
                    (
                        "if-match",
                        first["data"]["etag"].as_str().unwrap().to_owned()
                    )
                ],
            )
            .await
            .status(),
            StatusCode::PRECONDITION_FAILED
        );
        assert_eq!(
            call(
                &router,
                Method::DELETE,
                &path,
                serde_json::Value::Null,
                Some(owner.token()),
                &[header]
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
    }

    #[tokio::test]
    async fn upgrade_keeps_existing_approved_routes_distributing() {
        for sql in [
            include_str!("../migrations/sqlite/0019_network_resources.sql"),
            include_str!("../migrations/postgres/0019_network_resources.sql"),
        ] {
            assert!(sql.contains("CREATE TABLE IF NOT EXISTS network_resources"));
            assert!(!sql.to_ascii_lowercase().contains("alter table"));
            assert!(!sql.contains("UPDATE"));
        }
        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), SECRET);
        let org = create_org(&router, "upgrade-org").await;
        let owner = Who::person(org.id, "owner-1", "owner");
        let subnet_router = register(
            &router,
            &owner,
            "router-one",
            &["10.50.0.0/24", "0.0.0.0/0"],
        )
        .await;
        let client = register(&router, &owner, "client-one", &[]).await;
        assert_eq!(
            call(
                &router,
                Method::PUT,
                &format!("/v1/orgs/{}/nodes/{}/routes", org.id, subnet_router.id),
                serde_json::json!({"approved_routes":["10.50.0.0/24","0.0.0.0/0"]}),
                Some(owner.token()),
                &[],
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        let before = peers(&router, &client, "?exit_node=router-one").await;
        // Simulate a pre-slot-19 database holding approvals, then apply slot 19.
        sqlx::raw_sql("DROP TABLE network_resources")
            .execute(&store.pool)
            .await
            .unwrap();
        sqlx::raw_sql(include_str!(
            "../migrations/sqlite/0019_network_resources.sql"
        ))
        .execute(&store.pool)
        .await
        .unwrap();
        let after = peers(&router, &client, "?exit_node=router-one").await;
        // Same order and content as distribution before resources existed.
        assert_eq!(
            routes_via(&after, &subnet_router),
            vec!["100.64.0.1/32", "0.0.0.0/0", "10.50.0.0/24"]
        );
        assert_eq!(
            routes_via(&before, &subnet_router),
            routes_via(&after, &subnet_router)
        );
        assert_eq!(before.exit_node_active, after.exit_node_active);
        let approved: String =
            sqlx::query_scalar("SELECT approved_routes_json FROM nodes WHERE id=$1")
                .bind(subnet_router.id.to_string())
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(approved, r#"["0.0.0.0/0","10.50.0.0/24"]"#);
        let overview: NetworksOverview = json(
            call(
                &router,
                Method::GET,
                &format!("/v1/orgs/{}/networks", org.id),
                serde_json::Value::Null,
                Some(owner.token()),
                &[],
            )
            .await,
        )
        .await;
        assert!(overview.resources.is_empty());
        assert_eq!(overview.device_routes.len(), 1);
        assert!(overview.device_routes[0].unapproved_routes.is_empty());
    }
}
