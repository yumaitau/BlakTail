//! Routing-peer forwarding allow-lists (security follow-up to drafts 04, 05
//! and 07).
//!
//! Route distribution decides which clients *receive* a subnet route, but a
//! modified client can send to any destination through a routing peer it is
//! paired with. A routing peer that reports `forward-filter` therefore gets,
//! in its own peer map, the exact (client overlay address x destination
//! prefix x service) tuples it may forward; the agent drops everything else
//! arriving from the overlay. The list is compiled from the same inputs that
//! decide distribution (`list_peers`, `resources::Distribution`) and the same
//! policy rule matcher, so a client can only use what it was given.

use crate::{
    ipam,
    resources::{self, Distribution, ResourceProtocol},
    Acl, AclProtocol, Action, ApiError, Role, Subject,
};
use serde::{Deserialize, Serialize};
use sqlx::{AnyPool, Row};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use uuid::Uuid;

/// Reported by agents that install the forward allow-list.
pub(crate) const CAP_FORWARD_FILTER: &str = "forward-filter";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ForwardService {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) all: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) tcp: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) udp: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) icmp: bool,
}

impl ForwardService {
    fn everything() -> Self {
        Self {
            all: true,
            ..Self::default()
        }
    }

    fn is_empty(&self) -> bool {
        !self.all && !self.icmp && self.tcp.is_empty() && self.udp.is_empty()
    }

    fn merge(&mut self, other: &ForwardService) {
        if self.all || other.all {
            *self = Self::everything();
            return;
        }
        let union = |left: &[String], right: &[String]| {
            left.iter()
                .chain(right)
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        };
        self.tcp = union(&self.tcp, &other.tcp);
        self.udp = union(&self.udp, &other.udp);
        self.icmp |= other.icmp;
    }

    /// Whether this service admits `protocol`/`port` (`None` means any).
    pub(crate) fn admits(&self, protocol: Option<AclProtocol>, port: Option<u16>) -> bool {
        if self.all {
            return true;
        }
        let covers = |specs: &[String]| {
            specs.iter().any(|spec| match port {
                None => true,
                Some(port) => crate::parse_acl_port_spec(spec)
                    .is_ok_and(|(start, end)| (start..=end).contains(&port)),
            })
        };
        match protocol {
            Some(AclProtocol::Tcp) => covers(&self.tcp),
            Some(AclProtocol::Udp) => covers(&self.udp),
            Some(AclProtocol::Icmp) => self.icmp,
            None => covers(&self.tcp) || covers(&self.udp) || (port.is_none() && self.icmp),
        }
    }
}

/// Resource constraints as a service: no ports and no protocols is
/// everything; ports without protocols mean TCP and UDP (as in policy).
pub(crate) fn resource_service(ports: &[String], protocols: &[ResourceProtocol]) -> ForwardService {
    if ports.is_empty() && protocols.is_empty() {
        return ForwardService::everything();
    }
    let any = protocols.is_empty();
    let specs = if ports.is_empty() {
        vec!["1-65535".to_owned()]
    } else {
        ports.to_vec()
    };
    ForwardService {
        all: false,
        tcp: if any || protocols.contains(&ResourceProtocol::Tcp) {
            specs.clone()
        } else {
            Vec::new()
        },
        udp: if any || protocols.contains(&ResourceProtocol::Udp) {
            specs
        } else {
            Vec::new()
        },
        icmp: ports.is_empty() && protocols.contains(&ResourceProtocol::Icmp),
    }
}

fn rule_service(rule: &crate::AclRule) -> ForwardService {
    let mut tcp = BTreeSet::new();
    let mut udp = BTreeSet::new();
    let mut icmp = false;
    Acl::collect_service_specs(rule, &mut tcp, &mut udp, &mut icmp);
    ForwardService {
        all: false,
        tcp: tcp.into_iter().collect(),
        udp: udp.into_iter().collect(),
        icmp,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ForwardRule {
    /// The client node these sources belong to (diagnostics only).
    pub(crate) client: Uuid,
    /// The client's overlay host addresses (`/32`, `/128`).
    pub(crate) sources: Vec<String>,
    pub(crate) destination: String,
    #[serde(flatten)]
    pub(crate) service: ForwardService,
}

/// What a routing peer may forward from the overlay. Agents apply every
/// `deny` before any `allow` and drop anything neither lists.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ForwardFilter {
    #[serde(default)]
    pub(crate) deny: Vec<ForwardRule>,
    #[serde(default)]
    pub(crate) allow: Vec<ForwardRule>,
}

/// The routing peer whose allow-list is being compiled.
pub(crate) struct RouterView<'a> {
    pub(crate) id: Uuid,
    pub(crate) name: &'a str,
    pub(crate) dns_name: &'a str,
    pub(crate) subject: &'a Subject,
    pub(crate) approved: &'a [String],
    /// Advertised (possibly unapproved) routes: networks the router can
    /// reach that exit clients must not reach through the exit route.
    pub(crate) advertised: &'a [String],
}

impl RouterView<'_> {
    /// Same matching `list_peers` uses for the client's `exit_node` choice.
    pub(crate) fn selected_by(&self, requested: Option<&str>) -> bool {
        requested.is_some_and(|requested| {
            requested == self.id.to_string() || requested == self.name || requested == self.dns_name
        })
    }
}

/// One client the routing peer could forward for.
pub(crate) struct ClientView<'a> {
    pub(crate) id: Uuid,
    pub(crate) subject: &'a Subject,
    /// The client's own overlay addresses, before any routes are appended.
    pub(crate) overlay: &'a [String],
    pub(crate) exit_request: Option<&'a str>,
}

fn host_addresses(allowed_ips: &[String]) -> Vec<String> {
    allowed_ips
        .iter()
        .filter(|route| {
            ipam::parse_cidr(route).is_ok_and(|(address, prefix)| {
                (address.is_ipv4() && prefix == 32) || (address.is_ipv6() && prefix == 128)
            })
        })
        .cloned()
        .collect()
}

/// A policy host value (`10.0.0.10` or `10.0.0.0/24`) as a CIDR.
pub(crate) fn host_cidr(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Ok(address) = value.parse::<IpAddr>() {
        return Some(match address {
            IpAddr::V4(_) => format!("{address}/32"),
            IpAddr::V6(_) => format!("{address}/128"),
        });
    }
    ipam::parse_cidr(&value).ok().map(|_| value)
}

/// `universe` (a default route) minus every prefix of the same family in
/// `excluded`, as the fewest covering CIDRs.
fn complement<'a>(universe: &str, excluded: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let Ok((network, _)) = ipam::parse_cidr(universe) else {
        return Vec::new();
    };
    let ipv4 = network.is_ipv4();
    let bits: u8 = if ipv4 { 32 } else { 128 };
    let excluded: Vec<(u128, u8)> = excluded
        .into_iter()
        .filter_map(|prefix| ipam::parse_cidr(prefix).ok())
        .filter(|(address, _)| address.is_ipv4() == ipv4)
        .map(|(address, prefix)| (address_bits(address), prefix))
        .collect();
    let mut out = Vec::new();
    split(&mut out, ipv4, bits, 0, 0, &excluded);
    out
}

fn address_bits(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(address) => u128::from(u32::from(address)),
        IpAddr::V6(address) => u128::from(address),
    }
}

fn split(out: &mut Vec<String>, ipv4: bool, bits: u8, net: u128, len: u8, excluded: &[(u128, u8)]) {
    // `a/alen` contains `b` when `b` is at least as long and agrees on alen bits.
    let contains = |a: u128, alen: u8, b: u128, blen: u8| {
        blen >= alen && (alen == 0 || (a ^ b) >> (u32::from(bits) - u32::from(alen)) == 0)
    };
    if excluded
        .iter()
        .any(|&(prefix, plen)| contains(prefix, plen, net, len))
    {
        return;
    }
    if !excluded
        .iter()
        .any(|&(prefix, plen)| contains(net, len, prefix, plen))
    {
        out.push(if ipv4 {
            // `bits` is 32 here, so `net` fits.
            format!("{}/{len}", Ipv4Addr::from(net as u32))
        } else {
            format!("{}/{len}", Ipv6Addr::from(net))
        });
        return;
    }
    let half = 1u128 << (u32::from(bits) - u32::from(len) - 1);
    split(out, ipv4, bits, net, len + 1, excluded);
    split(out, ipv4, bits, net | half, len + 1, excluded);
}

/// The destination subject for named-host rules, as `policy explain` and
/// policy tests evaluate them: the host itself, not the routing peer.
fn host_subject() -> Subject {
    Subject::new(Role::Member, Vec::new())
}

/// Prefixes `client` may reach through `router` and the service on each,
/// mirroring what `list_peers` distributes to that client.
fn grants(
    acl: &Acl,
    distribution: &Distribution,
    router: &RouterView,
    client: &ClientView,
) -> BTreeMap<String, ForwardService> {
    let mut grants: BTreeMap<String, ForwardService> = BTreeMap::new();
    let exit = router.selected_by(client.exit_request);
    for route in router.approved {
        if !resources::is_default_route(route) || exit {
            grants.insert(route.clone(), ForwardService::everything());
        }
    }
    for (cidr, service) in distribution.grants_via(router.id, client.id, client.subject, acl, exit)
    {
        grants.entry(cidr).or_default().merge(&service);
    }
    grants
}

/// Adds `client`'s entries to `filter`. Nothing is added unless policy lets
/// the client reach the routing peer, exactly as distribution requires.
pub(crate) fn compile_client(
    acl: &Acl,
    distribution: &Distribution,
    router: &RouterView,
    client: &ClientView,
    filter: &mut ForwardFilter,
) {
    if client.id == router.id || !acl.allows(client.subject, router.subject) {
        return;
    }
    let sources = host_addresses(client.overlay);
    if sources.is_empty() {
        return;
    }
    let grants = grants(acl, distribution, router, client);
    if grants.is_empty() {
        return;
    }
    let entry = |destination: &str, service: ForwardService| ForwardRule {
        client: client.id,
        sources: sources.clone(),
        destination: destination.to_owned(),
        service,
    };
    let mut deny = Vec::new();
    let mut allow = Vec::new();
    // An exit-node client must not reach prefixes this router carries (or
    // could carry) just because the default route covers them: traffic to
    // such a prefix is governed only by the client's grant for it. Ungranted
    // prefixes are denied outright, and the default route is allowed as its
    // complement around every carried prefix, so a port-limited grant is
    // never widened by the exit route.
    let carried = router
        .approved
        .iter()
        .chain(router.advertised)
        .map(String::as_str)
        .chain(distribution.reserved_for(router.id))
        .filter(|prefix| !resources::is_default_route(prefix))
        .collect::<BTreeSet<_>>();
    let exits = grants
        .keys()
        .any(|prefix| resources::is_default_route(prefix));
    if exits {
        for prefix in carried
            .iter()
            .filter(|prefix| !grants.contains_key(**prefix))
        {
            deny.push(entry(prefix, ForwardService::everything()));
        }
    }
    let destination = host_subject();
    for (name, value) in &acl.hosts {
        let Some(host) = host_cidr(value) else {
            continue;
        };
        let within = |prefix: &str| resources::cidr_within(&host, prefix);
        let routed = grants.keys().any(|prefix| within(prefix));
        if !routed {
            continue;
        }
        let mut denied = ForwardService::default();
        let mut allowed = ForwardService::default();
        for rule in acl.rules.iter().filter(|rule| {
            acl.rule_matches(rule, client.subject, &destination, None, None, Some(name))
        }) {
            match rule.action {
                Action::Deny => denied.merge(&rule_service(rule)),
                // Only rules that name hosts open a host; a general
                // device-to-device allow says nothing about subnet hosts.
                Action::Allow if !rule.dst_hosts.is_empty() => {
                    allowed.merge(&rule_service(rule));
                }
                Action::Allow => {}
            }
        }
        if !denied.is_empty() {
            deny.push(entry(&host, denied));
        }
        // Host allow rules widen only prefixes the client was given, never
        // the exit route.
        let routed_privately = grants
            .keys()
            .any(|prefix| !resources::is_default_route(prefix) && within(prefix));
        if !allowed.is_empty() && routed_privately {
            allow.push(entry(&host, allowed));
        }
    }
    for (prefix, service) in grants {
        if resources::is_default_route(&prefix) {
            for part in complement(&prefix, carried.iter().copied()) {
                allow.push(entry(&part, service.clone()));
            }
        } else {
            allow.push(entry(&prefix, service));
        }
    }
    filter.deny.extend(deny);
    filter.allow.extend(allow);
}

/// The requesting node's name, approved routes and advertised routes, for
/// its own allow-list.
pub(crate) struct RouterRow {
    pub(crate) name: String,
    pub(crate) approved: Vec<String>,
    pub(crate) advertised: Vec<String>,
}

pub(crate) async fn load_router(pool: &AnyPool, node_id: Uuid) -> Result<RouterRow, ApiError> {
    let row = sqlx::query(
        "SELECT name,approved_routes_json,advertised_routes_json FROM nodes WHERE id=$1",
    )
    .bind(node_id.to_string())
    .fetch_optional(pool)
    .await?
    .ok_or(ApiError::Unauthorized)?;
    Ok(RouterRow {
        name: row.try_get(0)?,
        approved: serde_json::from_str(&row.try_get::<String, _>(1)?).unwrap_or_default(),
        advertised: serde_json::from_str(&row.try_get::<String, _>(2)?).unwrap_or_default(),
    })
}

// ---------- exit-node selections ----------
//
// Clients choose an exit node per request (`exit_node=`). The request is
// persisted in `nodes.exit_node_id` (the requested name, matched the same way
// `list_peers` matches it), so every replica and a restarted coordinator
// compile the same allow-list. A change bumps the control revision so the
// exit node's allow-list follows.

/// Records `node_id`'s exit-node request inside `tx`. Returns whether it changed.
pub(crate) async fn record_exit_selection(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    node_id: Uuid,
    requested: Option<&str>,
) -> Result<bool, ApiError> {
    let changed = sqlx::query(
        "UPDATE nodes SET exit_node_id=$1 WHERE id=$2 AND COALESCE(exit_node_id,'')<>COALESCE($1,'')",
    )
    .bind(requested)
    .bind(node_id.to_string())
    .execute(&mut **tx)
    .await?
    .rows_affected();
    Ok(changed > 0)
}

/// Every current exit-node request in an organisation, by client node id.
pub(crate) async fn exit_selections(
    pool: &AnyPool,
    org_id: &str,
) -> Result<HashMap<Uuid, String>, ApiError> {
    let rows = sqlx::query(
        "SELECT id,exit_node_id FROM nodes WHERE org_id=$1 AND exit_node_id IS NOT NULL AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;
    let mut selections = HashMap::new();
    for row in rows {
        let id: String = row.try_get(0)?;
        if let Ok(id) = id.parse() {
            selections.insert(id, row.try_get(1)?);
        }
    }
    Ok(selections)
}

async fn exit_selection(pool: &AnyPool, node_id: Uuid) -> Result<Option<String>, ApiError> {
    Ok(
        sqlx::query_scalar("SELECT exit_node_id FROM nodes WHERE id=$1")
            .bind(node_id.to_string())
            .fetch_optional(pool)
            .await?
            .flatten(),
    )
}

// ---------- enforcement status ----------

/// Whether a node's reported capabilities include `forward-filter`.
pub(crate) fn enforces(capabilities: &[String]) -> bool {
    capabilities
        .iter()
        .any(|capability| capability == CAP_FORWARD_FILTER)
}

/// `enforced` or `not_enforced`, plus the operator-facing explanation.
pub(crate) fn status(router_label: &str, capabilities: &[String]) -> (&'static str, String) {
    if enforces(capabilities) {
        (
            "enforced",
            format!(
                "{router_label} forwards only the clients, prefixes and ports compiled for it."
            ),
        )
    } else {
        (
            "not_enforced",
            format!("Forwarding not enforced on {router_label}: upgrade its agent. Any client paired with it can reach the whole advertised subnet on any port."),
        )
    }
}

/// A routing peer that carries `host` (a CIDR) to clients.
pub(crate) struct HostRouter {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) prefix: String,
    pub(crate) enforced: bool,
}

/// Routing peers whose approved routes or selected resources contain `host`.
pub(crate) async fn host_routers(
    pool: &AnyPool,
    org_id: &str,
    host: &str,
) -> Result<Vec<HostRouter>, ApiError> {
    let distribution = resources::load_distribution(pool, org_id).await?;
    let rows = sqlx::query(
        "SELECT id,COALESCE(NULLIF(TRIM(display_name),''),name),approved_routes_json,capabilities_json FROM nodes WHERE org_id=$1 AND revoked_at IS NULL AND deleted_at IS NULL ORDER BY name",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;
    let mut routers = Vec::new();
    for row in rows {
        let id =
            Uuid::parse_str(&row.try_get::<String, _>(0)?).map_err(|_| ApiError::CorruptData)?;
        let approved: Vec<String> =
            serde_json::from_str(&row.try_get::<String, _>(2)?).unwrap_or_default();
        let capabilities: Vec<String> =
            serde_json::from_str(&row.try_get::<String, _>(3)?).unwrap_or_default();
        let prefixes = approved
            .iter()
            .map(String::as_str)
            .chain(distribution.carried_by(id))
            .filter(|prefix| {
                !resources::is_default_route(prefix) && resources::cidr_within(host, prefix)
            })
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        for prefix in prefixes {
            routers.push(HostRouter {
                id,
                name: row.try_get(1)?,
                prefix,
                enforced: enforces(&capabilities),
            });
        }
    }
    Ok(routers)
}

/// Whether `filter` lets `source` reach `host` with this service.
pub(crate) fn permits(
    filter: &ForwardFilter,
    host: &str,
    protocol: Option<AclProtocol>,
    port: Option<u16>,
) -> bool {
    let applies = |rule: &&ForwardRule| resources::cidr_within(host, &rule.destination);
    if filter
        .deny
        .iter()
        .filter(applies)
        .any(|rule| rule.service.admits(protocol, port))
    {
        return false;
    }
    filter
        .allow
        .iter()
        .filter(applies)
        .any(|rule| rule.service.admits(protocol, port))
}

/// The allow-list `router` would receive, restricted to one client: what
/// `policy explain` checks a subnet flow against.
pub(crate) async fn client_filter(
    pool: &AnyPool,
    org_id: &str,
    acl: &Acl,
    router: (Uuid, &Subject),
    client: (Uuid, &Subject),
) -> Result<ForwardFilter, ApiError> {
    let distribution = resources::load_distribution(pool, org_id).await?;
    let rows = sqlx::query(
        "SELECT id,name,dns_name,approved_routes_json,allowed_ips_json,advertised_routes_json FROM nodes WHERE org_id=$1 AND (id=$2 OR id=$3) AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(org_id)
    .bind(router.0.to_string())
    .bind(client.0.to_string())
    .fetch_all(pool)
    .await?;
    let mut router_row = None;
    let mut overlay = Vec::new();
    for row in rows {
        let id: String = row.try_get(0)?;
        if id == router.0.to_string() {
            router_row = Some((
                row.try_get::<String, _>(1)?,
                row.try_get::<String, _>(2)?,
                serde_json::from_str::<Vec<String>>(&row.try_get::<String, _>(3)?)
                    .unwrap_or_default(),
                serde_json::from_str::<Vec<String>>(&row.try_get::<String, _>(5)?)
                    .unwrap_or_default(),
            ));
        } else {
            overlay = serde_json::from_str(&row.try_get::<String, _>(4)?).unwrap_or_default();
        }
    }
    let mut filter = ForwardFilter::default();
    let Some((name, dns_name, approved, advertised)) = router_row else {
        return Ok(filter);
    };
    let exit_request = exit_selection(pool, client.0).await?;
    compile_client(
        acl,
        &distribution,
        &RouterView {
            id: router.0,
            name: &name,
            dns_name: &dns_name,
            subject: router.1,
            approved: &approved,
            advertised: &advertised,
        },
        &ClientView {
            id: client.0,
            subject: client.1,
            overlay: &overlay,
            exit_request: exit_request.as_deref(),
        },
        &mut filter,
    );
    Ok(filter)
}
