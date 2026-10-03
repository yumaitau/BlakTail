//! Opt-in per-flow traffic events (draft 17).
//!
//! While an organisation has traffic diagnostics on, agents upload one event
//! per connection start, end or drop they see: overlay source and
//! destination addresses and ports, protocol (ICMP type and code), direction,
//! byte and packet counters, and how the connection travelled. The
//! coordinator never sees traffic itself. At ingest it resolves each address
//! to a device, network resource or approved route of the same organisation
//! (or "unknown"), names the routing peer, and evaluates the published policy
//! to name the rule that allows or denies the flow.
//!
//! Nothing payload-shaped is accepted: unknown fields are refused, as are
//! URL, DNS-name, host and body keys at any depth. Uploads are refused while
//! the organisation is opted out, sampled per flow, capped per batch and per
//! organisation, and deleted past the organisation's retention.

use crate::flows::{should_sample, validate_flow_json};
use crate::permissions::{require, Permission};
use crate::policy_explain::device_subject;
use crate::posture::PostureContext;
use crate::traffic::{load_settings_pool, traffic_state, TrafficSettings};
use crate::{
    admin::{authenticate_org_header, require_scope, Envelope, Scope},
    append_audit, console_session, now, Acl, AclProtocol, Action, ApiError, AppState, Role,
    Session, Store, Subject,
};
use axum::{
    body::Bytes,
    extract::{Path as UrlPath, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use uuid::Uuid;

/// Events accepted in one upload.
pub(crate) const MAX_EVENTS_PER_BATCH: usize = 1_000;
const MAX_UPLOAD_BYTES: usize = 1024 * 1024;
/// Storage bound per organisation; uploads beyond it are refused.
pub(crate) const MAX_EVENTS_PER_ORG: i64 = 500_000;
/// Agents upload about every 30 seconds; this leaves room for retries.
const UPLOADS_PER_NODE_PER_MINUTE: u32 = 6;
/// An aggregation window may span at most an hour.
pub(crate) const MAX_WINDOW_SECS: i64 = 3_600;
const CLOCK_SKEW_SECS: i64 = 300;
/// Older windows are refused: agents drop what they could not upload.
const MAX_WINDOW_AGE_SECS: i64 = 2 * DAY_SECS;
const DAY_SECS: i64 = 24 * 60 * 60;
const MAX_FLOW_ID_CHARS: usize = 64;
const MAX_RULE_HINT_CHARS: usize = 48;
const DEFAULT_PAGE: i64 = 50;
const MAX_PAGE: i64 = 500;
const MAX_EXPORT_ROWS: i64 = 50_000;
/// Events shown per flow in a timeline.
const MAX_EVENTS_PER_FLOW: usize = 50;
/// Default query window when `from` is not given.
const DEFAULT_WINDOW_SECS: i64 = DAY_SECS;
const MAX_SEARCH_CHARS: usize = 100;

const COLUMNS: &str = "id,reporter_id,flow_id,event_type,event_at,window_start,window_end,direction,protocol,protocol_number,icmp_type,icmp_code,src_ip,src_port,dst_ip,dst_port,src_kind,src_id,src_name,src_user,dst_kind,dst_id,dst_name,dst_user,dst_route,router_id,router_name,rule_basis,rule_index,rule_label,rule_hint,connection_type,rx_bytes,tx_bytes,rx_packets,tx_packets,aggregated,created_at";

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/nodes/:node_id/flow-events", post(ingest))
        .route("/v1/orgs/:org_id/traffic/events", get(list_events_console))
        .route(
            "/v1/orgs/:org_id/traffic/events/export",
            get(export_console),
        )
        .route("/v1/orgs/:org_id/traffic/flows", get(list_flows_console))
}

// ---------------------------------------------------------------------------
// Wire format

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EventType {
    Start,
    End,
    Drop,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Direction {
    /// The connection arrived at the reporting device (or, on a routing
    /// peer, arrived to be forwarded).
    Inbound,
    /// The reporting device started it.
    Outbound,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConnectionType {
    /// Directly between two devices.
    P2p,
    /// Through a routing peer to a resource, route or exit.
    Routed,
    /// Between two devices through a BlakTail relay.
    Relay,
}

fn label<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// One event as an agent reports it. Unknown fields are refused.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UploadEvent {
    /// The reporter's own id for the connection; start, end and drop events
    /// of one connection share it.
    pub(crate) flow_id: String,
    #[serde(rename = "type")]
    pub(crate) event_type: EventType,
    /// Unix seconds when the device saw the event.
    pub(crate) at: i64,
    pub(crate) direction: Direction,
    pub(crate) protocol: Protocol,
    /// IP protocol number, for `other`.
    #[serde(default)]
    pub(crate) protocol_number: Option<u8>,
    #[serde(default)]
    pub(crate) icmp_type: Option<u8>,
    #[serde(default)]
    pub(crate) icmp_code: Option<u8>,
    pub(crate) src_ip: String,
    #[serde(default)]
    pub(crate) src_port: u16,
    pub(crate) dst_ip: String,
    #[serde(default)]
    pub(crate) dst_port: u16,
    /// The WireGuard peer (device id) that carried the connection.
    #[serde(default)]
    pub(crate) peer_id: Option<String>,
    pub(crate) connection_type: ConnectionType,
    #[serde(default)]
    pub(crate) rx_bytes: u64,
    #[serde(default)]
    pub(crate) tx_bytes: u64,
    #[serde(default)]
    pub(crate) rx_packets: u64,
    #[serde(default)]
    pub(crate) tx_packets: u64,
    /// Which local filter rule decided, as the device knows it (for example
    /// `acl:default` or `fwd:deny`). Short lowercase label only.
    #[serde(default)]
    pub(crate) rule_hint: Option<String>,
    /// True when the device cannot see single connections and reports a
    /// filter rule's counters for the window instead (macOS pf).
    #[serde(default)]
    pub(crate) aggregated: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventUpload {
    pub(crate) org_id: String,
    pub(crate) window_start: i64,
    pub(crate) window_end: i64,
    pub(crate) events: Vec<UploadEvent>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct EventUploadResult {
    pub(crate) accepted: usize,
    pub(crate) sampled_out: usize,
    pub(crate) sampling_rate: f64,
}

/// Checks the window against the coordinator's clock and the batch cap.
pub(crate) fn validate_window(upload: &EventUpload, at: i64) -> Result<(), String> {
    if upload.events.len() > MAX_EVENTS_PER_BATCH {
        return Err(format!(
            "flow event batch has {} events, max is {MAX_EVENTS_PER_BATCH}",
            upload.events.len()
        ));
    }
    if upload.window_start < 0 || upload.window_end < upload.window_start {
        return Err("invalid aggregation window".into());
    }
    if upload.window_end - upload.window_start > MAX_WINDOW_SECS {
        return Err(format!(
            "aggregation window may span at most {MAX_WINDOW_SECS}s"
        ));
    }
    if upload.window_end > at + CLOCK_SKEW_SECS {
        return Err("aggregation window is in the future".into());
    }
    if upload.window_start < at - MAX_WINDOW_AGE_SECS {
        return Err("aggregation window is too old".into());
    }
    Ok(())
}

fn valid_flow_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_FLOW_ID_CHARS
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn valid_rule_hint(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RULE_HINT_CHARS
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, ':' | '-' | '_'))
}

/// Field-level validation of one event. Returns the parsed addresses.
pub(crate) fn validate_event(
    event: &UploadEvent,
    window_start: i64,
    window_end: i64,
) -> Result<(IpAddr, IpAddr), String> {
    if !valid_flow_id(&event.flow_id) {
        return Err("flow_id must be 1-64 letters, digits, '-' or '_'".into());
    }
    if event.at < window_start - MAX_WINDOW_SECS || event.at > window_end + CLOCK_SKEW_SECS {
        return Err("event time is outside its aggregation window".into());
    }
    let source: IpAddr = event
        .src_ip
        .parse()
        .map_err(|_| "src_ip must be an IP address".to_owned())?;
    let destination: IpAddr = event
        .dst_ip
        .parse()
        .map_err(|_| "dst_ip must be an IP address".to_owned())?;
    if source.is_ipv4() != destination.is_ipv4() {
        return Err("source and destination must be the same address family".into());
    }
    match event.protocol {
        Protocol::Tcp | Protocol::Udp => {
            if event.dst_port == 0 || (event.src_port == 0 && !event.aggregated) {
                return Err("tcp and udp events need source and destination ports".into());
            }
            if event.icmp_type.is_some() || event.icmp_code.is_some() {
                return Err("icmp type and code are only for icmp".into());
            }
        }
        Protocol::Icmp | Protocol::Icmpv6 => {
            if event.src_port != 0 || event.dst_port != 0 {
                return Err("icmp events have no ports".into());
            }
            if event.icmp_type.is_none() && !event.aggregated {
                return Err("icmp events need an icmp type".into());
            }
            if (event.protocol == Protocol::Icmp) != source.is_ipv4() {
                return Err("icmp is for IPv4 and icmpv6 for IPv6".into());
            }
        }
        Protocol::Other => {
            if event.src_port != 0 || event.dst_port != 0 {
                return Err("other protocols have no ports".into());
            }
            if !matches!(event.protocol_number, Some(n) if n != 0) {
                return Err("other protocols need a protocol_number".into());
            }
        }
    }
    if event.protocol != Protocol::Other && event.protocol_number.is_some() {
        return Err("protocol_number is only for other protocols".into());
    }
    if let Some(peer) = &event.peer_id {
        if Uuid::parse_str(peer).is_err() {
            return Err("peer_id must be a device id".into());
        }
    }
    if let Some(hint) = &event.rule_hint {
        if !valid_rule_hint(hint) {
            return Err("rule_hint must be a short lowercase label".into());
        }
    }
    Ok((source, destination))
}

/// Per-flow sampling draw: every event of one connection is kept or dropped
/// together. Agents use the same draw so they skip what would be dropped.
pub(crate) fn sample_draw(org_id: &str, reporter_id: &str, flow_id: &str) -> u64 {
    let digest = Sha256::digest(format!("{org_id}|{reporter_id}|{flow_id}").as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes)
}

// ---------------------------------------------------------------------------
// Address directory: overlay addresses, resources and routes of one org.

fn parse_cidr(value: &str) -> Option<(IpAddr, u8)> {
    let value = value.trim();
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address.parse::<IpAddr>().ok()?, prefix.parse::<u8>().ok()?),
        None => {
            let address: IpAddr = value.parse().ok()?;
            (address, if address.is_ipv4() { 32 } else { 128 })
        }
    };
    let max = if address.is_ipv4() { 32 } else { 128 };
    (prefix <= max).then_some((address, prefix))
}

fn cidr_contains((network, prefix): (IpAddr, u8), address: IpAddr) -> bool {
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            u32::from(network) & mask == u32::from(address) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

#[derive(Clone, Debug)]
struct NodeEntry {
    id: Uuid,
    name: String,
    user_id: String,
    addresses: Vec<IpAddr>,
    routes: Vec<String>,
}

#[derive(Clone, Debug)]
struct ResourceEntry {
    id: String,
    name: String,
    cidr: String,
    network: (IpAddr, u8),
    routing_peers: Vec<Uuid>,
    ports: Vec<(u16, u16)>,
    /// `tcp`, `udp`, `icmp`; empty means every protocol the ports allow.
    protocols: Vec<String>,
}

impl ResourceEntry {
    /// Whether the resource grants this protocol and port, as the routing
    /// peer's forward filter compiles it.
    fn grants(&self, protocol: Protocol, port: u16) -> bool {
        let everything = self.ports.is_empty() && self.protocols.is_empty();
        let named = |name: &str| self.protocols.iter().any(|p| p == name);
        match protocol {
            Protocol::Icmp | Protocol::Icmpv6 => everything || named("icmp"),
            Protocol::Tcp | Protocol::Udp => {
                let name = if protocol == Protocol::Tcp {
                    "tcp"
                } else {
                    "udp"
                };
                (self.protocols.is_empty() || named(name))
                    && (self.ports.is_empty()
                        || self.ports.iter().any(|(a, b)| (*a..=*b).contains(&port)))
            }
            Protocol::Other => everything,
        }
    }
}

#[derive(Default)]
struct Directory {
    nodes: HashMap<Uuid, NodeEntry>,
    by_address: HashMap<IpAddr, Uuid>,
    resources: Vec<ResourceEntry>,
    /// Approved device routes: (network, cidr text, router).
    routes: Vec<((IpAddr, u8), String, Uuid)>,
}

/// Who an address belongs to, as far as the coordinator knows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Identity {
    /// `device`, `resource`, `route` or `unknown`.
    kind: &'static str,
    id: Option<String>,
    name: String,
    user: Option<String>,
    /// The resource prefix or approved route that covers the address.
    route: Option<String>,
}

impl Directory {
    async fn load(pool: &sqlx::AnyPool, org_id: &str) -> Result<Self, ApiError> {
        let mut directory = Directory::default();
        let rows = sqlx::query(
            "SELECT id,name,display_name,allowed_ips_json,user_id,user_role,approved_routes_json,CASE WHEN revoked_at IS NULL AND deleted_at IS NULL THEN 1 ELSE 0 END FROM nodes WHERE org_id=$1",
        )
        .bind(org_id)
        .fetch_all(pool)
        .await?;
        let mut active_addresses: HashMap<IpAddr, Uuid> = HashMap::new();
        for row in rows {
            let Ok(id) = Uuid::parse_str(&row.try_get::<String, _>(0)?) else {
                continue;
            };
            let name: String = row.try_get(1)?;
            let display: Option<String> = row.try_get(2)?;
            let allowed: Vec<String> =
                serde_json::from_str(&row.try_get::<String, _>(3)?).unwrap_or_default();
            let routes: Vec<String> =
                serde_json::from_str(&row.try_get::<String, _>(6)?).unwrap_or_default();
            let active = row.try_get::<i64, _>(7)? == 1;
            let addresses: Vec<IpAddr> = allowed
                .iter()
                .filter_map(|value| parse_cidr(value))
                .filter(|(address, prefix)| *prefix == if address.is_ipv4() { 32 } else { 128 })
                .map(|(address, _)| address)
                .collect();
            for address in &addresses {
                // A reused address belongs to the device that holds it now.
                if active {
                    active_addresses.insert(*address, id);
                } else {
                    directory.by_address.entry(*address).or_insert(id);
                }
            }
            if active {
                for route in &routes {
                    if let Some(network) = parse_cidr(route) {
                        directory.routes.push((network, route.clone(), id));
                    }
                }
            }
            directory.nodes.insert(
                id,
                NodeEntry {
                    id,
                    name: display
                        .filter(|value| !value.trim().is_empty())
                        .unwrap_or(name),
                    user_id: row.try_get(4)?,
                    addresses,
                    routes,
                },
            );
        }
        directory.by_address.extend(active_addresses);
        let rows = sqlx::query(
            "SELECT id,name,cidr,routing_peers_json,ports_json,protocols_json FROM network_resources WHERE org_id=$1 AND kind='cidr' AND cidr IS NOT NULL",
        )
        .bind(org_id)
        .fetch_all(pool)
        .await?;
        for row in rows {
            let cidr: String = row.try_get(2)?;
            let Some(network) = parse_cidr(&cidr) else {
                continue;
            };
            let peers: Vec<serde_json::Value> =
                serde_json::from_str(&row.try_get::<String, _>(3)?).unwrap_or_default();
            let ports: Vec<String> =
                serde_json::from_str(&row.try_get::<String, _>(4)?).unwrap_or_default();
            let protocols: Vec<String> =
                serde_json::from_str(&row.try_get::<String, _>(5)?).unwrap_or_default();
            directory.resources.push(ResourceEntry {
                id: row.try_get(0)?,
                name: row.try_get(1)?,
                cidr,
                network,
                routing_peers: peers
                    .iter()
                    .filter_map(|peer| peer.get("node_id")?.as_str()?.parse().ok())
                    .collect(),
                ports: ports
                    .iter()
                    .filter_map(|spec| crate::parse_acl_port_spec(spec).ok())
                    .collect(),
                protocols: protocols.iter().map(|p| p.to_ascii_lowercase()).collect(),
            });
        }
        // Most specific prefix first.
        directory
            .resources
            .sort_by(|a, b| b.network.1.cmp(&a.network.1).then(a.name.cmp(&b.name)));
        directory
            .routes
            .sort_by_key(|route| std::cmp::Reverse(route.0 .1));
        Ok(directory)
    }

    fn resolve(&self, address: IpAddr) -> Identity {
        if let Some(node) = self
            .by_address
            .get(&address)
            .and_then(|id| self.nodes.get(id))
        {
            return Identity {
                kind: "device",
                id: Some(node.id.to_string()),
                name: node.name.clone(),
                user: Some(node.user_id.clone()).filter(|user| !user.is_empty()),
                route: None,
            };
        }
        if let Some(resource) = self
            .resources
            .iter()
            .find(|resource| cidr_contains(resource.network, address))
        {
            return Identity {
                kind: "resource",
                id: Some(resource.id.clone()),
                name: resource.name.clone(),
                user: None,
                route: Some(resource.cidr.clone()),
            };
        }
        if let Some((_, cidr, _)) = self
            .routes
            .iter()
            .find(|(network, _, _)| cidr_contains(*network, address))
        {
            return Identity {
                kind: "route",
                id: Some(cidr.clone()),
                name: cidr.clone(),
                user: None,
                route: Some(cidr.clone()),
            };
        }
        Identity {
            kind: "unknown",
            ..Identity::default()
        }
    }

    /// Whether this device forwards for any resource or approved route.
    fn is_router(&self, id: Uuid) -> bool {
        self.nodes
            .get(&id)
            .is_some_and(|node| !node.routes.is_empty())
            || self
                .resources
                .iter()
                .any(|resource| resource.routing_peers.contains(&id))
    }
}

// ---------------------------------------------------------------------------
// Matched rule

#[derive(Clone, Debug, PartialEq, Eq)]
struct RuleOutcome {
    /// `rule` (an allow rule), `deny_rule`, `default_same_tag`,
    /// `default_deny`, `resource` (granted by a network resource), `route`
    /// (an approved device route) or `unknown`.
    basis: &'static str,
    index: Option<i64>,
    label: String,
}

fn subject_words(roles: &[Role], tags: &[crate::DeviceTag], groups: &[String]) -> String {
    let mut words: Vec<String> = Vec::new();
    words.extend(roles.iter().map(|role| format!("role:{}", role.as_str())));
    words.extend(tags.iter().map(|tag| format!("tag:{}", tag.as_str())));
    words.extend(groups.iter().map(|group| format!("group:{group}")));
    if words.is_empty() {
        "anyone".into()
    } else {
        words.join(", ")
    }
}

fn rule_label(acl: &Acl, index: usize) -> String {
    let Some(rule) = acl.rules.get(index) else {
        return format!("Rule {}", index + 1);
    };
    let mut destination = subject_words(&rule.dst_roles, &rule.dst_tags, &rule.dst_groups);
    if !rule.dst_hosts.is_empty() {
        destination = format!("host:{}", rule.dst_hosts.join(", host:"));
    }
    let mut detail = Vec::new();
    if !rule.protocols.is_empty() {
        detail.push(
            rule.protocols
                .iter()
                .map(label)
                .collect::<Vec<_>>()
                .join("/"),
        );
    }
    if !rule.dst_ports.is_empty() {
        detail.push(format!("port {}", rule.dst_ports.join(",")));
    }
    let detail = if detail.is_empty() {
        String::new()
    } else {
        format!(" ({})", detail.join(" "))
    };
    format!(
        "Rule {}: {} {} → {}{}",
        index + 1,
        match rule.action {
            Action::Allow => "allow",
            Action::Deny => "deny",
        },
        subject_words(&rule.src_roles, &rule.src_tags, &rule.src_groups),
        destination,
        detail
    )
}

fn acl_protocol(protocol: Protocol) -> Option<AclProtocol> {
    match protocol {
        Protocol::Tcp => Some(AclProtocol::Tcp),
        Protocol::Udp => Some(AclProtocol::Udp),
        Protocol::Icmp | Protocol::Icmpv6 => Some(AclProtocol::Icmp),
        Protocol::Other => None,
    }
}

/// The policy rule that decides this flow, through the same evaluator the
/// peer maps are compiled from: a deny rule wins, then the first allow rule,
/// then the policy default.
fn evaluate(
    acl: &Acl,
    source: &Subject,
    destination: &Subject,
    protocol: Protocol,
    port: Option<u16>,
    host: Option<&str>,
) -> RuleOutcome {
    let protocol = acl_protocol(protocol);
    let (mut allow, mut deny) = (None, None);
    for (index, rule) in acl.rules.iter().enumerate() {
        if acl.rule_matches(rule, source, destination, port, protocol, host) {
            match rule.action {
                Action::Allow => {
                    allow.get_or_insert(index);
                }
                Action::Deny => {
                    deny.get_or_insert(index);
                }
            }
        }
    }
    if let Some(index) = deny {
        return RuleOutcome {
            basis: "deny_rule",
            index: Some(index as i64),
            label: rule_label(acl, index),
        };
    }
    let allowed = acl.allows_flow(source, destination, port, protocol, host);
    match (allowed, allow) {
        (true, Some(index)) => RuleOutcome {
            basis: "rule",
            index: Some(index as i64),
            label: rule_label(acl, index),
        },
        (true, None) => RuleOutcome {
            basis: "default_same_tag",
            index: None,
            label: "Policy default: same tag".into(),
        },
        (false, _) => RuleOutcome {
            basis: "default_deny",
            index: None,
            label: "Default deny".into(),
        },
    }
}

fn host_for(acl: &Acl, address: IpAddr) -> Option<String> {
    acl.hosts
        .iter()
        .filter_map(|(name, value)| Some((name, parse_cidr(value)?)))
        .filter(|(_, network)| cidr_contains(*network, address))
        .max_by_key(|(_, network)| network.1)
        .map(|(name, _)| name.clone())
}

struct Evaluator<'a> {
    acl: Option<&'a Acl>,
    directory: &'a Directory,
    ctx: &'a PostureContext,
    cache: HashMap<String, RuleOutcome>,
}

impl Evaluator<'_> {
    fn outcome(
        &mut self,
        event: &UploadEvent,
        source: &Identity,
        destination: &Identity,
        destination_ip: IpAddr,
    ) -> RuleOutcome {
        let Some(acl) = self.acl else {
            return RuleOutcome {
                basis: "unknown",
                index: None,
                label: "Policy could not be read".into(),
            };
        };
        let port = matches!(event.protocol, Protocol::Tcp | Protocol::Udp)
            .then_some(event.dst_port)
            .filter(|port| *port != 0);
        let key = format!(
            "{:?}|{:?}|{}|{:?}|{:?}|{}",
            source.id, destination.id, destination_ip, event.protocol, port, destination.kind
        );
        if let Some(outcome) = self.cache.get(&key) {
            return outcome.clone();
        }
        let facts = |identity: &Identity| {
            identity
                .id
                .as_deref()
                .and_then(|id| Uuid::parse_str(id).ok())
                .and_then(|id| self.ctx.facts.get(&id))
        };
        let outcome = match (source.kind, facts(source)) {
            ("device", Some(source_facts)) => {
                let subject = device_subject(source_facts, self.ctx);
                match (destination.kind, facts(destination)) {
                    ("device", Some(destination_facts)) => evaluate(
                        acl,
                        &subject,
                        &device_subject(destination_facts, self.ctx),
                        event.protocol,
                        port,
                        None,
                    ),
                    ("device", None) => RuleOutcome {
                        basis: "unknown",
                        index: None,
                        label: "Destination device is no longer active".into(),
                    },
                    _ => {
                        let host = host_for(acl, destination_ip);
                        let by_host = host.as_deref().map(|host| {
                            evaluate(
                                acl,
                                &subject,
                                &Subject::new(Role::Member, Vec::new()),
                                event.protocol,
                                port,
                                Some(host),
                            )
                        });
                        match (by_host, destination.kind) {
                            (Some(outcome), _) if outcome.basis != "default_deny" => outcome,
                            (_, "resource") => {
                                let granted = self
                                    .directory
                                    .resources
                                    .iter()
                                    .find(|r| destination.id.as_deref() == Some(r.id.as_str()))
                                    .is_none_or(|r| r.grants(event.protocol, event.dst_port));
                                if granted {
                                    RuleOutcome {
                                        basis: "resource",
                                        index: None,
                                        label: format!("Network resource {}", destination.name),
                                    }
                                } else {
                                    RuleOutcome {
                                        basis: "default_deny",
                                        index: None,
                                        label: format!(
                                            "Default deny: network resource {} does not grant this port",
                                            destination.name
                                        ),
                                    }
                                }
                            }
                            (_, "route") => RuleOutcome {
                                basis: "route",
                                index: None,
                                label: format!("Approved route {}", destination.name),
                            },
                            _ => RuleOutcome {
                                basis: "unknown",
                                index: None,
                                label: "Destination is outside the organisation".into(),
                            },
                        }
                    }
                }
            }
            _ => RuleOutcome {
                basis: "unknown",
                index: None,
                label: "Source is not an active device".into(),
            },
        };
        self.cache.insert(key, outcome.clone());
        outcome
    }
}

/// Reconciles the policy outcome with what the device did. A drop the
/// current policy would allow means the device enforced an older policy or
/// a resource limit; say so rather than claim a rule allowed it.
fn reconcile(event_type: EventType, outcome: RuleOutcome) -> RuleOutcome {
    let allows = matches!(
        outcome.basis,
        "rule" | "default_same_tag" | "resource" | "route"
    );
    let granted_by_route = matches!(outcome.basis, "resource" | "route");
    if event_type == EventType::Drop && allows && !granted_by_route {
        return RuleOutcome {
            basis: "unknown",
            index: outcome.index,
            label: format!(
                "Dropped by the device although {} allows it now (the device may have had an older policy)",
                outcome.label
            ),
        };
    }
    if event_type == EventType::Drop && granted_by_route {
        return RuleOutcome {
            basis: "default_deny",
            index: None,
            label: format!(
                "Default deny: {} does not grant this port or source",
                outcome.label
            ),
        };
    }
    outcome
}

// ---------------------------------------------------------------------------
// Ingest

async fn authenticate_node(
    s: &AppState,
    node_id: Uuid,
    headers: &HeaderMap,
) -> Result<String, ApiError> {
    let token = crate::bearer(headers)?;
    let row = sqlx::query(
        "SELECT org_id,credential_expires_at,CASE WHEN suspended_at IS NULL THEN 0 ELSE 1 END FROM nodes WHERE id=$1 AND token_hash=$2 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(node_id.to_string())
    .bind(token)
    .fetch_optional(&s.store.pool)
    .await?
    .ok_or(ApiError::Unauthorized)?;
    if row.try_get::<i64, _>(1)? <= now() {
        return Err(ApiError::CredentialExpired);
    }
    if row.try_get::<i64, _>(2)? != 0 {
        return Err(ApiError::Suspended);
    }
    Ok(row.try_get(0)?)
}

fn disabled() -> ApiError {
    ApiError::Conflict("traffic diagnostics are turned off for this organisation".into())
}

struct Resolved {
    event: UploadEvent,
    source: Identity,
    destination: Identity,
    router: Option<(String, String)>,
    connection_type: ConnectionType,
    rule: RuleOutcome,
}

async fn ingest(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<EventUploadResult>), ApiError> {
    let org_id = authenticate_node(&s, node_id, &headers).await?;
    if !s.api_rate.allow(
        &format!("flow-events:{node_id}"),
        now(),
        UPLOADS_PER_NODE_PER_MINUTE,
        60,
    ) {
        return Err(ApiError::Conflict(
            "flow event uploads are limited to 6 a minute per device".into(),
        ));
    }
    if !load_settings_pool(&s.store.pool, &org_id).await?.enabled {
        return Err(disabled());
    }
    if body.len() > MAX_UPLOAD_BYTES {
        return Err(ApiError::BadRequest(
            "flow event upload is too large".into(),
        ));
    }
    let raw: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| ApiError::BadRequest("flow event upload must be JSON".into()))?;
    validate_flow_json(&raw).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let upload: EventUpload = serde_json::from_value(raw)
        .map_err(|error| ApiError::BadRequest(format!("invalid flow event upload: {error}")))?;
    if upload.org_id != org_id {
        // A device reports only into its own organisation.
        return Err(ApiError::Forbidden);
    }
    let at = now();
    validate_window(&upload, at).map_err(ApiError::BadRequest)?;
    let mut addresses = Vec::with_capacity(upload.events.len());
    for event in &upload.events {
        addresses.push(
            validate_event(event, upload.window_start, upload.window_end)
                .map_err(ApiError::BadRequest)?,
        );
    }

    let directory = Directory::load(&s.store.pool, &org_id).await?;
    let reporter = directory
        .nodes
        .get(&node_id)
        .cloned()
        .ok_or(ApiError::Unauthorized)?;
    let reporter_is_router = directory.is_router(node_id);
    for (event, (source, destination)) in upload.events.iter().zip(&addresses) {
        let own = |address: &IpAddr| reporter.addresses.contains(address);
        let attributed = match (event.connection_type, event.direction) {
            // A routing peer reports connections it forwards for others.
            (ConnectionType::Routed, _) if !own(source) && !own(destination) => reporter_is_router,
            (_, Direction::Outbound) => own(source),
            (_, Direction::Inbound) => own(destination),
        };
        if !attributed {
            // A device reports only its own connections (or, as a routing
            // peer, ones it forwards); never a third party's.
            return Err(ApiError::Forbidden);
        }
        if let Some(peer) = &event.peer_id {
            let known = Uuid::parse_str(peer)
                .ok()
                .is_some_and(|peer| directory.nodes.contains_key(&peer));
            if !known {
                return Err(ApiError::Forbidden);
            }
        }
    }

    let settings = load_settings_pool(&s.store.pool, &org_id).await?;
    let reporter_id = node_id.to_string();
    let total = upload.events.len();
    let kept: Vec<(UploadEvent, (IpAddr, IpAddr))> = upload
        .events
        .into_iter()
        .zip(addresses)
        .filter(|(event, _)| {
            should_sample(
                settings.sampling_rate,
                sample_draw(&org_id, &reporter_id, &event.flow_id),
            )
        })
        .collect();

    let org_uuid = Uuid::parse_str(&org_id).map_err(|_| ApiError::CorruptData)?;
    let acl: Option<Acl> = crate::load_acl_row(&s.store, org_uuid)
        .await
        .ok()
        .and_then(|row| serde_json::from_str(&row.json).ok());
    let ctx = PostureContext::load(&s.store.pool, &org_id).await?;
    let mut evaluator = Evaluator {
        acl: acl.as_ref(),
        directory: &directory,
        ctx: &ctx,
        cache: HashMap::new(),
    };
    let mut resolved = Vec::with_capacity(kept.len());
    for (event, (source_ip, destination_ip)) in kept {
        let source = directory.resolve(source_ip);
        let destination = directory.resolve(destination_ip);
        let forwarding = !reporter.addresses.contains(&source_ip)
            && !reporter.addresses.contains(&destination_ip);
        let routed_destination = matches!(destination.kind, "resource" | "route" | "unknown");
        let router = if forwarding {
            Some((reporter.id.to_string(), reporter.name.clone()))
        } else if routed_destination {
            event
                .peer_id
                .as_deref()
                .and_then(|peer| Uuid::parse_str(peer).ok())
                .filter(|peer| destination.id.as_deref() != Some(&peer.to_string()))
                .and_then(|peer| directory.nodes.get(&peer))
                .map(|node| (node.id.to_string(), node.name.clone()))
        } else {
            None
        };
        let connection_type = if forwarding || (routed_destination && router.is_some()) {
            ConnectionType::Routed
        } else {
            event.connection_type
        };
        let rule = reconcile(
            event.event_type,
            evaluator.outcome(&event, &source, &destination, destination_ip),
        );
        resolved.push(Resolved {
            event,
            source,
            destination,
            router,
            connection_type,
            rule,
        });
    }

    let mut tx = s.store.pool.begin().await?;
    // Re-read inside the write so turning collection off stops ingestion
    // from the next request, even one that raced the toggle.
    let settings = crate::traffic::load_settings(&mut tx, &org_id).await?;
    if !settings.enabled {
        return Err(disabled());
    }
    sqlx::query("DELETE FROM flow_events WHERE org_id=$1 AND created_at<$2")
        .bind(&org_id)
        .bind(at - settings.retention_days * DAY_SECS)
        .execute(&mut *tx)
        .await?;
    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM flow_events WHERE org_id=$1")
        .bind(&org_id)
        .fetch_one(&mut *tx)
        .await?;
    if stored + resolved.len() as i64 > MAX_EVENTS_PER_ORG {
        return Err(ApiError::Conflict(
            "traffic event storage limit reached; lower the sampling rate or retention".into(),
        ));
    }
    let clamp = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
    for item in &resolved {
        let event = &item.event;
        sqlx::query(
            "INSERT INTO flow_events(id,org_id,reporter_id,flow_id,event_type,event_at,window_start,window_end,direction,protocol,protocol_number,icmp_type,icmp_code,src_ip,src_port,dst_ip,dst_port,src_kind,src_id,src_name,src_user,dst_kind,dst_id,dst_name,dst_user,dst_route,router_id,router_name,rule_basis,rule_index,rule_label,rule_hint,connection_type,rx_bytes,tx_bytes,rx_packets,tx_packets,aggregated,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&org_id)
        .bind(&reporter_id)
        .bind(&event.flow_id)
        .bind(label(&event.event_type))
        .bind(event.at)
        .bind(upload.window_start)
        .bind(upload.window_end)
        .bind(label(&event.direction))
        .bind(label(&event.protocol))
        .bind(i64::from(event.protocol_number.unwrap_or(0)))
        .bind(event.icmp_type.map(i64::from))
        .bind(event.icmp_code.map(i64::from))
        .bind(&event.src_ip)
        .bind(i64::from(event.src_port))
        .bind(&event.dst_ip)
        .bind(i64::from(event.dst_port))
        .bind(item.source.kind)
        .bind(item.source.id.as_deref())
        .bind(&item.source.name)
        .bind(item.source.user.as_deref())
        .bind(item.destination.kind)
        .bind(item.destination.id.as_deref())
        .bind(&item.destination.name)
        .bind(item.destination.user.as_deref())
        .bind(item.destination.route.as_deref())
        .bind(item.router.as_ref().map(|(id, _)| id.as_str()))
        .bind(item.router.as_ref().map(|(_, name)| name.as_str()))
        .bind(item.rule.basis)
        .bind(item.rule.index)
        .bind(&item.rule.label)
        .bind(event.rule_hint.as_deref())
        .bind(label(&item.connection_type))
        .bind(clamp(event.rx_bytes))
        .bind(clamp(event.tx_bytes))
        .bind(clamp(event.rx_packets))
        .bind(clamp(event.tx_packets))
        .bind(i64::from(event.aggregated))
        .bind(at)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(EventUploadResult {
            accepted: resolved.len(),
            sampled_out: total - resolved.len(),
            sampling_rate: settings.sampling_rate,
        }),
    ))
}

/// Deletes events older than each organisation's retention.
pub(crate) async fn purge_expired(store: &Store) -> Result<u64, ApiError> {
    Ok(sqlx::query(
        "DELETE FROM flow_events WHERE created_at < $1 - COALESCE((SELECT CAST(f.retention_days AS BIGINT) FROM flow_settings f WHERE f.org_id=flow_events.org_id),$2)*$3",
    )
    .bind(now())
    .bind(crate::traffic::DEFAULT_RETENTION_DAYS)
    .bind(DAY_SECS)
    .execute(&store.pool)
    .await?
    .rows_affected())
}

// ---------------------------------------------------------------------------
// Query

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventQuery {
    /// Unix seconds; default the last 24 hours.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) from: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) to: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) limit: Option<i64>,
    /// Free text: names, addresses, rule labels; a number also matches ports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) q: Option<String>,
    /// Source device or resource id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) source: Option<String>,
    /// Destination device id, resource id or route prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) destination: Option<String>,
    /// Owner of the source or destination device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reporter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) direction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) event_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) connection_type: Option<String>,
    /// Export only: `csv` (default) or `json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) format: Option<String>,
}

enum Bind {
    Text(String),
    Int(i64),
}

struct Filter {
    clauses: Vec<String>,
    binds: Vec<Bind>,
}

impl Filter {
    fn param(&mut self, bind: Bind) -> String {
        self.binds.push(bind);
        format!("${}", self.binds.len())
    }

    fn eq(&mut self, column: &str, value: Bind) {
        let param = self.param(value);
        self.clauses.push(format!("{column}={param}"));
    }
}

fn one_of(value: &str, allowed: &[&str], name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_ascii_lowercase();
    if allowed.contains(&value.as_str()) {
        Ok(value)
    } else {
        Err(ApiError::BadRequest(format!(
            "{name} must be one of {}",
            allowed.join(", ")
        )))
    }
}

fn like_pattern(value: &str) -> String {
    let mut out = String::from("%");
    for c in value.to_lowercase().chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

fn build_filter(org_id: &str, query: &EventQuery, at: i64) -> Result<Filter, ApiError> {
    let mut filter = Filter {
        clauses: Vec::new(),
        binds: Vec::new(),
    };
    filter.eq("org_id", Bind::Text(org_id.to_owned()));
    let from = query.from.unwrap_or(at - DEFAULT_WINDOW_SECS);
    let to = query.to.unwrap_or(at + CLOCK_SKEW_SECS);
    if from < 0 || to < from {
        return Err(ApiError::BadRequest("invalid time range".into()));
    }
    let param = filter.param(Bind::Int(from));
    filter.clauses.push(format!("event_at>={param}"));
    let param = filter.param(Bind::Int(to));
    filter.clauses.push(format!("event_at<={param}"));
    let id = |value: &str, name: &str| -> Result<String, ApiError> {
        let value = value.trim();
        if value.is_empty()
            || value.len() > 64
            || !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'))
        {
            return Err(ApiError::BadRequest(format!("invalid {name}")));
        }
        Ok(value.to_owned())
    };
    if let Some(source) = &query.source {
        filter.eq("src_id", Bind::Text(id(source, "source")?));
    }
    if let Some(destination) = &query.destination {
        let value = id(destination, "destination")?;
        let a = filter.param(Bind::Text(value.clone()));
        let b = filter.param(Bind::Text(value));
        filter
            .clauses
            .push(format!("(dst_id={a} OR dst_route={b})"));
    }
    if let Some(user) = &query.user {
        let value = user.trim();
        if value.is_empty() || value.len() > 128 {
            return Err(ApiError::BadRequest("invalid user".into()));
        }
        let a = filter.param(Bind::Text(value.to_owned()));
        let b = filter.param(Bind::Text(value.to_owned()));
        filter
            .clauses
            .push(format!("(src_user={a} OR dst_user={b})"));
    }
    if let Some(reporter) = &query.reporter {
        filter.eq("reporter_id", Bind::Text(id(reporter, "reporter")?));
    }
    if let Some(ip) = &query.ip {
        let address: IpAddr = ip
            .trim()
            .parse()
            .map_err(|_| ApiError::BadRequest("ip must be an IP address".into()))?;
        let a = filter.param(Bind::Text(address.to_string()));
        let b = filter.param(Bind::Text(address.to_string()));
        filter.clauses.push(format!("(src_ip={a} OR dst_ip={b})"));
    }
    if let Some(port) = query.port {
        let a = filter.param(Bind::Int(i64::from(port)));
        let b = filter.param(Bind::Int(i64::from(port)));
        filter
            .clauses
            .push(format!("(src_port={a} OR dst_port={b})"));
    }
    if let Some(protocol) = &query.protocol {
        filter.eq(
            "protocol",
            Bind::Text(one_of(
                protocol,
                &["tcp", "udp", "icmp", "icmpv6", "other"],
                "protocol",
            )?),
        );
    }
    if let Some(direction) = &query.direction {
        filter.eq(
            "direction",
            Bind::Text(one_of(direction, &["inbound", "outbound"], "direction")?),
        );
    }
    if let Some(event_type) = &query.event_type {
        filter.eq(
            "event_type",
            Bind::Text(one_of(event_type, &["start", "end", "drop"], "event_type")?),
        );
    }
    if let Some(connection_type) = &query.connection_type {
        filter.eq(
            "connection_type",
            Bind::Text(one_of(
                connection_type,
                &["p2p", "routed", "relay"],
                "connection_type",
            )?),
        );
    }
    if let Some(q) = query.q.as_deref().map(str::trim).filter(|q| !q.is_empty()) {
        if q.chars().count() > MAX_SEARCH_CHARS {
            return Err(ApiError::BadRequest("search is too long".into()));
        }
        let mut parts = Vec::new();
        for column in [
            "src_name",
            "dst_name",
            "src_ip",
            "dst_ip",
            "router_name",
            "rule_label",
            "dst_route",
        ] {
            let param = filter.param(Bind::Text(like_pattern(q)));
            parts.push(format!(
                "LOWER(COALESCE({column},'')) LIKE {param} ESCAPE '\\'"
            ));
        }
        if let Ok(port) = q.parse::<u16>() {
            let a = filter.param(Bind::Int(i64::from(port)));
            let b = filter.param(Bind::Int(i64::from(port)));
            parts.push(format!("src_port={a} OR dst_port={b}"));
        }
        filter.clauses.push(format!("({})", parts.join(" OR ")));
    }
    Ok(filter)
}

fn page_limit(query: &EventQuery) -> Result<i64, ApiError> {
    let limit = query.limit.unwrap_or(DEFAULT_PAGE);
    if !(1..=MAX_PAGE).contains(&limit) {
        return Err(ApiError::BadRequest(format!(
            "limit must be between 1 and {MAX_PAGE}"
        )));
    }
    Ok(limit)
}

/// Runs a statement assembled only from fixed SQL fragments and numbered
/// placeholders; every user value is a bind parameter.
fn statement(
    sql: String,
    binds: &[Bind],
) -> sqlx::query::Query<'static, sqlx::Any, sqlx::any::AnyArguments> {
    let mut statement = sqlx::query(sqlx::AssertSqlSafe(sql));
    for bind in binds {
        statement = match bind {
            Bind::Text(value) => statement.bind(value.clone()),
            Bind::Int(value) => statement.bind(*value),
        };
    }
    statement
}

/// `<at>:<tail>` where the tail orders ties.
fn parse_cursor(cursor: &str) -> Result<(i64, String), ApiError> {
    let invalid = || ApiError::BadRequest("invalid cursor".into());
    let (at, tail) = cursor.split_once(':').ok_or_else(invalid)?;
    let at: i64 = at.parse().map_err(|_| invalid())?;
    if tail.is_empty()
        || tail.len() > 160
        || !tail
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/'))
    {
        return Err(invalid());
    }
    Ok((at, tail.to_owned()))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct Endpoint {
    /// `device`, `resource`, `route` or `unknown`.
    pub(crate) kind: String,
    pub(crate) id: Option<String>,
    pub(crate) name: String,
    pub(crate) ip: String,
    pub(crate) port: u16,
    pub(crate) os: Option<String>,
    pub(crate) user_id: Option<String>,
    pub(crate) route: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct NodeRef {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) os: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct RuleView {
    pub(crate) basis: String,
    pub(crate) index: Option<i64>,
    pub(crate) label: String,
    pub(crate) hint: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct FlowEventView {
    pub(crate) id: String,
    pub(crate) flow_id: String,
    pub(crate) event_type: String,
    pub(crate) at: i64,
    pub(crate) window_start: i64,
    pub(crate) window_end: i64,
    pub(crate) reporter: NodeRef,
    pub(crate) direction: String,
    pub(crate) protocol: String,
    pub(crate) protocol_number: Option<i64>,
    pub(crate) icmp_type: Option<i64>,
    pub(crate) icmp_code: Option<i64>,
    pub(crate) icmp_name: Option<String>,
    pub(crate) source: Endpoint,
    pub(crate) destination: Endpoint,
    pub(crate) router: Option<NodeRef>,
    pub(crate) rule: RuleView,
    pub(crate) connection_type: String,
    pub(crate) rx_bytes: i64,
    pub(crate) tx_bytes: i64,
    pub(crate) rx_packets: i64,
    pub(crate) tx_packets: i64,
    pub(crate) aggregated: bool,
    pub(crate) received_at: i64,
}

/// Short name of an ICMP or ICMPv6 type.
pub(crate) fn icmp_name(protocol: &str, kind: i64, code: Option<i64>) -> Option<String> {
    let name = match (protocol, kind) {
        ("icmp", 0) | ("icmpv6", 129) => "Echo reply",
        ("icmp", 3) | ("icmpv6", 1) => match (protocol, code) {
            ("icmp", Some(3)) | ("icmpv6", Some(4)) => "Port unreachable",
            ("icmp", Some(1)) | ("icmpv6", Some(3)) => "Host unreachable",
            ("icmp", Some(13)) | ("icmpv6", Some(1)) => "Administratively prohibited",
            _ => "Destination unreachable",
        },
        ("icmp", 5) | ("icmpv6", 137) => "Redirect",
        ("icmp", 8) | ("icmpv6", 128) => "Echo",
        ("icmp", 11) | ("icmpv6", 3) => "Time exceeded",
        ("icmp", 12) | ("icmpv6", 4) => "Parameter problem",
        ("icmp", 13) => "Timestamp",
        ("icmp", 14) => "Timestamp reply",
        ("icmpv6", 2) => "Packet too big",
        ("icmpv6", 133) => "Router solicitation",
        ("icmpv6", 134) => "Router advertisement",
        ("icmpv6", 135) => "Neighbour solicitation",
        ("icmpv6", 136) => "Neighbour advertisement",
        ("icmp" | "icmpv6", _) => return Some(format!("Type {kind}")),
        _ => return None,
    };
    Some(name.into())
}

/// Current names and OS of the organisation's devices, for display.
async fn node_refs(
    pool: &sqlx::AnyPool,
    org_id: &str,
) -> Result<HashMap<String, NodeRef>, ApiError> {
    let rows = sqlx::query("SELECT id,name,display_name,os FROM nodes WHERE org_id=$1")
        .bind(org_id)
        .fetch_all(pool)
        .await?;
    let mut out = HashMap::new();
    for row in rows {
        let id: String = row.try_get(0)?;
        let name: String = row.try_get(1)?;
        let display: Option<String> = row.try_get(2)?;
        out.insert(
            id.clone(),
            NodeRef {
                id,
                name: display.filter(|v| !v.trim().is_empty()).unwrap_or(name),
                os: row.try_get(3)?,
            },
        );
    }
    Ok(out)
}

fn view(
    row: &sqlx::any::AnyRow,
    nodes: &HashMap<String, NodeRef>,
) -> Result<FlowEventView, ApiError> {
    let reporter_id: String = row.try_get(1)?;
    let protocol: String = row.try_get(8)?;
    let icmp_type: Option<i64> = row.try_get(10)?;
    let icmp_code: Option<i64> = row.try_get(11)?;
    let protocol_number: i64 = row.try_get(9)?;
    let port = |index: usize| -> Result<u16, ApiError> {
        Ok(u16::try_from(row.try_get::<i64, _>(index)?).unwrap_or(0))
    };
    let endpoint = |kind: usize, ip: usize, port_at: usize| -> Result<Endpoint, ApiError> {
        let id: Option<String> = row.try_get(kind + 1)?;
        let kind_text: String = row.try_get(kind)?;
        let os = (kind_text == "device")
            .then(|| {
                id.as_ref()
                    .and_then(|id| nodes.get(id))
                    .and_then(|n| n.os.clone())
            })
            .flatten();
        Ok(Endpoint {
            kind: kind_text,
            id,
            name: row.try_get(kind + 2)?,
            ip: row.try_get(ip)?,
            port: port(port_at)?,
            os,
            user_id: row.try_get(kind + 3)?,
            route: None,
        })
    };
    let source = endpoint(16, 12, 13)?;
    let mut destination = endpoint(20, 14, 15)?;
    destination.route = row.try_get(24)?;
    let router_id: Option<String> = row.try_get(25)?;
    let router_name: Option<String> = row.try_get(26)?;
    Ok(FlowEventView {
        id: row.try_get(0)?,
        flow_id: row.try_get(2)?,
        event_type: row.try_get(3)?,
        at: row.try_get(4)?,
        window_start: row.try_get(5)?,
        window_end: row.try_get(6)?,
        reporter: nodes.get(&reporter_id).cloned().unwrap_or(NodeRef {
            id: reporter_id,
            name: "Deleted device".into(),
            os: None,
        }),
        direction: row.try_get(7)?,
        icmp_name: icmp_type.and_then(|kind| icmp_name(&protocol, kind, icmp_code)),
        protocol,
        protocol_number: (protocol_number != 0).then_some(protocol_number),
        icmp_type,
        icmp_code,
        source,
        destination,
        router: router_id.map(|id| NodeRef {
            name: nodes
                .get(&id)
                .map(|node| node.name.clone())
                .or(router_name.clone())
                .unwrap_or_default(),
            os: nodes.get(&id).and_then(|node| node.os.clone()),
            id,
        }),
        rule: RuleView {
            basis: row.try_get(27)?,
            index: row.try_get(28)?,
            label: row.try_get(29)?,
            hint: row.try_get(30)?,
        },
        connection_type: row.try_get(31)?,
        rx_bytes: row.try_get(32)?,
        tx_bytes: row.try_get(33)?,
        rx_packets: row.try_get(34)?,
        tx_packets: row.try_get(35)?,
        aggregated: row.try_get::<i64, _>(36)? != 0,
        received_at: row.try_get(37)?,
    })
}

/// Flat event list, newest first.
pub(crate) async fn load_events(
    pool: &sqlx::AnyPool,
    org_id: &str,
    query: &EventQuery,
    limit: i64,
) -> Result<(Vec<FlowEventView>, Option<String>), ApiError> {
    let mut filter = build_filter(org_id, query, now())?;
    if let Some(cursor) = &query.cursor {
        let (at, id) = parse_cursor(cursor)?;
        let a = filter.param(Bind::Int(at));
        let b = filter.param(Bind::Int(at));
        let c = filter.param(Bind::Text(id));
        filter
            .clauses
            .push(format!("(event_at<{a} OR (event_at={b} AND id<{c}))"));
    }
    let limit_param = filter.param(Bind::Int(limit + 1));
    let sql = format!(
        "SELECT {COLUMNS} FROM flow_events WHERE {} ORDER BY event_at DESC, id DESC LIMIT {limit_param}",
        filter.clauses.join(" AND ")
    );
    let rows = statement(sql, &filter.binds).fetch_all(pool).await?;
    let nodes = node_refs(pool, org_id).await?;
    let mut events = rows
        .iter()
        .map(|row| view(row, &nodes))
        .collect::<Result<Vec<_>, _>>()?;
    let next = if events.len() as i64 > limit {
        events.truncate(limit as usize);
        events
            .last()
            .map(|event| format!("{}:{}", event.at, event.id))
    } else {
        None
    };
    Ok((events, next))
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct FlowGroup {
    /// `<reporter id>/<flow id>`.
    pub(crate) key: String,
    pub(crate) reporter_id: String,
    pub(crate) flow_id: String,
    pub(crate) first_at: i64,
    pub(crate) last_at: i64,
    /// Every stored event of the flow, oldest first (start → end or drop).
    pub(crate) events: Vec<FlowEventView>,
}

/// Flows (one reporter's view of one connection), most recent activity first.
/// Filters select which flows appear; each flow then carries all its events.
pub(crate) async fn load_flows(
    pool: &sqlx::AnyPool,
    org_id: &str,
    query: &EventQuery,
    limit: i64,
) -> Result<(Vec<FlowGroup>, Option<String>), ApiError> {
    let mut filter = build_filter(org_id, query, now())?;
    let mut having = String::new();
    if let Some(cursor) = &query.cursor {
        let (at, key) = parse_cursor(cursor)?;
        let a = filter.param(Bind::Int(at));
        let b = filter.param(Bind::Int(at));
        let c = filter.param(Bind::Text(key));
        having = format!(
            " HAVING (MAX(event_at)<{a} OR (MAX(event_at)={b} AND (reporter_id || '/' || flow_id)<{c}))"
        );
    }
    let limit_param = filter.param(Bind::Int(limit + 1));
    let sql = format!(
        "SELECT reporter_id,flow_id,MAX(event_at),MIN(event_at) FROM flow_events WHERE {} GROUP BY reporter_id,flow_id{having} ORDER BY MAX(event_at) DESC, (reporter_id || '/' || flow_id) DESC LIMIT {limit_param}",
        filter.clauses.join(" AND ")
    );
    let rows = statement(sql, &filter.binds).fetch_all(pool).await?;
    let mut groups = Vec::with_capacity(rows.len());
    for row in &rows {
        let reporter_id: String = row.try_get(0)?;
        let flow_id: String = row.try_get(1)?;
        groups.push(FlowGroup {
            key: format!("{reporter_id}/{flow_id}"),
            reporter_id,
            flow_id,
            last_at: row.try_get(2)?,
            first_at: row.try_get(3)?,
            events: Vec::new(),
        });
    }
    let next = if groups.len() as i64 > limit {
        groups.truncate(limit as usize);
        groups
            .last()
            .map(|group| format!("{}:{}", group.last_at, group.key))
    } else {
        None
    };
    if groups.is_empty() {
        return Ok((groups, next));
    }
    let flow_ids: BTreeSet<&str> = groups.iter().map(|group| group.flow_id.as_str()).collect();
    let placeholders: Vec<String> = (0..flow_ids.len()).map(|i| format!("${}", i + 2)).collect();
    let sql = format!(
        "SELECT {COLUMNS} FROM flow_events WHERE org_id=$1 AND flow_id IN ({}) ORDER BY event_at ASC, CASE event_type WHEN 'start' THEN 0 ELSE 1 END, id ASC",
        placeholders.join(",")
    );
    let mut binds = vec![Bind::Text(org_id.to_owned())];
    binds.extend(flow_ids.iter().map(|id| Bind::Text((*id).to_owned())));
    let rows = statement(sql, &binds).fetch_all(pool).await?;
    let nodes = node_refs(pool, org_id).await?;
    let mut index: HashMap<String, usize> = HashMap::new();
    for (position, group) in groups.iter().enumerate() {
        index.insert(group.key.clone(), position);
    }
    for row in &rows {
        let event = view(row, &nodes)?;
        let key = format!("{}/{}", event.reporter.id, event.flow_id);
        if let Some(group) = index.get(&key).and_then(|i| groups.get_mut(*i)) {
            if group.events.len() < MAX_EVENTS_PER_FLOW {
                group.events.push(event);
            }
        }
    }
    Ok((groups, next))
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Freshness {
    pub(crate) settings: TrafficSettings,
    /// `disabled`, `no_data`, `stale` or `current`.
    pub(crate) state: String,
    pub(crate) last_received_at: Option<i64>,
    pub(crate) reporting_devices: i64,
    pub(crate) generated_at: i64,
}

async fn freshness(pool: &sqlx::AnyPool, org_id: &str) -> Result<Freshness, ApiError> {
    let settings = load_settings_pool(pool, org_id).await?;
    let at = now();
    let row = sqlx::query(
        "SELECT MAX(created_at),COUNT(DISTINCT reporter_id) FROM flow_events WHERE org_id=$1 AND created_at>=$2",
    )
    .bind(org_id)
    .bind(at - DEFAULT_WINDOW_SECS)
    .fetch_one(pool)
    .await?;
    let last: Option<i64> = row.try_get(0)?;
    let last_received_at = match last {
        Some(last) => Some(last),
        None => {
            sqlx::query_scalar("SELECT MAX(created_at) FROM flow_events WHERE org_id=$1")
                .bind(org_id)
                .fetch_one(pool)
                .await?
        }
    };
    Ok(Freshness {
        state: traffic_state(settings.enabled, last_received_at, at).into(),
        settings,
        last_received_at,
        reporting_devices: row.try_get(1)?,
        generated_at: at,
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct EventsPage {
    pub(crate) events: Vec<FlowEventView>,
    pub(crate) next_cursor: Option<String>,
    #[serde(flatten)]
    pub(crate) freshness: Freshness,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct FlowsPage {
    pub(crate) flows: Vec<FlowGroup>,
    pub(crate) next_cursor: Option<String>,
    #[serde(flatten)]
    pub(crate) freshness: Freshness,
}

async fn list_events_console(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Query(query): Query<EventQuery>,
) -> Result<Json<EventsPage>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewAudit)?;
    let org = org_id.to_string();
    let limit = page_limit(&query)?;
    let (events, next_cursor) = load_events(&s.store.pool, &org, &query, limit).await?;
    Ok(Json(EventsPage {
        events,
        next_cursor,
        freshness: freshness(&s.store.pool, &org).await?,
    }))
}

async fn list_flows_console(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Query(query): Query<EventQuery>,
) -> Result<Json<FlowsPage>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewAudit)?;
    let org = org_id.to_string();
    let limit = page_limit(&query)?;
    let (flows, next_cursor) = load_flows(&s.store.pool, &org, &query, limit).await?;
    Ok(Json(FlowsPage {
        flows,
        next_cursor,
        freshness: freshness(&s.store.pool, &org).await?,
    }))
}

/// `GET /api/v1/traffic/events`: the flat list for API clients with
/// `audit:read`.
pub(crate) async fn api_list_events(
    State(s): State<AppState>,
    Query(query): Query<EventQuery>,
    headers: HeaderMap,
) -> Result<Json<Envelope<Vec<FlowEventView>>>, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::AuditRead)?;
    require(&caller.session, Permission::ViewAudit)?;
    let limit = page_limit(&query)?;
    let (events, next_cursor) =
        load_events(&s.store.pool, &org_id.to_string(), &query, limit).await?;
    Ok(Json(Envelope {
        data: events,
        next_cursor,
    }))
}

fn csv_cell(value: &str) -> String {
    // Spreadsheet formula injection: prefix cells a spreadsheet would run.
    let value = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value
    }
}

pub(crate) fn to_csv(events: &[FlowEventView]) -> String {
    let mut out = String::from(
        "time_utc,event,reporter,direction,connection_type,protocol,icmp,source_kind,source_name,source_ip,source_port,destination_kind,destination_name,destination_ip,destination_port,destination_route,router,rule_basis,rule,rx_bytes,tx_bytes,rx_packets,tx_packets,aggregated,flow_id\r\n",
    );
    for event in events {
        let time = chrono_utc(event.at);
        let cells = [
            time,
            event.event_type.clone(),
            event.reporter.name.clone(),
            event.direction.clone(),
            event.connection_type.clone(),
            event.protocol.clone(),
            event.icmp_name.clone().unwrap_or_default(),
            event.source.kind.clone(),
            event.source.name.clone(),
            event.source.ip.clone(),
            event.source.port.to_string(),
            event.destination.kind.clone(),
            event.destination.name.clone(),
            event.destination.ip.clone(),
            event.destination.port.to_string(),
            event.destination.route.clone().unwrap_or_default(),
            event
                .router
                .as_ref()
                .map(|router| router.name.clone())
                .unwrap_or_default(),
            event.rule.basis.clone(),
            event.rule.label.clone(),
            event.rx_bytes.to_string(),
            event.tx_bytes.to_string(),
            event.rx_packets.to_string(),
            event.tx_packets.to_string(),
            event.aggregated.to_string(),
            event.flow_id.clone(),
        ];
        out.push_str(
            &cells
                .iter()
                .map(|cell| csv_cell(cell))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str("\r\n");
    }
    out
}

/// RFC 3339 UTC without pulling in a date crate.
fn chrono_utc(seconds: i64) -> String {
    let days = seconds.div_euclid(DAY_SECS);
    let rem = seconds.rem_euclid(DAY_SECS);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

async fn export_console(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Query(query): Query<EventQuery>,
) -> Result<Response, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    export(&s.store, org_id, &session, query).await
}

async fn export(
    store: &Store,
    org_id: Uuid,
    session: &Session,
    mut query: EventQuery,
) -> Result<Response, ApiError> {
    require(session, Permission::ExportAudit)?;
    let format = query.format.take().unwrap_or_else(|| "csv".into());
    if !matches!(format.as_str(), "csv" | "json") {
        return Err(ApiError::BadRequest("format must be csv or json".into()));
    }
    query.cursor = None;
    query.limit = None;
    let org = org_id.to_string();
    let mut events = Vec::new();
    let mut truncated = false;
    loop {
        let (page, next) = load_events(&store.pool, &org, &query, MAX_PAGE).await?;
        events.extend(page);
        match next {
            Some(cursor) if (events.len() as i64) < MAX_EXPORT_ROWS => query.cursor = Some(cursor),
            Some(_) => {
                truncated = true;
                break;
            }
            None => break,
        }
    }
    query.cursor = None;
    let mut tx = store.pool.begin().await?;
    append_audit(
        &mut tx,
        org_id,
        session,
        "traffic.events_exported",
        "traffic_events",
        Some(&org),
        &serde_json::json!({
            "format": format,
            "count": events.len(),
            "truncated": truncated,
            "filters": serde_json::to_value(&query).unwrap_or_default(),
        }),
    )
    .await?;
    tx.commit().await?;
    let mut response = if format == "csv" {
        let mut response = to_csv(&events).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/csv; charset=utf-8"),
        );
        response
    } else {
        Json(serde_json::json!({ "data": events, "truncated": truncated })).into_response()
    };
    if let Ok(value) = HeaderValue::from_str(&format!(
        "attachment; filename=\"blaktail-traffic-events-{org_id}.{format}\""
    )) {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, value);
    }
    response.headers_mut().insert(
        "x-blaktail-export-truncated",
        HeaderValue::from_static(if truncated { "true" } else { "false" }),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> UploadEvent {
        UploadEvent {
            flow_id: "f-1".into(),
            event_type: EventType::Start,
            at: 1_000,
            direction: Direction::Outbound,
            protocol: Protocol::Tcp,
            protocol_number: None,
            icmp_type: None,
            icmp_code: None,
            src_ip: "100.64.0.2".into(),
            src_port: 50_000,
            dst_ip: "100.64.0.3".into(),
            dst_port: 22,
            peer_id: None,
            connection_type: ConnectionType::P2p,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            rule_hint: None,
            aggregated: false,
        }
    }

    #[test]
    fn events_validate_ports_icmp_families_and_labels() {
        assert!(validate_event(&event(), 990, 1_020).is_ok());
        let mut bad = event();
        bad.src_port = 0;
        assert!(validate_event(&bad, 990, 1_020).is_err());
        bad.aggregated = true;
        assert!(validate_event(&bad, 990, 1_020).is_ok());
        let mut icmp = event();
        icmp.protocol = Protocol::Icmp;
        icmp.src_port = 0;
        icmp.dst_port = 0;
        assert!(validate_event(&icmp, 990, 1_020).is_err(), "needs a type");
        icmp.icmp_type = Some(8);
        assert!(validate_event(&icmp, 990, 1_020).is_ok());
        icmp.dst_ip = "fd7a::1".into();
        assert!(validate_event(&icmp, 990, 1_020).is_err(), "mixed family");
        let mut v6 = icmp.clone();
        v6.src_ip = "fd7a::2".into();
        assert!(validate_event(&v6, 990, 1_020).is_err(), "icmp on v6");
        v6.protocol = Protocol::Icmpv6;
        assert!(validate_event(&v6, 990, 1_020).is_ok());
        for (field, value) in [
            ("flow", "has space"),
            ("hint", "Acl:Default"),
            ("peer", "x"),
        ] {
            let mut bad = event();
            match field {
                "flow" => bad.flow_id = value.into(),
                "hint" => bad.rule_hint = Some(value.into()),
                _ => bad.peer_id = Some(value.into()),
            }
            assert!(validate_event(&bad, 990, 1_020).is_err(), "{field}");
        }
        let mut late = event();
        late.at = 1_020 + CLOCK_SKEW_SECS + 1;
        assert!(validate_event(&late, 990, 1_020).is_err());
        let mut other = event();
        other.protocol = Protocol::Other;
        other.src_port = 0;
        other.dst_port = 0;
        assert!(validate_event(&other, 990, 1_020).is_err());
        other.protocol_number = Some(47);
        assert!(validate_event(&other, 990, 1_020).is_ok());
    }

    #[test]
    fn upload_refuses_unknown_and_payload_fields_and_large_or_odd_windows() {
        let raw = serde_json::json!({
            "org_id": "o", "window_start": 0, "window_end": 30,
            "events": [{"flow_id":"a","type":"start","at":1,"direction":"outbound","protocol":"tcp",
                        "src_ip":"100.64.0.1","src_port":1,"dst_ip":"100.64.0.2","dst_port":2,
                        "connection_type":"p2p","url":"https://x"}]
        });
        assert!(validate_flow_json(&raw).is_err());
        let mut unknown = raw.clone();
        unknown["events"][0].as_object_mut().unwrap().remove("url");
        unknown["events"][0]["payload_hash"] = serde_json::json!("x");
        assert!(serde_json::from_value::<EventUpload>(unknown).is_err());
        let upload = EventUpload {
            org_id: "o".into(),
            window_start: 100,
            window_end: 100 + MAX_WINDOW_SECS + 1,
            events: vec![],
        };
        assert!(validate_window(&upload, 10_000).is_err());
        let upload = EventUpload {
            org_id: "o".into(),
            window_start: 0,
            window_end: 30,
            events: vec![event(); MAX_EVENTS_PER_BATCH + 1],
        };
        assert!(validate_window(&upload, 30).is_err());
        let upload = EventUpload {
            org_id: "o".into(),
            window_start: 10_000,
            window_end: 10_000 + CLOCK_SKEW_SECS + 31,
            events: vec![],
        };
        assert!(validate_window(&upload, 10_000).is_err(), "future");
    }

    #[test]
    fn cidr_matching_and_icmp_names() {
        let net = parse_cidr("10.20.0.0/16").unwrap();
        assert!(cidr_contains(net, "10.20.3.4".parse().unwrap()));
        assert!(!cidr_contains(net, "10.21.0.1".parse().unwrap()));
        assert!(!cidr_contains(net, "fd7a::1".parse().unwrap()));
        let v6 = parse_cidr("fd7a:115c::/32").unwrap();
        assert!(cidr_contains(v6, "fd7a:115c:1::5".parse().unwrap()));
        assert_eq!(parse_cidr("10.0.0.1").unwrap().1, 32);
        assert!(parse_cidr("10.0.0.0/33").is_none());
        assert_eq!(icmp_name("icmp", 8, Some(0)).as_deref(), Some("Echo"));
        assert_eq!(icmp_name("icmpv6", 128, None).as_deref(), Some("Echo"));
        assert_eq!(
            icmp_name("icmp", 3, Some(3)).as_deref(),
            Some("Port unreachable")
        );
        assert_eq!(icmp_name("tcp", 8, None), None);
    }

    #[test]
    fn resource_grants_follow_ports_and_protocols() {
        let resource = |ports: Vec<(u16, u16)>, protocols: Vec<&str>| ResourceEntry {
            id: "r".into(),
            name: "db".into(),
            cidr: "10.0.0.0/24".into(),
            network: parse_cidr("10.0.0.0/24").unwrap(),
            routing_peers: vec![],
            ports,
            protocols: protocols.into_iter().map(str::to_owned).collect(),
        };
        let all = resource(vec![], vec![]);
        assert!(all.grants(Protocol::Tcp, 1) && all.grants(Protocol::Icmp, 0));
        let db = resource(vec![(5432, 5432)], vec!["tcp"]);
        assert!(db.grants(Protocol::Tcp, 5432));
        assert!(!db.grants(Protocol::Tcp, 8080));
        assert!(!db.grants(Protocol::Udp, 5432));
        assert!(!db.grants(Protocol::Icmp, 0));
        let ping = resource(vec![], vec!["icmp"]);
        assert!(ping.grants(Protocol::Icmp, 0) && !ping.grants(Protocol::Tcp, 80));
        let both = resource(vec![(443, 443)], vec![]);
        assert!(both.grants(Protocol::Udp, 443) && !both.grants(Protocol::Icmp, 0));
    }

    #[test]
    fn drops_never_claim_an_allow_rule() {
        let allowed = RuleOutcome {
            basis: "rule",
            index: Some(0),
            label: "Rule 1".into(),
        };
        assert_eq!(reconcile(EventType::Start, allowed.clone()).basis, "rule");
        let dropped = reconcile(EventType::Drop, allowed);
        assert_eq!(dropped.basis, "unknown");
        assert!(dropped.label.contains("older policy"));
        let resource = RuleOutcome {
            basis: "resource",
            index: None,
            label: "Network resource db".into(),
        };
        assert_eq!(reconcile(EventType::Drop, resource).basis, "default_deny");
    }

    #[test]
    fn csv_is_quoted_and_formula_safe_and_times_are_utc() {
        assert_eq!(chrono_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(chrono_utc(1_782_000_000), "2026-06-21T00:00:00Z");
        assert_eq!(csv_cell("=cmd"), "'=cmd");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(like_pattern("a_b%"), "%a\\_b\\%%");
    }

    #[test]
    fn sampling_keeps_or_drops_whole_flows() {
        let a = sample_draw("org", "dev", "flow-1");
        assert_eq!(a, sample_draw("org", "dev", "flow-1"));
        assert_ne!(a, sample_draw("org", "dev", "flow-2"));
    }
}
