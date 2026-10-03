//! Control Center topology read model (NetBird-parity draft 02).
//!
//! One organisation's devices, network resources, approved routes and the
//! effective reachability between them, computed by the same evaluator and
//! peer-map compiler agents receive (`policy_explain::device_flow`,
//! `resources::overview_conn`). There is no second policy engine here, and
//! nothing reads or reveals another organisation's inventory.

use crate::{
    console_session, load_acl_row, now,
    permissions::{require, Permission},
    policy_explain::{device_flow, device_subject},
    posture::{enforcement_profile, PostureContext},
    resources::{self, NetworksOverview, ResourceAccess, ResourceKind, ResourceProtocol},
    subject_in_group, Acl, AclProtocol, Action, ApiError, AppState, DeviceTag, Role, Subject,
    NODE_ONLINE_SECS,
};
use axum::{
    extract::{Path as UrlPath, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::BTreeMap;
use uuid::Uuid;

/// Agent transport reports older than this are shown as stale telemetry.
const TRANSPORT_FRESH_SECS: i64 = 10 * 60;
/// Pairwise evaluation is quadratic; past this many devices edges are
/// truncated rather than letting one request monopolise the coordinator.
const MAX_EDGE_NODES: usize = 400;
const TRANSPORTS: [&str; 3] = ["direct", "relay", "mixed"];

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/v1/orgs/:org_id/topology", get(get_topology))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct TransportView {
    /// `direct`, `relay`, `mixed` or `not_measured`, as the agent reported.
    pub(crate) state: String,
    pub(crate) reported_at: Option<i64>,
    /// True when a report exists but is older than ten minutes.
    pub(crate) stale: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct NodeView {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) label: String,
    pub(crate) role: Role,
    pub(crate) tags: Vec<DeviceTag>,
    /// `online`, `stale`, `never`, `suspended` or `expired`.
    pub(crate) state: String,
    pub(crate) last_seen_at: Option<i64>,
    pub(crate) transport: TransportView,
    /// `enforced`, `unknown` or `not_enforced` inbound packet filtering.
    pub(crate) packet_filter: String,
    pub(crate) advertised_routes: Vec<String>,
    pub(crate) approved_routes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RoutingPeerView {
    pub(crate) node_id: Uuid,
    pub(crate) name: Option<String>,
    pub(crate) state: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ResourceView {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) destination: String,
    pub(crate) enabled: bool,
    pub(crate) state: String,
    pub(crate) selected_routing_peer: Option<Uuid>,
    pub(crate) routing_peers: Vec<RoutingPeerView>,
    pub(crate) receiving: usize,
    /// `cidr` or `dns`.
    pub(crate) kind: ResourceKind,
    /// Ports and protocols the resource admits; empty means all.
    pub(crate) ports: Vec<String>,
    pub(crate) protocols: Vec<ResourceProtocol>,
    /// `enforced` when the selected routing peer filters forwarded ports.
    pub(crate) port_enforcement: String,
    /// Which roles, device tags or policy groups receive it.
    pub(crate) access: ResourceAccess,
}

/// A policy selector as written; the graph draws one node per item.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct SelectorView {
    pub(crate) roles: Vec<Role>,
    pub(crate) tags: Vec<DeviceTag>,
    pub(crate) groups: Vec<String>,
    /// Destination only: named policy hosts behind subnet routes.
    #[serde(default)]
    pub(crate) hosts: Vec<String>,
}

/// One access rule of the published policy. Rules carry no names, so the
/// console labels them by position (`index` is zero-based).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RuleView {
    pub(crate) index: usize,
    /// `allow` or `deny`.
    pub(crate) action: String,
    pub(crate) src: SelectorView,
    pub(crate) dst: SelectorView,
    /// Empty means every protocol.
    pub(crate) protocols: Vec<AclProtocol>,
    /// Empty means every port.
    pub(crate) ports: Vec<String>,
    pub(crate) posture: Vec<String>,
}

/// A named policy group and which of this organisation's active devices it
/// matches today. Member identities are not exposed, only their count.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct GroupView {
    pub(crate) name: String,
    pub(crate) members: usize,
    pub(crate) devices: Vec<Uuid>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RouteView {
    pub(crate) node_id: Uuid,
    pub(crate) cidr: String,
    /// `subnet` or `exit`.
    pub(crate) kind: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct EditTarget {
    /// `policy`, `network_resource` or `device`.
    pub(crate) surface: String,
    pub(crate) id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct Edge {
    /// `device`, `resource`, `route` or `exit`.
    pub(crate) kind: String,
    pub(crate) source_node_id: Uuid,
    /// Destination device for `device` edges, routing peer otherwise.
    pub(crate) target_node_id: Option<Uuid>,
    pub(crate) resource_id: Option<Uuid>,
    pub(crate) destination: String,
    /// Why policy admits it: an explain basis, `resource_access` or `route_approved`.
    pub(crate) basis: String,
    /// `device_enforced`, `not_enforced`, `unknown` or `route_not_filtered`.
    pub(crate) enforcement: String,
    /// `direct`, `relay`, `mixed`, `unknown` or `peer_offline`.
    pub(crate) path: String,
    pub(crate) explanation: String,
    pub(crate) edit: EditTarget,
    /// Device edges: indices of the policy rules whose selectors match this
    /// pair (allow and deny), from the same evaluator. Empty when only the
    /// same-tag default admits it, and for route and resource edges.
    #[serde(default)]
    pub(crate) rules: Vec<usize>,
}

impl Edge {
    /// Identity used to diff two topologies: what is reachable, not how.
    pub(crate) fn key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.kind,
            self.source_node_id,
            self.target_node_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            self.resource_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            self.destination
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct PolicyMeta {
    pub(crate) revision: i64,
    pub(crate) etag: String,
    pub(crate) defaults: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Topology {
    pub(crate) org_id: Uuid,
    /// Coordinator time this snapshot was computed. The control plane
    /// answered; data-plane state is only what agents last reported.
    pub(crate) generated_at: i64,
    pub(crate) control_revision: i64,
    pub(crate) policy: PolicyMeta,
    pub(crate) nodes: Vec<NodeView>,
    pub(crate) resources: Vec<ResourceView>,
    pub(crate) routes: Vec<RouteView>,
    pub(crate) edges: Vec<Edge>,
    #[serde(default)]
    pub(crate) rules: Vec<RuleView>,
    #[serde(default)]
    pub(crate) groups: Vec<GroupView>,
    pub(crate) truncated: bool,
    pub(crate) notes: Vec<String>,
}

/// Everything a change draft cannot alter: devices, their posture facts and
/// reported transport. Loaded from the pool before any draft transaction.
pub(crate) struct Inputs {
    pub(crate) ctx: PostureContext,
    pub(crate) nodes: Vec<NodeView>,
}

pub(crate) async fn load_inputs(pool: &sqlx::AnyPool, org_id: Uuid) -> Result<Inputs, ApiError> {
    let org = org_id.to_string();
    let ctx = PostureContext::load(pool, &org).await?;
    let rows = sqlx::query(
        "SELECT id,name,display_name,user_role,tags_json,last_seen_at,suspended_at,credential_expires_at,transport,transport_reported_at,advertised_routes_json,approved_routes_json,os,capabilities_json FROM nodes WHERE org_id=$1 AND revoked_at IS NULL AND deleted_at IS NULL ORDER BY name,id",
    )
    .bind(&org)
    .fetch_all(pool)
    .await?;
    let at = ctx.now;
    let mut nodes = Vec::with_capacity(rows.len());
    for row in rows {
        let id =
            Uuid::parse_str(&row.try_get::<String, _>(0)?).map_err(|_| ApiError::CorruptData)?;
        let name: String = row.try_get(1)?;
        let display_name: Option<String> = row.try_get(2)?;
        let last_seen_at: Option<i64> = row.try_get(5)?;
        let suspended_at: Option<i64> = row.try_get(6)?;
        let credential_expires_at: i64 = row.try_get(7)?;
        let transport: Option<String> = row.try_get(8)?;
        let reported_at: Option<i64> = row.try_get(9)?;
        let os: Option<String> = row.try_get(12)?;
        let capabilities: Vec<String> =
            serde_json::from_str(&row.try_get::<String, _>(13)?).unwrap_or_default();
        let state = if suspended_at.is_some() {
            "suspended"
        } else if credential_expires_at <= at {
            "expired"
        } else {
            match last_seen_at {
                None => "never",
                Some(seen) if at - seen <= NODE_ONLINE_SECS => "online",
                Some(_) => "stale",
            }
        };
        let transport = transport.filter(|value| TRANSPORTS.contains(&value.as_str()));
        nodes.push(NodeView {
            id,
            label: display_name
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| name.clone()),
            name,
            role: row
                .try_get::<String, _>(3)?
                .parse()
                .map_err(|_| ApiError::CorruptData)?,
            tags: serde_json::from_str(&row.try_get::<String, _>(4)?).unwrap_or_default(),
            state: state.into(),
            last_seen_at,
            transport: TransportView {
                stale: transport.is_some()
                    && reported_at.is_none_or(|reported| at - reported > TRANSPORT_FRESH_SECS),
                state: transport.unwrap_or_else(|| "not_measured".into()),
                reported_at,
            },
            packet_filter: enforcement_profile(os.as_deref(), &capabilities)
                .packet_filter
                .into(),
            advertised_routes: serde_json::from_str(&row.try_get::<String, _>(10)?)
                .unwrap_or_default(),
            approved_routes: serde_json::from_str(&row.try_get::<String, _>(11)?)
                .unwrap_or_default(),
        });
    }
    Ok(Inputs { ctx, nodes })
}

/// Peer maps exclude suspended and expired devices entirely.
fn in_peer_maps(node: &NodeView) -> bool {
    !matches!(node.state.as_str(), "suspended" | "expired")
}

/// Combines the two endpoints' own transport summaries. Agents report one
/// summary for all their peers, so this is not a per-pair measurement.
fn path_between(a: &NodeView, b: &NodeView) -> &'static str {
    if a.state != "online" || b.state != "online" {
        return "peer_offline";
    }
    fn fresh(node: &NodeView) -> &str {
        if node.transport.stale {
            "not_measured"
        } else {
            node.transport.state.as_str()
        }
    }
    match (fresh(a), fresh(b)) {
        ("relay", _) | (_, "relay") => "relay",
        ("mixed", _) | (_, "mixed") => "mixed",
        ("direct", "direct") => "direct",
        _ => "unknown",
    }
}

fn path_text(path: &str) -> &'static str {
    match path {
        "direct" => "both agents report direct UDP",
        "relay" => "an agent reports the Australian relay",
        "mixed" => "an agent reports some peers relayed",
        "peer_offline" => "an endpoint is not online, so no live path",
        _ => "path not measured",
    }
}

fn subjects(inputs: &Inputs) -> BTreeMap<Uuid, Subject> {
    inputs
        .nodes
        .iter()
        .filter(|node| in_peer_maps(node))
        .filter_map(|node| {
            inputs
                .ctx
                .facts
                .get(&node.id)
                .map(|facts| (node.id, device_subject(facts, &inputs.ctx)))
        })
        .collect()
}

/// Effective reachability edges for `acl` and `networks`, as agents would
/// receive them from the peer-map compiler.
pub(crate) fn edges(inputs: &Inputs, acl: &Acl, networks: &NetworksOverview) -> (Vec<Edge>, bool) {
    let subjects = subjects(inputs);
    let active: Vec<&NodeView> = inputs
        .nodes
        .iter()
        .filter(|node| subjects.contains_key(&node.id))
        .collect();
    let truncated = active.len() > MAX_EDGE_NODES;
    let active = &active[..active.len().min(MAX_EDGE_NODES)];
    let mut edges = Vec::new();
    for source in active {
        let source_subject = &subjects[&source.id];
        for target in active.iter().filter(|target| target.id != source.id) {
            let target_subject = &subjects[&target.id];
            let facts = &inputs.ctx.facts[&target.id];
            let flow = device_flow(acl, source_subject, target_subject, facts, None, None);
            let paired = flow.paired();
            if flow.decision() {
                let path = path_between(source, target);
                edges.push(Edge {
                    kind: "device".into(),
                    source_node_id: source.id,
                    target_node_id: Some(target.id),
                    resource_id: None,
                    destination: target.label.clone(),
                    basis: flow.basis().into(),
                    enforcement: flow.enforcement().into(),
                    path: path.into(),
                    explanation: format!(
                        "{} can reach {} (policy basis: {}; {}); {}.",
                        source.label,
                        target.label,
                        flow.basis().replace('_', " "),
                        match flow.enforcement() {
                            "device_enforced" => "ports enforced on the destination",
                            "unknown" => "port enforcement unproven on the destination",
                            _ => "ports not enforced on the destination",
                        },
                        path_text(path)
                    ),
                    edit: EditTarget {
                        surface: "policy".into(),
                        id: None,
                    },
                    rules: flow.rules.clone(),
                });
            }
            // Approved device routes ride on the router's peer entry.
            if !paired {
                continue;
            }
            for cidr in &target.approved_routes {
                let exit = cidr == "0.0.0.0/0" || cidr == "::/0";
                let path = path_between(source, target);
                edges.push(Edge {
                    kind: if exit { "exit" } else { "route" }.into(),
                    source_node_id: source.id,
                    target_node_id: Some(target.id),
                    resource_id: None,
                    destination: cidr.clone(),
                    basis: "route_approved".into(),
                    enforcement: "route_not_filtered".into(),
                    path: path.into(),
                    explanation: if exit {
                        format!(
                            "{} may use {} as an exit node, only when it selects it; {}.",
                            source.label,
                            target.label,
                            path_text(path)
                        )
                    } else {
                        format!(
                            "{} can reach {cidr} via router {} (route approved on the device; subnet traffic is not port-filtered); {}.",
                            source.label,
                            target.label,
                            path_text(path)
                        )
                    },
                    edit: EditTarget {
                        surface: "device".into(),
                        id: Some(target.id),
                    },
                    rules: Vec::new(),
                });
            }
        }
    }
    let by_id: BTreeMap<Uuid, &NodeView> = active.iter().map(|node| (node.id, *node)).collect();
    for detail in &networks.resources {
        let Some(router) = detail
            .status
            .selected_routing_peer
            .and_then(|id| by_id.get(&id))
        else {
            continue;
        };
        let destination = detail
            .resource
            .cidr
            .clone()
            .or_else(|| detail.resource.dns_target.clone())
            .unwrap_or_default();
        for client in detail
            .status
            .clients
            .iter()
            .filter(|client| client.receives)
        {
            let Some(source) = by_id.get(&client.node_id) else {
                continue;
            };
            let path = path_between(source, router);
            edges.push(Edge {
                kind: "resource".into(),
                source_node_id: source.id,
                target_node_id: Some(router.id),
                resource_id: Some(detail.resource.id),
                destination: format!("{} ({destination})", detail.resource.name),
                basis: "resource_access".into(),
                enforcement: "route_not_filtered".into(),
                path: path.into(),
                explanation: format!(
                    "{} can reach network resource {} ({destination}) via routing peer {}; {}.",
                    source.label,
                    detail.resource.name,
                    router.label,
                    path_text(path)
                ),
                edit: EditTarget {
                    surface: "network_resource".into(),
                    id: Some(detail.resource.id),
                },
                rules: Vec::new(),
            });
        }
    }
    (edges, truncated)
}

pub(crate) fn resource_views(networks: &NetworksOverview) -> Vec<ResourceView> {
    networks
        .resources
        .iter()
        .map(|detail| ResourceView {
            id: detail.resource.id,
            name: detail.resource.name.clone(),
            destination: detail
                .resource
                .cidr
                .clone()
                .or_else(|| detail.resource.dns_target.clone())
                .unwrap_or_default(),
            enabled: detail.resource.enabled,
            state: detail.status.state.clone(),
            selected_routing_peer: detail.status.selected_routing_peer,
            routing_peers: detail
                .status
                .routing_peers
                .iter()
                .map(|peer| RoutingPeerView {
                    node_id: peer.node_id,
                    name: peer.name.clone(),
                    state: peer.state.clone(),
                })
                .collect(),
            receiving: detail
                .status
                .clients
                .iter()
                .filter(|client| client.receives)
                .count(),
            kind: detail.resource.kind,
            ports: detail.resource.ports.clone(),
            protocols: detail.resource.protocols.clone(),
            port_enforcement: detail.resource.port_enforcement.clone(),
            access: detail.resource.access.clone(),
        })
        .collect()
}

/// The published rules as written, labelled by position.
pub(crate) fn rule_views(acl: &Acl) -> Vec<RuleView> {
    acl.rules
        .iter()
        .enumerate()
        .map(|(index, rule)| RuleView {
            index,
            action: match rule.action {
                Action::Allow => "allow",
                Action::Deny => "deny",
            }
            .into(),
            src: SelectorView {
                roles: rule.src_roles.clone(),
                tags: rule.src_tags.clone(),
                groups: rule.src_groups.clone(),
                hosts: Vec::new(),
            },
            dst: SelectorView {
                roles: rule.dst_roles.clone(),
                tags: rule.dst_tags.clone(),
                groups: rule.dst_groups.clone(),
                hosts: rule.dst_hosts.clone(),
            },
            protocols: rule.protocols.clone(),
            ports: rule.dst_ports.clone(),
            posture: rule.posture.clone(),
        })
        .collect()
}

/// Policy groups with a member count and the devices whose owner they name.
pub(crate) fn group_views(inputs: &Inputs, acl: &Acl) -> Vec<GroupView> {
    let subjects = subjects(inputs);
    acl.groups
        .iter()
        .map(|(name, members)| GroupView {
            name: name.clone(),
            members: members.iter().filter(|m| !m.trim().is_empty()).count(),
            devices: inputs
                .nodes
                .iter()
                .filter(|node| {
                    subjects
                        .get(&node.id)
                        .is_some_and(|subject| subject_in_group(subject, members))
                })
                .map(|node| node.id)
                .collect(),
        })
        .collect()
}

pub(crate) async fn build(state: &AppState, org_id: Uuid) -> Result<Topology, ApiError> {
    let inputs = load_inputs(&state.store.pool, org_id).await?;
    let row = load_acl_row(&state.store, org_id).await?;
    let acl: Acl = serde_json::from_str(&row.json).map_err(|_| ApiError::CorruptData)?;
    let networks = {
        let mut conn = state.store.pool.acquire().await?;
        resources::overview_conn(&mut conn, org_id).await?
    };
    let control_revision: i64 = sqlx::query_scalar("SELECT control_revision FROM orgs WHERE id=$1")
        .bind(org_id.to_string())
        .fetch_optional(&state.store.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    let (edges, truncated) = edges(&inputs, &acl, &networks);
    let rules = rule_views(&acl);
    let groups = group_views(&inputs, &acl);
    let routes = inputs
        .nodes
        .iter()
        .flat_map(|node| {
            node.approved_routes.iter().map(|cidr| RouteView {
                node_id: node.id,
                cidr: cidr.clone(),
                kind: if cidr == "0.0.0.0/0" || cidr == "::/0" {
                    "exit"
                } else {
                    "subnet"
                }
                .into(),
            })
        })
        .collect();
    let mut notes = vec![
        "Edges are what the coordinator compiles into peer maps now; a packet was not sent.".into(),
        "Path type combines each agent's own transport summary; it is not a per-pair measurement, and older agents report nothing.".into(),
    ];
    if truncated {
        notes.push(format!(
            "Only the first {MAX_EDGE_NODES} active devices are evaluated pairwise."
        ));
    }
    Ok(Topology {
        org_id,
        generated_at: now(),
        control_revision,
        policy: PolicyMeta {
            revision: row.revision,
            etag: crate::hash(&row.json),
            defaults: acl.defaults.as_str().into(),
        },
        nodes: inputs.nodes,
        resources: resource_views(&networks),
        routes,
        edges,
        rules,
        groups,
        truncated,
        notes,
    })
}

async fn get_topology(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Topology>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewNetwork)?;
    Ok(Json(build(&s, org_id).await?))
}
