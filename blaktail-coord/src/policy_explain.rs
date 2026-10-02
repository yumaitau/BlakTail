//! Effective-access explanation (draft 07).
//!
//! Re-runs the same evaluator and peer-map compiler the coordinator uses for
//! agents, against the published policy, and says where the result is
//! actually enforced. Members may explain; nothing here mutates state.

use crate::{
    console_session, load_acl_row, now,
    permissions::{require, Permission},
    posture::{enforcement_profile, Enforcement, NodeFacts, PostureContext, CAP_SSH_USERS},
    subject_in_group, valid_ssh_os_user, Acl, AclProtocol, AclSshAction, Action, ApiError,
    AppState, DeviceTag, PeerIngress, Role, Subject,
};
use axum::{
    extract::{Path as UrlPath, State},
    http::HeaderMap,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/v1/orgs/:org_id/policy/explain", post(explain))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplainRequest {
    #[serde(default)]
    source_node_id: Option<Uuid>,
    /// A person or role/tag selector with no device behind it.
    #[serde(default)]
    source: Option<SyntheticSource>,
    #[serde(default)]
    destination_node_id: Option<Uuid>,
    /// Named policy host reached through a subnet route.
    #[serde(default)]
    dst_host: Option<String>,
    #[serde(default)]
    protocol: Option<AclProtocol>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    ssh_user: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyntheticSource {
    #[serde(default)]
    user: String,
    #[serde(default)]
    role: Option<Role>,
    #[serde(default)]
    tags: Vec<DeviceTag>,
}

#[derive(Serialize)]
struct PostureView {
    check: String,
    passed: bool,
    reasons: Vec<String>,
}

#[derive(Serialize)]
struct SubjectView {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    node_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    role: Role,
    tags: Vec<DeviceTag>,
    user_id: String,
    groups: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    posture: Vec<PostureView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_version: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    capabilities: Vec<String>,
}

#[derive(Serialize)]
struct RuleView {
    section: &'static str,
    index: usize,
    action: &'static str,
    /// `matched`, `skipped_posture` or `skipped_check_expired`.
    outcome: &'static str,
    detail: String,
}

#[derive(Serialize)]
struct Pairing {
    source_map_includes_destination: bool,
    destination_map_includes_source: bool,
}

#[derive(Serialize)]
struct EnforcementView {
    /// `device_enforced`, `peer_map`, `not_enforced` or `unknown`.
    state: &'static str,
    detail: String,
    destination: Enforcement,
}

#[derive(Serialize)]
struct PolicyView {
    revision: i64,
    etag: String,
    defaults: &'static str,
    published: bool,
}

#[derive(Serialize)]
struct ExplainResponse {
    /// Always true: the coordinator evaluated this; no packet was sent.
    simulated: bool,
    evaluated_at: i64,
    policy: PolicyView,
    source: SubjectView,
    destination: SubjectView,
    #[serde(skip_serializing_if = "Option::is_none")]
    dst_host: Option<String>,
    protocol: Option<AclProtocol>,
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_user: Option<String>,
    decision: &'static str,
    /// `rule`, `deny_rule`, `default_same_tag`, `default_deny`, `ssh_rules`,
    /// `ssh_closed` or `no_pairing`.
    basis: &'static str,
    deny_precedence: bool,
    rules: Vec<RuleView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pairing: Option<Pairing>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compiled_ingress: Option<PeerIngress>,
    enforcement: EnforcementView,
    reasons: Vec<String>,
}

/// One device-to-device evaluation through the same evaluator and peer-map
/// compiler agents receive. The topology view and change-draft previews call
/// this so there is exactly one policy engine.
pub(crate) struct DeviceFlow {
    pairing: Pairing,
    compiled: PeerIngress,
    profile: Enforcement,
    pub(crate) policy_allows: bool,
    pub(crate) admitted: bool,
    basis: &'static str,
}

impl DeviceFlow {
    pub(crate) fn paired(&self) -> bool {
        self.pairing.source_map_includes_destination && self.pairing.destination_map_includes_source
    }
    pub(crate) fn decision(&self) -> bool {
        self.policy_allows && self.admitted && self.paired()
    }
    pub(crate) fn basis(&self) -> &'static str {
        if !self.paired() && self.policy_allows {
            "no_pairing"
        } else {
            self.basis
        }
    }
    pub(crate) fn enforcement(&self) -> &'static str {
        enforcement_state(self.paired(), &self.profile)
    }
}

fn enforcement_state(paired: bool, profile: &Enforcement) -> &'static str {
    if !paired {
        "peer_map"
    } else {
        match profile.packet_filter {
            "enforced" => "device_enforced",
            "unknown" => "unknown",
            _ => "not_enforced",
        }
    }
}

pub(crate) fn device_flow(
    acl: &Acl,
    source: &Subject,
    destination: &Subject,
    dest: &NodeFacts,
    protocol: Option<AclProtocol>,
    port: Option<u16>,
) -> DeviceFlow {
    let profile = enforcement_profile(dest.os.as_deref(), &dest.capabilities);
    let compiled = acl.peer_ingress_for(
        source,
        destination,
        dest.capabilities.iter().any(|c| c == CAP_SSH_USERS),
    );
    let pairing = Pairing {
        source_map_includes_destination: acl.allows(source, destination),
        destination_map_includes_source: acl.allows(destination, source),
    };
    let (mut flow_allow, mut flow_deny) = (false, false);
    for rule in &acl.rules {
        if acl.rule_matches(rule, source, destination, port, protocol, None) {
            match rule.action {
                Action::Allow => flow_allow = true,
                Action::Deny => flow_deny = true,
            }
        }
    }
    let policy_allows = acl.allows_flow(source, destination, port, protocol, None);
    let admitted = ingress_admits(&compiled, protocol, port);
    let basis = if flow_deny {
        "deny_rule"
    } else if flow_allow {
        "rule"
    } else if policy_allows {
        "default_same_tag"
    } else if acl.ssh_governed(source, destination) && port == Some(22) {
        "ssh_closed"
    } else {
        "default_deny"
    };
    DeviceFlow {
        pairing,
        compiled,
        profile,
        policy_allows,
        admitted,
        basis,
    }
}

/// Builds the subject the peer-map compiler uses for an active device.
pub(crate) fn device_subject(facts: &NodeFacts, ctx: &PostureContext) -> Subject {
    let mut subject = Subject::new(facts.role, facts.tags.clone()).with_user(facts.user_id.clone());
    ctx.apply(facts.id, &mut subject);
    subject
}

/// The same subject with every posture check and SSH re-auth satisfied, used
/// only to spot rules that posture or a lapsed check skipped.
fn lenient(subject: &Subject, acl: &Acl) -> Subject {
    let mut passed = subject.passed_posture.clone();
    for rule in &acl.rules {
        passed.extend(rule.posture.iter().cloned());
    }
    for rule in &acl.ssh {
        passed.extend(rule.posture.iter().cloned());
    }
    Subject {
        role: subject.role,
        tags: subject.tags.clone(),
        user_id: subject.user_id.clone(),
        email: subject.email.clone(),
        passed_posture: passed,
        authenticated_at: Some(now()),
    }
}

fn groups_of(acl: &Acl, subject: &Subject) -> Vec<String> {
    acl.groups
        .iter()
        .filter(|(_, members)| subject_in_group(subject, members))
        .map(|(name, _)| name.clone())
        .collect()
}

fn subject_view(
    kind: &'static str,
    acl: &Acl,
    subject: &Subject,
    facts: Option<&NodeFacts>,
    ctx: &PostureContext,
) -> SubjectView {
    let posture = facts
        .map(|facts| {
            ctx.assess(facts)
                .into_iter()
                .map(|assessment| PostureView {
                    check: assessment.check,
                    passed: assessment.passed,
                    reasons: assessment.reasons.into_iter().map(|r| r.text).collect(),
                })
                .collect()
        })
        .unwrap_or_default();
    SubjectView {
        kind,
        node_id: facts.map(|f| f.id),
        name: facts.map(|f| f.display_name.clone().unwrap_or_else(|| f.name.clone())),
        role: subject.role,
        tags: subject.tags.clone(),
        user_id: subject.user_id.clone(),
        groups: groups_of(acl, subject),
        posture,
        os: facts.and_then(|f| f.os.clone()),
        agent_version: facts.and_then(|f| f.agent_version.clone()),
        capabilities: facts.map(|f| f.capabilities.clone()).unwrap_or_default(),
    }
}

/// Whether a compiled grant admits this protocol/port, mirroring the agent.
fn ingress_admits(ingress: &PeerIngress, protocol: Option<AclProtocol>, port: Option<u16>) -> bool {
    let covers = |specs: &[String]| match port {
        None => !specs.is_empty(),
        Some(port) => specs.iter().any(|spec| {
            crate::parse_acl_port_spec(spec).is_ok_and(|(a, b)| (a..=b).contains(&port))
        }),
    };
    let denies = |specs: &[String]| {
        port.is_some_and(|port| {
            specs.iter().any(|spec| {
                crate::parse_acl_port_spec(spec).is_ok_and(|(a, b)| (a..=b).contains(&port))
            })
        })
    };
    match protocol {
        Some(AclProtocol::Icmp) => !ingress.deny_icmp && (ingress.all || ingress.icmp),
        Some(AclProtocol::Udp) => {
            !denies(&ingress.deny_udp) && (ingress.all || covers(&ingress.udp))
        }
        Some(AclProtocol::Tcp) => {
            !denies(&ingress.deny_tcp) && (ingress.all || covers(&ingress.tcp))
        }
        None => {
            (!denies(&ingress.deny_tcp) && (ingress.all || covers(&ingress.tcp)))
                || (!denies(&ingress.deny_udp) && (ingress.all || covers(&ingress.udp)))
                || (port.is_none() && !ingress.deny_icmp && (ingress.all || ingress.icmp))
        }
    }
}

async fn explain(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<ExplainRequest>,
) -> Result<Json<ExplainResponse>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewNetwork)?;
    if input.source_node_id.is_some() == input.source.is_some() {
        return Err(ApiError::BadRequest(
            "choose exactly one of source_node_id or source".into(),
        ));
    }
    let dst_host = input
        .dst_host
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned);
    if input.destination_node_id.is_none() && dst_host.is_none() {
        return Err(ApiError::BadRequest(
            "choose a destination device or a named host".into(),
        ));
    }
    if input.port == Some(0) {
        return Err(ApiError::BadRequest("port must be 1-65535".into()));
    }
    if input.protocol == Some(AclProtocol::Icmp) && input.port.is_some() {
        return Err(ApiError::BadRequest("ICMP has no port".into()));
    }
    let ssh_user = input
        .ssh_user
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    if let Some(user) = ssh_user {
        if user == "*" || !valid_ssh_os_user(user) || input.port.is_some() || dst_host.is_some() {
            return Err(ApiError::BadRequest(
                "an SSH check names one login and a destination device, without a port".into(),
            ));
        }
    }

    let row = load_acl_row(&s.store, org_id).await?;
    let acl: Acl = serde_json::from_str(&row.json).map_err(|_| ApiError::CorruptData)?;
    if let Some(host) = &dst_host {
        if !acl.hosts.contains_key(host) {
            return Err(ApiError::BadRequest(format!("unknown policy host {host}")));
        }
    }
    let ctx = PostureContext::load(&s.store.pool, &org_id.to_string()).await?;
    // Device lookups only see this organisation's active nodes, so another
    // organisation's node id is indistinguishable from a missing one.
    let source_facts = match input.source_node_id {
        Some(id) => Some(ctx.facts.get(&id).ok_or(ApiError::NotFound)?),
        None => None,
    };
    let destination_facts = match input.destination_node_id {
        Some(id) => Some(ctx.facts.get(&id).ok_or(ApiError::NotFound)?),
        None => None,
    };
    let source = match (source_facts, &input.source) {
        (Some(facts), _) => device_subject(facts, &ctx),
        (None, Some(synthetic)) => {
            let user = synthetic.user.trim().to_owned();
            Subject {
                email: if user.contains('@') {
                    user.clone()
                } else {
                    String::new()
                },
                ..Subject::new(
                    synthetic.role.unwrap_or(Role::Member),
                    crate::canonical_tags(synthetic.tags.clone()),
                )
                .with_user(user)
            }
        }
        (None, None) => unreachable!("validated above"),
    };
    let destination = match destination_facts {
        Some(facts) => device_subject(facts, &ctx),
        None => Subject::new(Role::Member, Vec::new()),
    };

    let mut reasons = Vec::new();
    if source_facts.is_none() {
        reasons.push(
            "The source is a person or selector, not a device: posture checks and SSH re-authentication cannot pass, so rules that need them are skipped.".into(),
        );
    }
    let loose = lenient(&source, &acl);
    let mut rules = Vec::new();
    let host = dst_host.as_deref();
    let mut deny_precedence = false;
    let mut flow_allow = false;
    let mut flow_deny = false;
    if ssh_user.is_none() {
        for (index, rule) in acl.rules.iter().enumerate() {
            let strict = acl.rule_matches(
                rule,
                &source,
                &destination,
                input.port,
                input.protocol,
                host,
            );
            let relaxed =
                acl.rule_matches(rule, &loose, &destination, input.port, input.protocol, host);
            if strict {
                match rule.action {
                    Action::Allow => flow_allow = true,
                    Action::Deny => flow_deny = true,
                }
            }
            if strict || relaxed {
                let missing: Vec<_> = rule
                    .posture
                    .iter()
                    .filter(|name| !source.passed_posture.contains(*name))
                    .cloned()
                    .collect();
                rules.push(RuleView {
                    section: "rules",
                    index,
                    action: match rule.action {
                        Action::Allow => "allow",
                        Action::Deny => "deny",
                    },
                    outcome: if strict { "matched" } else { "skipped_posture" },
                    detail: if strict {
                        "selectors, ports and protocols match".into()
                    } else {
                        format!("source does not pass posture: {}", missing.join(", "))
                    },
                });
            }
        }
        deny_precedence = flow_deny && flow_allow;
    }
    for (index, rule) in acl.ssh.iter().enumerate() {
        if !acl.ssh_subjects_match(rule, &source, &destination) {
            continue;
        }
        if let Some(user) = ssh_user {
            if !rule.users.iter().any(|u| u == "*" || u == user) {
                continue;
            }
        }
        let strict = crate::ssh_source_eligible(rule, &source);
        let relaxed = crate::ssh_source_eligible(rule, &loose);
        if !strict && !relaxed {
            continue;
        }
        let action = match rule.action {
            AclSshAction::Allow => "allow",
            AclSshAction::Deny => "deny",
            AclSshAction::Check => "check",
        };
        let posture_ok = crate::posture_satisfied(&rule.posture, &source);
        rules.push(RuleView {
            section: "ssh",
            index,
            action,
            outcome: if strict {
                "matched"
            } else if posture_ok {
                "skipped_check_expired"
            } else {
                "skipped_posture"
            },
            detail: format!("users {}", rule.users.join(", ")),
        });
    }

    let (decision, basis, pairing, compiled, enforcement) = if let Some(host_name) = host {
        let allowed = acl.allows_flow(
            &source,
            &destination,
            input.port,
            input.protocol,
            Some(host_name),
        );
        reasons.push("Subnet-route traffic is not filtered by agents. Host rules are evaluated here and in policy tests, but nothing enforces them at packet level yet.".into());
        let enforcement = EnforcementView {
            state: "not_enforced",
            detail: "Route destinations are not filtered by any agent.".into(),
            destination: enforcement_profile(None, &[]),
        };
        (
            allowed,
            if flow_deny {
                "deny_rule"
            } else if allowed {
                "rule"
            } else {
                "default_deny"
            },
            None,
            None,
            enforcement,
        )
    } else {
        let dest = destination_facts.expect("validated destination device");
        let flow = device_flow(
            &acl,
            &source,
            &destination,
            dest,
            input.protocol,
            input.port,
        );
        let profile = flow.profile;
        let compiled = flow.compiled;
        let pairing = flow.pairing;
        let paired =
            pairing.source_map_includes_destination && pairing.destination_map_includes_source;
        let (policy_allows, compiled_allows, basis) = if let Some(user) = ssh_user {
            let allowed = acl.allows_ssh(&source, &destination, user);
            let port_open = ingress_admits(&compiled, Some(AclProtocol::Tcp), Some(22));
            if allowed && !port_open {
                reasons.push(format!(
                    "Policy allows {user}, but TCP 22 stays closed: the destination agent has not proven per-user SSH enforcement ({CAP_SSH_USERS})."
                ));
            }
            (
                allowed,
                port_open,
                if allowed && port_open {
                    "ssh_rules"
                } else if allowed {
                    "ssh_closed"
                } else {
                    "ssh_rules"
                },
            )
        } else {
            if flow.policy_allows && !flow.admitted {
                reasons.push("Rules allow this, but the compiled grant for this destination does not open it (SSH rules govern TCP 22, or an explicit deny covers it).".into());
            }
            (flow.policy_allows, flow.admitted, flow.basis)
        };
        if !paired {
            reasons.push("WireGuard pairing needs policy in both directions: each device only receives peers it may itself reach. One side does not include the other, so no tunnel exists.".into());
        }
        let decision = policy_allows && compiled_allows && paired;
        let state = enforcement_state(paired, &profile);
        let detail = match state {
            "peer_map" => {
                "No tunnel is configured between these devices, on every client type.".to_string()
            }
            "device_enforced" => {
                "The destination agent's inbound filter applies this result.".to_string()
            }
            "unknown" => format!("Not proven on this device. {}", profile.detail),
            _ => format!("Not enforced on this device. {}", profile.detail),
        };
        (
            decision,
            if !paired && policy_allows {
                "no_pairing"
            } else {
                basis
            },
            Some(pairing),
            Some(compiled),
            EnforcementView {
                state,
                detail,
                destination: profile,
            },
        )
    };
    match acl.defaults {
        crate::AclDefaults::SameTag => reasons.push("This policy still uses the legacy same-tag default: devices sharing a tag, or both untagged, are allowed unless a deny matches.".into()),
        crate::AclDefaults::Deny => reasons.push("Anything not allowed by a rule is denied (default deny). Deny rules always win over allow rules.".into()),
    }

    Ok(Json(ExplainResponse {
        simulated: true,
        evaluated_at: now(),
        policy: PolicyView {
            revision: row.revision,
            etag: crate::hash(&row.json),
            defaults: acl.defaults.as_str(),
            published: true,
        },
        source: subject_view(
            if source_facts.is_some() {
                "device"
            } else {
                "person"
            },
            &acl,
            &source,
            source_facts,
            &ctx,
        ),
        destination: subject_view(
            if destination_facts.is_some() {
                "device"
            } else {
                "host"
            },
            &acl,
            &destination,
            destination_facts,
            &ctx,
        ),
        dst_host,
        protocol: input.protocol,
        port: input.port,
        ssh_user: ssh_user.map(str::to_owned),
        decision: if decision { "allow" } else { "deny" },
        basis,
        deny_precedence,
        rules,
        pairing,
        compiled_ingress: compiled,
        enforcement,
        reasons,
    }))
}
