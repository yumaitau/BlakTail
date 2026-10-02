//! Server-side change drafts (NetBird-parity draft 03).
//!
//! A draft is organisation-bound and versioned. It holds proposed policy,
//! DNS and network-resource documents plus the live etags they were based
//! on. Preview and publish run the SAME write path: every surface is applied
//! with the ordinary validators inside one database transaction, which
//! preview rolls back and publish commits. Publish therefore either applies
//! every surface or none of them, and bumps the control revision once.

use crate::{
    append_audit, bump_control_revision, console_session, hash, load_acl_row_tx, load_org_dns_tx,
    now, org_dns,
    permissions::{require, Permission},
    policy_explain::{device_flow, device_subject},
    publish_acl_tx, resources, storeable_acl_json,
    topology::{self, Edge},
    webhooks, write_org_dns_tx, Acl, AclProtocol, ApiError, AppState, Session,
};
use axum::{
    extract::{Path as UrlPath, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::{any::AnyRow, Row};
use std::collections::BTreeSet;
use uuid::Uuid;

const DRAFT_TTL_SECS: i64 = 7 * 24 * 60 * 60;
const MAX_PAYLOAD_BYTES: usize = 256 * 1024;
const MAX_OPEN_DRAFTS: i64 = 50;
const MAX_PAIRS: usize = 20;
/// Draft payloads describe configuration only. Credentials never belong in
/// a policy, DNS or resource document, so keys that look like one are refused.
const SECRET_KEYS: [&str; 6] = [
    "secret",
    "password",
    "token",
    "private_key",
    "api_key",
    "preshared",
];

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/orgs/:org_id/changes", get(list).post(create))
        .route(
            "/v1/orgs/:org_id/changes/:draft_id",
            get(get_one).put(update),
        )
        .route("/v1/orgs/:org_id/changes/:draft_id/rebase", post(rebase))
        .route("/v1/orgs/:org_id/changes/:draft_id/preview", post(preview))
        .route("/v1/orgs/:org_id/changes/:draft_id/publish", post(publish))
        .route("/v1/orgs/:org_id/changes/:draft_id/discard", post(discard))
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Surface {
    Policy,
    Dns,
    Resources,
}

impl Surface {
    fn permission(self) -> Permission {
        match self {
            Surface::Policy => Permission::ManagePolicy,
            Surface::Dns => Permission::ManageDns,
            Surface::Resources => Permission::ManageNetworks,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Surface::Policy => "access policy",
            Surface::Dns => "DNS",
            Surface::Resources => "network resources",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Payload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dns: Option<serde_json::Value>,
    /// The full desired set: items with an `id` update that resource, items
    /// without one are created, and live resources left out are deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resources: Option<Vec<serde_json::Value>>,
}

impl Payload {
    fn surfaces(&self) -> Vec<Surface> {
        let mut surfaces = Vec::new();
        if self.policy.is_some() {
            surfaces.push(Surface::Policy);
        }
        if self.dns.is_some() {
            surfaces.push(Surface::Dns);
        }
        if self.resources.is_some() {
            surfaces.push(Surface::Resources);
        }
        surfaces
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct Base {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_revision: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dns_etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dns_revision: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resources_etag: Option<String>,
}

struct Draft {
    id: Uuid,
    title: String,
    status: String,
    version: i64,
    payload: Payload,
    base: Base,
    created_by: String,
    created_by_name: String,
    updated_by: String,
    created_at: i64,
    updated_at: i64,
    expires_at: i64,
    closed_at: Option<i64>,
    closed_by: Option<String>,
    result: Option<serde_json::Value>,
}

const COLUMNS: &str = "id,title,status,version,payload_json,base_json,created_by,created_by_name,updated_by,created_at,updated_at,expires_at,closed_at,closed_by,result_json";

fn draft_from_row(row: &AnyRow) -> Result<Draft, ApiError> {
    let result: Option<String> = row.try_get(14)?;
    Ok(Draft {
        id: Uuid::parse_str(&row.try_get::<String, _>(0)?).map_err(|_| ApiError::CorruptData)?,
        title: row.try_get(1)?,
        status: row.try_get(2)?,
        version: row.try_get(3)?,
        payload: serde_json::from_str(&row.try_get::<String, _>(4)?)
            .map_err(|_| ApiError::CorruptData)?,
        base: serde_json::from_str(&row.try_get::<String, _>(5)?)
            .map_err(|_| ApiError::CorruptData)?,
        created_by: row.try_get(6)?,
        created_by_name: row.try_get(7)?,
        updated_by: row.try_get(8)?,
        created_at: row.try_get(9)?,
        updated_at: row.try_get(10)?,
        expires_at: row.try_get(11)?,
        closed_at: row.try_get(12)?,
        closed_by: row.try_get(13)?,
        result: result.and_then(|value| serde_json::from_str(&value).ok()),
    })
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct DraftView {
    id: Uuid,
    title: String,
    /// `open`, `published`, `discarded` or `expired`.
    status: String,
    version: i64,
    surfaces: Vec<Surface>,
    created_by: String,
    created_by_name: String,
    updated_by: String,
    created_at: i64,
    updated_at: i64,
    expires_at: i64,
    closed_at: Option<i64>,
    closed_by: Option<String>,
    base: Base,
    /// Omitted unless the caller may manage every surface the draft touches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payload: Option<Payload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    can_edit: bool,
}

fn may_manage(session: &Session, surfaces: &[Surface]) -> bool {
    surfaces
        .iter()
        .all(|surface| session.role.can(surface.permission()))
}

fn require_surfaces(session: &Session, surfaces: &[Surface]) -> Result<(), ApiError> {
    for surface in surfaces {
        require(session, surface.permission())?;
    }
    Ok(())
}

fn view(draft: Draft, session: &Session) -> DraftView {
    let surfaces = draft.payload.surfaces();
    let full = may_manage(session, &surfaces);
    DraftView {
        id: draft.id,
        title: draft.title,
        can_edit: full && draft.status == "open",
        status: draft.status,
        version: draft.version,
        surfaces,
        created_by: draft.created_by,
        created_by_name: draft.created_by_name,
        updated_by: draft.updated_by,
        created_at: draft.created_at,
        updated_at: draft.updated_at,
        expires_at: draft.expires_at,
        closed_at: draft.closed_at,
        closed_by: draft.closed_by,
        base: draft.base,
        payload: full.then_some(draft.payload),
        result: if full { draft.result } else { None },
    }
}

async fn expire_drafts(state: &AppState, org_id: Uuid) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE change_drafts SET status='expired',closed_at=$1 WHERE org_id=$2 AND status='open' AND expires_at<=$1",
    )
    .bind(now())
    .bind(org_id.to_string())
    .execute(&state.store.pool)
    .await?;
    Ok(())
}

/// Org-bound lookup: another organisation's draft id is indistinguishable
/// from a missing one.
async fn load_draft(state: &AppState, org_id: Uuid, id: Uuid) -> Result<Draft, ApiError> {
    expire_drafts(state, org_id).await?;
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM change_drafts WHERE id=$1 AND org_id=$2"
    )))
    .bind(id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&state.store.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    draft_from_row(&row)
}

fn ensure_open(draft: &Draft) -> Result<(), ApiError> {
    if draft.status != "open" {
        return Err(ApiError::Conflict(format!(
            "this draft is {} and can no longer change",
            draft.status
        )));
    }
    Ok(())
}

fn ensure_version(draft: &Draft, version: i64) -> Result<(), ApiError> {
    if draft.version != version {
        return Err(ApiError::PreconditionFailed);
    }
    Ok(())
}

fn reject_secrets(value: &serde_json::Value, path: &str) -> Result<(), ApiError> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let lower = key.to_ascii_lowercase();
                if SECRET_KEYS.iter().any(|word| lower.contains(word)) {
                    return Err(ApiError::BadRequest(format!(
                        "{path}.{key} looks like a credential; drafts never store secrets"
                    )));
                }
                reject_secrets(child, &format!("{path}.{key}"))?;
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                reject_secrets(child, &format!("{path}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn check_payload(payload: &Payload) -> Result<String, ApiError> {
    if payload.surfaces().is_empty() {
        return Err(ApiError::BadRequest(
            "a draft must change at least one of policy, dns or resources".into(),
        ));
    }
    if payload.policy.as_ref().is_some_and(|v| !v.is_object())
        || payload.dns.as_ref().is_some_and(|v| !v.is_object())
    {
        return Err(ApiError::BadRequest(
            "policy and dns must be JSON objects".into(),
        ));
    }
    let json = serde_json::to_string(payload).map_err(|_| ApiError::CorruptData)?;
    if json.len() > MAX_PAYLOAD_BYTES {
        return Err(ApiError::BadRequest(
            "a draft is limited to 256 KiB of JSON".into(),
        ));
    }
    reject_secrets(
        &serde_json::to_value(payload).unwrap_or_default(),
        "payload",
    )?;
    Ok(json)
}

fn normalise_title(title: &str) -> Result<String, ApiError> {
    let title = title.trim();
    if title.is_empty() || title.chars().count() > 120 || title.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "title must be 1-120 characters without control characters".into(),
        ));
    }
    Ok(title.to_owned())
}

// ---------- live state ----------

struct Live {
    policy: serde_json::Value,
    policy_etag: String,
    policy_revision: i64,
    dns: serde_json::Value,
    dns_etag: String,
    dns_revision: i64,
    resources: Vec<serde_json::Value>,
    resources_etag: String,
}

async fn live_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: Uuid,
) -> Result<Live, ApiError> {
    let acl = load_acl_row_tx(tx, org_id).await?;
    let dns = load_org_dns_tx(tx, org_id).await?;
    let (items, resources_etag) = resources::draft_snapshot(tx, org_id).await?;
    Ok(Live {
        policy: serde_json::from_str(&acl.json).map_err(|_| ApiError::CorruptData)?,
        policy_etag: hash(&acl.json),
        policy_revision: acl.revision,
        dns: serde_json::to_value(&dns.dns).map_err(|_| ApiError::CorruptData)?,
        dns_etag: dns.etag,
        dns_revision: dns.revision,
        resources: items,
        resources_etag,
    })
}

async fn live(state: &AppState, org_id: Uuid) -> Result<Live, ApiError> {
    let mut tx = state.store.pool.begin().await?;
    let live = live_tx(&mut tx, org_id).await?;
    tx.rollback().await?;
    Ok(live)
}

fn capture_base(base: &mut Base, surface: Surface, live: &Live) {
    match surface {
        Surface::Policy => {
            base.policy_etag = Some(live.policy_etag.clone());
            base.policy_revision = Some(live.policy_revision);
        }
        Surface::Dns => {
            base.dns_etag = Some(live.dns_etag.clone());
            base.dns_revision = Some(live.dns_revision);
        }
        Surface::Resources => base.resources_etag = Some(live.resources_etag.clone()),
    }
}

fn stale_surfaces(draft: &Draft, live: &Live) -> Vec<Surface> {
    draft
        .payload
        .surfaces()
        .into_iter()
        .filter(|surface| match surface {
            Surface::Policy => draft.base.policy_etag.as_deref() != Some(&live.policy_etag),
            Surface::Dns => draft.base.dns_etag.as_deref() != Some(&live.dns_etag),
            Surface::Resources => {
                draft.base.resources_etag.as_deref() != Some(&live.resources_etag)
            }
        })
        .collect()
}

// ---------- apply (shared by preview and publish) ----------

#[derive(Debug, Default, Deserialize, Serialize)]
struct RevisionChange {
    before_revision: i64,
    after_revision: i64,
    changed: bool,
}

#[derive(Debug, Default, Serialize)]
struct Applied {
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<RevisionChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns: Option<RevisionChange>,
    resources: Vec<resources::ResourceChange>,
    control_revision: i64,
    #[serde(skip)]
    dns_settings: Option<org_dns::OrgDnsSettings>,
    #[serde(skip)]
    acl: Option<Acl>,
}

/// Labels a validator error with the surface it came from, keeping status.
fn on(surface: Surface, error: ApiError) -> ApiError {
    match error {
        ApiError::BadRequest(message) => {
            ApiError::BadRequest(format!("{}: {message}", surface.label()))
        }
        ApiError::Conflict(message) => {
            ApiError::Conflict(format!("{}: {message}", surface.label()))
        }
        other => other,
    }
}

/// Applies every surface of `draft` with the ordinary validators and writers
/// on one transaction. The caller decides whether to commit.
async fn apply_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: Uuid,
    session: &Session,
    draft: &Draft,
    enforce_base: bool,
) -> Result<Applied, ApiError> {
    // Bumping first takes the org row lock on PostgreSQL, serialising this
    // publish against every other policy, DNS or resource writer.
    let control_revision = bump_control_revision(tx, org_id.to_string()).await?;
    if enforce_base {
        let live = live_tx(tx, org_id).await?;
        let stale = stale_surfaces(draft, &live);
        if !stale.is_empty() {
            return Err(ApiError::Conflict(format!(
                "rebase required: {} changed since this draft was based",
                stale
                    .iter()
                    .map(|surface| surface.label())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
    }
    let via = format!("change_draft:{}", draft.id);
    let mut applied = Applied {
        control_revision,
        ..Applied::default()
    };
    if let Some(policy) = &draft.payload.policy {
        let current = load_acl_row_tx(tx, org_id).await?;
        let next = storeable_acl_json(policy.clone()).map_err(|e| on(Surface::Policy, e))?;
        let changed = next != current.json;
        if changed {
            publish_acl_tx(tx, org_id, &current.json, &next, current.revision).await?;
        }
        applied.acl = Some(serde_json::from_str(&next).map_err(|_| ApiError::CorruptData)?);
        applied.policy = Some(RevisionChange {
            before_revision: current.revision,
            after_revision: current.revision + i64::from(changed),
            changed,
        });
    }
    if let Some(items) = &draft.payload.resources {
        applied.resources = resources::apply_draft_tx(tx, org_id, session, items, &via)
            .await
            .map_err(|e| on(Surface::Resources, e))?;
    }
    if let Some(dns) = &draft.payload.dns {
        let current = load_org_dns_tx(tx, org_id).await?;
        let next = org_dns::parse_settings(&dns.to_string()).map_err(|e| on(Surface::Dns, e))?;
        let changed = serde_json::to_value(&next).ok() != serde_json::to_value(&current.dns).ok();
        if changed {
            write_org_dns_tx(tx, org_id, &current, &next).await?;
        }
        applied.dns_settings = Some(next);
        applied.dns = Some(RevisionChange {
            before_revision: current.revision,
            after_revision: current.revision + i64::from(changed),
            changed,
        });
    }
    Ok(applied)
}

// ---------- preview ----------

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct PairRequest {
    source_node_id: Uuid,
    destination_node_id: Uuid,
    #[serde(default)]
    protocol: Option<AclProtocol>,
    #[serde(default)]
    port: Option<u16>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewRequest {
    #[serde(default)]
    pairs: Vec<PairRequest>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Verdict {
    decision: String,
    basis: String,
    enforcement: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct PairResult {
    #[serde(flatten)]
    pair: PairRequest,
    before: Verdict,
    after: Option<Verdict>,
    changed: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub(crate) struct RiskFlag {
    code: String,
    /// `high` or `warning`. Every flag must be confirmed to publish.
    severity: String,
    message: String,
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct SurfaceDiff {
    before: serde_json::Value,
    after: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct Reachability {
    added: Vec<Edge>,
    removed: Vec<Edge>,
    truncated: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Preview {
    draft_id: Uuid,
    version: i64,
    generated_at: i64,
    valid: bool,
    errors: Vec<String>,
    /// Surfaces whose live state moved since the draft's base: rebase first.
    stale_surfaces: Vec<Surface>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy: Option<SurfaceDiff>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dns: Option<SurfaceDiff>,
    #[serde(default)]
    resources: Vec<serde_json::Value>,
    reachability: Reachability,
    pairs: Vec<PairResult>,
    risks: Vec<RiskFlag>,
    dns_warnings: Vec<String>,
    notes: Vec<String>,
}

fn flag(code: &str, severity: &str, message: String) -> RiskFlag {
    RiskFlag {
        code: code.into(),
        severity: severity.into(),
        message,
    }
}

fn is_default_route(value: &serde_json::Value) -> bool {
    matches!(value.as_str(), Some("0.0.0.0/0" | "::/0"))
}

fn deny_rules(policy: &serde_json::Value) -> Vec<serde_json::Value> {
    ["rules", "ssh"]
        .iter()
        .flat_map(|section| {
            policy[*section]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|rule| rule["action"] == "deny")
        })
        .collect()
}

fn risks(
    live: &Live,
    draft: &Draft,
    applied: &Applied,
    reach: &Reachability,
    dns_warnings: &[String],
) -> Vec<RiskFlag> {
    let mut flags = Vec::new();
    if let Some(policy) = &draft.payload.policy {
        let after = deny_rules(policy);
        let removed = deny_rules(&live.policy)
            .into_iter()
            .filter(|rule| !after.contains(rule))
            .count();
        if removed > 0 {
            flags.push(flag(
                "deny_removed",
                "high",
                format!(
                    "{removed} deny rule(s) are removed or changed; access they blocked may open."
                ),
            ));
        }
        if live.policy["defaults"] != "same_tag" && policy["defaults"] == "same_tag" {
            flags.push(flag(
                "default_widened",
                "high",
                "Defaults change to the legacy same-tag allow: devices sharing a tag are allowed without a rule.".into(),
            ));
        }
    }
    for change in &applied.resources {
        let Some(after) = &change.after else {
            flags.push(flag(
                "resource_deleted",
                "warning",
                format!(
                    "Network resource {} is deleted; devices that receive it lose the route.",
                    change.name
                ),
            ));
            continue;
        };
        let was_default = change
            .before
            .as_ref()
            .is_some_and(|before| is_default_route(&before["cidr"]) && before["enabled"] == true);
        if is_default_route(&after["cidr"]) && after["enabled"] == true {
            let widened = change
                .before
                .as_ref()
                .is_none_or(|before| !was_default || before["access"] != after["access"]);
            if widened {
                flags.push(flag(
                    "default_route_exposure",
                    "high",
                    format!("{} offers a default route (exit through a routing peer) to its access selection.", change.name),
                ));
            }
        }
        if after["allow_nested_overlap"] == true
            && change.before.as_ref().is_none_or(|before| {
                before["allow_nested_overlap"] != true || before["cidr"] != after["cidr"]
            })
        {
            flags.push(flag(
                "route_overlap",
                "warning",
                format!("{} allows nested overlap with another resource; the longest prefix wins on clients.", change.name),
            ));
        }
    }
    if reach.added.iter().any(|edge| edge.kind == "exit") {
        flags.push(flag(
            "default_route_exposure",
            "high",
            "A device gains an exit-node route it may select.".into(),
        ));
    }
    if !reach.added.is_empty() {
        flags.push(flag(
            "access_widened",
            "high",
            format!(
                "{} new reachability path(s) open; review them below.",
                reach.added.len()
            ),
        ));
    }
    if !reach.removed.is_empty() {
        flags.push(flag(
            "access_removed",
            "warning",
            format!(
                "{} reachability path(s) close; check nobody depends on them.",
                reach.removed.len()
            ),
        ));
    }
    if draft.payload.dns.is_some() && !dns_warnings.is_empty() {
        flags.push(flag(
            "dns_conflict",
            "warning",
            format!(
                "{} DNS warning(s): {}",
                dns_warnings.len(),
                dns_warnings.join("; ")
            ),
        ));
    }
    let mut seen = BTreeSet::new();
    flags.retain(|flag| seen.insert(flag.code.clone()));
    flags
}

fn verdict(inputs: &topology::Inputs, acl: &Acl, pair: &PairRequest) -> Result<Verdict, ApiError> {
    // Only this organisation's active devices are in the context.
    let source = inputs
        .ctx
        .facts
        .get(&pair.source_node_id)
        .ok_or(ApiError::NotFound)?;
    let destination = inputs
        .ctx
        .facts
        .get(&pair.destination_node_id)
        .ok_or(ApiError::NotFound)?;
    let flow = device_flow(
        acl,
        &device_subject(source, &inputs.ctx),
        &device_subject(destination, &inputs.ctx),
        destination,
        pair.protocol,
        pair.port,
    );
    Ok(Verdict {
        decision: if flow.decision() { "allow" } else { "deny" }.into(),
        basis: flow.basis().into(),
        enforcement: flow.enforcement().into(),
    })
}

fn edge_delta(before: &[Edge], after: &[Edge]) -> (Vec<Edge>, Vec<Edge>) {
    let keys = |edges: &[Edge]| edges.iter().map(Edge::key).collect::<BTreeSet<_>>();
    let (before_keys, after_keys) = (keys(before), keys(after));
    (
        after
            .iter()
            .filter(|edge| !before_keys.contains(&edge.key()))
            .cloned()
            .collect(),
        before
            .iter()
            .filter(|edge| !after_keys.contains(&edge.key()))
            .cloned()
            .collect(),
    )
}

async fn compute_preview(
    state: &AppState,
    org_id: Uuid,
    session: &Session,
    draft: &Draft,
    pairs: &[PairRequest],
) -> Result<Preview, ApiError> {
    if pairs.len() > MAX_PAIRS {
        return Err(ApiError::BadRequest("preview at most 20 pairs".into()));
    }
    for pair in pairs {
        if pair.port == Some(0) || (pair.protocol == Some(AclProtocol::Icmp) && pair.port.is_some())
        {
            return Err(ApiError::BadRequest(
                "pair ports must be 1-65535 and ICMP has no port".into(),
            ));
        }
    }
    // Everything a draft cannot change is read before the transaction: the
    // SQLite pool has a single connection.
    let inputs = topology::load_inputs(&state.store.pool, org_id).await?;
    let live = live(state, org_id).await?;
    let before_acl: Acl =
        serde_json::from_value(live.policy.clone()).map_err(|_| ApiError::CorruptData)?;
    let before_networks = {
        let mut conn = state.store.pool.acquire().await?;
        resources::overview_conn(&mut conn, org_id).await?
    };
    let (before_edges, before_truncated) = topology::edges(&inputs, &before_acl, &before_networks);
    let mut pair_results = Vec::new();
    for pair in pairs {
        pair_results.push(PairResult {
            pair: pair.clone(),
            before: verdict(&inputs, &before_acl, pair)?,
            after: None,
            changed: false,
        });
    }

    let mut tx = state.store.pool.begin().await?;
    let outcome = match apply_tx(&mut tx, org_id, session, draft, false).await {
        Ok(applied) => {
            let networks = resources::overview_conn(&mut tx, org_id).await?;
            Ok((applied, networks))
        }
        Err(error) => Err(error),
    };
    tx.rollback().await?;

    let mut preview = Preview {
        draft_id: draft.id,
        version: draft.version,
        generated_at: now(),
        valid: true,
        errors: Vec::new(),
        stale_surfaces: stale_surfaces(draft, &live),
        policy: draft.payload.policy.as_ref().map(|after| SurfaceDiff {
            before: live.policy.clone(),
            after: after.clone(),
        }),
        dns: None,
        resources: Vec::new(),
        reachability: Reachability::default(),
        pairs: Vec::new(),
        risks: Vec::new(),
        dns_warnings: Vec::new(),
        notes: vec![
            "Preview applies the draft with the same validators as publish inside a transaction that is rolled back.".into(),
            "Policy, DNS and network resources cannot remove console access, so last-owner lockout does not apply to these surfaces.".into(),
            "Reachability is compiled from policy for current devices; it is address-family neutral, and routes list both IPv4 and IPv6 prefixes as written.".into(),
        ],
    };
    match outcome {
        Err(error) => {
            preview.valid = false;
            preview.errors.push(match error {
                ApiError::Forbidden => "your role cannot make one of these changes (a public or default route needs an organisation owner)".into(),
                other => other.to_string(),
            });
            preview.pairs = pair_results;
        }
        Ok((applied, networks)) => {
            let after_acl = applied.acl.as_ref().unwrap_or(&before_acl);
            let (after_edges, after_truncated) = topology::edges(&inputs, after_acl, &networks);
            let (added, removed) = edge_delta(&before_edges, &after_edges);
            preview.reachability = Reachability {
                added,
                removed,
                truncated: before_truncated || after_truncated,
            };
            for mut result in pair_results {
                let after = verdict(&inputs, after_acl, &result.pair)?;
                result.changed =
                    after.decision != result.before.decision || after.basis != result.before.basis;
                result.after = Some(after);
                preview.pairs.push(result);
            }
            if let Some(settings) = &applied.dns_settings {
                preview.dns = Some(SurfaceDiff {
                    before: live.dns.clone(),
                    after: serde_json::to_value(settings).unwrap_or_default(),
                });
                let mut warnings = settings.warnings();
                warnings.extend(
                    crate::dns_workspace::route_warnings(&state.store, org_id, settings).await?,
                );
                preview.dns_warnings = warnings;
            }
            preview.resources = applied
                .resources
                .iter()
                .map(|change| serde_json::to_value(change).unwrap_or_default())
                .collect();
            preview.risks = risks(
                &live,
                draft,
                &applied,
                &preview.reachability,
                &preview.dns_warnings,
            );
        }
    }
    Ok(preview)
}

// ---------- handlers ----------

#[derive(Deserialize, Serialize)]
pub(crate) struct DraftList {
    drafts: Vec<DraftView>,
}

async fn list(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<DraftList>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewNetwork)?;
    expire_drafts(&s, org_id).await?;
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM change_drafts WHERE org_id=$1 ORDER BY updated_at DESC,id LIMIT 100"
    )))
    .bind(org_id.to_string())
    .fetch_all(&s.store.pool)
    .await?;
    let drafts = rows
        .iter()
        .map(draft_from_row)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|draft| {
            // The list is a summary for everyone; payloads come from GET.
            let mut view = view(draft, &session);
            view.payload = None;
            view
        })
        .collect();
    Ok(Json(DraftList { drafts }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    title: String,
    surfaces: Vec<Surface>,
}

async fn create(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<CreateRequest>,
) -> Result<(StatusCode, Json<DraftView>), ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    let surfaces: Vec<Surface> = input
        .surfaces
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if surfaces.is_empty() {
        return Err(ApiError::BadRequest("choose at least one surface".into()));
    }
    require_surfaces(&session, &surfaces)?;
    let title = normalise_title(&input.title)?;
    expire_drafts(&s, org_id).await?;
    let open: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM change_drafts WHERE org_id=$1 AND status='open'")
            .bind(org_id.to_string())
            .fetch_one(&s.store.pool)
            .await?;
    if open >= MAX_OPEN_DRAFTS {
        return Err(ApiError::Conflict(
            "an organisation may keep at most 50 open drafts; publish or discard some".into(),
        ));
    }
    let mut tx = s.store.pool.begin().await?;
    let live = live_tx(&mut tx, org_id).await?;
    let mut payload = Payload::default();
    let mut base = Base::default();
    for surface in &surfaces {
        match surface {
            Surface::Policy => payload.policy = Some(live.policy.clone()),
            Surface::Dns => payload.dns = Some(live.dns.clone()),
            Surface::Resources => payload.resources = Some(live.resources.clone()),
        }
        capture_base(&mut base, *surface, &live);
    }
    let payload_json = check_payload(&payload)?;
    let id = Uuid::new_v4();
    let at = now();
    sqlx::query(
        "INSERT INTO change_drafts(id,org_id,title,status,version,surfaces_json,payload_json,base_json,created_by,created_by_name,updated_by,created_at,updated_at,expires_at) VALUES($1,$2,$3,'open',1,$4,$5,$6,$7,$8,$7,$9,$9,$10)",
    )
    .bind(id.to_string())
    .bind(org_id.to_string())
    .bind(&title)
    .bind(serde_json::to_string(&surfaces).map_err(|_| ApiError::CorruptData)?)
    .bind(&payload_json)
    .bind(serde_json::to_string(&base).map_err(|_| ApiError::CorruptData)?)
    .bind(&session.user_id)
    .bind(if session.name.is_empty() { &session.email } else { &session.name })
    .bind(at)
    .bind(at + DRAFT_TTL_SECS)
    .execute(&mut *tx)
    .await?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "change_draft.created",
        "change_draft",
        Some(&id.to_string()),
        &serde_json::json!({"title": title, "surfaces": surfaces, "base": base}),
    )
    .await?;
    tx.commit().await?;
    let draft = load_draft(&s, org_id, id).await?;
    Ok((StatusCode::CREATED, Json(view(draft, &session))))
}

async fn get_one(
    State(s): State<AppState>,
    UrlPath((org_id, draft_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<DraftView>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewNetwork)?;
    let draft = load_draft(&s, org_id, draft_id).await?;
    Ok(Json(view(draft, &session)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateRequest {
    version: i64,
    #[serde(default)]
    title: Option<String>,
    payload: Payload,
}

async fn update(
    State(s): State<AppState>,
    UrlPath((org_id, draft_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<UpdateRequest>,
) -> Result<Json<DraftView>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    let draft = load_draft(&s, org_id, draft_id).await?;
    let old_surfaces = draft.payload.surfaces();
    let new_surfaces = input.payload.surfaces();
    let union: Vec<Surface> = old_surfaces
        .iter()
        .chain(new_surfaces.iter())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    require_surfaces(&session, &union)?;
    ensure_open(&draft)?;
    ensure_version(&draft, input.version)?;
    let title = match &input.title {
        Some(title) => normalise_title(title)?,
        None => draft.title.clone(),
    };
    let payload_json = check_payload(&input.payload)?;
    let mut base = Base::default();
    let added: Vec<Surface> = new_surfaces
        .iter()
        .filter(|surface| !old_surfaces.contains(surface))
        .copied()
        .collect();
    let live = if added.is_empty() {
        None
    } else {
        Some(live(&s, org_id).await?)
    };
    for surface in &new_surfaces {
        if old_surfaces.contains(surface) {
            match surface {
                Surface::Policy => {
                    base.policy_etag = draft.base.policy_etag.clone();
                    base.policy_revision = draft.base.policy_revision;
                }
                Surface::Dns => {
                    base.dns_etag = draft.base.dns_etag.clone();
                    base.dns_revision = draft.base.dns_revision;
                }
                Surface::Resources => base.resources_etag = draft.base.resources_etag.clone(),
            }
        } else if let Some(live) = &live {
            capture_base(&mut base, *surface, live);
        }
    }
    let mut tx = s.store.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE change_drafts SET title=$1,payload_json=$2,base_json=$3,surfaces_json=$4,version=version+1,updated_by=$5,updated_at=$6 WHERE id=$7 AND org_id=$8 AND status='open' AND version=$9",
    )
    .bind(&title)
    .bind(&payload_json)
    .bind(serde_json::to_string(&base).map_err(|_| ApiError::CorruptData)?)
    .bind(serde_json::to_string(&new_surfaces).map_err(|_| ApiError::CorruptData)?)
    .bind(&session.user_id)
    .bind(now())
    .bind(draft_id.to_string())
    .bind(org_id.to_string())
    .bind(input.version)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::PreconditionFailed);
    }
    append_audit(
        &mut tx,
        org_id,
        &session,
        "change_draft.updated",
        "change_draft",
        Some(&draft_id.to_string()),
        &serde_json::json!({
            "version": input.version + 1,
            "surfaces": new_surfaces,
            "sha256": hash(&payload_json),
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(view(
        load_draft(&s, org_id, draft_id).await?,
        &session,
    )))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionRequest {
    version: i64,
}

/// Accepts the current live state as the draft's new base. The proposed
/// documents are kept as they are, so preview shows what they now replace.
async fn rebase(
    State(s): State<AppState>,
    UrlPath((org_id, draft_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<VersionRequest>,
) -> Result<Json<DraftView>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    let draft = load_draft(&s, org_id, draft_id).await?;
    require_surfaces(&session, &draft.payload.surfaces())?;
    ensure_open(&draft)?;
    ensure_version(&draft, input.version)?;
    let live = live(&s, org_id).await?;
    let mut base = Base::default();
    for surface in draft.payload.surfaces() {
        capture_base(&mut base, surface, &live);
    }
    let mut tx = s.store.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE change_drafts SET base_json=$1,version=version+1,updated_by=$2,updated_at=$3 WHERE id=$4 AND org_id=$5 AND status='open' AND version=$6",
    )
    .bind(serde_json::to_string(&base).map_err(|_| ApiError::CorruptData)?)
    .bind(&session.user_id)
    .bind(now())
    .bind(draft_id.to_string())
    .bind(org_id.to_string())
    .bind(input.version)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::PreconditionFailed);
    }
    append_audit(
        &mut tx,
        org_id,
        &session,
        "change_draft.rebased",
        "change_draft",
        Some(&draft_id.to_string()),
        &serde_json::json!({"previous_base": draft.base, "base": base}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(view(
        load_draft(&s, org_id, draft_id).await?,
        &session,
    )))
}

async fn preview(
    State(s): State<AppState>,
    UrlPath((org_id, draft_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    body: Option<Json<PreviewRequest>>,
) -> Result<Json<Preview>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    let draft = load_draft(&s, org_id, draft_id).await?;
    require_surfaces(&session, &draft.payload.surfaces())?;
    ensure_open(&draft)?;
    let request = body.map(|Json(body)| body).unwrap_or_default();
    Ok(Json(
        compute_preview(&s, org_id, &session, &draft, &request.pairs).await?,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishRequest {
    version: i64,
    #[serde(default)]
    confirm_risks: Vec<String>,
}

async fn publish(
    State(s): State<AppState>,
    UrlPath((org_id, draft_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<PublishRequest>,
) -> Result<Json<DraftView>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    let draft = load_draft(&s, org_id, draft_id).await?;
    let surfaces = draft.payload.surfaces();
    require_surfaces(&session, &surfaces)?;
    ensure_open(&draft)?;
    ensure_version(&draft, input.version)?;
    let preview = compute_preview(&s, org_id, &session, &draft, &[]).await?;
    if !preview.stale_surfaces.is_empty() {
        return Err(ApiError::Conflict(format!(
            "rebase required: {} changed since this draft was based",
            preview
                .stale_surfaces
                .iter()
                .map(|surface| surface.label())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    if !preview.valid {
        return Err(ApiError::BadRequest(preview.errors.join("; ")));
    }
    let unconfirmed: Vec<&str> = preview
        .risks
        .iter()
        .map(|risk| risk.code.as_str())
        .filter(|code| !input.confirm_risks.iter().any(|c| c == code))
        .collect();
    if !unconfirmed.is_empty() {
        return Err(ApiError::Conflict(format!(
            "confirm these risks to publish: {}",
            unconfirmed.join(", ")
        )));
    }

    let mut tx = s.store.pool.begin().await?;
    let applied = apply_tx(&mut tx, org_id, &session, &draft, true).await?;
    let result = serde_json::json!({
        "published_at": now(),
        "applied": applied,
        "confirmed_risks": preview.risks.iter().map(|risk| &risk.code).collect::<Vec<_>>(),
    });
    let changed = sqlx::query(
        "UPDATE change_drafts SET status='published',version=version+1,closed_at=$1,closed_by=$2,updated_by=$2,updated_at=$1,result_json=$3 WHERE id=$4 AND org_id=$5 AND status='open' AND version=$6",
    )
    .bind(now())
    .bind(&session.user_id)
    .bind(result.to_string())
    .bind(draft_id.to_string())
    .bind(org_id.to_string())
    .bind(input.version)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::PreconditionFailed);
    }
    let draft_ref = draft_id.to_string();
    if let (Some(policy), Some(acl)) = (&applied.policy, &applied.acl) {
        if policy.changed {
            append_audit(
                &mut tx,
                org_id,
                &session,
                "acl.updated",
                "acl",
                Some(&org_id.to_string()),
                &serde_json::json!({
                    "rule_count": acl.rules.len(),
                    "defaults": acl.defaults.as_str(),
                    "revision": policy.after_revision,
                    "previous_revision": policy.before_revision,
                    "draft_id": draft_ref,
                }),
            )
            .await?;
            webhooks::enqueue(
                &mut tx,
                org_id,
                "policy.published",
                &serde_json::json!({"revision": policy.after_revision, "defaults": acl.defaults.as_str()}),
            )
            .await?;
        }
    }
    if let (Some(dns), Some(settings)) = (&applied.dns, &applied.dns_settings) {
        if dns.changed {
            append_audit(
                &mut tx,
                org_id,
                &session,
                "dns.updated",
                "dns",
                Some(&org_id.to_string()),
                &serde_json::json!({
                    "revision": dns.after_revision,
                    "previous_revision": dns.before_revision,
                    "managed": settings.managed,
                    "draft_id": draft_ref,
                }),
            )
            .await?;
            webhooks::enqueue(
                &mut tx,
                org_id,
                "dns.published",
                &serde_json::json!({"revision": dns.after_revision, "managed": settings.managed}),
            )
            .await?;
        }
    }
    append_audit(
        &mut tx,
        org_id,
        &session,
        "change_draft.published",
        "change_draft",
        Some(&draft_ref),
        &serde_json::json!({
            "draft_id": draft_ref,
            "title": draft.title,
            "version": input.version,
            "surfaces": surfaces,
            "policy": applied.policy,
            "dns": applied.dns,
            "resources": applied.resources.iter().map(|change| serde_json::json!({"op": change.op, "id": change.id, "name": change.name})).collect::<Vec<_>>(),
            "control_revision": applied.control_revision,
            "confirmed_risks": preview.risks.iter().map(|risk| &risk.code).collect::<Vec<_>>(),
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(view(
        load_draft(&s, org_id, draft_id).await?,
        &session,
    )))
}

async fn discard(
    State(s): State<AppState>,
    UrlPath((org_id, draft_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<VersionRequest>,
) -> Result<Json<DraftView>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    let draft = load_draft(&s, org_id, draft_id).await?;
    require_surfaces(&session, &draft.payload.surfaces())?;
    ensure_open(&draft)?;
    ensure_version(&draft, input.version)?;
    let mut tx = s.store.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE change_drafts SET status='discarded',version=version+1,closed_at=$1,closed_by=$2,updated_by=$2,updated_at=$1 WHERE id=$3 AND org_id=$4 AND status='open' AND version=$5",
    )
    .bind(now())
    .bind(&session.user_id)
    .bind(draft_id.to_string())
    .bind(org_id.to_string())
    .bind(input.version)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::PreconditionFailed);
    }
    append_audit(
        &mut tx,
        org_id,
        &session,
        "change_draft.discarded",
        "change_draft",
        Some(&draft_id.to_string()),
        &serde_json::json!({"title": draft.title, "version": input.version}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(view(
        load_draft(&s, org_id, draft_id).await?,
        &session,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app, AssertionClaims, JoinKeyResponse, OrgResponse, RegisterResponse, Store,
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
    use topology::Topology;
    use tower::ServiceExt;

    const SECRET: &[u8] = b"test-only-hmac-secret-at-least-32-bytes";

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
        who: &Who,
    ) -> Response {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", who.token()));
        router
            .clone()
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }

    async fn json<T: serde::de::DeserializeOwned>(response: Response) -> T {
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
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
            &service("bootstrap.prepare"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let response = call(
            router,
            Method::POST,
            &format!("/v1/orgs/{id}/bootstrap-commit"),
            serde_json::json!({}),
            &service("bootstrap.commit"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        json(response).await
    }

    async fn register(router: &Router, who: &Who, name: &str) -> RegisterResponse {
        let key: JoinKeyResponse = json(
            call(
                router,
                Method::POST,
                &format!("/v1/orgs/{}/join-keys", who.org),
                serde_json::json!({"expires_in_seconds":60}),
                who,
            )
            .await,
        )
        .await;
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/nodes/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "join_key": key.key,
                            "name": name,
                            "wg_public_key": format!("{name}-key"),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        json(response).await
    }

    async fn topology_of(router: &Router, who: &Who) -> Topology {
        let response = call(
            router,
            Method::GET,
            &format!("/v1/orgs/{}/topology", who.org),
            serde_json::Value::Null,
            who,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        json(response).await
    }

    async fn new_draft(router: &Router, who: &Who, surfaces: serde_json::Value) -> DraftView {
        let response = call(
            router,
            Method::POST,
            &format!("/v1/orgs/{}/changes", who.org),
            serde_json::json!({"title": "Tighten access", "surfaces": surfaces}),
            who,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        json(response).await
    }

    async fn edit(
        router: &Router,
        who: &Who,
        draft: &DraftView,
        payload: serde_json::Value,
    ) -> Response {
        call(
            router,
            Method::PUT,
            &format!("/v1/orgs/{}/changes/{}", who.org, draft.id),
            serde_json::json!({"version": draft.version, "payload": payload}),
            who,
        )
        .await
    }

    async fn action(
        router: &Router,
        who: &Who,
        id: Uuid,
        verb: &str,
        body: serde_json::Value,
    ) -> Response {
        call(
            router,
            Method::POST,
            &format!("/v1/orgs/{}/changes/{id}/{verb}", who.org),
            body,
            who,
        )
        .await
    }

    async fn get(router: &Router, who: &Who, path: &str) -> Response {
        call(
            router,
            Method::GET,
            &format!("/v1/orgs/{}{path}", who.org),
            serde_json::Value::Null,
            who,
        )
        .await
    }

    async fn policy_of(router: &Router, who: &Who) -> serde_json::Value {
        json(get(router, who, "/acl").await).await
    }

    fn deny_all() -> serde_json::Value {
        serde_json::json!({"version":1,"defaults":"deny","rules":[]})
    }

    #[tokio::test]
    async fn topology_reflects_publish_and_revoke_and_never_leaks_other_orgs() {
        let router = app(
            Store::memory().await.unwrap(),
            "ap-southeast-2".into(),
            SECRET,
        );
        let org_a = create_org(&router, "Alpha").await;
        let org_b = create_org(&router, "Bravo").await;
        let owner = Who::person(org_a.id, "owner-a", "owner");
        let member = Who::person(org_a.id, "member-a", "member");
        let other = Who::person(org_b.id, "owner-b", "owner");
        let laptop = register(&router, &owner, "laptop").await;
        let server = register(&router, &owner, "server").await;
        let outsider = register(&router, &other, "outsider").await;

        let before = topology_of(&router, &member).await;
        let ids: Vec<Uuid> = before.nodes.iter().map(|node| node.id).collect();
        assert!(ids.contains(&laptop.id) && ids.contains(&server.id));
        assert!(
            !ids.contains(&outsider.id),
            "another organisation's node leaked"
        );
        assert!(before.edges.iter().all(|edge| {
            edge.source_node_id != outsider.id && edge.target_node_id != Some(outsider.id)
        }));
        let device_edges = |topology: &Topology| {
            topology
                .edges
                .iter()
                .filter(|edge| edge.kind == "device")
                .count()
        };
        assert_eq!(device_edges(&before), 2, "same-tag default pairs both ways");
        assert!(before
            .nodes
            .iter()
            .all(|node| node.transport.state == "not_measured"));
        // Nothing measured a path, so none is claimed.
        assert!(before
            .edges
            .iter()
            .all(|edge| matches!(edge.path.as_str(), "unknown" | "peer_offline")));
        let other_view = topology_of(&router, &other).await;
        assert_eq!(other_view.nodes.len(), 1);
        assert!(other_view.edges.is_empty());

        // Another organisation cannot read this topology even by direct URL.
        let response = call(
            &router,
            Method::GET,
            &format!("/v1/orgs/{}/topology", org_a.id),
            serde_json::Value::Null,
            &other,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let draft = new_draft(&router, &owner, serde_json::json!(["policy"])).await;
        let draft: DraftView = json(
            edit(
                &router,
                &owner,
                &draft,
                serde_json::json!({"policy": deny_all()}),
            )
            .await,
        )
        .await;
        let preview: Preview = json(
            action(
                &router,
                &owner,
                draft.id,
                "preview",
                serde_json::json!({"pairs": [{"source_node_id": laptop.id, "destination_node_id": server.id, "protocol": "tcp", "port": 443}]}),
            )
            .await,
        )
        .await;
        assert!(preview.valid, "{:?}", preview.errors);
        assert_eq!(preview.reachability.removed.len(), 2);
        assert!(preview.reachability.added.is_empty());
        let pair = &preview.pairs[0];
        assert_eq!(pair.before.decision, "allow");
        assert_eq!(pair.after.as_ref().unwrap().decision, "deny");
        assert!(pair.changed);
        assert!(preview
            .risks
            .iter()
            .any(|risk| risk.code == "access_removed"));
        // Preview never changes live state.
        assert_eq!(
            topology_of(&router, &member).await.policy.revision,
            before.policy.revision
        );

        // Another organisation's device cannot be named in a preview pair.
        let response = action(
            &router,
            &owner,
            draft.id,
            "preview",
            serde_json::json!({"pairs": [{"source_node_id": laptop.id, "destination_node_id": outsider.id}]}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Unconfirmed risks block publish.
        let response = action(
            &router,
            &owner,
            draft.id,
            "publish",
            serde_json::json!({"version": draft.version}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let response = action(
            &router,
            &owner,
            draft.id,
            "publish",
            serde_json::json!({"version": draft.version, "confirm_risks": ["access_removed"]}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let published: DraftView = json(response).await;
        assert_eq!(published.status, "published");

        let after = topology_of(&router, &member).await;
        assert_eq!(device_edges(&after), 0);
        assert_eq!(after.policy.revision, before.policy.revision + 1);
        assert_eq!(after.policy.defaults, "deny");
        assert_eq!(
            after.control_revision,
            before.control_revision + 1,
            "one bump per publish"
        );

        // Revoking a device removes it from the read model.
        let response = call(
            &router,
            Method::DELETE,
            &format!("/v1/orgs/{}/nodes/{}", org_a.id, server.id),
            serde_json::Value::Null,
            &owner,
        )
        .await;
        assert!(response.status().is_success());
        let revoked = topology_of(&router, &member).await;
        assert!(revoked.nodes.iter().all(|node| node.id != server.id));
    }

    #[tokio::test]
    async fn concurrent_editors_cannot_overwrite_each_other() {
        let router = app(
            Store::memory().await.unwrap(),
            "ap-southeast-2".into(),
            SECRET,
        );
        let org = create_org(&router, "Alpha").await;
        let alice = Who::person(org.id, "alice", "owner");
        let bob = Who::person(org.id, "bob", "admin");
        let first = new_draft(&router, &alice, serde_json::json!(["policy"])).await;
        let second = new_draft(&router, &bob, serde_json::json!(["policy"])).await;

        // Same draft, stale version: 412.
        let edited = edit(
            &router,
            &alice,
            &first,
            serde_json::json!({"policy": deny_all()}),
        )
        .await;
        assert_eq!(edited.status(), StatusCode::OK);
        let first: DraftView = json(edited).await;
        let stale = call(
            &router,
            Method::PUT,
            &format!("/v1/orgs/{}/changes/{}", org.id, first.id),
            serde_json::json!({"version": first.version - 1, "payload": {"policy": deny_all()}}),
            &bob,
        )
        .await;
        assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);

        let tagged = serde_json::json!({"version":1,"defaults":"deny","rules":[{"action":"allow","src_tags":["office"],"dst_tags":["office"]}]});
        let second: DraftView = json(
            edit(
                &router,
                &bob,
                &second,
                serde_json::json!({"policy": tagged}),
            )
            .await,
        )
        .await;

        let response = action(
            &router,
            &alice,
            first.id,
            "publish",
            serde_json::json!({"version": first.version, "confirm_risks": ["access_removed"]}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let live = policy_of(&router, &alice).await;

        // The second editor's base is stale: rebase required, live unchanged.
        let preview: Preview =
            json(action(&router, &bob, second.id, "preview", serde_json::json!({})).await).await;
        assert_eq!(preview.stale_surfaces, vec![Surface::Policy]);
        let response = action(
            &router,
            &bob,
            second.id,
            "publish",
            serde_json::json!({"version": second.version, "confirm_risks": ["access_removed", "access_widened"]}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: serde_json::Value = json(response).await;
        assert!(body["error"].as_str().unwrap().contains("rebase required"));
        assert_eq!(policy_of(&router, &alice).await, live);

        // Publishing the same draft twice is refused.
        let again = action(
            &router,
            &alice,
            first.id,
            "publish",
            serde_json::json!({"version": first.version + 1}),
        )
        .await;
        assert_eq!(again.status(), StatusCode::CONFLICT);

        // After an explicit rebase the second draft can publish.
        let rebased: DraftView = json(
            action(
                &router,
                &bob,
                second.id,
                "rebase",
                serde_json::json!({"version": second.version}),
            )
            .await,
        )
        .await;
        let response = action(
            &router,
            &bob,
            rebased.id,
            "publish",
            serde_json::json!({"version": rebased.version, "confirm_risks": ["access_removed", "access_widened"]}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            policy_of(&router, &alice).await["rules"][0]["src_tags"][0],
            "office"
        );
    }

    #[tokio::test]
    async fn invalid_surface_leaves_every_surface_unpublished() {
        let router = app(
            Store::memory().await.unwrap(),
            "ap-southeast-2".into(),
            SECRET,
        );
        let org = create_org(&router, "Alpha").await;
        let owner = Who::person(org.id, "owner", "owner");
        let gateway = register(&router, &owner, "gateway").await;
        let live_policy = policy_of(&router, &owner).await;
        let draft = new_draft(
            &router,
            &owner,
            serde_json::json!(["policy", "resources", "dns"]),
        )
        .await;
        let payload = draft.payload.clone().unwrap();
        assert_eq!(payload.resources.as_ref().map(Vec::len), Some(0));
        let office = serde_json::json!({
            "name": "office",
            "cidr": "192.168.50.0/24",
            "routing_peers": [{"node_id": gateway.id}],
            "access": {"roles": ["member"]},
        });

        // Valid policy and resource, invalid DNS (applied last).
        let draft: DraftView = json(
            edit(
                &router,
                &owner,
                &draft,
                serde_json::json!({
                    "policy": deny_all(),
                    "resources": [office.clone()],
                    "dns": {"global_resolvers": ["not-an-ip"]},
                }),
            )
            .await,
        )
        .await;
        let preview: Preview =
            json(action(&router, &owner, draft.id, "preview", serde_json::json!({})).await).await;
        assert!(!preview.valid);
        assert!(
            preview.errors[0].starts_with("DNS:"),
            "{:?}",
            preview.errors
        );
        let response = action(
            &router,
            &owner,
            draft.id,
            "publish",
            serde_json::json!({"version": draft.version, "confirm_risks": ["access_removed", "access_widened"]}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            policy_of(&router, &owner).await,
            live_policy,
            "policy must not apply alone"
        );
        let networks: serde_json::Value = json(get(&router, &owner, "/networks").await).await;
        assert_eq!(
            networks["resources"].as_array().unwrap().len(),
            0,
            "resource must not apply alone"
        );

        // An invalid resource in the middle also rolls back the policy.
        let draft: DraftView = json(
            edit(
                &router,
                &owner,
                &draft,
                serde_json::json!({
                    "policy": deny_all(),
                    "resources": [{"name": "bad", "cidr": "10.0.0.1/24", "access": {"roles": ["member"]}}],
                }),
            )
            .await,
        )
        .await;
        let response = action(
            &router,
            &owner,
            draft.id,
            "publish",
            serde_json::json!({"version": draft.version, "confirm_risks": ["access_removed"]}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = json(response).await;
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("network resources"));
        assert_eq!(policy_of(&router, &owner).await, live_policy);

        // Credentials are refused outright.
        let response = edit(
            &router,
            &owner,
            &draft,
            serde_json::json!({"policy": {"version": 1, "defaults": "deny", "rules": [], "api_token": "x"}}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Fixing the draft publishes every surface together with one bump.
        let before = topology_of(&router, &owner).await;
        let draft: DraftView = json(
            edit(
                &router,
                &owner,
                &draft,
                serde_json::json!({
                    "policy": deny_all(),
                    "resources": [office],
                    "dns": {"managed": true, "search_domains": ["corp.example.org.au"]},
                }),
            )
            .await,
        )
        .await;
        let preview: Preview =
            json(action(&router, &owner, draft.id, "preview", serde_json::json!({})).await).await;
        assert!(preview.valid, "{:?}", preview.errors);
        let codes: Vec<String> = preview.risks.iter().map(|risk| risk.code.clone()).collect();
        let response = action(
            &router,
            &owner,
            draft.id,
            "publish",
            serde_json::json!({"version": draft.version, "confirm_risks": codes}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let published: DraftView = json(response).await;
        let result = published.result.unwrap();
        assert_eq!(result["applied"]["policy"]["changed"], true);
        assert_eq!(result["applied"]["dns"]["changed"], true);
        assert_eq!(result["applied"]["resources"][0]["op"], "create");
        let after = topology_of(&router, &owner).await;
        assert_eq!(after.control_revision, before.control_revision + 1);
        assert_eq!(after.resources.len(), 1);
        let audit: Vec<serde_json::Value> = json(get(&router, &owner, "/audit").await).await;
        let event = audit
            .iter()
            .find(|event| event["action"] == "change_draft.published")
            .expect("publish is audited");
        let details: serde_json::Value = match &event["details"] {
            serde_json::Value::String(text) => serde_json::from_str(text).unwrap(),
            other => other.clone(),
        };
        assert_eq!(details["draft_id"], draft.id.to_string());
        assert_eq!(
            details["policy"]["after_revision"],
            details["policy"]["before_revision"].as_i64().unwrap() + 1
        );
    }

    #[tokio::test]
    async fn drafts_are_org_bound_and_members_see_summaries_only() {
        let store = Store::memory().await.unwrap();
        let router = app(store.clone(), "ap-southeast-2".into(), SECRET);
        let org_a = create_org(&router, "Alpha").await;
        let org_b = create_org(&router, "Bravo").await;
        let owner = Who::person(org_a.id, "owner", "owner");
        let member = Who::person(org_a.id, "member", "member");
        let network_admin = Who::person(org_a.id, "netadmin", "network_admin");
        let auditor = Who::person(org_a.id, "auditor", "auditor");
        let other = Who::person(org_b.id, "intruder", "owner");
        let draft = new_draft(&router, &owner, serde_json::json!(["policy", "dns"])).await;

        // Another organisation's owner cannot see or act on it.
        let response = get(&router, &other, &format!("/changes/{}", draft.id)).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        for verb in ["preview", "publish", "discard", "rebase"] {
            let response = action(
                &router,
                &other,
                draft.id,
                verb,
                serde_json::json!({"version": draft.version}),
            )
            .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{verb}");
        }
        let listed: DraftList = json(get(&router, &other, "/changes").await).await;
        assert!(listed.drafts.is_empty());

        // Members and auditors see summaries, never payloads, and cannot act.
        for viewer in [&member, &auditor] {
            let listed: DraftList = json(get(&router, viewer, "/changes").await).await;
            assert_eq!(listed.drafts.len(), 1);
            let seen: DraftView =
                json(get(&router, viewer, &format!("/changes/{}", draft.id)).await).await;
            assert!(seen.payload.is_none() && !seen.can_edit);
            assert_eq!(seen.surfaces, vec![Surface::Policy, Surface::Dns]);
            for verb in ["preview", "publish", "discard", "rebase"] {
                let response = action(
                    &router,
                    viewer,
                    draft.id,
                    verb,
                    serde_json::json!({"version": draft.version}),
                )
                .await;
                assert_eq!(response.status(), StatusCode::FORBIDDEN, "{verb}");
            }
            let response = call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{}/changes", org_a.id),
                serde_json::json!({"title": "x", "surfaces": ["dns"]}),
                viewer,
            )
            .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        // A network admin holds every surface permission here.
        let seen: DraftView =
            json(get(&router, &network_admin, &format!("/changes/{}", draft.id)).await).await;
        assert!(seen.payload.is_some() && seen.can_edit);

        // Expired drafts cannot publish.
        sqlx::query("UPDATE change_drafts SET expires_at=$1 WHERE id=$2")
            .bind(now() - 1)
            .bind(draft.id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        let response = action(
            &router,
            &owner,
            draft.id,
            "publish",
            serde_json::json!({"version": draft.version}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let seen: DraftView =
            json(get(&router, &owner, &format!("/changes/{}", draft.id)).await).await;
        assert_eq!(seen.status, "expired");

        // Discard closes a draft for good.
        let fresh = new_draft(&router, &owner, serde_json::json!(["dns"])).await;
        let response = action(
            &router,
            &owner,
            fresh.id,
            "discard",
            serde_json::json!({"version": fresh.version}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = edit(&router, &owner, &fresh, serde_json::json!({"dns": {}})).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
}
