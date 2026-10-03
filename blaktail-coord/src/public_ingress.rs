//! Public HTTPS ingress (draft 11, ADR 0007). An organisation runs its own
//! onshore `blaktail-ingress` next to a blaktaild that reports the
//! `public-ingress` capability and that an owner designated as an ingress
//! device (the capability alone is never enough: an ingress receives every
//! route's overlay target and access policy). This module holds the public
//! route model,
//! owner-only management, and the node-token config feed that ingress polls.
//!
//! A route is delivered to an ingress only when the organisation has public
//! ingress enabled, the route is enabled and not emergency-disabled, the
//! target is an active device in the same organisation, and the published
//! access policy lets the ingress device reach the exact target port. A URL
//! never widens policy.

use crate::{
    append_audit, bearer, bump_control_revision, console_session, designations, now,
    permissions::{require, Permission},
    policy_explain::{device_flow, device_subject},
    posture::PostureContext,
    Acl, AclProtocol, ApiError, AppState,
};
use axum::{
    extract::{Path as UrlPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, patch, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use uuid::Uuid;

pub(crate) const CAP_PUBLIC_INGRESS: &str = "public-ingress";
/// Longest a config long-poll waits before answering "unchanged".
const MAX_CONFIG_WAIT_SECS: u64 = 20;
/// An ingress stops serving every route when it has not refreshed its config
/// for this long, so an emergency disable takes effect within this bound even
/// if the coordinator becomes unreachable.
pub(crate) const STALE_AFTER_SECS: u64 = 30;
/// An ingress counts as online when it fetched config this recently.
const ONLINE_WINDOW_SECS: i64 = 90;
const MAX_ROUTES: i64 = 32;
const ENABLE_PHRASE: &str = "PUBLIC";
const TLS_MODES: &[&str] = &["operator_files", "acme_http01"];
const AUTH_MODES: &[&str] = &["none", "oidc"];
const RATE_RANGE: (i64, i64) = (1, 60_000);
const BODY_RANGE: (i64, i64) = (0, 100 * 1024 * 1024);
const CONNECTION_RANGE: (i64, i64) = (1, 4096);
const RETENTION_RANGE: (i64, i64) = (1, 365);
const MAX_REASON: usize = 200;
const MAX_CONTACT: usize = 200;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/orgs/:org_id/public-ingress", get(workspace))
        .route(
            "/v1/orgs/:org_id/public-ingress/settings",
            put(put_settings),
        )
        .route("/v1/orgs/:org_id/public-ingress/routes", post(create_route))
        .route(
            "/v1/orgs/:org_id/public-ingress/routes/:route_id",
            patch(update_route).delete(delete_route),
        )
        .route(
            "/v1/orgs/:org_id/public-ingress/routes/:route_id/emergency-disable",
            post(emergency_disable),
        )
        .route(
            "/v1/orgs/:org_id/public-ingress/nodes/:node_id",
            put(designate_node),
        )
        .route("/v1/nodes/:node_id/public-ingress/config", get(node_config))
        .route(
            "/v1/nodes/:node_id/public-ingress/report",
            post(node_report),
        )
}

// ---------- validation ----------

/// Public names must be real, organisation-owned DNS names: ASCII
/// (punycode for IDNs), at least two labels, no wildcard, no IP literal and
/// nothing under BlakTail's private namespaces or special-use suffixes.
pub(crate) fn validate_fqdn(raw: &str) -> Result<String, String> {
    let fqdn = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if fqdn.is_empty() || fqdn.len() > 253 {
        return Err("public hostname must be 1-253 characters".into());
    }
    if fqdn.parse::<std::net::IpAddr>().is_ok() {
        return Err("public hostname must be a DNS name, not an IP address".into());
    }
    let labels: Vec<&str> = fqdn.split('.').collect();
    if labels.len() < 2 {
        return Err("public hostname needs at least two labels, such as app.example.org.au".into());
    }
    for label in &labels {
        let valid = !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !valid {
            return Err(format!(
                "{label:?} is not a valid DNS label; use letters, digits and hyphens (punycode for non-ASCII names)"
            ));
        }
    }
    let tld = labels.last().copied().unwrap_or_default();
    if tld.chars().all(|c| c.is_ascii_digit()) {
        return Err("public hostname must end in a real top-level domain".into());
    }
    for reserved in [
        "blaktail",
        "local",
        "localhost",
        "internal",
        "arpa",
        "test",
        "invalid",
        "example",
        "home",
        "lan",
        "corp",
    ] {
        if tld == reserved {
            return Err(format!(
                "names under .{reserved} cannot be published to the Internet"
            ));
        }
    }
    Ok(fqdn)
}

fn canonical_domains(domains: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for domain in domains {
        let domain = domain.trim().trim_start_matches('@').to_ascii_lowercase();
        if domain.is_empty() {
            continue;
        }
        if !domain.contains('.')
            || !domain
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
        {
            return Err(format!("{domain:?} is not an email domain"));
        }
        out.push(domain);
    }
    out.sort();
    out.dedup();
    if out.len() > 16 {
        return Err("at most 16 allowed email domains".into());
    }
    Ok(out)
}

/// Canonical `address/prefix` strings (host bits cleared), IPv4 or IPv6.
fn canonical_cidrs(cidrs: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for cidr in cidrs {
        let cidr = cidr.trim();
        if cidr.is_empty() {
            continue;
        }
        let (address, prefix) = cidr.split_once('/').unwrap_or((cidr, ""));
        let invalid = || format!("{cidr:?} is not a network such as 203.0.113.0/24");
        let address: std::net::IpAddr = address.parse().map_err(|_| invalid())?;
        let max = if address.is_ipv4() { 32 } else { 128 };
        let prefix: u32 = if prefix.is_empty() {
            max
        } else {
            prefix.parse().map_err(|_| invalid())?
        };
        if prefix > max {
            return Err(invalid());
        }
        let network = match address {
            std::net::IpAddr::V4(v4) => {
                let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
                std::net::IpAddr::from(std::net::Ipv4Addr::from(u32::from(v4) & mask))
            }
            std::net::IpAddr::V6(v6) => {
                let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
                std::net::IpAddr::from(std::net::Ipv6Addr::from(u128::from(v6) & mask))
            }
        };
        out.push(format!("{network}/{prefix}"));
    }
    out.sort();
    out.dedup();
    if out.len() > 64 {
        return Err("at most 64 allowed client networks".into());
    }
    Ok(out)
}

fn in_range(name: &str, value: i64, (low, high): (i64, i64)) -> Result<i64, String> {
    if (low..=high).contains(&value) {
        Ok(value)
    } else {
        Err(format!("{name} must be between {low} and {high}"))
    }
}

fn printable(value: &str, max: usize) -> bool {
    value.chars().count() <= max && !value.chars().any(char::is_control)
}

// ---------- model ----------

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Limits {
    #[serde(default = "default_rate")]
    rate_limit_per_minute: i64,
    #[serde(default = "default_body")]
    max_body_bytes: i64,
    #[serde(default = "default_connections")]
    max_connections: i64,
    #[serde(default = "default_retention")]
    log_retention_days: i64,
}

fn default_rate() -> i64 {
    600
}
fn default_body() -> i64 {
    10 * 1024 * 1024
}
fn default_connections() -> i64 {
    256
}
fn default_retention() -> i64 {
    30
}
fn default_tls() -> String {
    "operator_files".into()
}
fn default_auth() -> String {
    "none".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteInput {
    fqdn: String,
    /// Must repeat `fqdn` exactly: a high-signal confirmation that this
    /// exposes a device to the Internet.
    confirm_fqdn: String,
    #[serde(default)]
    target_service_id: Option<Uuid>,
    #[serde(default)]
    target_node_id: Option<Uuid>,
    #[serde(default)]
    target_port: Option<u16>,
    #[serde(default = "default_tls")]
    tls_mode: String,
    #[serde(default = "default_auth")]
    auth_mode: String,
    #[serde(default)]
    allowed_email_domains: Vec<String>,
    /// Client networks allowed to use the route; empty means any.
    #[serde(default)]
    allowed_source_cidrs: Vec<String>,
    #[serde(default = "default_rate")]
    rate_limit_per_minute: i64,
    #[serde(default = "default_body")]
    max_body_bytes: i64,
    #[serde(default = "default_connections")]
    max_connections: i64,
    #[serde(default = "default_retention")]
    log_retention_days: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoutePatch {
    revision: i64,
    #[serde(default)]
    confirm_fqdn: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    tls_mode: Option<String>,
    #[serde(default)]
    auth_mode: Option<String>,
    #[serde(default)]
    allowed_email_domains: Option<Vec<String>>,
    #[serde(default)]
    allowed_source_cidrs: Option<Vec<String>>,
    #[serde(default)]
    rate_limit_per_minute: Option<i64>,
    #[serde(default)]
    max_body_bytes: Option<i64>,
    #[serde(default)]
    max_connections: Option<i64>,
    #[serde(default)]
    log_retention_days: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsInput {
    enabled: bool,
    #[serde(default)]
    abuse_contact: Option<String>,
    /// Must be `PUBLIC` to enable.
    #[serde(default)]
    confirm: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmergencyInput {
    #[serde(default)]
    reason: String,
}

/// A stored route, before deciding whether it can be delivered.
#[derive(Clone, Debug)]
struct StoredRoute {
    id: Uuid,
    fqdn: String,
    target_service_id: Option<Uuid>,
    target_node_id: Uuid,
    target_port: u16,
    tls_mode: String,
    auth_mode: String,
    allowed_email_domains: Vec<String>,
    allowed_source_cidrs: Vec<String>,
    rate_limit_per_minute: i64,
    max_body_bytes: i64,
    max_connections: i64,
    log_retention_days: i64,
    enabled: bool,
    emergency_disabled_at: Option<i64>,
    emergency_disabled_by: Option<String>,
    emergency_reason: Option<String>,
    revision: i64,
    created_at: i64,
    updated_at: i64,
}

macro_rules! route_select {
    ($tail:literal) => {
        concat!("SELECT id,fqdn,target_service_id,target_node_id,target_port,tls_mode,auth_mode,allowed_email_domains_json,rate_limit_per_minute,max_body_bytes,max_connections,log_retention_days,enabled,emergency_disabled_at,emergency_disabled_by,emergency_reason,revision,created_at,updated_at,allowed_source_cidrs_json FROM public_routes ", $tail)
    };
}

fn parse_route(row: &sqlx::any::AnyRow) -> Result<StoredRoute, ApiError> {
    let uuid = |value: String| value.parse::<Uuid>().map_err(|_| ApiError::CorruptData);
    Ok(StoredRoute {
        id: uuid(row.try_get(0)?)?,
        fqdn: row.try_get(1)?,
        target_service_id: row.try_get::<Option<String>, _>(2)?.map(uuid).transpose()?,
        target_node_id: uuid(row.try_get(3)?)?,
        target_port: u16::try_from(row.try_get::<i64, _>(4)?).map_err(|_| ApiError::CorruptData)?,
        tls_mode: row.try_get(5)?,
        auth_mode: row.try_get(6)?,
        allowed_email_domains: serde_json::from_str(&row.try_get::<String, _>(7)?)
            .map_err(|_| ApiError::CorruptData)?,
        rate_limit_per_minute: row.try_get(8)?,
        max_body_bytes: row.try_get(9)?,
        max_connections: row.try_get(10)?,
        log_retention_days: row.try_get(11)?,
        enabled: row.try_get::<i64, _>(12)? != 0,
        emergency_disabled_at: row.try_get(13)?,
        emergency_disabled_by: row.try_get(14)?,
        emergency_reason: row.try_get(15)?,
        revision: row.try_get(16)?,
        created_at: row.try_get(17)?,
        updated_at: row.try_get(18)?,
        allowed_source_cidrs: serde_json::from_str(&row.try_get::<String, _>(19)?)
            .map_err(|_| ApiError::CorruptData)?,
    })
}

async fn load_routes(pool: &sqlx::AnyPool, org_id: &str) -> Result<Vec<StoredRoute>, ApiError> {
    sqlx::query(route_select!("WHERE org_id=$1 ORDER BY fqdn"))
        .bind(org_id)
        .fetch_all(pool)
        .await?
        .iter()
        .map(parse_route)
        .collect()
}

async fn load_route(
    connection: &mut sqlx::AnyConnection,
    org_id: Uuid,
    route_id: Uuid,
) -> Result<StoredRoute, ApiError> {
    let row = sqlx::query(route_select!("WHERE id=$1 AND org_id=$2"))
        .bind(route_id.to_string())
        .bind(org_id.to_string())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or(ApiError::NotFound)?;
    parse_route(&row)
}

struct Settings {
    enabled: bool,
    abuse_contact: String,
    updated_at: Option<i64>,
}

async fn load_settings(
    connection: &mut sqlx::AnyConnection,
    org_id: &str,
) -> Result<Settings, ApiError> {
    let row = sqlx::query(
        "SELECT enabled,abuse_contact,updated_at FROM public_ingress_settings WHERE org_id=$1",
    )
    .bind(org_id)
    .fetch_optional(&mut *connection)
    .await?;
    Ok(match row {
        Some(row) => Settings {
            enabled: row.try_get::<i64, _>(0)? != 0,
            abuse_contact: row.try_get(1)?,
            updated_at: Some(row.try_get(2)?),
        },
        None => Settings {
            enabled: false,
            abuse_contact: String::new(),
            updated_at: None,
        },
    })
}

// ---------- delivery decision ----------

/// Everything needed to decide, per ingress node, which routes are live.
struct OrgView {
    enabled: bool,
    acl: Acl,
    ctx: PostureContext,
    /// Active (not revoked, deleted, suspended or expired) devices and their
    /// first overlay IPv4 address.
    active: BTreeMap<Uuid, Option<String>>,
    /// Enabled services: id -> (target node, port, protocol).
    services: BTreeMap<Uuid, (Uuid, u16, String)>,
}

impl OrgView {
    async fn load(pool: &sqlx::AnyPool, org_id: &str) -> Result<Self, ApiError> {
        let mut connection = pool.acquire().await?;
        let enabled = load_settings(&mut connection, org_id).await?.enabled;
        let acl_json: String = sqlx::query_scalar("SELECT acl_json FROM orgs WHERE id=$1")
            .bind(org_id)
            .fetch_optional(&mut *connection)
            .await?
            .ok_or(ApiError::NotFound)?;
        let acl: Acl = serde_json::from_str(&acl_json).map_err(|_| ApiError::CorruptData)?;
        let mut active = BTreeMap::new();
        for row in sqlx::query(
            "SELECT id,allowed_ips_json FROM nodes WHERE org_id=$1 AND revoked_at IS NULL AND deleted_at IS NULL AND suspended_at IS NULL AND credential_expires_at>$2",
        )
        .bind(org_id)
        .bind(now())
        .fetch_all(&mut *connection)
        .await?
        {
            let id: Uuid = row
                .try_get::<String, _>(0)?
                .parse()
                .map_err(|_| ApiError::CorruptData)?;
            let ips: Vec<String> =
                serde_json::from_str(&row.try_get::<String, _>(1)?).unwrap_or_default();
            active.insert(id, overlay_ipv4(&ips));
        }
        let mut services = BTreeMap::new();
        for row in sqlx::query(
            "SELECT id,target_node,port,protocol FROM org_services WHERE org_id=$1 AND enabled=1",
        )
        .bind(org_id)
        .fetch_all(&mut *connection)
        .await?
        {
            let parse = |value: String| value.parse::<Uuid>().map_err(|_| ApiError::CorruptData);
            services.insert(
                parse(row.try_get(0)?)?,
                (
                    parse(row.try_get(1)?)?,
                    u16::try_from(row.try_get::<i64, _>(2)?).map_err(|_| ApiError::CorruptData)?,
                    row.try_get(3)?,
                ),
            );
        }
        drop(connection);
        Ok(Self {
            enabled,
            acl,
            ctx: PostureContext::load(pool, org_id).await?,
            active,
            services,
        })
    }

    /// The device and port a route really reaches (a service route follows
    /// the service's current target), or why it cannot be resolved.
    fn target(&self, route: &StoredRoute) -> Result<(Uuid, u16, String), &'static str> {
        let (node, port) = match route.target_service_id {
            Some(service) => match self.services.get(&service) {
                Some((node, port, protocol)) if protocol == "http" => (*node, *port),
                Some(_) => return Err("target_unsupported"),
                None => return Err("target_unavailable"),
            },
            None => (route.target_node_id, route.target_port),
        };
        match self.active.get(&node) {
            Some(Some(address)) => Ok((node, port, address.clone())),
            _ => Err("target_unavailable"),
        }
    }

    /// Delivery state of `route` for one ingress device.
    fn state(&self, route: &StoredRoute, ingress: Uuid) -> &'static str {
        if !self.enabled {
            return "organisation_disabled";
        }
        if route.emergency_disabled_at.is_some() {
            return "emergency_disabled";
        }
        if !route.enabled {
            return "disabled";
        }
        let (node, port) = match self.target(route) {
            Ok((node, port, _)) => (node, port),
            Err(state) => return state,
        };
        if node == ingress {
            return "target_is_ingress";
        }
        let (Some(source), Some(destination)) =
            (self.ctx.facts.get(&ingress), self.ctx.facts.get(&node))
        else {
            return "target_unavailable";
        };
        let flow = device_flow(
            &self.acl,
            &device_subject(source, &self.ctx),
            &device_subject(destination, &self.ctx),
            destination,
            Some(AclProtocol::Tcp),
            Some(port),
        );
        if flow.decision() {
            "active"
        } else {
            "blocked_by_policy"
        }
    }
}

fn overlay_ipv4(allowed_ips: &[String]) -> Option<String> {
    allowed_ips.iter().find_map(|cidr| {
        let (address, prefix) = cidr.split_once('/').unwrap_or((cidr, "32"));
        (prefix == "32")
            .then(|| address.parse::<std::net::Ipv4Addr>().ok())
            .flatten()
            .map(|ip| ip.to_string())
    })
}

// ---------- console views ----------

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct IngressRouteState {
    node_id: Uuid,
    node_name: String,
    pub(crate) state: String,
    certificate_not_after: Option<i64>,
    certificate_source: Option<String>,
    last_error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RouteView {
    pub(crate) id: Uuid,
    pub(crate) fqdn: String,
    target_service_id: Option<Uuid>,
    target_node_id: Uuid,
    target_node_name: Option<String>,
    target_port: u16,
    tls_mode: String,
    auth_mode: String,
    allowed_email_domains: Vec<String>,
    allowed_source_cidrs: Vec<String>,
    limits: Limits,
    pub(crate) enabled: bool,
    pub(crate) emergency_disabled_at: Option<i64>,
    emergency_disabled_by: Option<String>,
    emergency_reason: Option<String>,
    pub(crate) revision: i64,
    /// `active` when at least one online ingress serves it, else the most
    /// useful blocking reason.
    pub(crate) status: String,
    pub(crate) ingress: Vec<IngressRouteState>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct IngressNodeView {
    pub(crate) id: Uuid,
    name: String,
    pub(crate) online: bool,
    last_config_at: Option<i64>,
    capable: bool,
    /// Designated by an owner; only capable and designated devices receive
    /// routes.
    pub(crate) designated: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SettingsView {
    pub(crate) enabled: bool,
    abuse_contact: String,
    updated_at: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Workspace {
    pub(crate) settings: SettingsView,
    pub(crate) ingress_nodes: Vec<IngressNodeView>,
    pub(crate) routes: Vec<RouteView>,
    stale_after_secs: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RouteReport {
    route_id: Uuid,
    #[serde(default)]
    certificate_not_after: Option<i64>,
    #[serde(default)]
    certificate_source: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

struct IngressNode {
    id: Uuid,
    name: String,
    capable: bool,
    designated: bool,
    last_config_at: Option<i64>,
    reports: Vec<RouteReport>,
}

async fn ingress_nodes(pool: &sqlx::AnyPool, org_id: &str) -> Result<Vec<IngressNode>, ApiError> {
    let rows = sqlx::query(
        "SELECT n.id,COALESCE(NULLIF(TRIM(n.display_name),''),n.name),n.capabilities_json,p.last_config_at,p.report_json FROM nodes n LEFT JOIN public_ingress_nodes p ON p.node_id=n.id AND p.org_id=n.org_id WHERE n.org_id=$1 AND n.revoked_at IS NULL AND n.deleted_at IS NULL ORDER BY n.name",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;
    let designated = {
        let mut connection = pool.acquire().await?;
        designations::designated(&mut connection, org_id, designations::PUBLIC_INGRESS).await?
    };
    let mut out = Vec::new();
    for row in rows {
        let capabilities: Vec<String> =
            serde_json::from_str(&row.try_get::<String, _>(2)?).unwrap_or_default();
        let capable = capabilities.iter().any(|c| c == CAP_PUBLIC_INGRESS);
        let last_config_at: Option<i64> = row.try_get(3)?;
        let id: String = row.try_get(0)?;
        let is_designated = designated.contains(&id);
        if !capable && !is_designated && last_config_at.is_none() {
            continue;
        }
        out.push(IngressNode {
            id: id.parse().map_err(|_| ApiError::CorruptData)?,
            name: row.try_get(1)?,
            capable,
            designated: is_designated,
            last_config_at,
            reports: row
                .try_get::<Option<String>, _>(4)?
                .and_then(|json| serde_json::from_str(&json).ok())
                .unwrap_or_default(),
        });
    }
    Ok(out)
}

async fn workspace(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Workspace>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewNetwork)?;
    Ok(Json(build_workspace(&s, org_id).await?))
}

async fn build_workspace(s: &AppState, org_id: Uuid) -> Result<Workspace, ApiError> {
    let org = org_id.to_string();
    let settings = {
        let mut connection = s.store.pool.acquire().await?;
        load_settings(&mut connection, &org).await?
    };
    let view = OrgView::load(&s.store.pool, &org).await?;
    let nodes = ingress_nodes(&s.store.pool, &org).await?;
    let names: BTreeMap<Uuid, String> = view
        .ctx
        .facts
        .values()
        .map(|f| {
            (
                f.id,
                f.display_name.clone().unwrap_or_else(|| f.name.clone()),
            )
        })
        .collect();
    let current = now();
    let online = |node: &IngressNode| {
        node.capable
            && node.designated
            && node
                .last_config_at
                .is_some_and(|at| current - at <= ONLINE_WINDOW_SECS)
    };
    let routes = load_routes(&s.store.pool, &org)
        .await?
        .into_iter()
        .map(|route| {
            let ingress: Vec<IngressRouteState> = nodes
                .iter()
                .map(|node| {
                    let report = node.reports.iter().find(|r| r.route_id == route.id);
                    let state = if !node.capable {
                        "ingress_not_capable"
                    } else if !node.designated {
                        "ingress_not_designated"
                    } else {
                        view.state(&route, node.id)
                    };
                    IngressRouteState {
                        node_id: node.id,
                        node_name: node.name.clone(),
                        state: if state == "active" && !online(node) {
                            "ingress_offline".into()
                        } else {
                            state.into()
                        },
                        certificate_not_after: report.and_then(|r| r.certificate_not_after),
                        certificate_source: report.and_then(|r| r.certificate_source.clone()),
                        last_error: report.and_then(|r| r.error.clone()),
                    }
                })
                .collect();
            let status = if ingress.iter().any(|i| i.state == "active") {
                "active".to_owned()
            } else if let Some(first) = ingress.first() {
                first.state.clone()
            } else {
                let state = view.state(&route, Uuid::nil());
                if matches!(
                    state,
                    "organisation_disabled"
                        | "emergency_disabled"
                        | "disabled"
                        | "target_unavailable"
                        | "target_unsupported"
                ) {
                    state.to_owned()
                } else {
                    "no_ingress_node".to_owned()
                }
            };
            RouteView {
                target_node_name: view
                    .target(&route)
                    .ok()
                    .and_then(|(node, _, _)| names.get(&node).cloned())
                    .or_else(|| names.get(&route.target_node_id).cloned()),
                id: route.id,
                fqdn: route.fqdn,
                target_service_id: route.target_service_id,
                target_node_id: route.target_node_id,
                target_port: route.target_port,
                tls_mode: route.tls_mode,
                auth_mode: route.auth_mode,
                allowed_email_domains: route.allowed_email_domains,
                allowed_source_cidrs: route.allowed_source_cidrs,
                limits: Limits {
                    rate_limit_per_minute: route.rate_limit_per_minute,
                    max_body_bytes: route.max_body_bytes,
                    max_connections: route.max_connections,
                    log_retention_days: route.log_retention_days,
                },
                enabled: route.enabled,
                emergency_disabled_at: route.emergency_disabled_at,
                emergency_disabled_by: route.emergency_disabled_by,
                emergency_reason: route.emergency_reason,
                revision: route.revision,
                status,
                ingress,
                created_at: route.created_at,
                updated_at: route.updated_at,
            }
        })
        .collect();
    Ok(Workspace {
        settings: SettingsView {
            enabled: settings.enabled,
            abuse_contact: settings.abuse_contact,
            updated_at: settings.updated_at,
        },
        ingress_nodes: nodes
            .iter()
            .map(|node| IngressNodeView {
                id: node.id,
                name: node.name.clone(),
                online: online(node),
                last_config_at: node.last_config_at,
                capable: node.capable,
                designated: node.designated,
            })
            .collect(),
        routes,
        stale_after_secs: STALE_AFTER_SECS,
    })
}

// ---------- console mutations ----------

async fn put_settings(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<SettingsInput>,
) -> Result<Json<Workspace>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManagePublicIngress)?;
    let org = org_id.to_string();
    let mut tx = s.store.pool.begin().await?;
    let current = load_settings(&mut tx, &org).await?;
    let contact = input
        .abuse_contact
        .as_deref()
        .map(str::trim)
        .unwrap_or(&current.abuse_contact)
        .to_owned();
    if !printable(&contact, MAX_CONTACT) {
        return Err(ApiError::BadRequest(format!(
            "abuse contact must be at most {MAX_CONTACT} printable characters"
        )));
    }
    if input.enabled {
        if input.confirm.as_deref() != Some(ENABLE_PHRASE) {
            return Err(ApiError::BadRequest(format!(
                "type {ENABLE_PHRASE} to confirm that this organisation may publish services to the Internet"
            )));
        }
        if !(contact.contains('@') || contact.starts_with("https://")) {
            return Err(ApiError::BadRequest(
                "record an abuse contact (an email address or https:// URL) before enabling public ingress".into(),
            ));
        }
    }
    sqlx::query(
        "INSERT INTO public_ingress_settings(org_id,enabled,abuse_contact,updated_at,updated_by) VALUES($1,$2,$3,$4,$5) ON CONFLICT(org_id) DO UPDATE SET enabled=excluded.enabled,abuse_contact=excluded.abuse_contact,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
    )
    .bind(&org)
    .bind(i64::from(input.enabled))
    .bind(&contact)
    .bind(now())
    .bind(&session.user_id)
    .execute(&mut *tx)
    .await?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        match (current.enabled, input.enabled) {
            (false, true) => "public_ingress.enabled",
            (true, false) => "public_ingress.disabled",
            _ => "public_ingress.updated",
        },
        "organisation",
        Some(&org),
        &serde_json::json!({"enabled": input.enabled, "abuse_contact": contact}),
    )
    .await?;
    bump_control_revision(&mut tx, &org).await?;
    tx.commit().await?;
    Ok(Json(build_workspace(&s, org_id).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DesignationInput {
    designated: bool,
}

/// Designates (or releases) a device as a public ingress. Owner-only, like
/// every other public ingress decision.
async fn designate_node(
    State(s): State<AppState>,
    UrlPath((org_id, node_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<DesignationInput>,
) -> Result<Json<Workspace>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManagePublicIngress)?;
    let mut tx = s.store.pool.begin().await?;
    if designations::set(
        &mut tx,
        org_id,
        &session,
        node_id,
        designations::PUBLIC_INGRESS,
        input.designated,
    )
    .await?
    {
        bump_control_revision(&mut tx, org_id.to_string()).await?;
    }
    tx.commit().await?;
    Ok(Json(build_workspace(&s, org_id).await?))
}

struct CheckedTarget {
    service_id: Option<Uuid>,
    node_id: Uuid,
    port: u16,
}

async fn check_target(
    connection: &mut sqlx::AnyConnection,
    org_id: Uuid,
    service_id: Option<Uuid>,
    node_id: Option<Uuid>,
    port: Option<u16>,
) -> Result<CheckedTarget, ApiError> {
    match (service_id, node_id, port) {
        (Some(service_id), None, None) => {
            // Scoped to this organisation: another org's service is not found.
            let row = sqlx::query(
                "SELECT target_node,port,protocol FROM org_services WHERE id=$1 AND org_id=$2",
            )
            .bind(service_id.to_string())
            .bind(org_id.to_string())
            .fetch_optional(&mut *connection)
            .await?
            .ok_or_else(|| {
                ApiError::BadRequest("target service is not in this organisation".into())
            })?;
            if row.try_get::<String, _>(2)? != "http" {
                return Err(ApiError::BadRequest(
                    "ingress reaches targets over plain HTTP inside the encrypted overlay; choose an http service".into(),
                ));
            }
            Ok(CheckedTarget {
                service_id: Some(service_id),
                node_id: row
                    .try_get::<String, _>(0)?
                    .parse()
                    .map_err(|_| ApiError::CorruptData)?,
                port: u16::try_from(row.try_get::<i64, _>(1)?)
                    .map_err(|_| ApiError::CorruptData)?,
            })
        }
        (None, Some(node_id), Some(port)) if port != 0 => {
            let exists: Option<String> = sqlx::query_scalar(
                "SELECT id FROM nodes WHERE id=$1 AND org_id=$2 AND revoked_at IS NULL AND deleted_at IS NULL",
            )
            .bind(node_id.to_string())
            .bind(org_id.to_string())
            .fetch_optional(&mut *connection)
            .await?;
            if exists.is_none() {
                return Err(ApiError::BadRequest(
                    "target device is not an active device in this organisation".into(),
                ));
            }
            Ok(CheckedTarget {
                service_id: None,
                node_id,
                port,
            })
        }
        _ => Err(ApiError::BadRequest(
            "choose either a target service, or a target device and port 1-65535".into(),
        )),
    }
}

fn check_modes(tls: &str, auth: &str) -> Result<(), ApiError> {
    if !TLS_MODES.contains(&tls) {
        return Err(ApiError::BadRequest(
            "tls_mode must be operator_files or acme_http01".into(),
        ));
    }
    if !AUTH_MODES.contains(&auth) {
        return Err(ApiError::BadRequest(
            "auth_mode must be none or oidc".into(),
        ));
    }
    Ok(())
}

fn check_limits(limits: &Limits) -> Result<(), ApiError> {
    in_range(
        "rate_limit_per_minute",
        limits.rate_limit_per_minute,
        RATE_RANGE,
    )
    .and_then(|_| in_range("max_body_bytes", limits.max_body_bytes, BODY_RANGE))
    .and_then(|_| in_range("max_connections", limits.max_connections, CONNECTION_RANGE))
    .and_then(|_| {
        in_range(
            "log_retention_days",
            limits.log_retention_days,
            RETENTION_RANGE,
        )
    })
    .map(|_| ())
    .map_err(ApiError::BadRequest)
}

async fn create_route(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<RouteInput>,
) -> Result<(StatusCode, Json<RouteView>), ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManagePublicIngress)?;
    let org = org_id.to_string();
    let fqdn = validate_fqdn(&input.fqdn).map_err(ApiError::BadRequest)?;
    if input
        .confirm_fqdn
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
        != fqdn
    {
        return Err(ApiError::BadRequest(format!(
            "type {fqdn} exactly to confirm publishing it to the Internet"
        )));
    }
    let tls_mode = input.tls_mode.trim().to_owned();
    let auth_mode = input.auth_mode.trim().to_owned();
    check_modes(&tls_mode, &auth_mode)?;
    let domains = canonical_domains(&input.allowed_email_domains).map_err(ApiError::BadRequest)?;
    let sources = canonical_cidrs(&input.allowed_source_cidrs).map_err(ApiError::BadRequest)?;
    let limits = Limits {
        rate_limit_per_minute: input.rate_limit_per_minute,
        max_body_bytes: input.max_body_bytes,
        max_connections: input.max_connections,
        log_retention_days: input.log_retention_days,
    };
    check_limits(&limits)?;
    let mut tx = s.store.pool.begin().await?;
    if !load_settings(&mut tx, &org).await?.enabled {
        return Err(ApiError::Conflict(
            "public ingress is off for this organisation; an owner must enable it first".into(),
        ));
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM public_routes WHERE org_id=$1")
        .bind(&org)
        .fetch_one(&mut *tx)
        .await?;
    if count >= MAX_ROUTES {
        return Err(ApiError::BadRequest(format!(
            "organisations are limited to {MAX_ROUTES} public routes"
        )));
    }
    let target = check_target(
        &mut tx,
        org_id,
        input.target_service_id,
        input.target_node_id,
        input.target_port,
    )
    .await?;
    let id = Uuid::new_v4();
    let created_at = now();
    sqlx::query(
        "INSERT INTO public_routes(id,org_id,fqdn,target_service_id,target_node_id,target_port,tls_mode,auth_mode,allowed_email_domains_json,rate_limit_per_minute,max_body_bytes,max_connections,log_retention_days,enabled,revision,created_at,updated_at,allowed_source_cidrs_json) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,1,1,$14,$14,$15)",
    )
    .bind(id.to_string())
    .bind(&org)
    .bind(&fqdn)
    .bind(target.service_id.map(|id| id.to_string()))
    .bind(target.node_id.to_string())
    .bind(i64::from(target.port))
    .bind(&tls_mode)
    .bind(&auth_mode)
    .bind(serde_json::to_string(&domains).map_err(|_| ApiError::CorruptData)?)
    .bind(limits.rate_limit_per_minute)
    .bind(limits.max_body_bytes)
    .bind(limits.max_connections)
    .bind(limits.log_retention_days)
    .bind(created_at)
    .bind(serde_json::to_string(&sources).map_err(|_| ApiError::CorruptData)?)
    .execute(&mut *tx)
    .await
    .map_err(crate::conflict("a public route for that hostname already exists"))?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "public_route.created",
        "public_route",
        Some(&id.to_string()),
        &serde_json::json!({
            "fqdn": fqdn,
            "target_service_id": target.service_id,
            "target_node_id": target.node_id,
            "target_port": target.port,
            "tls_mode": tls_mode,
            "auth_mode": auth_mode,
            "allowed_email_domains": domains,
            "allowed_source_cidrs": sources,
            "limits": limits,
        }),
    )
    .await?;
    bump_control_revision(&mut tx, &org).await?;
    tx.commit().await?;
    let view = route_view(&s, org_id, id).await?;
    Ok((StatusCode::CREATED, Json(view)))
}

async fn route_view(s: &AppState, org_id: Uuid, route_id: Uuid) -> Result<RouteView, ApiError> {
    build_workspace(s, org_id)
        .await?
        .routes
        .into_iter()
        .find(|route| route.id == route_id)
        .ok_or(ApiError::NotFound)
}

async fn update_route(
    State(s): State<AppState>,
    UrlPath((org_id, route_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<RoutePatch>,
) -> Result<Json<RouteView>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManagePublicIngress)?;
    let org = org_id.to_string();
    let mut tx = s.store.pool.begin().await?;
    let current = load_route(&mut tx, org_id, route_id).await?;
    if input.revision != current.revision {
        return Err(ApiError::PreconditionFailed);
    }
    let was_live = current.enabled && current.emergency_disabled_at.is_none();
    let enabled = input.enabled.unwrap_or(was_live);
    let tls_mode = input
        .tls_mode
        .as_deref()
        .map(str::trim)
        .unwrap_or(&current.tls_mode)
        .to_owned();
    let auth_mode = input
        .auth_mode
        .as_deref()
        .map(str::trim)
        .unwrap_or(&current.auth_mode)
        .to_owned();
    check_modes(&tls_mode, &auth_mode)?;
    let domains = match &input.allowed_email_domains {
        Some(domains) => canonical_domains(domains).map_err(ApiError::BadRequest)?,
        None => current.allowed_email_domains.clone(),
    };
    let sources = match &input.allowed_source_cidrs {
        Some(cidrs) => canonical_cidrs(cidrs).map_err(ApiError::BadRequest)?,
        None => current.allowed_source_cidrs.clone(),
    };
    let limits = Limits {
        rate_limit_per_minute: input
            .rate_limit_per_minute
            .unwrap_or(current.rate_limit_per_minute),
        max_body_bytes: input.max_body_bytes.unwrap_or(current.max_body_bytes),
        max_connections: input.max_connections.unwrap_or(current.max_connections),
        log_retention_days: input
            .log_retention_days
            .unwrap_or(current.log_retention_days),
    };
    check_limits(&limits)?;
    // Turning a route on (including clearing an emergency disable) or
    // dropping its identity gate widens exposure: repeat the hostname.
    let widens = (enabled && !was_live)
        || (current.auth_mode == "oidc" && auth_mode == "none")
        || (!current.allowed_source_cidrs.is_empty() && sources.is_empty());
    if widens
        && input
            .confirm_fqdn
            .as_deref()
            .map(|v| v.trim().trim_end_matches('.').to_ascii_lowercase())
            .as_deref()
            != Some(current.fqdn.as_str())
    {
        return Err(ApiError::BadRequest(format!(
            "type {} exactly to confirm exposing it to the Internet",
            current.fqdn
        )));
    }
    if enabled && !was_live && !load_settings(&mut tx, &org).await?.enabled {
        return Err(ApiError::Conflict(
            "public ingress is off for this organisation; an owner must enable it first".into(),
        ));
    }
    let clear_emergency = enabled && current.emergency_disabled_at.is_some();
    let changed = sqlx::query(
        "UPDATE public_routes SET enabled=$1,tls_mode=$2,auth_mode=$3,allowed_email_domains_json=$4,rate_limit_per_minute=$5,max_body_bytes=$6,max_connections=$7,log_retention_days=$8,emergency_disabled_at=CASE WHEN $9=1 THEN NULL ELSE emergency_disabled_at END,emergency_disabled_by=CASE WHEN $9=1 THEN NULL ELSE emergency_disabled_by END,emergency_reason=CASE WHEN $9=1 THEN NULL ELSE emergency_reason END,revision=revision+1,updated_at=$10,allowed_source_cidrs_json=$14 WHERE id=$11 AND org_id=$12 AND revision=$13",
    )
    .bind(i64::from(enabled))
    .bind(&tls_mode)
    .bind(&auth_mode)
    .bind(serde_json::to_string(&domains).map_err(|_| ApiError::CorruptData)?)
    .bind(limits.rate_limit_per_minute)
    .bind(limits.max_body_bytes)
    .bind(limits.max_connections)
    .bind(limits.log_retention_days)
    .bind(i64::from(clear_emergency))
    .bind(now())
    .bind(route_id.to_string())
    .bind(&org)
    .bind(current.revision)
    .bind(serde_json::to_string(&sources).map_err(|_| ApiError::CorruptData)?)
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
        match (was_live, enabled) {
            (false, true) => "public_route.enabled",
            (true, false) => "public_route.disabled",
            _ => "public_route.updated",
        },
        "public_route",
        Some(&route_id.to_string()),
        &serde_json::json!({
            "fqdn": current.fqdn,
            "revision": current.revision + 1,
            "enabled": enabled,
            "emergency_cleared": clear_emergency,
            "tls_mode": tls_mode,
            "auth_mode": auth_mode,
            "allowed_email_domains": domains,
            "allowed_source_cidrs": sources,
            "limits": limits,
        }),
    )
    .await?;
    bump_control_revision(&mut tx, &org).await?;
    tx.commit().await?;
    Ok(Json(route_view(&s, org_id, route_id).await?))
}

/// The kill switch. Narrowing exposure must be easy in an incident, so any
/// role that manages services (or public ingress) may pull it, without a
/// revision check. Re-enabling stays owner-only and needs the typed hostname.
async fn emergency_disable(
    State(s): State<AppState>,
    UrlPath((org_id, route_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<EmergencyInput>,
) -> Result<Json<RouteView>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    if !session.role.can(Permission::ManageServices)
        && !session.role.can(Permission::ManagePublicIngress)
    {
        return Err(ApiError::Forbidden);
    }
    let reason = input.reason.trim().to_owned();
    if !printable(&reason, MAX_REASON) {
        return Err(ApiError::BadRequest(format!(
            "reason must be at most {MAX_REASON} printable characters"
        )));
    }
    let org = org_id.to_string();
    let mut tx = s.store.pool.begin().await?;
    let current = load_route(&mut tx, org_id, route_id).await?;
    let at = now();
    sqlx::query(
        "UPDATE public_routes SET enabled=0,emergency_disabled_at=COALESCE(emergency_disabled_at,$1),emergency_disabled_by=COALESCE(emergency_disabled_by,$2),emergency_reason=COALESCE(emergency_reason,$3),revision=revision+1,updated_at=$1 WHERE id=$4 AND org_id=$5",
    )
    .bind(at)
    .bind(if session.email.is_empty() {
        session.user_id.clone()
    } else {
        session.email.clone()
    })
    .bind(&reason)
    .bind(route_id.to_string())
    .bind(&org)
    .execute(&mut *tx)
    .await?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "public_route.emergency_disabled",
        "public_route",
        Some(&route_id.to_string()),
        &serde_json::json!({
            "fqdn": current.fqdn,
            "reason": reason,
            "already_disabled": current.emergency_disabled_at.is_some(),
        }),
    )
    .await?;
    bump_control_revision(&mut tx, &org).await?;
    tx.commit().await?;
    Ok(Json(route_view(&s, org_id, route_id).await?))
}

async fn delete_route(
    State(s): State<AppState>,
    UrlPath((org_id, route_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManagePublicIngress)?;
    let org = org_id.to_string();
    let mut tx = s.store.pool.begin().await?;
    let current = load_route(&mut tx, org_id, route_id).await?;
    sqlx::query("DELETE FROM public_routes WHERE id=$1 AND org_id=$2")
        .bind(route_id.to_string())
        .bind(&org)
        .execute(&mut *tx)
        .await?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "public_route.deleted",
        "public_route",
        Some(&route_id.to_string()),
        &serde_json::json!({"fqdn": current.fqdn}),
    )
    .await?;
    bump_control_revision(&mut tx, &org).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- ingress node feed ----------

/// Authenticates an ingress device: a valid, unsuspended node token whose
/// device reports the `public-ingress` capability and is designated by an
/// owner. Both the config feed and reports go through here.
async fn ingress_node(
    s: &AppState,
    headers: &HeaderMap,
    node_id: Uuid,
) -> Result<String, ApiError> {
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
    if !capabilities.iter().any(|c| c == CAP_PUBLIC_INGRESS) {
        return Err(ApiError::Forbidden);
    }
    let org: String = row.try_get(0)?;
    let mut connection = s.store.pool.acquire().await?;
    if !designations::is_designated(&mut connection, &org, node_id, designations::PUBLIC_INGRESS)
        .await?
    {
        return Err(ApiError::Forbidden);
    }
    Ok(org)
}

#[derive(Default, Deserialize)]
struct ConfigQuery {
    #[serde(default)]
    since: i64,
    #[serde(default)]
    wait: u64,
}

/// What an ingress needs to serve one route. The target address is the only
/// place the proxy may connect for this hostname.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct DeliveredRoute {
    pub(crate) id: Uuid,
    pub(crate) fqdn: String,
    pub(crate) target_address: String,
    pub(crate) target_port: u16,
    tls_mode: String,
    auth_mode: String,
    allowed_email_domains: Vec<String>,
    allowed_source_cidrs: Vec<String>,
    rate_limit_per_minute: i64,
    max_body_bytes: i64,
    max_connections: i64,
    log_retention_days: i64,
    revision: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct IngressConfig {
    pub(crate) revision: i64,
    pub(crate) stale_after_secs: u64,
    pub(crate) routes: Vec<DeliveredRoute>,
}

async fn deliverable(
    s: &AppState,
    org: &str,
    node_id: Uuid,
) -> Result<Vec<DeliveredRoute>, ApiError> {
    let view = OrgView::load(&s.store.pool, org).await?;
    let mut out = Vec::new();
    for route in load_routes(&s.store.pool, org).await? {
        if view.state(&route, node_id) != "active" {
            continue;
        }
        let Ok((_, port, address)) = view.target(&route) else {
            continue;
        };
        out.push(DeliveredRoute {
            id: route.id,
            fqdn: route.fqdn,
            target_address: address,
            target_port: port,
            tls_mode: route.tls_mode,
            auth_mode: route.auth_mode,
            allowed_email_domains: route.allowed_email_domains,
            allowed_source_cidrs: route.allowed_source_cidrs,
            rate_limit_per_minute: route.rate_limit_per_minute,
            max_body_bytes: route.max_body_bytes,
            max_connections: route.max_connections,
            log_retention_days: route.log_retention_days,
            revision: route.revision,
        });
    }
    Ok(out)
}

/// Long-poll: answers at once when `since` is behind the organisation's
/// control revision (every route, settings, policy or device change bumps
/// it), otherwise within `wait` seconds (at most 20) with 204.
async fn node_config(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    Query(query): Query<ConfigQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let org = ingress_node(&s, &headers, node_id).await?;
    let wait = Duration::from_secs(query.wait.min(MAX_CONFIG_WAIT_SECS));
    let started = Instant::now();
    loop {
        let revision: i64 = sqlx::query_scalar("SELECT control_revision FROM orgs WHERE id=$1")
            .bind(&org)
            .fetch_optional(&s.store.pool)
            .await?
            .ok_or(ApiError::CorruptData)?;
        let changed = query.since == 0 || revision != query.since;
        if changed || started.elapsed() >= wait {
            sqlx::query(
                "INSERT INTO public_ingress_nodes(node_id,org_id,last_config_at,config_revision) VALUES($1,$2,$3,$4) ON CONFLICT(node_id) DO UPDATE SET org_id=excluded.org_id,last_config_at=excluded.last_config_at,config_revision=excluded.config_revision",
            )
            .bind(node_id.to_string())
            .bind(&org)
            .bind(now())
            .bind(revision)
            .execute(&s.store.pool)
            .await?;
            if !changed {
                return Ok(StatusCode::NO_CONTENT.into_response());
            }
            let routes = deliverable(&s, &org, node_id).await?;
            return Ok(Json(IngressConfig {
                revision,
                stale_after_secs: STALE_AFTER_SECS,
                routes,
            })
            .into_response());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportInput {
    routes: Vec<RouteReport>,
}

async fn node_report(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<ReportInput>,
) -> Result<StatusCode, ApiError> {
    let org = ingress_node(&s, &headers, node_id).await?;
    if input.routes.len() > MAX_ROUTES as usize {
        return Err(ApiError::BadRequest("too many route reports".into()));
    }
    let known: Vec<Uuid> = load_routes(&s.store.pool, &org)
        .await?
        .into_iter()
        .map(|r| r.id)
        .collect();
    let routes: Vec<RouteReport> = input
        .routes
        .into_iter()
        .filter(|r| known.contains(&r.route_id))
        .map(|r| RouteReport {
            route_id: r.route_id,
            certificate_not_after: r.certificate_not_after,
            certificate_source: r
                .certificate_source
                .filter(|v| printable(v, 32))
                .map(|v| v.trim().to_owned()),
            error: r.error.map(|v| {
                v.chars()
                    .filter(|c| !c.is_control())
                    .take(MAX_REASON)
                    .collect()
            }),
        })
        .collect();
    sqlx::query(
        "INSERT INTO public_ingress_nodes(node_id,org_id,last_config_at,report_json,reported_at) VALUES($1,$2,$3,$4,$3) ON CONFLICT(node_id) DO UPDATE SET org_id=excluded.org_id,report_json=excluded.report_json,reported_at=excluded.reported_at",
    )
    .bind(node_id.to_string())
    .bind(&org)
    .bind(now())
    .bind(serde_json::to_string(&routes).map_err(|_| ApiError::CorruptData)?)
    .execute(&s.store.pool)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_services::test_support::{call, create_org, register, router, Auth};
    use crate::Role;
    use axum::http::Method;
    use serde_json::{json, Value};

    #[test]
    fn fqdn_validation_rejects_private_and_malformed_names() {
        assert_eq!(
            validate_fqdn("App.Example.org.au.").unwrap(),
            "app.example.org.au"
        );
        for bad in [
            "",
            "localhost",
            "app",
            "100.64.0.2",
            "*.example.org.au",
            "app.blaktail",
            "svc.12345678.blaktail",
            "nas.local",
            "x.internal",
            "1.2.3.4.in-addr.arpa",
            "-bad.example.org",
            "bad_.example.org",
            "app.example.123",
            "kāinga.example.org",
        ] {
            assert!(validate_fqdn(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn source_networks_are_canonical() {
        assert_eq!(
            canonical_cidrs(&[
                "203.0.113.77/24".into(),
                " 198.51.100.9 ".into(),
                "2001:db8::1/32".into(),
                "203.0.113.0/24".into(),
                "".into(),
            ])
            .unwrap(),
            vec!["198.51.100.9/32", "2001:db8::/32", "203.0.113.0/24"]
        );
        assert!(canonical_cidrs(&["0.0.0.0/0".into()]).is_ok());
        assert!(canonical_cidrs(&["::/129".into()]).is_err());
    }

    #[test]
    fn stale_bound_is_within_thirty_seconds() {
        const _: () = assert!(STALE_AFTER_SECS <= 30);
        const _: () = assert!(MAX_CONFIG_WAIT_SECS < STALE_AFTER_SECS);
    }

    struct Lab {
        router: Router,
        org: Uuid,
        ingress: (Uuid, String),
        target: Uuid,
    }

    /// Makes `node` report the ingress capability, as blaktaild
    /// `--public-ingress` does on every poll.
    async fn claim_capability(router: &Router, node: Uuid, token: &str) {
        let (status, body) = call(
            router,
            Method::GET,
            &format!("/v1/nodes/{node}/peers?capabilities=wireguard,public-ingress"),
            Value::Null,
            Auth::Node(token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn designate(
        router: &Router,
        org: Uuid,
        node: Uuid,
        designated: bool,
        role: Role,
    ) -> (StatusCode, Value) {
        call(
            router,
            Method::PUT,
            &format!("/v1/orgs/{org}/public-ingress/nodes/{node}"),
            json!({"designated": designated}),
            Auth::Console(org, role),
        )
        .await
    }

    async fn enable(router: &Router, org: Uuid) {
        let (status, body) = call(
            router,
            Method::PUT,
            &format!("/v1/orgs/{org}/public-ingress/settings"),
            json!({"enabled": true, "abuse_contact": "abuse@example.org.au", "confirm": "PUBLIC"}),
            Auth::Console(org, Role::Owner),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn lab(target_tag: &str) -> Lab {
        let (router, _) = router().await;
        let org = create_org(&router, "Ingress org").await;
        let (ingress, token, _) = register(&router, org, "edge", &["office"]).await;
        let (target, _, _) = register(&router, org, "app", &[target_tag]).await;
        claim_capability(&router, ingress, &token).await;
        let (status, body) = designate(&router, org, ingress, true, Role::Owner).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        enable(&router, org).await;
        Lab {
            router,
            org,
            ingress: (ingress, token),
            target,
        }
    }

    async fn create(lab: &Lab, fqdn: &str, role: Role) -> (StatusCode, Value) {
        call(
            &lab.router,
            Method::POST,
            &format!("/v1/orgs/{}/public-ingress/routes", lab.org),
            json!({
                "fqdn": fqdn,
                "confirm_fqdn": fqdn,
                "target_node_id": lab.target,
                "target_port": 8080,
                "max_body_bytes": 1024,
                "allowed_source_cidrs": ["203.0.113.0/24"],
            }),
            Auth::Console(lab.org, role),
        )
        .await
    }

    async fn config(lab: &Lab) -> Value {
        let (status, body) = call(
            &lab.router,
            Method::GET,
            &format!("/v1/nodes/{}/public-ingress/config", lab.ingress.0),
            Value::Null,
            Auth::Node(&lab.ingress.1),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    fn fqdns(config: &Value) -> Vec<String> {
        config["routes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["fqdn"].as_str().unwrap().to_owned())
            .collect()
    }

    async fn post_route(
        router: &Router,
        org: Uuid,
        role: Role,
        body: Value,
    ) -> (StatusCode, Value) {
        call(
            router,
            Method::POST,
            &format!("/v1/orgs/{org}/public-ingress/routes"),
            body,
            Auth::Console(org, role),
        )
        .await
    }

    #[tokio::test]
    async fn only_owners_create_or_enable_and_org_starts_off() {
        let (router, _) = router().await;
        let org = create_org(&router, "Perms").await;
        let (status, body) = call(
            &router,
            Method::GET,
            &format!("/v1/orgs/{org}/public-ingress"),
            Value::Null,
            Auth::Console(org, Role::Member),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["settings"]["enabled"], false, "default off");
        for role in [Role::Admin, Role::NetworkAdmin, Role::Auditor, Role::Member] {
            let (status, _) = call(
                &router,
                Method::PUT,
                &format!("/v1/orgs/{org}/public-ingress/settings"),
                json!({"enabled": true, "abuse_contact": "abuse@example.org.au", "confirm": "PUBLIC"}),
                Auth::Console(org, role),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{role:?} enabled ingress");
        }
        // Owner must type the phrase and record an abuse contact.
        for input in [
            json!({"enabled": true, "abuse_contact": "abuse@example.org.au"}),
            json!({"enabled": true, "abuse_contact": "abuse@example.org.au", "confirm": "public"}),
            json!({"enabled": true, "confirm": "PUBLIC"}),
        ] {
            let (status, _) = call(
                &router,
                Method::PUT,
                &format!("/v1/orgs/{org}/public-ingress/settings"),
                input,
                Auth::Console(org, Role::Owner),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        let (target, _, _) = register(&router, org, "app", &["office"]).await;
        let route = |confirm: &str, port: u16| json!({"fqdn": "app.example.org.au", "confirm_fqdn": confirm, "target_node_id": target, "target_port": port});
        // Creating while the organisation is off is refused.
        let (status, _) =
            post_route(&router, org, Role::Owner, route("app.example.org.au", 80)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        enable(&router, org).await;
        for role in [Role::Admin, Role::NetworkAdmin, Role::Auditor, Role::Member] {
            let (status, _) = post_route(&router, org, role, route("app.example.org.au", 80)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{role:?} created a route");
        }
        // The confirmation must repeat the hostname.
        let (status, body) =
            post_route(&router, org, Role::Owner, route("app.example.org", 80)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let (status, body) =
            post_route(&router, org, Role::Owner, route("APP.example.org.au", 80)).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let id = body["id"].as_str().unwrap().to_owned();
        // Duplicate hostname in the same organisation conflicts.
        let (status, _) =
            post_route(&router, org, Role::Owner, route("app.example.org.au", 81)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        // Non-owners cannot change or delete it.
        for role in [Role::Admin, Role::NetworkAdmin, Role::Member] {
            for (method, body) in [
                (Method::PATCH, json!({"revision": 1, "enabled": false})),
                (Method::DELETE, Value::Null),
            ] {
                let (status, _) = call(
                    &router,
                    method,
                    &format!("/v1/orgs/{org}/public-ingress/routes/{id}"),
                    body,
                    Auth::Console(org, role),
                )
                .await;
                assert_eq!(status, StatusCode::FORBIDDEN);
            }
        }
        // Members and auditors cannot pull the emergency switch; admins can.
        for role in [Role::Member, Role::Auditor] {
            let (status, _) = call(
                &router,
                Method::POST,
                &format!("/v1/orgs/{org}/public-ingress/routes/{id}/emergency-disable"),
                json!({"reason": "test"}),
                Auth::Console(org, role),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
        let (status, body) = call(
            &router,
            Method::POST,
            &format!("/v1/orgs/{org}/public-ingress/routes/{id}/emergency-disable"),
            json!({"reason": "abuse report"}),
            Auth::Console(org, Role::Admin),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "emergency_disabled");
        assert_eq!(body["emergency_reason"], "abuse report");
        // Re-enabling needs the owner, the current revision and the hostname.
        let revision = body["revision"].as_i64().unwrap();
        let path = format!("/v1/orgs/{org}/public-ingress/routes/{id}");
        let (status, _) = call(
            &router,
            Method::PATCH,
            &path,
            json!({"revision": revision, "enabled": true}),
            Auth::Console(org, Role::Owner),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = call(
            &router,
            Method::PATCH,
            &path,
            json!({"revision": revision, "enabled": true, "confirm_fqdn": "app.example.org.au"}),
            Auth::Console(org, Role::Admin),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call(
            &router,
            Method::PATCH,
            &path,
            json!({"revision": revision - 1, "enabled": true, "confirm_fqdn": "app.example.org.au"}),
            Auth::Console(org, Role::Owner),
        )
        .await;
        assert_eq!(status, StatusCode::PRECONDITION_FAILED);
        let (status, body) = call(
            &router,
            Method::PATCH,
            &path,
            json!({"revision": revision, "enabled": true, "confirm_fqdn": "app.example.org.au"}),
            Auth::Console(org, Role::Owner),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["emergency_disabled_at"].is_null());
        assert_eq!(body["enabled"], true);
        let (status, _) = call(
            &router,
            Method::DELETE,
            &path,
            Value::Null,
            Auth::Console(org, Role::Owner),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn validation_failures_are_reported() {
        let lab = lab("office").await;
        let base = |extra: Value| {
            let mut body = json!({"fqdn": "a.example.org.au", "confirm_fqdn": "a.example.org.au", "target_node_id": lab.target, "target_port": 80});
            for (key, value) in extra.as_object().unwrap() {
                body[key] = value.clone();
            }
            body
        };
        for (input, why) in [
            (
                base(json!({"fqdn": "app.blaktail", "confirm_fqdn": "app.blaktail"})),
                "private suffix",
            ),
            (base(json!({"target_port": 0})), "port 0"),
            (base(json!({"target_port": null})), "no port"),
            (
                base(json!({"target_node_id": Uuid::new_v4()})),
                "unknown node",
            ),
            (
                base(
                    json!({"target_service_id": Uuid::new_v4(), "target_node_id": null, "target_port": null}),
                ),
                "unknown service",
            ),
            (base(json!({"tls_mode": "passthrough"})), "tls mode"),
            (base(json!({"auth_mode": "basic"})), "auth mode"),
            (base(json!({"max_body_bytes": 1_000_000_000})), "body limit"),
            (base(json!({"rate_limit_per_minute": 0})), "rate limit"),
            (base(json!({"max_connections": 0})), "connections"),
            (base(json!({"log_retention_days": 0})), "retention"),
            (
                base(json!({"allowed_email_domains": ["not a domain"]})),
                "domains",
            ),
            (
                base(json!({"allowed_source_cidrs": ["10.0.0.0/33"]})),
                "source network",
            ),
            (
                base(json!({"allowed_source_cidrs": ["not-an-ip"]})),
                "source address",
            ),
        ] {
            let (status, body) = post_route(&lab.router, lab.org, Role::Owner, input).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{why}: {body}");
        }
    }

    #[tokio::test]
    async fn routes_reach_only_capable_ingress_of_the_same_org() {
        let lab = lab("office").await;
        let (status, body) = create(&lab, "app.example.org.au", Role::Owner).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        // Policy allows it, but no ingress has fetched config yet.
        assert_eq!(body["status"], "ingress_offline", "{body}");
        let delivered = config(&lab).await;
        assert_eq!(fqdns(&delivered), vec!["app.example.org.au"]);
        let route = &delivered["routes"][0];
        assert_eq!(route["target_port"], 8080);
        assert!(route["target_address"]
            .as_str()
            .unwrap()
            .starts_with("100.64."));
        assert_eq!(route["max_body_bytes"], 1024);
        assert_eq!(route["allowed_source_cidrs"], json!(["203.0.113.0/24"]));
        assert_eq!(delivered["stale_after_secs"], 30);

        // A device without the capability gets nothing.
        let (plain, plain_token, _) = register(&lab.router, lab.org, "plain", &["office"]).await;
        let (status, _) = call(
            &lab.router,
            Method::GET,
            &format!("/v1/nodes/{plain}/public-ingress/config"),
            Value::Null,
            Auth::Node(&plain_token),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // Another device's token is unauthorised.
        let (status, _) = call(
            &lab.router,
            Method::GET,
            &format!("/v1/nodes/{}/public-ingress/config", lab.ingress.0),
            Value::Null,
            Auth::Node(&plain_token),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Another organisation's ingress never sees this route, and its
        // owner cannot touch it.
        let other = create_org(&lab.router, "Other org").await;
        let (other_edge, other_token, _) = register(&lab.router, other, "edge", &["office"]).await;
        claim_capability(&lab.router, other_edge, &other_token).await;
        designate(&lab.router, other, other_edge, true, Role::Owner).await;
        enable(&lab.router, other).await;
        let (status, body) = call(
            &lab.router,
            Method::GET,
            &format!("/v1/nodes/{other_edge}/public-ingress/config"),
            Value::Null,
            Auth::Node(&other_token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(fqdns(&body).is_empty(), "{body}");
        let id = delivered["routes"][0]["id"].as_str().unwrap();
        for (method, uri, body) in [
            (
                Method::PATCH,
                format!("/v1/orgs/{other}/public-ingress/routes/{id}"),
                json!({"revision": 1, "enabled": false}),
            ),
            (
                Method::DELETE,
                format!("/v1/orgs/{other}/public-ingress/routes/{id}"),
                Value::Null,
            ),
            (
                Method::POST,
                format!("/v1/orgs/{other}/public-ingress/routes/{id}/emergency-disable"),
                json!({}),
            ),
        ] {
            let (status, _) = call(
                &lab.router,
                method,
                &uri,
                body,
                Auth::Console(other, Role::Owner),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
        // A session for the other organisation cannot read this one.
        let (status, _) = call(
            &lab.router,
            Method::GET,
            &format!("/v1/orgs/{}/public-ingress", lab.org),
            Value::Null,
            Auth::Console(other, Role::Owner),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // The other org cannot point a route at this org's device.
        let (status, _) = post_route(
            &lab.router,
            other,
            Role::Owner,
            json!({"fqdn": "app.example.org.au", "confirm_fqdn": "app.example.org.au", "target_node_id": lab.target, "target_port": 8080}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // The original route is still intact.
        assert_eq!(fqdns(&config(&lab).await).len(), 1);
    }

    #[tokio::test]
    async fn capable_ingress_needs_an_owner_designation() {
        let lab = lab("office").await;
        let (status, body) = create(&lab, "app.example.org.au", Role::Owner).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        // Any device can claim the capability; undesignated, it receives no
        // routes (overlay targets, email allowlists) and cannot report.
        let (rogue, rogue_token, _) = register(&lab.router, lab.org, "rogue", &["office"]).await;
        claim_capability(&lab.router, rogue, &rogue_token).await;
        let (status, _) = call(
            &lab.router,
            Method::GET,
            &format!("/v1/nodes/{rogue}/public-ingress/config"),
            Value::Null,
            Auth::Node(&rogue_token),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call(
            &lab.router,
            Method::POST,
            &format!("/v1/nodes/{rogue}/public-ingress/report"),
            json!({"routes": [{"route_id": body["id"], "certificate_not_after": 1}]}),
            Auth::Node(&rogue_token),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (_, workspace) = call(
            &lab.router,
            Method::GET,
            &format!("/v1/orgs/{}/public-ingress", lab.org),
            Value::Null,
            Auth::Console(lab.org, Role::Owner),
        )
        .await;
        let node = workspace["ingress_nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["id"] == rogue.to_string())
            .unwrap()
            .clone();
        assert_eq!(
            (node["capable"].clone(), node["designated"].clone()),
            (json!(true), json!(false))
        );
        let state = workspace["routes"][0]["ingress"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["node_id"] == rogue.to_string())
            .unwrap()["state"]
            .clone();
        assert_eq!(state, "ingress_not_designated");

        // Designation is an owner decision, scoped to the organisation.
        for role in [Role::Admin, Role::NetworkAdmin, Role::Member] {
            let (status, _) = designate(&lab.router, lab.org, rogue, true, role).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{role:?} designates");
        }
        let other = create_org(&lab.router, "Designating org").await;
        let (status, _) = designate(&lab.router, other, rogue, true, Role::Owner).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, workspace) = designate(&lab.router, lab.org, rogue, true, Role::Owner).await;
        assert_eq!(status, StatusCode::OK, "{workspace}");
        let (status, delivered) = call(
            &lab.router,
            Method::GET,
            &format!("/v1/nodes/{rogue}/public-ingress/config"),
            Value::Null,
            Auth::Node(&rogue_token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(fqdns(&delivered), vec!["app.example.org.au"]);

        // Releasing it bumps the revision and cuts the feed at once.
        let (status, _) = designate(&lab.router, lab.org, rogue, false, Role::Owner).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &lab.router,
            Method::GET,
            &format!("/v1/nodes/{rogue}/public-ingress/config"),
            Value::Null,
            Auth::Node(&rogue_token),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let revision: i64 = delivered["revision"].as_i64().unwrap();
        assert!(config(&lab).await["revision"].as_i64().unwrap() > revision);
    }

    async fn patch(lab: &Lab, id: &str, body: Value) -> Value {
        let (status, body) = call(
            &lab.router,
            Method::PATCH,
            &format!("/v1/orgs/{}/public-ingress/routes/{id}", lab.org),
            body,
            Auth::Console(lab.org, Role::Owner),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    #[tokio::test]
    async fn disabled_emergency_and_org_off_routes_are_not_delivered() {
        let lab = lab("office").await;
        let (_, route) = create(&lab, "app.example.org.au", Role::Owner).await;
        let id = route["id"].as_str().unwrap().to_owned();
        let route = patch(&lab, &id, json!({"revision": 1, "enabled": false})).await;
        assert_eq!(route["status"], "disabled");
        assert!(fqdns(&config(&lab).await).is_empty());
        let route = patch(
            &lab,
            &id,
            json!({"revision": 2, "enabled": true, "confirm_fqdn": "app.example.org.au"}),
        )
        .await;
        assert_eq!(fqdns(&config(&lab).await).len(), 1);
        let (status, _) = call(
            &lab.router,
            Method::POST,
            &format!(
                "/v1/orgs/{}/public-ingress/routes/{id}/emergency-disable",
                lab.org
            ),
            json!({"reason": "incident"}),
            Auth::Console(lab.org, Role::Owner),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(fqdns(&config(&lab).await).is_empty());
        let revision = route["revision"].as_i64().unwrap() + 1;
        patch(
            &lab,
            &id,
            json!({"revision": revision, "enabled": true, "confirm_fqdn": "app.example.org.au"}),
        )
        .await;
        assert_eq!(fqdns(&config(&lab).await).len(), 1);
        // Turning the organisation off withdraws every route.
        let (status, body) = call(
            &lab.router,
            Method::PUT,
            &format!("/v1/orgs/{}/public-ingress/settings", lab.org),
            json!({"enabled": false}),
            Auth::Console(lab.org, Role::Owner),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["routes"][0]["status"], "organisation_disabled");
        assert!(fqdns(&config(&lab).await).is_empty());
        // Every mutation is audited.
        let (_, audit) = call(
            &lab.router,
            Method::GET,
            &format!("/v1/orgs/{}/audit", lab.org),
            Value::Null,
            Auth::Console(lab.org, Role::Owner),
        )
        .await;
        let text = audit.to_string();
        for action in [
            "public_ingress.enabled",
            "public_route.created",
            "public_route.disabled",
            "public_route.enabled",
            "public_route.emergency_disabled",
            "public_ingress.disabled",
        ] {
            assert!(text.contains(action), "audit lacks {action}: {text}");
        }
    }

    #[tokio::test]
    async fn widening_a_route_needs_the_typed_hostname() {
        let lab = lab("office").await;
        let (_, route) = create(&lab, "app.example.org.au", Role::Owner).await;
        let id = route["id"].as_str().unwrap();
        let path = format!("/v1/orgs/{}/public-ingress/routes/{id}", lab.org);
        for body in [
            json!({"revision": 1, "allowed_source_cidrs": []}),
            json!({"revision": 1, "allowed_source_cidrs": [], "confirm_fqdn": "other.example.org.au"}),
        ] {
            let (status, _) = call(
                &lab.router,
                Method::PATCH,
                &path,
                body,
                Auth::Console(lab.org, Role::Owner),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        // Narrowing needs no confirmation.
        let route = patch(
            &lab,
            id,
            json!({"revision": 1, "allowed_source_cidrs": ["203.0.113.8/29"]}),
        )
        .await;
        assert_eq!(route["allowed_source_cidrs"], json!(["203.0.113.8/29"]));
        let route = patch(
            &lab,
            id,
            json!({"revision": 2, "allowed_source_cidrs": [], "confirm_fqdn": "app.example.org.au"}),
        )
        .await;
        assert_eq!(route["allowed_source_cidrs"], json!([]));
    }

    #[tokio::test]
    async fn policy_must_allow_the_ingress_to_reach_the_target() {
        // Default same-tag policy: an office ingress cannot reach a store device.
        let lab = lab("store").await;
        let (status, body) = create(&lab, "app.example.org.au", Role::Owner).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["status"], "blocked_by_policy", "{body}");
        assert_eq!(body["ingress"][0]["state"], "blocked_by_policy", "{body}");
        assert!(fqdns(&config(&lab).await).is_empty());
    }

    #[tokio::test]
    async fn emergency_disable_wakes_the_long_poll_within_the_bound() {
        let lab = lab("office").await;
        let (_, route) = create(&lab, "app.example.org.au", Role::Owner).await;
        let id = route["id"].as_str().unwrap().to_owned();
        let revision = config(&lab).await["revision"].as_i64().unwrap();
        let router = lab.router.clone();
        let (node, token) = lab.ingress.clone();
        let poll = tokio::spawn(async move {
            call(
                &router,
                Method::GET,
                &format!("/v1/nodes/{node}/public-ingress/config?since={revision}&wait=20"),
                Value::Null,
                Auth::Node(&token),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(500)).await;
        let disabled_at = Instant::now();
        let (status, _) = call(
            &lab.router,
            Method::POST,
            &format!(
                "/v1/orgs/{}/public-ingress/routes/{id}/emergency-disable",
                lab.org
            ),
            json!({"reason": "timing test"}),
            Auth::Console(lab.org, Role::Admin),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = poll.await.unwrap();
        let propagation = disabled_at.elapsed();
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(fqdns(&body).is_empty(), "{body}");
        assert!(
            propagation < Duration::from_secs(2),
            "emergency disable took {propagation:?} to reach the ingress"
        );
        // Without a change the poll answers 204 within the wait, which the
        // ingress counts as a fresh config.
        let started = Instant::now();
        let (status, _) = call(
            &lab.router,
            Method::GET,
            &format!(
                "/v1/nodes/{}/public-ingress/config?since={}&wait=1",
                lab.ingress.0, body["revision"]
            ),
            Value::Null,
            Auth::Node(&lab.ingress.1),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn reports_surface_certificate_expiry_for_known_routes_only() {
        let lab = lab("office").await;
        let (_, route) = create(&lab, "app.example.org.au", Role::Owner).await;
        let id = route["id"].as_str().unwrap();
        config(&lab).await;
        let (status, _) = call(
            &lab.router,
            Method::POST,
            &format!("/v1/nodes/{}/public-ingress/report", lab.ingress.0),
            json!({"routes": [
                {"route_id": id, "certificate_not_after": 1_900_000_000_i64, "certificate_source": "operator_files"},
                {"route_id": Uuid::new_v4(), "error": "foreign"}
            ]}),
            Auth::Node(&lab.ingress.1),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, workspace) = call(
            &lab.router,
            Method::GET,
            &format!("/v1/orgs/{}/public-ingress", lab.org),
            Value::Null,
            Auth::Console(lab.org, Role::Member),
        )
        .await;
        assert_eq!(workspace["ingress_nodes"][0]["online"], true);
        let state = &workspace["routes"][0]["ingress"][0];
        assert_eq!(state["state"], "active");
        assert_eq!(state["certificate_not_after"], 1_900_000_000_i64);
        assert!(!workspace.to_string().contains("foreign"));
    }
}
