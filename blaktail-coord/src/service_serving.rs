//! Serving side of private services (draft 10). The target node's agent
//! reports listener and local-target health; the coordinator compiles which
//! peers may reach each service, narrows the serving node's port-level
//! ingress to match, and publishes a service name to authorised clients'
//! MagicDNS only while a fresh, healthy report names a live certificate.

use crate::{
    bump_control_revision, now, posture,
    private_services::{namespace, node_org},
    ApiError, AppState, Peer,
};
use axum::{
    extract::{Path as UrlPath, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::BTreeSet;
use uuid::Uuid;

/// Listener port assumed until the serving agent reports its own.
pub(crate) const DEFAULT_LISTEN_PORT: u16 = 443;
/// A health report older than this no longer publishes the name.
pub(crate) const HEALTH_FRESH_SECS: i64 = 120;
const MAX_REPORTED: usize = 64;
const MAX_DETAIL: usize = 200;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/nodes/:node_id/services/health", post(report_health))
        .route("/v1/nodes/:node_id/service-ca", get(service_ca))
}

/// Overlay sources the serving node may accept for one service. Delivered
/// only to that service's target node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ServiceAccess {
    pub(crate) id: Uuid,
    pub(crate) fqdn: String,
    pub(crate) allowed_sources: Vec<String>,
}

/// A service name an authorised client's MagicDNS answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ServiceRecord {
    pub(crate) name: String,
    pub(crate) addresses: Vec<String>,
}

/// What the serving node last reported, as stored.
pub(crate) struct Health {
    pub(crate) state: String,
    pub(crate) detail: String,
    pub(crate) node: Option<String>,
    pub(crate) reported_at: Option<i64>,
    pub(crate) served_serial: Option<String>,
}

impl Health {
    pub(crate) fn fresh_for(&self, target: &str, at: i64) -> bool {
        self.node.as_deref() == Some(target)
            && self
                .reported_at
                .is_some_and(|reported| reported > at - HEALTH_FRESH_SECS)
    }
}

/// Live (unrevoked, unexpired) certificate expiry for `serial`, if any.
pub(crate) async fn live_certificate(
    connection: &mut sqlx::AnyConnection,
    org_id: &str,
    service_id: &str,
    target: &str,
    serial: Option<&str>,
) -> Result<Option<i64>, ApiError> {
    let Some(serial) = serial else {
        return Ok(None);
    };
    Ok(sqlx::query_scalar(
        "SELECT not_after FROM service_certificates WHERE org_id=$1 AND service_id=$2 AND node_id=$3 AND serial=$4 AND revoked_at IS NULL AND not_after>$5",
    )
    .bind(org_id)
    .bind(service_id)
    .bind(target)
    .bind(serial)
    .bind(now())
    .fetch_optional(&mut *connection)
    .await?)
}

struct EnabledService {
    id: String,
    name: String,
    target: String,
    access_tags: Vec<String>,
    listen_port: u16,
    /// Until when the name may be published; `None` means not published.
    publish_until: Option<i64>,
}

async fn enabled_services(
    pool: &sqlx::AnyPool,
    org_id: &str,
) -> Result<Vec<EnabledService>, ApiError> {
    let rows = sqlx::query(
        "SELECT id,service_name,target_node,access_tags_json,listen_port,health_state,health_detail,health_node,health_reported_at,served_serial FROM org_services WHERE org_id=$1 AND enabled=1 ORDER BY service_name",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;
    let mut connection = pool.acquire().await?;
    let mut services = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row.try_get(0)?;
        let target: String = row.try_get(2)?;
        let health = Health {
            state: row.try_get(5)?,
            detail: row.try_get(6)?,
            node: row.try_get(7)?,
            reported_at: row.try_get(8)?,
            served_serial: row.try_get(9)?,
        };
        let at = now();
        let publish_until = if health.state == "healthy" && health.fresh_for(&target, at) {
            live_certificate(
                &mut connection,
                org_id,
                &id,
                &target,
                health.served_serial.as_deref(),
            )
            .await?
            .map(|not_after| not_after.min(health.reported_at.unwrap_or(at) + HEALTH_FRESH_SECS))
        } else {
            None
        };
        services.push(EnabledService {
            id,
            name: row.try_get(1)?,
            target,
            access_tags: serde_json::from_str(&row.try_get::<String, _>(3)?)
                .map_err(|_| ApiError::CorruptData)?,
            listen_port: row
                .try_get::<Option<i64>, _>(4)?
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
                .unwrap_or(DEFAULT_LISTEN_PORT),
            publish_until,
        });
    }
    Ok(services)
}

fn tags_match(peer_tags: &[crate::DeviceTag], access_tags: &[String]) -> bool {
    peer_tags
        .iter()
        .any(|tag| access_tags.iter().any(|allowed| allowed == tag.as_str()))
}

/// Whether an ingress port list (`22`, `8000-8100`, `*`) covers `port`.
fn port_listed(specs: &[String], port: u16) -> bool {
    specs.iter().any(|spec| {
        let spec = spec.trim();
        if spec == "*" {
            return true;
        }
        match spec.split_once('-') {
            Some((start, end)) => matches!(
                (start.parse::<u16>(), end.parse::<u16>()),
                (Ok(start), Ok(end)) if start <= port && port <= end
            ),
            None => spec.parse::<u16>() == Ok(port),
        }
    })
}

fn host_addresses(routes: &[String]) -> Vec<String> {
    routes
        .iter()
        .filter_map(|route| {
            let (address, prefix) = route.split_once('/')?;
            let parsed: std::net::IpAddr = address.parse().ok()?;
            let host = if parsed.is_ipv4() { "32" } else { "128" };
            (prefix == host).then(|| parsed.to_string())
        })
        .collect()
}

/// Applies private services to one node's peer map, which `peers` already
/// holds after policy filtering (a service never creates connectivity the
/// policy does not):
///
/// - when `node_id` serves services, each peer's ingress gains the listener
///   port if it holds a service's access tag and a port deny otherwise, and
///   the per-service allowed sources are returned for the listener;
/// - for every other node, the names of published services it may reach.
pub(crate) async fn apply_to_peer_map(
    pool: &sqlx::AnyPool,
    org_id: &str,
    node_id: Uuid,
    own_tags: &[crate::DeviceTag],
    peers: &mut [Peer],
) -> Result<(Vec<ServiceAccess>, Vec<ServiceRecord>), ApiError> {
    let services = enabled_services(pool, org_id).await?;
    if services.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let org: Uuid = org_id.parse().map_err(|_| ApiError::CorruptData)?;
    let fqdn = |name: &str| format!("{name}.{}", namespace(org));
    let me = node_id.to_string();

    let serving = services
        .iter()
        .filter(|service| service.target == me)
        .collect::<Vec<_>>();
    // A policy deny on the listener port wins over a service grant, here and
    // at the listener, so macOS serving nodes (no packet filter) agree.
    let may_reach = |peer: &Peer, service: &EnabledService| {
        tags_match(&peer.tags, &service.access_tags)
            && !peer
                .ingress
                .as_ref()
                .is_some_and(|ingress| port_listed(&ingress.deny_tcp, service.listen_port))
    };
    let mut access = Vec::new();
    for service in &serving {
        access.push(ServiceAccess {
            id: service.id.parse().map_err(|_| ApiError::CorruptData)?,
            fqdn: fqdn(&service.name),
            allowed_sources: peers
                .iter()
                .filter(|peer| may_reach(peer, service))
                .flat_map(|peer| host_addresses(&peer.allowed_ips))
                .collect(),
        });
    }
    let ports = serving
        .iter()
        .map(|service| service.listen_port)
        .collect::<BTreeSet<_>>();
    for peer in peers.iter_mut() {
        let allowed_ports = ports
            .iter()
            .filter(|port| {
                serving
                    .iter()
                    .any(|service| service.listen_port == **port && may_reach(peer, service))
            })
            .copied()
            .collect::<BTreeSet<_>>();
        let Some(ingress) = peer.ingress.as_mut() else {
            continue;
        };
        for port in &ports {
            let allowed = allowed_ports.contains(port);
            let port = port.to_string();
            let list = if allowed {
                if ingress.all {
                    continue;
                }
                &mut ingress.tcp
            } else {
                &mut ingress.deny_tcp
            };
            if !list.contains(&port) {
                list.push(port);
            }
        }
    }

    let mut records = Vec::new();
    let mut deadline: Option<i64> = None;
    let visible = peers
        .iter()
        .map(|peer| peer.id.to_string())
        .collect::<BTreeSet<_>>();
    for service in &services {
        let Some(until) = service.publish_until else {
            continue;
        };
        deadline = Some(deadline.map_or(until, |current| current.min(until)));
        if service.target == me
            || !visible.contains(&service.target)
            || !tags_match(own_tags, &service.access_tags)
        {
            continue;
        }
        let routes: String = sqlx::query_scalar(
            "SELECT allowed_ips_json FROM nodes WHERE id=$1 AND org_id=$2 AND revoked_at IS NULL AND deleted_at IS NULL AND suspended_at IS NULL",
        )
        .bind(&service.target)
        .bind(org_id)
        .fetch_optional(pool)
        .await?
        .unwrap_or_else(|| "[]".into());
        let addresses =
            host_addresses(&serde_json::from_str::<Vec<String>>(&routes).unwrap_or_default());
        if !addresses.is_empty() {
            records.push(ServiceRecord {
                name: fqdn(&service.name),
                addresses,
            });
        }
    }
    // Recompile everyone when a published name's report or certificate lapses.
    posture::record_deadline(pool, org_id, deadline).await?;
    Ok((access, records))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthReport {
    listen_port: u16,
    services: Vec<ServiceHealth>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceHealth {
    id: Uuid,
    listening: bool,
    healthy: bool,
    #[serde(default)]
    detail: String,
    #[serde(default)]
    serial: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct HealthAccepted {
    pub(crate) accepted: usize,
}

fn clean_detail(detail: &str) -> String {
    detail
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_DETAIL)
        .collect()
}

async fn report_health(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(report): Json<HealthReport>,
) -> Result<Json<HealthAccepted>, ApiError> {
    let (org_id, _) = node_org(&s, &headers, node_id).await?;
    if report.listen_port == 0 {
        return Err(ApiError::BadRequest("listen_port must be 1-65535".into()));
    }
    if report.services.len() > MAX_REPORTED {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_REPORTED} services per report"
        )));
    }
    let org = org_id.to_string();
    let me = node_id.to_string();
    let at = now();
    let mut tx = s.store.pool.begin().await?;
    let mut accepted = 0;
    let mut changed = false;
    for service in report.services {
        let id = service.id.to_string();
        // Only an enabled service targeting this node in its organisation.
        let Some(row) = sqlx::query(
            "SELECT health_state,health_node,health_reported_at,served_serial,listen_port FROM org_services WHERE id=$1 AND org_id=$2 AND target_node=$3 AND enabled=1",
        )
        .bind(&id)
        .bind(&org)
        .bind(&me)
        .fetch_optional(&mut *tx)
        .await?
        else {
            continue;
        };
        let before = Health {
            state: row.try_get(0)?,
            detail: String::new(),
            node: row.try_get(1)?,
            reported_at: row.try_get(2)?,
            served_serial: row.try_get(3)?,
        };
        let previous_port: Option<i64> = row.try_get(4)?;
        let serial = service
            .serial
            .filter(|serial| serial.len() <= 64 && serial.chars().all(|ch| ch.is_ascii_hexdigit()));
        // A failed target check is reported whether or not the listener is
        // up: the agent stops routing (and may stop listening) for it.
        let state = match (service.listening, service.healthy) {
            (_, false) => "unhealthy",
            (false, true) => "not_listening",
            (true, true) => "healthy",
        };
        let was_published = before.state == "healthy"
            && before.fresh_for(&me, at)
            && live_certificate(&mut tx, &org, &id, &me, before.served_serial.as_deref())
                .await?
                .is_some();
        let now_published = state == "healthy"
            && live_certificate(&mut tx, &org, &id, &me, serial.as_deref())
                .await?
                .is_some();
        sqlx::query(
            "UPDATE org_services SET health_state=$1,health_detail=$2,health_node=$3,health_reported_at=$4,listen_port=$5,served_serial=$6 WHERE id=$7 AND org_id=$8",
        )
        .bind(state)
        .bind(clean_detail(&service.detail))
        .bind(&me)
        .bind(at)
        .bind(i64::from(report.listen_port))
        .bind(serial.as_deref())
        .bind(&id)
        .bind(&org)
        .execute(&mut *tx)
        .await?;
        accepted += 1;
        changed |=
            was_published != now_published || previous_port != Some(i64::from(report.listen_port));
    }
    if changed {
        bump_control_revision(&mut tx, &org).await?;
    }
    tx.commit().await?;
    Ok(Json(HealthAccepted { accepted }))
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ServiceCa {
    pub(crate) namespace: String,
    pub(crate) cert_pem: String,
    pub(crate) fingerprint_sha256: String,
    pub(crate) not_after: i64,
}

/// The organisation's service CA, for `blaktaild trust-service-ca` on
/// client devices. Public material only.
async fn service_ca(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ServiceCa>, ApiError> {
    let (org_id, _) = node_org(&s, &headers, node_id).await?;
    let row = sqlx::query(
        "SELECT cert_pem,fingerprint_sha256,not_after FROM service_cas WHERE org_id=$1",
    )
    .bind(org_id.to_string())
    .fetch_optional(&s.store.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(ServiceCa {
        namespace: namespace(org_id),
        cert_pem: row.try_get(0)?,
        fingerprint_sha256: row.try_get(1)?,
        not_after: row.try_get(2)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_services::test_support::{call, create_org, register, router, Auth};
    use crate::Role;
    use axum::http::{Method, StatusCode};

    fn csr(fqdn: &str) -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        rcgen::CertificateParams::new(vec![fqdn.to_owned()])
            .unwrap()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap()
    }

    async fn peers(r: &Router, node: Uuid, token: &str) -> serde_json::Value {
        let (status, body) = call(
            r,
            Method::GET,
            &format!("/v1/nodes/{node}/peers?ipv6=true"),
            serde_json::Value::Null,
            Auth::Node(token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    fn peer(map: &serde_json::Value, id: Uuid) -> &serde_json::Value {
        map["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|peer| peer["id"] == id.to_string().as_str())
            .expect("peer in map")
    }

    fn ipv4(map: &serde_json::Value, id: Uuid) -> String {
        peer(map, id)["allowed_ips"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|route| route.as_str()?.strip_suffix("/32"))
            .next()
            .unwrap()
            .to_owned()
    }

    fn lists(value: &serde_json::Value, item: &str) -> bool {
        value
            .as_array()
            .is_some_and(|items| items.iter().any(|entry| entry == item))
    }

    async fn report(
        r: &Router,
        node: Uuid,
        token: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        call(
            r,
            Method::POST,
            &format!("/v1/nodes/{node}/services/health"),
            body,
            Auth::Node(token),
        )
        .await
    }

    async fn status(r: &Router, org: Uuid) -> serde_json::Value {
        call(
            r,
            Method::GET,
            &format!("/v1/orgs/{org}/services"),
            serde_json::Value::Null,
            Auth::Console(org, Role::Member),
        )
        .await
        .1["services"][0]
            .clone()
    }

    async fn revision(store: &crate::Store, org: Uuid) -> i64 {
        sqlx::query_scalar("SELECT control_revision FROM orgs WHERE id=$1")
            .bind(org.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap()
    }

    #[test]
    fn port_lists_cover_singletons_ranges_and_wildcards() {
        let specs = |items: &[&str]| items.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(port_listed(&specs(&["443"]), 443));
        assert!(port_listed(&specs(&["400-500"]), 443));
        assert!(port_listed(&specs(&["*"]), 443));
        assert!(!port_listed(&specs(&["22", "8443"]), 443));
    }

    /// Server is office+ranger; `ally` (office) holds the service's access
    /// tag; `outsider` (ranger) is a policy peer of the server without it.
    #[tokio::test]
    async fn access_ingress_and_dns_follow_health_and_certificates() {
        let (r, store) = router().await;
        let org = create_org(&r, "serving-org").await;
        let (server, server_token, _) = register(&r, org, "wiki-host", &["office", "ranger"]).await;
        let (ally, ally_token, _) = register(&r, org, "ally", &["office"]).await;
        let (outsider, outsider_token, _) = register(&r, org, "outsider", &["ranger"]).await;
        let (code, service) = call(
            &r,
            Method::POST,
            &format!("/v1/orgs/{org}/services"),
            serde_json::json!({"name": "wiki", "target_node_id": server, "port": 8080, "access_tags": ["office"]}),
            Auth::Console(org, Role::Owner),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "{service}");
        let id = service["id"].as_str().unwrap().to_owned();
        let fqdn = service["fqdn"].as_str().unwrap().to_owned();
        assert_eq!(status(&r, org).await["status"], "awaiting_certificate");

        // Compiled access: only the tag holder may reach port 443 on the server.
        let map = peers(&r, server, &server_token).await;
        let access = &map["service_access"][0];
        assert_eq!(access["id"], id.as_str());
        assert_eq!(access["fqdn"], fqdn.as_str());
        let ally_ip = ipv4(&map, ally);
        let outsider_ip = ipv4(&map, outsider);
        assert!(lists(&access["allowed_sources"], &ally_ip));
        assert!(!lists(&access["allowed_sources"], &outsider_ip));
        let opens = |ingress: &serde_json::Value, port: &str| {
            ingress["all"] == true || lists(&ingress["tcp"], port)
        };
        assert!(opens(&peer(&map, ally)["ingress"], "443"));
        assert!(!lists(&peer(&map, ally)["ingress"]["deny_tcp"], "443"));
        assert!(lists(&peer(&map, outsider)["ingress"]["deny_tcp"], "443"));
        // Clients never see another node's access list.
        assert!(peers(&r, ally, &ally_token).await["service_access"].is_null());

        // No certificate yet: a healthy report still publishes nothing.
        let healthy = |serial: &str| {
            serde_json::json!({"listen_port": 443, "services": [
                {"id": id, "listening": true, "healthy": true, "serial": serial}
            ]})
        };
        assert_eq!(
            report(&r, server, &server_token, healthy("00")).await.1["accepted"],
            1
        );
        assert!(peers(&r, ally, &ally_token).await["service_records"].is_null());
        assert_eq!(status(&r, org).await["status"], "awaiting_certificate");

        // The agent refuses a port outside its allow-list without a listener
        // or certificate; the console shows the device's reason.
        report(
            &r,
            server,
            &server_token,
            serde_json::json!({"listen_port": 443, "services": [
                {"id": id, "listening": false, "healthy": false, "detail": "port 8080 is not in this agent's --serve-services-ports list"}
            ]}),
        )
        .await;
        let view = status(&r, org).await;
        assert_eq!(view["status"], "target_unhealthy");
        assert!(view["status_detail"]
            .as_str()
            .unwrap()
            .contains("--serve-services-ports"));
        assert!(peers(&r, ally, &ally_token).await["service_records"].is_null());
        report(&r, server, &server_token, healthy("00")).await;
        assert_eq!(status(&r, org).await["status"], "awaiting_certificate");

        let (_, issued) = call(
            &r,
            Method::POST,
            &format!("/v1/nodes/{server}/services/{id}/certificate"),
            serde_json::json!({"csr_pem": csr(&fqdn)}),
            Auth::Node(&server_token),
        )
        .await;
        let serial = issued["serial"].as_str().unwrap().to_owned();
        assert_eq!(status(&r, org).await["status"], "certificate_issued");

        // The target is down: the agent drops the route, so it reports no
        // listener and no serial, only the failed check.
        let before = revision(&store, org).await;
        report(
            &r,
            server,
            &server_token,
            serde_json::json!({"listen_port": 443, "services": [
                {"id": id, "listening": false, "healthy": false, "detail": "connect 127.0.0.1:8080 refused\u{7}"}
            ]}),
        )
        .await;
        let view = status(&r, org).await;
        assert_eq!(view["status"], "target_unhealthy");
        assert_eq!(view["reachable"], false);
        assert!(!view["status_detail"].as_str().unwrap().contains('\u{7}'));
        assert!(peers(&r, ally, &ally_token).await["service_records"].is_null());

        // Healthy with the live certificate: published to the tag holder only.
        report(&r, server, &server_token, healthy(&serial)).await;
        assert!(
            revision(&store, org).await > before,
            "publication bumps revision"
        );
        let view = status(&r, org).await;
        assert_eq!(view["status"], "serving");
        assert_eq!(view["reachable"], true);
        let ally_map = peers(&r, ally, &ally_token).await;
        let records = &ally_map["service_records"];
        assert_eq!(records[0]["name"], fqdn.as_str());
        assert!(lists(&records[0]["addresses"], &ipv4(&ally_map, server)));
        assert!(peers(&r, outsider, &outsider_token).await["service_records"].is_null());
        assert!(peers(&r, server, &server_token).await["service_records"].is_null());

        // A report naming some other serial does not publish.
        report(&r, server, &server_token, healthy("abcdef")).await;
        assert_eq!(status(&r, org).await["status"], "certificate_issued");
        assert!(peers(&r, ally, &ally_token).await["service_records"].is_null());

        // A stale report withdraws the name.
        report(&r, server, &server_token, healthy(&serial)).await;
        sqlx::query("UPDATE org_services SET health_reported_at=$1")
            .bind(now() - HEALTH_FRESH_SECS - 1)
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(status(&r, org).await["status"], "certificate_issued");
        assert!(peers(&r, ally, &ally_token).await["service_records"].is_null());

        // A reported listener port moves the compiled port rule.
        report(
            &r,
            server,
            &server_token,
            serde_json::json!({"listen_port": 8443, "services": [
                {"id": id, "listening": true, "healthy": true, "serial": serial}
            ]}),
        )
        .await;
        let map = peers(&r, server, &server_token).await;
        assert!(lists(&peer(&map, outsider)["ingress"]["deny_tcp"], "8443"));
        assert!(opens(&peer(&map, ally)["ingress"], "8443"));

        // Disabling withdraws the record, the access list and the listing.
        let (code, _) = call(
            &r,
            Method::PATCH,
            &format!("/v1/orgs/{org}/services/{id}"),
            serde_json::json!({"revision": 1, "enabled": false}),
            Auth::Console(org, Role::Owner),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert!(peers(&r, ally, &ally_token).await["service_records"].is_null());
        assert!(peers(&r, server, &server_token).await["service_access"].is_null());
        let (_, listed) = call(
            &r,
            Method::GET,
            &format!("/v1/nodes/{server}/services"),
            serde_json::Value::Null,
            Auth::Node(&server_token),
        )
        .await;
        assert_eq!(listed["services"], serde_json::json!([]));
        assert_eq!(
            report(&r, server, &server_token, healthy(&serial)).await.1["accepted"],
            0,
            "a disabled service takes no health"
        );
    }

    #[tokio::test]
    async fn health_reports_are_bound_to_target_node_and_org() {
        let (r, _store) = router().await;
        let org_a = create_org(&r, "org-a").await;
        let org_b = create_org(&r, "org-b").await;
        let (server, server_token, _) = register(&r, org_a, "wiki-host", &["office"]).await;
        let (other, other_token, _) = register(&r, org_a, "laptop", &["office"]).await;
        let (foreign, foreign_token, _) = register(&r, org_b, "wiki-host", &["office"]).await;
        let (_, service) = call(
            &r,
            Method::POST,
            &format!("/v1/orgs/{org_a}/services"),
            serde_json::json!({"name": "wiki", "target_node_id": server, "port": 8080, "access_tags": ["office"]}),
            Auth::Console(org_a, Role::Owner),
        )
        .await;
        let body = serde_json::json!({"listen_port": 443, "services": [
            {"id": service["id"], "listening": true, "healthy": true}
        ]});
        assert_eq!(
            report(&r, other, &other_token, body.clone()).await.1["accepted"],
            0
        );
        assert_eq!(
            report(&r, foreign, &foreign_token, body.clone()).await.1["accepted"],
            0
        );
        assert_eq!(
            report(&r, server, "wrong-token", body.clone()).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            report(
                &r,
                server,
                &server_token,
                serde_json::json!({"listen_port": 0, "services": []})
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            report(&r, server, &server_token, body).await.1["accepted"],
            1
        );

        // Each organisation's CA is served only to its own nodes.
        let (code, ca_a) = call(
            &r,
            Method::GET,
            &format!("/v1/nodes/{other}/service-ca"),
            serde_json::Value::Null,
            Auth::Node(&other_token),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert!(ca_a["cert_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE"));
        assert_eq!(ca_a["namespace"], namespace(org_a).as_str());
        let (code, _) = call(
            &r,
            Method::GET,
            &format!("/v1/nodes/{foreign}/service-ca"),
            serde_json::Value::Null,
            Auth::Node(&foreign_token),
        )
        .await;
        assert_eq!(code, StatusCode::NOT_FOUND, "org B has no services or CA");

        // A suspended target can no longer report.
        let (code, _) = call(
            &r,
            Method::POST,
            &format!("/v1/orgs/{org_a}/nodes/{server}/suspend"),
            serde_json::json!({"reason": "lost"}),
            Auth::Console(org_a, Role::Owner),
        )
        .await;
        assert_eq!(code, StatusCode::NO_CONTENT);
        assert_eq!(
            report(
                &r,
                server,
                &server_token,
                serde_json::json!({"listen_port": 443, "services": []})
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }
}
