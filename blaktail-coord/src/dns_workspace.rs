//! DNS workspace: revision history, draft validation and split-match preview
//! on top of the organisation DNS document in `org_dns`.

use crate::{console_session, now, org_dns, ApiError, AppState, Store};
use axum::{
    extract::{Path as UrlPath, Query, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::net::IpAddr;
use uuid::Uuid;

const KEEP_REVISIONS: i64 = 50;
const LIST_REVISIONS: i64 = 20;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/orgs/:org_id/dns/revisions", get(list_revisions))
        .route(
            "/v1/orgs/:org_id/dns/revisions/:revision",
            get(get_revision),
        )
        .route("/v1/orgs/:org_id/dns/validate", post(validate))
        .route("/v1/orgs/:org_id/dns/preview", get(preview))
}

pub(crate) async fn record_revision(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: Uuid,
    revision: i64,
    dns_json: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO org_dns_revisions(org_id,revision,dns_json,created_at) VALUES($1,$2,$3,$4)",
    )
    .bind(org_id.to_string())
    .bind(revision)
    .bind(dns_json)
    .bind(now())
    .execute(&mut **tx)
    .await?;
    sqlx::query("DELETE FROM org_dns_revisions WHERE org_id=$1 AND revision<=$2")
        .bind(org_id.to_string())
        .bind(revision - KEEP_REVISIONS)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(crate) async fn load_revision_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: Uuid,
    revision: i64,
) -> Result<org_dns::OrgDnsSettings, ApiError> {
    let json: String = sqlx::query_scalar(
        "SELECT dns_json FROM org_dns_revisions WHERE org_id=$1 AND revision=$2",
    )
    .bind(org_id.to_string())
    .bind(revision)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| {
        ApiError::BadRequest(format!(
            "DNS revision {revision} is not in the kept history"
        ))
    })?;
    org_dns::parse_settings(&json)
}

#[derive(Serialize)]
struct RevisionSummary {
    revision: i64,
    created_at: i64,
    current: bool,
    summary: DocumentSummary,
}

#[derive(Serialize)]
struct DocumentSummary {
    split: usize,
    records: usize,
    nameserver_groups: usize,
    zones: usize,
    zone_records: usize,
}

fn summarise(settings: &org_dns::OrgDnsSettings) -> DocumentSummary {
    DocumentSummary {
        split: settings.split.len(),
        records: settings.records.len(),
        nameserver_groups: settings.nameserver_groups.len(),
        zones: settings.zones.len(),
        zone_records: settings.zones.iter().map(|zone| zone.records.len()).sum(),
    }
}

#[derive(Serialize)]
struct RevisionList {
    revisions: Vec<RevisionSummary>,
}

async fn list_revisions(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<RevisionList>, ApiError> {
    console_session(&s, &headers, org_id).await?;
    let current: i64 = sqlx::query_scalar("SELECT dns_revision FROM orgs WHERE id=$1")
        .bind(org_id.to_string())
        .fetch_optional(&s.store.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    let rows = sqlx::query(
        "SELECT revision,created_at,dns_json FROM org_dns_revisions WHERE org_id=$1 ORDER BY revision DESC LIMIT $2",
    )
    .bind(org_id.to_string())
    .bind(LIST_REVISIONS)
    .fetch_all(&s.store.pool)
    .await?;
    let revisions = rows
        .into_iter()
        .map(|row| {
            let revision: i64 = row.try_get(0)?;
            let json: String = row.try_get(2)?;
            let settings = org_dns::parse_settings(&json).map_err(|_| ApiError::CorruptData)?;
            Ok(RevisionSummary {
                revision,
                created_at: row.try_get(1)?,
                current: revision == current,
                summary: summarise(&settings),
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(RevisionList { revisions }))
}

#[derive(Serialize)]
struct RevisionDocument {
    revision: i64,
    created_at: i64,
    dns: org_dns::OrgDnsSettings,
}

async fn get_revision(
    State(s): State<AppState>,
    UrlPath((org_id, revision)): UrlPath<(Uuid, i64)>,
    headers: HeaderMap,
) -> Result<Json<RevisionDocument>, ApiError> {
    console_session(&s, &headers, org_id).await?;
    let row = sqlx::query(
        "SELECT created_at,dns_json FROM org_dns_revisions WHERE org_id=$1 AND revision=$2",
    )
    .bind(org_id.to_string())
    .bind(revision)
    .fetch_optional(&s.store.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let json: String = row.try_get(1)?;
    Ok(Json(RevisionDocument {
        revision,
        created_at: row.try_get(0)?,
        dns: org_dns::parse_settings(&json).map_err(|_| ApiError::CorruptData)?,
    }))
}

#[derive(Deserialize)]
struct ValidateRequest {
    dns: serde_json::Value,
}

#[derive(Serialize)]
struct ValidateResponse {
    dns: org_dns::OrgDnsSettings,
    warnings: Vec<String>,
}

/// Read-only: canonicalises a draft without publishing it.
async fn validate(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<ValidateRequest>,
) -> Result<Json<ValidateResponse>, ApiError> {
    console_session(&s, &headers, org_id).await?;
    let dns = org_dns::parse_settings(&input.dns.to_string())?;
    let mut warnings = dns.warnings();
    warnings.extend(route_warnings(&s.store, org_id, &dns).await?);
    Ok(Json(ValidateResponse { dns, warnings }))
}

/// Private resolver and record addresses that no device address or approved
/// subnet route covers are reachable only from a device's own LAN.
pub(crate) async fn route_warnings(
    store: &Store,
    org_id: Uuid,
    dns: &org_dns::OrgDnsSettings,
) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query(
        "SELECT allowed_ips_json,approved_routes_json FROM nodes WHERE org_id=$1 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(org_id.to_string())
    .fetch_all(&store.pool)
    .await?;
    let mut prefixes = Vec::new();
    for row in rows {
        for column in [0, 1] {
            let json: String = row.try_get(column)?;
            let values: Vec<String> = serde_json::from_str(&json).unwrap_or_default();
            prefixes.extend(values.iter().filter_map(|value| parse_prefix(value)));
        }
    }
    let covered = |address: IpAddr| {
        prefixes
            .iter()
            .any(|(network, length)| prefix_contains(*network, *length, address))
    };
    let mut warnings = Vec::new();
    let resolvers = dns
        .split
        .iter()
        .flat_map(|route| route.resolvers.iter())
        .chain(
            dns.nameserver_groups
                .iter()
                .flat_map(|group| group.resolvers.iter()),
        )
        .collect::<std::collections::BTreeSet<_>>();
    for resolver in resolvers {
        if let Ok(address) = resolver.parse::<IpAddr>() {
            if is_private(address) && !covered(address) {
                warnings.push(format!(
                    "resolver {resolver} is not inside any device address or approved subnet route; only devices on its LAN can reach it"
                ));
            }
        }
    }
    let records = dns
        .records
        .iter()
        .map(|record| (&record.name, &record.value))
        .chain(
            dns.zones
                .iter()
                .filter(|zone| zone.enabled)
                .flat_map(|zone| {
                    zone.records
                        .iter()
                        .filter(|record| {
                            matches!(
                                record.record_type,
                                org_dns::ZoneRecordType::A | org_dns::ZoneRecordType::Aaaa
                            )
                        })
                        .map(|record| (&record.name, &record.value))
                }),
        );
    for (name, value) in records {
        if let Ok(address) = value.parse::<IpAddr>() {
            if is_private(address) && !covered(address) {
                warnings.push(format!(
                    "{name} points at {value}, which no approved subnet route covers; only devices on that LAN can reach it"
                ));
            }
        }
    }
    Ok(warnings)
}

fn is_private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => ip.is_private(),
        IpAddr::V6(ip) => (ip.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn parse_prefix(value: &str) -> Option<(IpAddr, u8)> {
    let (address, length) = value.split_once('/')?;
    Some((address.parse().ok()?, length.parse().ok()?))
}

fn prefix_contains(network: IpAddr, length: u8, address: IpAddr) -> bool {
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) if length <= 32 => {
            let mask = u32::MAX.checked_shl(32 - u32::from(length)).unwrap_or(0);
            u32::from(network) & mask == u32::from(address) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(address)) if length <= 128 => {
            let mask = u128::MAX.checked_shl(128 - u32::from(length)).unwrap_or(0);
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

#[derive(Deserialize)]
struct PreviewQuery {
    name: String,
    #[serde(default)]
    node_id: Option<Uuid>,
    #[serde(default)]
    tags: Option<String>,
}

#[derive(Serialize)]
struct PreviewResponse {
    node_id: Option<Uuid>,
    node_name: Option<String>,
    tags: Vec<String>,
    #[serde(flatten)]
    explanation: org_dns::DnsExplanation,
}

async fn preview(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    Query(query): Query<PreviewQuery>,
    headers: HeaderMap,
) -> Result<Json<PreviewResponse>, ApiError> {
    console_session(&s, &headers, org_id).await?;
    let dns_json: String = sqlx::query_scalar("SELECT dns_json FROM orgs WHERE id=$1")
        .bind(org_id.to_string())
        .fetch_optional(&s.store.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    let dns = org_dns::parse_settings(&dns_json).unwrap_or_else(|_| org_dns::default_settings());
    let (node_name, tags) = match query.node_id {
        Some(node_id) => {
            let row = sqlx::query(
                "SELECT COALESCE(NULLIF(TRIM(display_name),''),name),tags_json FROM nodes WHERE id=$1 AND org_id=$2 AND deleted_at IS NULL",
            )
            .bind(node_id.to_string())
            .bind(org_id.to_string())
            .fetch_optional(&s.store.pool)
            .await?
            .ok_or(ApiError::NotFound)?;
            let tags_json: String = row.try_get(1)?;
            (
                Some(row.try_get::<String, _>(0)?),
                serde_json::from_str::<Vec<String>>(&tags_json).unwrap_or_default(),
            )
        }
        None => {
            let mut tags = query
                .tags
                .unwrap_or_default()
                .split(',')
                .map(|tag| tag.trim().to_ascii_lowercase())
                .filter(|tag| !tag.is_empty())
                .collect::<Vec<_>>();
            if let Some(tag) = tags
                .iter()
                .find(|tag| !org_dns::DEVICE_TAGS.contains(&tag.as_str()))
            {
                return Err(ApiError::BadRequest(format!("unknown device tag {tag:?}")));
            }
            tags.sort();
            tags.dedup();
            (None, tags)
        }
    };
    let mut explanation = dns.explain(&query.name, &tags)?;
    if explanation.answer == "magic_dns" {
        magic_dns_records(&s.store, org_id, &mut explanation).await?;
    }
    Ok(Json(PreviewResponse {
        node_id: query.node_id,
        node_name,
        tags,
        explanation,
    }))
}

async fn magic_dns_records(
    store: &Store,
    org_id: Uuid,
    explanation: &mut org_dns::DnsExplanation,
) -> Result<(), ApiError> {
    let suffix = org_dns::organisation_magic_dns_suffix(&org_id.to_string());
    let name = if explanation.name.contains('.') {
        explanation.name.clone()
    } else {
        format!("{}.{suffix}", explanation.name)
    };
    let allowed: Option<String> = sqlx::query_scalar(
        "SELECT allowed_ips_json FROM nodes WHERE org_id=$1 AND dns_name=$2 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(org_id.to_string())
    .bind(&name)
    .fetch_optional(&store.pool)
    .await?;
    let Some(allowed) = allowed else {
        explanation.detail = format!(
            "{name} is in the protected MagicDNS namespace and no active device has that name, so devices answer NXDOMAIN and never forward it."
        );
        return Ok(());
    };
    let addresses: Vec<String> = serde_json::from_str(&allowed).unwrap_or_default();
    explanation.records = addresses
        .iter()
        .filter_map(|value| parse_prefix(value))
        .filter(|(address, length)| *length == if address.is_ipv4() { 32 } else { 128 })
        .map(|(address, _)| org_dns::ZoneRecord {
            name: name.clone(),
            record_type: if address.is_ipv4() {
                org_dns::ZoneRecordType::A
            } else {
                org_dns::ZoneRecordType::Aaaa
            },
            value: address.to_string(),
            ttl: 30,
        })
        .collect();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_containment() {
        let network: IpAddr = "10.2.0.0".parse().unwrap();
        assert!(prefix_contains(network, 16, "10.2.9.1".parse().unwrap()));
        assert!(!prefix_contains(network, 16, "10.3.0.1".parse().unwrap()));
        assert!(prefix_contains(network, 0, "8.8.8.8".parse().unwrap()));
        let v6: IpAddr = "fd00::".parse().unwrap();
        assert!(prefix_contains(v6, 8, "fd12::1".parse().unwrap()));
        assert!(!prefix_contains(v6, 8, "10.0.0.1".parse().unwrap()));
    }

    use crate::private_services::test_support::{call, create_org, register, router, Auth};
    use crate::Role;
    use axum::http::{Method, StatusCode};

    fn document(wiki: &str) -> serde_json::Value {
        serde_json::json!({
            "nameserver_groups": [{
                "name": "Office AD", "resolvers": ["10.0.0.53"],
                "match_domains": ["corp.example"], "tags": ["office"]
            }],
            "zones": [{"name": "apps.example", "records": [
                {"name": "wiki", "type": "A", "value": wiki},
                {"name": "docs", "type": "CNAME", "value": "wiki.apps.example"}
            ]}]
        })
    }

    /// Publishes without If-Match, which the console route permits.
    async fn publish(
        r: &axum::Router,
        org: Uuid,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        call(
            r,
            Method::PUT,
            &format!("/v1/orgs/{org}/dns"),
            body,
            Auth::Console(org, Role::Admin),
        )
        .await
    }

    #[tokio::test]
    async fn zones_and_groups_reach_the_right_devices_in_each_org() {
        let (r, _) = router().await;
        let org_a = create_org(&r, "org-a").await;
        let org_b = create_org(&r, "org-b").await;
        let (office_a, office_token, _) = register(&r, org_a, "office-pc", &["office"]).await;
        let (_, ranger_token, _) = register(&r, org_a, "ranger-tab", &["ranger"]).await;
        let (_, office_b_token, _) = register(&r, org_b, "office-pc", &["office"]).await;

        let (status, _) =
            publish(&r, org_a, serde_json::json!({"dns": document("10.1.0.10")})).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = publish(&r, org_b, serde_json::json!({"dns": {"zones": [{"name": "apps.example", "records": [{"name": "wiki", "type": "A", "value": "10.2.0.10"}]}]}})).await;
        assert_eq!(status, StatusCode::OK);

        let poll = |node: Uuid, token: String| {
            let r = r.clone();
            async move {
                let (status, body) = call(
                    &r,
                    Method::GET,
                    &format!("/v1/nodes/{node}/peers"),
                    serde_json::Value::Null,
                    Auth::Node(&token),
                )
                .await;
                assert_eq!(status, StatusCode::OK, "{body}");
                body["dns"].clone()
            }
        };
        let (status, peers) = call(
            &r,
            Method::GET,
            &format!("/v1/orgs/{org_a}/nodes"),
            serde_json::Value::Null,
            Auth::Console(org_a, Role::Owner),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let id_of = |name: &str| -> Uuid {
            peers
                .as_array()
                .unwrap()
                .iter()
                .find(|node| node["name"] == name)
                .unwrap()["id"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap()
        };
        let office = poll(office_a, office_token).await;
        let ranger = poll(id_of("ranger-tab"), ranger_token).await;
        let (_, nodes_b) = call(
            &r,
            Method::GET,
            &format!("/v1/orgs/{org_b}/nodes"),
            serde_json::Value::Null,
            Auth::Console(org_b, Role::Owner),
        )
        .await;
        let office_b = poll(
            nodes_b[0]["id"].as_str().unwrap().parse().unwrap(),
            office_b_token,
        )
        .await;
        let has_split = |dns: &serde_json::Value, suffix: &str| {
            dns["split"]
                .as_array()
                .unwrap()
                .iter()
                .any(|route| route["suffix"] == suffix)
        };
        assert!(has_split(&office, "corp.example"));
        assert!(!has_split(&ranger, "corp.example"));
        assert!(has_split(&ranger, "apps.example"));
        assert_eq!(office["zones"][0]["records"][0]["value"], "10.1.0.10");
        assert_eq!(office_b["zones"][0]["records"][0]["value"], "10.2.0.10");
        assert!(!has_split(&office_b, "corp.example"));

        let preview = |org: Uuid, query: String| {
            let r = r.clone();
            async move {
                call(
                    &r,
                    Method::GET,
                    &format!("/v1/orgs/{org}/dns/preview?{query}"),
                    serde_json::Value::Null,
                    Auth::Console(org, Role::Member),
                )
                .await
            }
        };
        let (_, answer) = preview(org_a, format!("name=db.corp.example&node_id={office_a}")).await;
        assert_eq!(answer["answer"], "forward");
        assert_eq!(answer["nameserver_group"], "Office AD");
        assert_eq!(answer["node_name"], "office-pc");
        let (_, answer) = preview(org_a, "name=db.corp.example&tags=ranger".into()).await;
        assert_eq!(answer["answer"], "not_handled");
        let (_, answer) = preview(org_a, "name=wiki.apps.example".into()).await;
        assert_eq!(answer["records"][0]["value"], "10.1.0.10");
        let (_, answer) = preview(org_b, "name=wiki.apps.example".into()).await;
        assert_eq!(answer["records"][0]["value"], "10.2.0.10");
        let (_, answer) = preview(org_a, "name=nope.apps.example".into()).await;
        assert_eq!(answer["answer"], "zone_nxdomain");
        let (_, answer) = preview(org_a, "name=office-pc".into()).await;
        assert_eq!(answer["answer"], "magic_dns");
        assert_eq!(answer["records"][0]["type"], "A");
        // Org B cannot preview org A's devices.
        let (status, _) = preview(org_b, format!("name=x.corp.example&node_id={office_a}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = preview(org_a, "name=x.example&tags=visitors".into()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn members_read_only_etag_conflicts_and_rollback_to_revision() {
        let (r, store) = router().await;
        let org = create_org(&r, "dns-org").await;
        let path = format!("/v1/orgs/{org}/dns");
        let (status, _) = call(
            &r,
            Method::PUT,
            &path,
            serde_json::json!({"dns": document("10.1.0.10")}),
            Auth::Console(org, Role::Member),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, checked) = call(
            &r,
            Method::POST,
            &format!("{path}/validate"),
            serde_json::json!({"dns": document("127.0.0.1")}),
            Auth::Console(org, Role::Member),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "validation is read-only");
        assert!(checked["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning.as_str().unwrap().contains("loopback")));
        assert_eq!(
            checked["dns"]["zones"][0]["records"][0]["name"],
            "wiki.apps.example"
        );
        let (status, error) = call(
            &r,
            Method::POST,
            &format!("{path}/validate"),
            serde_json::json!({"dns": {"zones": [{"name": "zone.blaktail"}]}}),
            Auth::Console(org, Role::Member),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(error["error"].as_str().unwrap().contains("MagicDNS"));

        for wiki in ["10.1.0.10", "10.1.0.11"] {
            let (status, published) =
                publish(&r, org, serde_json::json!({"dns": document(wiki)})).await;
            assert_eq!(status, StatusCode::OK, "{published}");
        }
        let (_, current) = call(
            &r,
            Method::GET,
            &path,
            serde_json::Value::Null,
            Auth::Console(org, Role::Member),
        )
        .await;
        assert_eq!(current["revision"], 2);
        assert!(current["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning
                .as_str()
                .unwrap()
                .contains("no approved subnet route")));

        // A stale etag from revision 1 is refused.
        let stale = crate::hash(&format!(
            "1:{}",
            serde_json::to_string(
                &org_dns::parse_settings(&document("10.1.0.10").to_string()).unwrap()
            )
            .unwrap()
        ));
        let request = axum::http::Request::builder()
            .method(Method::PUT)
            .uri(&path)
            .header("content-type", "application/json")
            .header("if-match", stale)
            .header(
                axum::http::header::AUTHORIZATION,
                format!(
                    "Bearer {}",
                    crate::private_services::test_support::console_token(org, Role::Owner)
                ),
            )
            .body(axum::body::Body::from(
                serde_json::json!({"dns": document("10.1.0.99")}).to_string(),
            ))
            .unwrap();
        let response = tower::ServiceExt::oneshot(r.clone(), request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);

        let (_, revisions) = call(
            &r,
            Method::GET,
            &format!("{path}/revisions"),
            serde_json::Value::Null,
            Auth::Console(org, Role::Member),
        )
        .await;
        let list = revisions["revisions"].as_array().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0]["revision"], 2);
        assert_eq!(list[0]["current"], true);
        assert_eq!(list[0]["summary"]["zone_records"], 2);

        let (status, _) = call(
            &r,
            Method::PUT,
            &path,
            serde_json::json!({"rollback_to": 1}),
            Auth::Console(org, Role::Member),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, rolled) = call(
            &r,
            Method::PUT,
            &path,
            serde_json::json!({"rollback_to": 1}),
            Auth::Console(org, Role::Owner),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(rolled["revision"], 3);
        assert_eq!(
            rolled["dns"]["zones"][0]["records"][0]["value"],
            "10.1.0.10"
        );
        let (_, old) = call(
            &r,
            Method::GET,
            &format!("{path}/revisions/2"),
            serde_json::Value::Null,
            Auth::Console(org, Role::Member),
        )
        .await;
        assert_eq!(old["dns"]["zones"][0]["records"][0]["value"], "10.1.0.11");
        let (status, _) = call(
            &r,
            Method::PUT,
            &path,
            serde_json::json!({"rollback_to": 40}),
            Auth::Console(org, Role::Owner),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let rollbacks: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE org_id=$1 AND action='dns.rolled_back'",
        )
        .bind(org.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(rollbacks, 1);
    }

    #[tokio::test]
    async fn pre_upgrade_dns_json_keeps_working() {
        let (r, store) = router().await;
        let org = create_org(&r, "legacy-org").await;
        let legacy = r#"{"managed":true,"global_resolvers":["1.1.1.1"],"split":[{"suffix":"internal.example","resolvers":["10.0.0.53"]}],"search_domains":["internal.example"],"records":[{"name":"wiki.internal.example","type":"A","value":"10.0.0.10"}]}"#;
        sqlx::query("UPDATE orgs SET dns_json=$1,dns_revision=7 WHERE id=$2")
            .bind(legacy)
            .bind(org.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        let (node, token, _) = register(&r, org, "old-agent", &["office"]).await;
        let (status, peers) = call(
            &r,
            Method::GET,
            &format!("/v1/nodes/{node}/peers"),
            serde_json::Value::Null,
            Auth::Node(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let dns = peers["dns"].as_object().unwrap();
        assert!(!dns.contains_key("zones"));
        assert_eq!(peers["dns"]["revision"], 7);
        assert_eq!(peers["dns"]["split"][0]["resolvers"][0], "10.0.0.53");
        assert_eq!(peers["dns"]["records"][0]["name"], "wiki.internal.example");
        let (_, current) = call(
            &r,
            Method::GET,
            &format!("/v1/orgs/{org}/dns"),
            serde_json::Value::Null,
            Auth::Console(org, Role::Owner),
        )
        .await;
        assert_eq!(
            current["etag"],
            crate::hash(&format!("7:{legacy}")).as_str()
        );
        assert!(current["dns"].get("zones").is_none());
        // Republishing the same document stores byte-identical JSON.
        let (status, _) = publish(&r, org, serde_json::json!({"dns": current["dns"]})).await;
        assert_eq!(status, StatusCode::OK);
        let stored: String = sqlx::query_scalar("SELECT dns_json FROM orgs WHERE id=$1")
            .bind(org.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(stored, legacy);
    }
}
