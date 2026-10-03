//! Private service lifecycle (draft 10): console CRUD, an organisation CA that
//! is name-constrained to the organisation's service namespace, and
//! short-lived certificate issuance from a CSR whose key stays on the serving
//! node. Serving-agent health, access compilation and DNS publication live in
//! `service_serving`; a service is `serving` only on a fresh healthy report.

use crate::{
    append_audit, audit_log, bearer, bump_control_revision, console_session, https_services,
    notifications, now, org_dns,
    permissions::{require, Permission},
    service_serving, ApiError, AppState,
};
use axum::{
    extract::{Path as UrlPath, State},
    http::{HeaderMap, StatusCode},
    routing::{get, patch, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints, SanType, SerialNumber,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use time::{Duration as TimeDuration, OffsetDateTime};
use uuid::Uuid;

const MAX_SERVICES: i64 = 64;
const MAX_DESCRIPTION: usize = 200;
const CA_LIFETIME_DAYS: i64 = 730;
pub(crate) const LEAF_LIFETIME_SECS: i64 = 24 * 60 * 60;
const SEALED_PREFIX: &str = "btca1.";
const RESERVED_NAMES: &[&str] = &["svc"];
const PROTOCOLS: &[&str] = &["http", "https"];

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/orgs/:org_id/services",
            get(list_services).post(create_service),
        )
        .route("/v1/orgs/:org_id/services/preview", post(preview_service))
        .route(
            "/v1/orgs/:org_id/services/:service_id",
            patch(update_service).delete(delete_service),
        )
        .route("/v1/nodes/:node_id/services", get(node_services))
        .route(
            "/v1/nodes/:node_id/services/:service_id/certificate",
            post(issue_certificate),
        )
}

/// Service names live under `svc.<org prefix>.blaktail`, a subtree no device
/// name can occupy (device names are a single label under the org suffix).
pub(crate) fn namespace(org_id: Uuid) -> String {
    format!(
        "svc.{}",
        org_dns::organisation_magic_dns_suffix(&org_id.to_string())
    )
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceInput {
    name: String,
    target_node_id: Uuid,
    port: u16,
    #[serde(default = "default_protocol")]
    protocol: String,
    #[serde(default)]
    access_tags: Vec<String>,
    #[serde(default)]
    description: String,
}

fn default_protocol() -> String {
    "http".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServicePatch {
    revision: i64,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    access_tags: Option<Vec<String>>,
    #[serde(default)]
    target_node_id: Option<Uuid>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CertificateSummary {
    serial: String,
    fingerprint_sha256: String,
    not_before: i64,
    not_after: i64,
    issued_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ServiceView {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) fqdn: String,
    description: String,
    target_node_id: String,
    target_node_name: Option<String>,
    target_node_available: bool,
    port: u16,
    protocol: String,
    access_tags: Vec<String>,
    enabled: bool,
    pub(crate) revision: i64,
    pub(crate) status: String,
    status_detail: String,
    reachable: bool,
    pub(crate) certificate: Option<CertificateSummary>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CaView {
    pub(crate) cert_pem: String,
    fingerprint_sha256: String,
    not_after: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ServiceList {
    namespace: String,
    pub(crate) ca: Option<CaView>,
    pub(crate) services: Vec<ServiceView>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PreviewResponse {
    pub(crate) fqdn: Option<String>,
    pub(crate) valid: bool,
    pub(crate) problems: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Default)]
struct Findings {
    problems: Vec<String>,
    collision: bool,
    warnings: Vec<String>,
}

fn canonical_tags(tags: &[String]) -> Result<Vec<String>, String> {
    let mut canonical = tags
        .iter()
        .map(|tag| {
            let tag = tag.trim().to_ascii_lowercase();
            if org_dns::DEVICE_TAGS.contains(&tag.as_str()) {
                Ok(tag)
            } else {
                Err(format!(
                    "unknown device tag {tag:?}; use one of {}",
                    org_dns::DEVICE_TAGS.join(", ")
                ))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    canonical.sort();
    canonical.dedup();
    Ok(canonical)
}

/// Checks everything except name uniqueness among services, which the
/// caller handles (it differs between create and update).
async fn check_fields(
    connection: &mut sqlx::AnyConnection,
    org_id: Uuid,
    input: &ServiceInput,
    findings: &mut Findings,
) -> Result<Vec<String>, ApiError> {
    let (target_node_id, port, protocol, access_tags, description) = (
        input.target_node_id,
        input.port,
        input.protocol.trim(),
        &input.access_tags,
        input.description.trim(),
    );
    if port == 0 {
        findings.problems.push("local port must be 1-65535".into());
    }
    if !PROTOCOLS.contains(&protocol) {
        findings
            .problems
            .push("protocol must be http or https (the local upstream scheme)".into());
    }
    let tags = match canonical_tags(access_tags) {
        Ok(tags) if tags.is_empty() => {
            findings
                .problems
                .push("choose at least one device tag that may reach this service".into());
            tags
        }
        Ok(tags) => tags,
        Err(problem) => {
            findings.problems.push(problem);
            Vec::new()
        }
    };
    if description.chars().count() > MAX_DESCRIPTION || description.chars().any(char::is_control) {
        findings.problems.push(format!(
            "description must be at most {MAX_DESCRIPTION} printable characters"
        ));
    }
    let node = sqlx::query(
        "SELECT credential_expires_at,revoked_at FROM nodes WHERE id=$1 AND org_id=$2 AND deleted_at IS NULL",
    )
    .bind(target_node_id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&mut *connection)
    .await?;
    match node {
        None => findings
            .problems
            .push("target device is not in this organisation".into()),
        Some(row) => {
            let expires: i64 = row.try_get(0)?;
            let revoked: Option<i64> = row.try_get(1)?;
            if revoked.is_some() {
                findings
                    .problems
                    .push("target device has been revoked".into());
            } else if expires <= now() {
                findings.warnings.push(
                    "target device credential has expired; it must reauthenticate before it can request a certificate".into(),
                );
            }
        }
    }
    Ok(tags)
}

async fn check_name(
    connection: &mut sqlx::AnyConnection,
    org_id: Uuid,
    name: &str,
    findings: &mut Findings,
) -> Result<(), ApiError> {
    let labels: Vec<String> =
        sqlx::query_scalar("SELECT dns_name FROM nodes WHERE org_id=$1 AND deleted_at IS NULL")
            .bind(org_id.to_string())
            .fetch_all(&mut *connection)
            .await?
            .into_iter()
            .filter_map(|dns_name: String| dns_name.split('.').next().map(str::to_owned))
            .chain(RESERVED_NAMES.iter().map(|name| (*name).to_owned()))
            .collect();
    match https_services::validate_service_name(name, &labels) {
        Ok(()) => {}
        Err(https_services::ServiceError::NameCollision(_)) => {
            findings.collision = true;
            findings.problems.push(format!(
                "{name} is reserved or matches a device name in this organisation"
            ));
        }
        Err(error) => findings.problems.push(error.to_string()),
    }
    let taken: Option<String> =
        sqlx::query_scalar("SELECT id FROM org_services WHERE org_id=$1 AND service_name=$2")
            .bind(org_id.to_string())
            .bind(name)
            .fetch_optional(&mut *connection)
            .await?;
    if taken.is_some() {
        findings.collision = true;
        findings
            .problems
            .push(format!("a service named {name} already exists"));
    }
    Ok(())
}

const NOT_SERVED_WARNING: &str = "The target device must run `blaktaild up --serve-services` (Linux or macOS) to generate its key, request a certificate and serve this name; until it reports healthy, the name is not published.";

async fn preview_service(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<ServiceInput>,
) -> Result<Json<PreviewResponse>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageServices)?;
    let mut connection = s.store.pool.acquire().await?;
    let mut findings = Findings::default();
    let name = input.name.trim().to_owned();
    check_name(&mut connection, org_id, &name, &mut findings).await?;
    check_fields(&mut connection, org_id, &input, &mut findings).await?;
    findings.warnings.push(NOT_SERVED_WARNING.into());
    let valid = findings.problems.is_empty();
    Ok(Json(PreviewResponse {
        fqdn: https_services::validate_service_name(&name, &[])
            .is_ok()
            .then(|| format!("{name}.{}", namespace(org_id))),
        valid,
        problems: findings.problems,
        warnings: findings.warnings,
    }))
}

async fn create_service(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<ServiceInput>,
) -> Result<(StatusCode, Json<ServiceView>), ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageServices)?;
    let mut tx = s.store.pool.begin().await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM org_services WHERE org_id=$1")
        .bind(org_id.to_string())
        .fetch_one(&mut *tx)
        .await?;
    if count >= MAX_SERVICES {
        return Err(ApiError::BadRequest(format!(
            "organisations are limited to {MAX_SERVICES} services"
        )));
    }
    let name = input.name.trim().to_owned();
    let protocol = input.protocol.trim().to_owned();
    let description = input.description.trim().to_owned();
    let mut findings = Findings::default();
    check_name(&mut tx, org_id, &name, &mut findings).await?;
    let tags = check_fields(&mut tx, org_id, &input, &mut findings).await?;
    if !findings.problems.is_empty() {
        let message = findings.problems.join("; ");
        return Err(if findings.collision {
            ApiError::Conflict(message)
        } else {
            ApiError::BadRequest(message)
        });
    }
    ensure_ca(&mut tx, &s.auth_hmac_secret, org_id).await?;
    let id = Uuid::new_v4();
    let created_at = now();
    sqlx::query(
        "INSERT INTO org_services(id,org_id,service_name,target_node,port,revision,created_at,updated_at,enabled,protocol,access_tags_json,description) VALUES($1,$2,$3,$4,$5,1,$6,$6,1,$7,$8,$9)",
    )
    .bind(id.to_string())
    .bind(org_id.to_string())
    .bind(&name)
    .bind(input.target_node_id.to_string())
    .bind(i64::from(input.port))
    .bind(created_at)
    .bind(&protocol)
    .bind(serde_json::to_string(&tags).map_err(|_| ApiError::CorruptData)?)
    .bind(&description)
    .execute(&mut *tx)
    .await
    .map_err(crate::conflict("a service with that name already exists"))?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "service.created",
        "service",
        Some(&id.to_string()),
        &serde_json::json!({
            "name": name,
            "fqdn": format!("{name}.{}", namespace(org_id)),
            "target_node_id": input.target_node_id,
            "port": input.port,
            "protocol": protocol,
            "access_tags": tags,
        }),
    )
    .await?;
    bump_control_revision(&mut tx, org_id.to_string()).await?;
    tx.commit().await?;
    let view = load_service(&s, org_id, id).await?;
    Ok((StatusCode::CREATED, Json(view)))
}

async fn update_service(
    State(s): State<AppState>,
    UrlPath((org_id, service_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<ServicePatch>,
) -> Result<Json<ServiceView>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageServices)?;
    let mut tx = s.store.pool.begin().await?;
    let row = sqlx::query(
        "SELECT service_name,target_node,port,revision,enabled,protocol,access_tags_json,description FROM org_services WHERE id=$1 AND org_id=$2",
    )
    .bind(service_id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let name: String = row.try_get(0)?;
    let current_target: String = row.try_get(1)?;
    let current_port: i64 = row.try_get(2)?;
    let revision: i64 = row.try_get(3)?;
    let current_enabled = row.try_get::<i64, _>(4)? != 0;
    let current_protocol: String = row.try_get(5)?;
    let current_tags: Vec<String> =
        serde_json::from_str(&row.try_get::<String, _>(6)?).map_err(|_| ApiError::CorruptData)?;
    let current_description: String = row.try_get(7)?;
    if input.revision != revision {
        return Err(ApiError::PreconditionFailed);
    }
    let target = match input.target_node_id {
        Some(target) => target,
        None => current_target.parse().map_err(|_| ApiError::CorruptData)?,
    };
    let port = input
        .port
        .unwrap_or_else(|| u16::try_from(current_port).unwrap_or(0));
    let protocol = input
        .protocol
        .as_deref()
        .map(str::trim)
        .unwrap_or(&current_protocol)
        .to_owned();
    let enabled = input.enabled.unwrap_or(current_enabled);
    let description = input
        .description
        .as_deref()
        .map(str::trim)
        .unwrap_or(&current_description)
        .to_owned();
    let mut findings = Findings::default();
    let next = ServiceInput {
        name: name.clone(),
        target_node_id: target,
        port,
        protocol: protocol.clone(),
        access_tags: input.access_tags.unwrap_or(current_tags),
        description: description.clone(),
    };
    let tags = check_fields(&mut tx, org_id, &next, &mut findings).await?;
    if !findings.problems.is_empty() {
        return Err(ApiError::BadRequest(findings.problems.join("; ")));
    }
    let changed = sqlx::query(
        "UPDATE org_services SET target_node=$1,port=$2,protocol=$3,enabled=$4,access_tags_json=$5,description=$6,revision=revision+1,updated_at=$7 WHERE id=$8 AND org_id=$9 AND revision=$10",
    )
    .bind(target.to_string())
    .bind(i64::from(port))
    .bind(&protocol)
    .bind(i64::from(enabled))
    .bind(serde_json::to_string(&tags).map_err(|_| ApiError::CorruptData)?)
    .bind(&description)
    .bind(now())
    .bind(service_id.to_string())
    .bind(org_id.to_string())
    .bind(revision)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::PreconditionFailed);
    }
    let target_changed = target.to_string() != current_target;
    let revoked = if target_changed || !enabled {
        sqlx::query(
            "UPDATE org_services SET health_state='unknown',health_detail='',health_node=NULL,health_reported_at=NULL,served_serial=NULL WHERE id=$1 AND org_id=$2",
        )
        .bind(service_id.to_string())
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await?;
        revoke_certificates(&mut tx, org_id, service_id).await?
    } else {
        0
    };
    append_audit(
        &mut tx,
        org_id,
        &session,
        match (current_enabled, enabled) {
            (true, false) => "service.disabled",
            (false, true) => "service.enabled",
            _ => "service.updated",
        },
        "service",
        Some(&service_id.to_string()),
        &serde_json::json!({
            "name": name,
            "revision": revision + 1,
            "target_node_id": target,
            "target_changed": target_changed,
            "port": port,
            "protocol": protocol,
            "enabled": enabled,
            "access_tags": tags,
            "certificates_revoked": revoked,
        }),
    )
    .await?;
    bump_control_revision(&mut tx, org_id.to_string()).await?;
    tx.commit().await?;
    Ok(Json(load_service(&s, org_id, service_id).await?))
}

async fn delete_service(
    State(s): State<AppState>,
    UrlPath((org_id, service_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageServices)?;
    let mut tx = s.store.pool.begin().await?;
    let name: String =
        sqlx::query_scalar("SELECT service_name FROM org_services WHERE id=$1 AND org_id=$2")
            .bind(service_id.to_string())
            .bind(org_id.to_string())
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ApiError::NotFound)?;
    let revoked = revoke_certificates(&mut tx, org_id, service_id).await?;
    sqlx::query("DELETE FROM org_services WHERE id=$1 AND org_id=$2")
        .bind(service_id.to_string())
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "service.deleted",
        "service",
        Some(&service_id.to_string()),
        &serde_json::json!({"name": name, "certificates_revoked": revoked}),
    )
    .await?;
    bump_control_revision(&mut tx, org_id.to_string()).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_certificates(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: Uuid,
    service_id: Uuid,
) -> Result<u64, ApiError> {
    Ok(sqlx::query(
        "UPDATE service_certificates SET revoked_at=$1 WHERE org_id=$2 AND service_id=$3 AND revoked_at IS NULL",
    )
    .bind(now())
    .bind(org_id.to_string())
    .bind(service_id.to_string())
    .execute(&mut **tx)
    .await?
    .rows_affected())
}

/// Revokes every live certificate issued to `node_id` (on suspension: a
/// suspended device must not keep serving under a valid certificate).
pub(crate) async fn revoke_node_certificates(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: Uuid,
    node_id: Uuid,
) -> Result<u64, ApiError> {
    Ok(sqlx::query(
        "UPDATE service_certificates SET revoked_at=$1 WHERE org_id=$2 AND node_id=$3 AND revoked_at IS NULL",
    )
    .bind(now())
    .bind(org_id.to_string())
    .bind(node_id.to_string())
    .execute(&mut **tx)
    .await?
    .rows_affected())
}

async fn list_services(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ServiceList>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewNetwork)?;
    let ids: Vec<String> =
        sqlx::query_scalar("SELECT id FROM org_services WHERE org_id=$1 ORDER BY service_name")
            .bind(org_id.to_string())
            .fetch_all(&s.store.pool)
            .await?;
    let mut services = Vec::with_capacity(ids.len());
    for id in ids {
        let id = id.parse().map_err(|_| ApiError::CorruptData)?;
        services.push(load_service(&s, org_id, id).await?);
    }
    let ca = sqlx::query(
        "SELECT cert_pem,fingerprint_sha256,not_after FROM service_cas WHERE org_id=$1",
    )
    .bind(org_id.to_string())
    .fetch_optional(&s.store.pool)
    .await?
    .map(|row| {
        Ok::<_, sqlx::Error>(CaView {
            cert_pem: row.try_get(0)?,
            fingerprint_sha256: row.try_get(1)?,
            not_after: row.try_get(2)?,
        })
    })
    .transpose()?;
    Ok(Json(ServiceList {
        namespace: namespace(org_id),
        ca,
        services,
    }))
}

async fn load_service(
    s: &AppState,
    org_id: Uuid,
    service_id: Uuid,
) -> Result<ServiceView, ApiError> {
    let row = sqlx::query(
        "SELECT s.service_name,s.target_node,s.port,s.revision,s.enabled,s.protocol,s.access_tags_json,s.description,s.created_at,s.updated_at,COALESCE(NULLIF(TRIM(n.display_name),''),n.name),CASE WHEN n.id IS NOT NULL AND n.revoked_at IS NULL AND n.deleted_at IS NULL THEN 1 ELSE 0 END,s.health_state,s.health_detail,s.health_node,s.health_reported_at,s.served_serial FROM org_services s LEFT JOIN nodes n ON n.id=s.target_node AND n.org_id=s.org_id WHERE s.id=$1 AND s.org_id=$2",
    )
    .bind(service_id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&s.store.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let name: String = row.try_get(0)?;
    let enabled = row.try_get::<i64, _>(4)? != 0;
    let available = row.try_get::<i64, _>(11)? != 0;
    let certificate = sqlx::query(
        "SELECT serial,fingerprint_sha256,not_before,not_after,issued_at FROM service_certificates WHERE org_id=$1 AND service_id=$2 AND revoked_at IS NULL AND not_after>$3 ORDER BY issued_at DESC LIMIT 1",
    )
    .bind(org_id.to_string())
    .bind(service_id.to_string())
    .bind(now())
    .fetch_optional(&s.store.pool)
    .await?
    .map(|row| {
        Ok::<_, sqlx::Error>(CertificateSummary {
            serial: row.try_get(0)?,
            fingerprint_sha256: row.try_get(1)?,
            not_before: row.try_get(2)?,
            not_after: row.try_get(3)?,
            issued_at: row.try_get(4)?,
        })
    })
    .transpose()?;
    let health = service_serving::Health {
        state: row.try_get(12)?,
        detail: row.try_get(13)?,
        node: row.try_get(14)?,
        reported_at: row.try_get(15)?,
        served_serial: row.try_get(16)?,
    };
    let target: String = row.try_get(1)?;
    let fresh = health.fresh_for(&target, now());
    let serving_live_certificate = certificate.as_ref().is_some_and(|certificate| {
        health.served_serial.as_deref() == Some(certificate.serial.as_str())
    });
    let (status, status_detail) = if !enabled {
        ("disabled", "Disabled; certificates were revoked and the target device stops serving it on its next update.".to_owned())
    } else if !available {
        (
            "target_unavailable",
            "The target device was revoked or removed; choose another device.".to_owned(),
        )
    } else if fresh && health.state == "unhealthy" {
        // The agent drops the route (and its listener, if nothing else is
        // routed) for a target that fails its check, so this is decided
        // before anything that needs a live listener or certificate.
        ("target_unhealthy", format!(
            "The target device reports that the local target failed its check ({}); the name is not published until it recovers.",
            if health.detail.is_empty() { "no detail" } else { health.detail.as_str() }
        ))
    } else if certificate.is_none() {
        ("awaiting_certificate", "Waiting for the target device to request a certificate. Run `blaktaild up --serve-services` on it; the name is not published until it serves.".to_owned())
    } else if !fresh || !serving_live_certificate || health.state != "healthy" {
        ("certificate_issued", format!(
            "A current certificate was issued, but the target device has not reported a listener serving it in the last {} seconds, so the name is not published.",
            service_serving::HEALTH_FRESH_SECS
        ))
    } else {
        ("serving", "The target device reports its listener serving the current certificate and a healthy local target; authorised devices resolve the name in MagicDNS. This is the device's own report, not a probe from a client.".to_owned())
    };
    let reachable = status == "serving";
    Ok(ServiceView {
        id: service_id,
        fqdn: format!("{name}.{}", namespace(org_id)),
        name,
        description: row.try_get(7)?,
        target_node_id: row.try_get(1)?,
        target_node_name: row.try_get(10)?,
        target_node_available: available,
        port: u16::try_from(row.try_get::<i64, _>(2)?).map_err(|_| ApiError::CorruptData)?,
        protocol: row.try_get(5)?,
        access_tags: serde_json::from_str(&row.try_get::<String, _>(6)?)
            .map_err(|_| ApiError::CorruptData)?,
        enabled,
        revision: row.try_get(3)?,
        status: status.into(),
        status_detail,
        reachable,
        certificate,
        created_at: row.try_get(8)?,
        updated_at: row.try_get(9)?,
    })
}

/// Authenticates a node bearer token; revoked, deleted and unknown nodes all
/// fail the same way. Suspended devices are refused (`suspended`).
pub(crate) async fn node_org(
    s: &AppState,
    headers: &HeaderMap,
    node_id: Uuid,
) -> Result<(Uuid, String), ApiError> {
    let token = bearer(headers)?;
    let row = sqlx::query(
        "SELECT org_id,credential_expires_at,name,suspended_at FROM nodes WHERE id=$1 AND token_hash=$2 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(node_id.to_string())
    .bind(token)
    .fetch_optional(&s.store.pool)
    .await?
    .ok_or(ApiError::Unauthorized)?;
    if row.try_get::<Option<i64>, _>(3)?.is_some() {
        return Err(ApiError::Suspended);
    }
    let expires: i64 = row.try_get(1)?;
    if expires <= now() {
        return Err(ApiError::CredentialExpired);
    }
    let org: String = row.try_get(0)?;
    Ok((
        org.parse().map_err(|_| ApiError::CorruptData)?,
        row.try_get(2)?,
    ))
}

#[derive(Serialize, Deserialize)]
pub(crate) struct NodeService {
    id: Uuid,
    name: String,
    fqdn: String,
    port: u16,
    protocol: String,
    access_tags: Vec<String>,
    revision: i64,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct NodeServices {
    pub(crate) services: Vec<NodeService>,
}

async fn node_services(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<NodeServices>, ApiError> {
    let (org_id, _) = node_org(&s, &headers, node_id).await?;
    let rows = sqlx::query(
        "SELECT id,service_name,port,protocol,access_tags_json,revision FROM org_services WHERE org_id=$1 AND target_node=$2 AND enabled=1 ORDER BY service_name",
    )
    .bind(org_id.to_string())
    .bind(node_id.to_string())
    .fetch_all(&s.store.pool)
    .await?;
    let services = rows
        .into_iter()
        .map(|row| {
            let name: String = row.try_get(1)?;
            Ok(NodeService {
                id: row
                    .try_get::<String, _>(0)?
                    .parse()
                    .map_err(|_| ApiError::CorruptData)?,
                fqdn: format!("{name}.{}", namespace(org_id)),
                name,
                port: u16::try_from(row.try_get::<i64, _>(2)?)
                    .map_err(|_| ApiError::CorruptData)?,
                protocol: row.try_get(3)?,
                access_tags: serde_json::from_str(&row.try_get::<String, _>(4)?)
                    .map_err(|_| ApiError::CorruptData)?,
                revision: row.try_get(5)?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(NodeServices { services }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificateRequest {
    csr_pem: String,
    /// Accepted only so a client that wrongly sends a key gets an explicit
    /// rejection instead of a generic parse error.
    #[serde(default)]
    private_key: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct IssuedCertificate {
    pub(crate) certificate_pem: String,
    pub(crate) ca_pem: String,
    pub(crate) serial: String,
    pub(crate) not_after: i64,
}

async fn issue_certificate(
    State(s): State<AppState>,
    UrlPath((node_id, service_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<CertificateRequest>,
) -> Result<Json<IssuedCertificate>, ApiError> {
    let (org_id, node_name) = node_org(&s, &headers, node_id).await?;
    let mut tx = s.store.pool.begin().await?;
    // Scoped to the caller's organisation: another org's service id is 404.
    let row = sqlx::query(
        "SELECT service_name,target_node,port,revision,enabled FROM org_services WHERE id=$1 AND org_id=$2",
    )
    .bind(service_id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let name: String = row.try_get(0)?;
    let target_node: String = row.try_get(1)?;
    let enabled = row.try_get::<i64, _>(4)? != 0;
    let request = https_services::CsrRequest {
        org_id: org_id.to_string(),
        service_name: name.clone(),
        target_node: node_id.to_string(),
        csr_pem: input.csr_pem,
        private_key: input.private_key,
    };
    request
        .validate(&[])
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    if request.csr_pem.contains("PRIVATE KEY") {
        return Err(ApiError::BadRequest(
            https_services::ServiceError::PrivateKeyPresent.to_string(),
        ));
    }
    let definition = https_services::ServiceDef {
        org_id: org_id.to_string(),
        service_name: name.clone(),
        target_node,
        port: u16::try_from(row.try_get::<i64, _>(2)?).map_err(|_| ApiError::CorruptData)?,
        revision: u64::try_from(row.try_get::<i64, _>(3)?).map_err(|_| ApiError::CorruptData)?,
    };
    https_services::check_cert_binding(
        &definition,
        &https_services::CertBinding {
            org_id: org_id.to_string(),
            service_name: name.clone(),
            node_id: node_id.to_string(),
        },
    )
    .map_err(|_| ApiError::Forbidden)?;
    if !enabled {
        return Err(ApiError::Conflict("service is disabled".into()));
    }
    let fqdn = format!("{name}.{}", namespace(org_id));
    let ca = ensure_ca(&mut tx, &s.auth_hmac_secret, org_id).await?;
    let issued = sign_leaf(&ca, &request.csr_pem, &fqdn, org_id, service_id, node_id)?;
    let issued_at = now();
    sqlx::query(
        "INSERT INTO service_csrs(id,org_id,service_name,target_node,csr_pem,created_at) VALUES($1,$2,$3,$4,$5,$6)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(org_id.to_string())
    .bind(&name)
    .bind(node_id.to_string())
    .bind(&request.csr_pem)
    .bind(issued_at)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO service_certificates(id,org_id,service_id,node_id,serial,fingerprint_sha256,not_before,not_after,issued_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(org_id.to_string())
    .bind(service_id.to_string())
    .bind(node_id.to_string())
    .bind(&issued.serial)
    .bind(&issued.fingerprint)
    .bind(issued.not_before)
    .bind(issued.not_after)
    .bind(issued_at)
    .execute(&mut *tx)
    .await?;
    // The actor is the serving node, not a console user, so this builds the
    // chained entry itself instead of `append_audit`'s session-shaped actor.
    let details = serde_json::json!({
        "fqdn": fqdn,
        "node_id": node_id,
        "serial": issued.serial,
        "fingerprint_sha256": issued.fingerprint,
        "not_after": issued.not_after,
    });
    let entry = audit_log::ChainEntry {
        org_id: org_id.to_string(),
        id: Uuid::new_v4().to_string(),
        actor_user_id: node_id.to_string(),
        actor_name: node_name,
        actor_email: String::new(),
        actor_role: "node".into(),
        action: "service.certificate_issued".into(),
        target_type: "service".into(),
        target_id: Some(service_id.to_string()),
        details_json: details.to_string(),
        created_at: issued_at,
    };
    audit_log::insert_chained(&mut tx, &entry).await?;
    notifications::enqueue_for_audit(&mut tx, org_id, &entry, &details).await?;
    tx.commit().await?;
    Ok(Json(IssuedCertificate {
        certificate_pem: issued.pem,
        ca_pem: ca.cert_pem,
        serial: issued.serial,
        not_after: issued.not_after,
    }))
}

struct OrgCa {
    cert_pem: String,
    key: KeyPair,
}

async fn ensure_ca(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    master: &[u8],
    org_id: Uuid,
) -> Result<OrgCa, ApiError> {
    let existing = sqlx::query("SELECT cert_pem,sealed_key FROM service_cas WHERE org_id=$1")
        .bind(org_id.to_string())
        .fetch_optional(&mut **tx)
        .await?;
    if let Some(row) = existing {
        let sealed: String = row.try_get(1)?;
        let key =
            KeyPair::from_pem(&open_key(master, &sealed)?).map_err(|_| ApiError::CorruptData)?;
        return Ok(OrgCa {
            cert_pem: row.try_get(0)?,
            key,
        });
    }
    let key = KeyPair::generate().map_err(|_| ApiError::Unavailable)?;
    let mut params = CertificateParams::default();
    let mut subject = DistinguishedName::new();
    subject.push(
        DnType::CommonName,
        format!("BlakTail private services CA {}", namespace(org_id)),
    );
    subject.push(
        DnType::OrganizationName,
        format!("BlakTail organisation {org_id}"),
    );
    params.distinguished_name = subject;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DnsName(namespace(org_id))],
        excluded_subtrees: Vec::new(),
    });
    let started = OffsetDateTime::now_utc();
    params.not_before = started - TimeDuration::hours(1);
    params.not_after = started + TimeDuration::days(CA_LIFETIME_DAYS);
    params.serial_number = Some(random_serial());
    let certificate = params
        .self_signed(&key)
        .map_err(|_| ApiError::Unavailable)?;
    let cert_pem = certificate.pem();
    sqlx::query(
        "INSERT INTO service_cas(org_id,cert_pem,sealed_key,fingerprint_sha256,not_after,created_at) VALUES($1,$2,$3,$4,$5,$6)",
    )
    .bind(org_id.to_string())
    .bind(&cert_pem)
    .bind(seal_key(master, &key.serialize_pem())?)
    .bind(fingerprint(certificate.der()))
    .bind(params.not_after.unix_timestamp())
    .bind(now())
    .execute(&mut **tx)
    .await?;
    Ok(OrgCa { cert_pem, key })
}

struct LeafCertificate {
    pem: String,
    serial: String,
    fingerprint: String,
    not_before: i64,
    not_after: i64,
}

/// Only the CSR's public key is used. The coordinator sets the name, subject,
/// usages and lifetime, so a CSR cannot widen what it is issued.
fn sign_leaf(
    ca: &OrgCa,
    csr_pem: &str,
    fqdn: &str,
    org_id: Uuid,
    service_id: Uuid,
    node_id: Uuid,
) -> Result<LeafCertificate, ApiError> {
    let csr = CertificateSigningRequestParams::from_pem(csr_pem).map_err(|_| {
        ApiError::BadRequest("CSR rejected: not a valid, correctly signed PKCS#10 request".into())
    })?;
    let algorithm = csr.public_key.algorithm();
    if ![
        &rcgen::PKCS_ECDSA_P256_SHA256,
        &rcgen::PKCS_ECDSA_P384_SHA384,
        &rcgen::PKCS_ED25519,
    ]
    .contains(&algorithm)
    {
        return Err(ApiError::BadRequest(
            "CSR rejected: use an ECDSA P-256, ECDSA P-384 or Ed25519 key".into(),
        ));
    }
    if matches!(csr.params.is_ca, IsCa::Ca(_)) {
        return Err(ApiError::BadRequest(
            "CSR rejected: service certificates cannot be CAs".into(),
        ));
    }
    for name in &csr.params.subject_alt_names {
        match name {
            SanType::DnsName(requested) if requested.as_str().eq_ignore_ascii_case(fqdn) => {}
            _ => {
                return Err(ApiError::BadRequest(format!(
                    "CSR rejected: it may only name {fqdn}"
                )))
            }
        }
    }
    let mut params =
        CertificateParams::new(vec![fqdn.to_owned()]).map_err(|_| ApiError::CorruptData)?;
    let mut subject = DistinguishedName::new();
    subject.push(DnType::CommonName, fqdn);
    subject.push(
        DnType::OrganizationName,
        format!("BlakTail organisation {org_id}"),
    );
    subject.push(
        DnType::OrganizationalUnitName,
        format!("service {service_id} node {node_id}"),
    );
    params.distinguished_name = subject;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    let started = OffsetDateTime::now_utc();
    params.not_before = started - TimeDuration::minutes(5);
    params.not_after = started + TimeDuration::seconds(LEAF_LIFETIME_SECS);
    let serial = random_serial();
    params.serial_number = Some(serial.clone());
    let issuer =
        Issuer::from_ca_cert_pem(&ca.cert_pem, &ca.key).map_err(|_| ApiError::CorruptData)?;
    let leaf = CertificateSigningRequestParams {
        params: params.clone(),
        public_key: csr.public_key,
    }
    .signed_by(&issuer)
    .map_err(|_| ApiError::BadRequest("CSR rejected: could not sign request".into()))?;
    Ok(LeafCertificate {
        pem: leaf.pem(),
        serial: hex(&serial.to_bytes()),
        fingerprint: fingerprint(leaf.der()),
        not_before: params.not_before.unix_timestamp(),
        not_after: params.not_after.unix_timestamp(),
    })
}

fn random_serial() -> SerialNumber {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes[0] &= 0x7f;
    bytes[0] |= 0x01;
    SerialNumber::from_slice(&bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn fingerprint(der: &[u8]) -> String {
    hex(&Sha256::digest(der))
}

fn seal_cipher(master: &[u8]) -> Result<ChaCha20Poly1305, ApiError> {
    let key = Sha256::new()
        .chain_update(b"blaktail-service-ca-v1")
        .chain_update(master)
        .finalize();
    ChaCha20Poly1305::new_from_slice(&key).map_err(|_| ApiError::CorruptData)
}

pub(crate) fn seal_key(master: &[u8], pem: &str) -> Result<String, ApiError> {
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ciphertext = seal_cipher(master)?
        .encrypt(Nonce::from_slice(&nonce), pem.as_bytes())
        .map_err(|_| ApiError::CorruptData)?;
    let mut packed = nonce.to_vec();
    packed.extend(ciphertext);
    Ok(format!("{SEALED_PREFIX}{}", STANDARD.encode(packed)))
}

pub(crate) fn open_key(master: &[u8], sealed: &str) -> Result<String, ApiError> {
    let raw = STANDARD
        .decode(
            sealed
                .strip_prefix(SEALED_PREFIX)
                .ok_or(ApiError::CorruptData)?,
        )
        .map_err(|_| ApiError::CorruptData)?;
    if raw.len() <= 12 {
        return Err(ApiError::CorruptData);
    }
    let (nonce, ciphertext) = raw.split_at(12);
    let plaintext = seal_cipher(master)?
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| ApiError::CorruptData)?;
    String::from_utf8(plaintext).map_err(|_| ApiError::CorruptData)
}

/// Router-level helpers shared by the DNS workspace and service tests.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::{
        app, now, AssertionClaims, Role, Store, CONSOLE_ASSERTION_AUDIENCE,
        CONSOLE_ASSERTION_ISSUER,
    };
    use axum::{
        body::{to_bytes, Body},
        http::{header::AUTHORIZATION, Method, Request, StatusCode},
        Router,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use tower::ServiceExt;
    use uuid::Uuid;

    const SECRET: &[u8] = b"test-only-hmac-secret-at-least-32-bytes";

    pub(crate) enum Auth<'a> {
        Console(Uuid, Role),
        Node(&'a str),
        Service(Uuid, &'a str),
    }

    pub(crate) async fn router() -> (Router, Store) {
        let store = Store::memory().await.unwrap();
        (app(store.clone(), "ap-southeast-2".into(), SECRET), store)
    }

    fn assertion(org_id: Uuid, user: &str, role: &str, action: Option<&str>) -> String {
        let issued = now();
        let claims = AssertionClaims {
            user_id: user.into(),
            org_id,
            role: role.into(),
            name: user.into(),
            email: format!("{user}@example.com"),
            iss: CONSOLE_ASSERTION_ISSUER.into(),
            aud: CONSOLE_ASSERTION_AUDIENCE.into(),
            iat: issued,
            exp: issued + 60,
            jti: Uuid::new_v4().to_string(),
            action: action.map(str::to_owned),
        };
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
        mac.update(payload.as_bytes());
        format!(
            "{payload}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        )
    }

    pub(crate) fn console_token(org_id: Uuid, role: Role) -> String {
        assertion(
            org_id,
            &format!("{}-user", role.as_str()),
            role.as_str(),
            None,
        )
    }

    pub(crate) async fn call(
        router: &Router,
        method: Method,
        uri: &str,
        body: serde_json::Value,
        auth: Auth<'_>,
    ) -> (StatusCode, serde_json::Value) {
        let token = match auth {
            Auth::Console(org_id, role) => assertion(
                org_id,
                &format!("{}-user", role.as_str()),
                role.as_str(),
                None,
            ),
            Auth::Node(token) => token.to_owned(),
            Auth::Service(org_id, action) => {
                assertion(org_id, "operator-cli", "service", Some(action))
            }
        };
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(if body.is_null() {
                String::new()
            } else {
                body.to_string()
            }))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    pub(crate) async fn create_org(router: &Router, name: &str) -> Uuid {
        let id = Uuid::new_v4();
        let (status, _) = call(
            router,
            Method::POST,
            "/v1/orgs",
            serde_json::json!({"id": id, "name": name, "acl": {"version": 1, "defaults": "same_tag", "rules": []}}),
            Auth::Service(id, "bootstrap.prepare"),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let (status, _) = call(
            router,
            Method::POST,
            &format!("/v1/orgs/{id}/bootstrap-commit"),
            serde_json::json!({}),
            Auth::Service(id, "bootstrap.commit"),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        id
    }

    /// Returns (node id, node token, MagicDNS name).
    pub(crate) async fn register(
        router: &Router,
        org_id: Uuid,
        name: &str,
        tags: &[&str],
    ) -> (Uuid, String, String) {
        let (status, key) = call(
            router,
            Method::POST,
            &format!("/v1/orgs/{org_id}/join-keys"),
            serde_json::json!({"expires_in_seconds": 60, "tags": tags}),
            Auth::Console(org_id, Role::Owner),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{key}");
        let public_key = format!("key-{}", Uuid::new_v4());
        let request = Request::builder()
            .method(Method::POST)
            .uri("/v1/nodes/register")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"join_key": key["key"], "name": name, "wg_public_key": public_key})
                    .to_string(),
            ))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(status, StatusCode::CREATED, "{body}");
        (
            body["id"].as_str().unwrap().parse().unwrap(),
            body["node_token"].as_str().unwrap().to_owned(),
            body["dns_name"].as_str().unwrap().to_owned(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_ca_key_round_trips_and_binds_to_master() {
        let master = b"test-only-hmac-secret-at-least-32-bytes";
        let sealed = seal_key(master, "pem-body").unwrap();
        assert!(!sealed.contains("pem-body"));
        assert_eq!(open_key(master, &sealed).unwrap(), "pem-body");
        assert!(open_key(b"another-master-secret-of-32-bytes!!", &sealed).is_err());
    }

    #[test]
    fn namespace_is_separate_from_device_names() {
        let org = Uuid::parse_str("12345678-0000-0000-0000-000000000000").unwrap();
        assert_eq!(namespace(org), "svc.12345678.blaktail");
    }

    use super::test_support::{call, create_org, register, router, Auth};
    use crate::Role;
    use axum::http::Method;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use std::sync::Arc;

    fn csr_for(names: &[&str]) -> String {
        let key = KeyPair::generate().unwrap();
        CertificateParams::new(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .unwrap()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap()
    }

    fn der(pem: &str) -> Vec<u8> {
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        STANDARD.decode(body).unwrap()
    }

    /// Validates the leaf the way a TLS client trusting only the org CA would.
    fn client_accepts(ca_pem: &str, leaf_pem: &str, host: &str) -> bool {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(der(ca_pem))).unwrap();
        let verifier =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .unwrap();
        verifier
            .verify_server_cert(
                &CertificateDer::from(der(leaf_pem)),
                &[],
                &ServerName::try_from(host.to_owned()).unwrap(),
                &[],
                UnixTime::now(),
            )
            .is_ok()
    }

    fn service_body(name: &str, node: Uuid) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "target_node_id": node,
            "port": 8080,
            "protocol": "http",
            "access_tags": ["office"],
            "description": "Staff wiki",
        })
    }

    #[tokio::test]
    async fn services_are_org_scoped_validated_and_admin_only() {
        let (r, store) = router().await;
        let org_a = create_org(&r, "org-a").await;
        let org_b = create_org(&r, "org-b").await;
        let (node_a, _, _) = register(&r, org_a, "wiki-host", &["office"]).await;
        let (_gateway, _, _) = register(&r, org_a, "gateway", &[]).await;
        let (node_b, _, _) = register(&r, org_b, "wiki-host", &["office"]).await;
        let owner_a = || Auth::Console(org_a, Role::Owner);
        let path_a = format!("/v1/orgs/{org_a}/services");

        let (status, preview) = call(
            &r,
            Method::POST,
            &format!("{path_a}/preview"),
            service_body("wiki", node_a),
            owner_a(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(preview["valid"], true);
        assert_eq!(
            preview["fqdn"],
            format!("wiki.{}", namespace(org_a)).as_str()
        );

        let (status, created_a) = call(
            &r,
            Method::POST,
            &path_a,
            service_body("wiki", node_a),
            owner_a(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created_a}");
        assert_eq!(created_a["status"], "awaiting_certificate");
        assert_eq!(created_a["reachable"], false);
        let (status, created_b) = call(
            &r,
            Method::POST,
            &format!("/v1/orgs/{org_b}/services"),
            service_body("wiki", node_b),
            Auth::Console(org_b, Role::Admin),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "two orgs may share a name");
        assert_ne!(created_a["fqdn"], created_b["fqdn"]);

        for (body, expected) in [
            (service_body("wiki", node_a), StatusCode::CONFLICT),
            (service_body("gateway", node_a), StatusCode::CONFLICT),
            (service_body("svc", node_a), StatusCode::CONFLICT),
            (service_body("wiki2", node_b), StatusCode::BAD_REQUEST),
            (service_body("Bad_Name", node_a), StatusCode::BAD_REQUEST),
            (
                serde_json::json!({"name": "wiki3", "target_node_id": node_a, "port": 0, "access_tags": ["office"]}),
                StatusCode::BAD_REQUEST,
            ),
            (
                serde_json::json!({"name": "wiki3", "target_node_id": node_a, "port": 80, "access_tags": []}),
                StatusCode::BAD_REQUEST,
            ),
            (
                serde_json::json!({"name": "wiki3", "target_node_id": node_a, "port": 80, "access_tags": ["visitors"]}),
                StatusCode::BAD_REQUEST,
            ),
            (
                serde_json::json!({"name": "wiki3", "target_node_id": node_a, "port": 80, "protocol": "ftp", "access_tags": ["office"]}),
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let (status, error) = call(&r, Method::POST, &path_a, body.clone(), owner_a()).await;
            assert_eq!(status, expected, "{body} -> {error}");
        }
        let (_, preview) = call(
            &r,
            Method::POST,
            &format!("{path_a}/preview"),
            service_body("gateway", node_a),
            owner_a(),
        )
        .await;
        assert_eq!(preview["valid"], false);

        let member = || Auth::Console(org_a, Role::Member);
        let service_a = created_a["id"].as_str().unwrap();
        let service_b = created_b["id"].as_str().unwrap();
        assert_eq!(
            call(
                &r,
                Method::POST,
                &path_a,
                service_body("notes", node_a),
                member()
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &r,
                Method::PATCH,
                &format!("{path_a}/{service_a}"),
                serde_json::json!({"revision": 1, "enabled": false}),
                member()
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &r,
                Method::DELETE,
                &format!("{path_a}/{service_a}"),
                serde_json::Value::Null,
                member()
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        let (status, listed) =
            call(&r, Method::GET, &path_a, serde_json::Value::Null, member()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed["services"].as_array().unwrap().len(), 1);
        assert!(listed["ca"]["cert_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE"));

        // Org A cannot see or change org B's service, even by id.
        for method in [Method::PATCH, Method::DELETE] {
            let (status, _) = call(
                &r,
                method,
                &format!("{path_a}/{service_b}"),
                serde_json::json!({"revision": 1}),
                owner_a(),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
        let (status, _) = call(
            &r,
            Method::GET,
            &format!("/v1/orgs/{org_b}/services"),
            serde_json::Value::Null,
            owner_a(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _) = call(
            &r,
            Method::PATCH,
            &format!("{path_a}/{service_a}"),
            serde_json::json!({"revision": 7, "port": 9090}),
            owner_a(),
        )
        .await;
        assert_eq!(status, StatusCode::PRECONDITION_FAILED);
        let (status, updated) = call(
            &r,
            Method::PATCH,
            &format!("{path_a}/{service_a}"),
            serde_json::json!({"revision": 1, "enabled": false}),
            owner_a(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(updated["status"], "disabled");
        assert_eq!(updated["revision"], 2);
        assert_eq!(
            call(
                &r,
                Method::DELETE,
                &format!("{path_a}/{service_a}"),
                serde_json::Value::Null,
                owner_a()
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );

        let actions: Vec<String> = sqlx::query_scalar(
            "SELECT action FROM audit_events WHERE org_id=$1 AND target_type='service' ORDER BY created_at,action",
        )
        .bind(org_a.to_string())
        .fetch_all(&store.pool)
        .await
        .unwrap();
        for action in ["service.created", "service.disabled", "service.deleted"] {
            assert!(actions.iter().any(|value| value == action), "{actions:?}");
        }
    }

    #[tokio::test]
    async fn certificates_bind_exact_service_node_and_org() {
        let (r, store) = router().await;
        let org_a = create_org(&r, "org-a").await;
        let org_b = create_org(&r, "org-b").await;
        let (node_a, token_a, _) = register(&r, org_a, "wiki-host", &["office"]).await;
        let (_other_a, other_token, _) = register(&r, org_a, "laptop", &["office"]).await;
        let (_node_b, token_b, _) = register(&r, org_b, "wiki-host", &["office"]).await;
        let owner_a = || Auth::Console(org_a, Role::Owner);
        let (_, service) = call(
            &r,
            Method::POST,
            &format!("/v1/orgs/{org_a}/services"),
            service_body("wiki", node_a),
            owner_a(),
        )
        .await;
        let service_id = service["id"].as_str().unwrap().to_owned();
        let fqdn = service["fqdn"].as_str().unwrap().to_owned();
        let issue_path = format!("/v1/nodes/{node_a}/services/{service_id}/certificate");

        let (status, served) = call(
            &r,
            Method::GET,
            &format!("/v1/nodes/{node_a}/services"),
            serde_json::Value::Null,
            Auth::Node(&token_a),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(served["services"][0]["fqdn"], fqdn.as_str());

        let (status, issued) = call(
            &r,
            Method::POST,
            &issue_path,
            serde_json::json!({"csr_pem": csr_for(&[&fqdn])}),
            Auth::Node(&token_a),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{issued}");
        let leaf = issued["certificate_pem"].as_str().unwrap();
        let ca = issued["ca_pem"].as_str().unwrap();
        assert!(client_accepts(ca, leaf, &fqdn));
        assert!(!client_accepts(
            ca,
            leaf,
            &format!("other.{}", namespace(org_a))
        ));

        let (_, list) = call(
            &r,
            Method::GET,
            &format!("/v1/orgs/{org_a}/services"),
            serde_json::Value::Null,
            owner_a(),
        )
        .await;
        assert_eq!(list["services"][0]["status"], "certificate_issued");
        assert_eq!(list["services"][0]["reachable"], false);

        let rejected = [
            // Another node in the same org is not the target.
            (
                format!("/v1/nodes/{_other_a}/services/{service_id}/certificate"),
                serde_json::json!({"csr_pem": csr_for(&[&fqdn])}),
                other_token.clone(),
                StatusCode::FORBIDDEN,
            ),
            // A node in another org cannot even see the service.
            (
                format!("/v1/nodes/{_node_b}/services/{service_id}/certificate"),
                serde_json::json!({"csr_pem": csr_for(&[&fqdn])}),
                token_b.clone(),
                StatusCode::NOT_FOUND,
            ),
            // Right node, wrong token.
            (
                issue_path.clone(),
                serde_json::json!({"csr_pem": csr_for(&[&fqdn])}),
                token_b.clone(),
                StatusCode::UNAUTHORIZED,
            ),
            (
                issue_path.clone(),
                serde_json::json!({"csr_pem": csr_for(&["evil.example"])}),
                token_a.clone(),
                StatusCode::BAD_REQUEST,
            ),
            (
                issue_path.clone(),
                serde_json::json!({"csr_pem": csr_for(&[&fqdn]), "private_key": concat!("-----BEGIN ", "PRIVATE KEY-----")}),
                token_a.clone(),
                StatusCode::BAD_REQUEST,
            ),
            (
                issue_path.clone(),
                // Split so secret scanners don't mistake this fake key for a real one.
                serde_json::json!({"csr_pem": format!("{}\n-----BEGIN {k}-----\nabc\n-----END {k}-----", csr_for(&[&fqdn]), k = "PRIVATE KEY")}),
                token_a.clone(),
                StatusCode::BAD_REQUEST,
            ),
            (
                issue_path.clone(),
                serde_json::json!({"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----"}),
                token_a.clone(),
                StatusCode::BAD_REQUEST,
            ),
        ];
        for (path, body, token, expected) in rejected {
            let (status, error) = call(&r, Method::POST, &path, body, Auth::Node(&token)).await;
            assert_eq!(status, expected, "{path}: {error}");
        }

        // Disabling revokes; a disabled service issues nothing.
        let (_, disabled) = call(
            &r,
            Method::PATCH,
            &format!("/v1/orgs/{org_a}/services/{service_id}"),
            serde_json::json!({"revision": 1, "enabled": false}),
            owner_a(),
        )
        .await;
        assert!(disabled["certificate"].is_null());
        let (status, _) = call(
            &r,
            Method::POST,
            &issue_path,
            serde_json::json!({"csr_pem": csr_for(&[&fqdn])}),
            Auth::Node(&token_a),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        call(
            &r,
            Method::PATCH,
            &format!("/v1/orgs/{org_a}/services/{service_id}"),
            serde_json::json!({"revision": 2, "enabled": true}),
            owner_a(),
        )
        .await;

        // A suspended node can neither list its services nor obtain a
        // certificate, and suspension revokes what it already holds.
        let (status, issued) = call(
            &r,
            Method::POST,
            &issue_path,
            serde_json::json!({"csr_pem": csr_for(&[&fqdn])}),
            Auth::Node(&token_a),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{issued}");
        let (status, _) = call(
            &r,
            Method::POST,
            &format!("/v1/orgs/{org_a}/nodes/{node_a}/suspend"),
            serde_json::json!({"reason": "lost"}),
            owner_a(),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let live: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM service_certificates WHERE node_id=$1 AND revoked_at IS NULL",
        )
        .bind(node_a.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(live, 0);
        let (status, error) = call(
            &r,
            Method::GET,
            &format!("/v1/nodes/{node_a}/services"),
            serde_json::Value::Null,
            Auth::Node(&token_a),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(error["code"], "suspended");
        let (status, _) = call(
            &r,
            Method::POST,
            &issue_path,
            serde_json::json!({"csr_pem": csr_for(&[&fqdn])}),
            Auth::Node(&token_a),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call(
            &r,
            Method::POST,
            &format!("/v1/orgs/{org_a}/nodes/{node_a}/resume"),
            serde_json::json!({}),
            owner_a(),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        // Issuance audit rows are part of the tamper-evident chain.
        let unchained: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE org_id=$1 AND action='service.certificate_issued' AND (chain_seq IS NULL OR actor_role<>'node' OR actor_user_id<>$2)",
        )
        .bind(org_a.to_string())
        .bind(node_a.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(unchained, 0);
        assert!(
            crate::audit_log::verify_chain(&store, org_a)
                .await
                .unwrap()
                .intact
        );

        // A revoked node can no longer obtain a certificate.
        let (status, _) = call(
            &r,
            Method::DELETE,
            &format!("/v1/orgs/{org_a}/nodes/{node_a}"),
            serde_json::Value::Null,
            owner_a(),
        )
        .await;
        assert!(status.is_success());
        let (status, _) = call(
            &r,
            Method::POST,
            &issue_path,
            serde_json::json!({"csr_pem": csr_for(&[&fqdn])}),
            Auth::Node(&token_a),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (_, list) = call(
            &r,
            Method::GET,
            &format!("/v1/orgs/{org_a}/services"),
            serde_json::Value::Null,
            owner_a(),
        )
        .await;
        assert_eq!(list["services"][0]["status"], "target_unavailable");

        let sealed: String =
            sqlx::query_scalar("SELECT sealed_key FROM service_cas WHERE org_id=$1")
                .bind(org_a.to_string())
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert!(sealed.starts_with(SEALED_PREFIX) && !sealed.contains("PRIVATE KEY"));
        let audit: Vec<(String, String)> = sqlx::query_as(
            "SELECT actor_role,details_json FROM audit_events WHERE org_id=$1 AND action='service.certificate_issued'",
        )
        .bind(org_a.to_string())
        .fetch_all(&store.pool)
        .await
        .unwrap();
        // The first issuance plus the one revoked by suspension.
        assert_eq!(audit.len(), 2);
        for (role, details) in &audit {
            assert_eq!(role, "node");
            assert!(!details.contains("PRIVATE KEY") && !details.contains("BEGIN"));
        }
    }
}
