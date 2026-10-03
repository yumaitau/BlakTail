//! Browser remote access and allowlisted remote jobs (draft 13, ADR 0006).
//!
//! The coordinator decides; the onshore gateway and the device agents only
//! execute. A browser session starts from a single-use ticket bound to one
//! person, organisation, gateway node, target node and OS user. The gateway
//! redeems it once, receives a short-lived SSH user certificate for an
//! ephemeral key it generated itself, and reports every few seconds; any
//! revoke, suspend, policy change or deadline ends the session on the next
//! report. Only metadata (who, what, when, bytes) is stored or audited.
//!
//! Remote jobs are owner-defined argv templates. A run needs owner approval,
//! is signed with a key derived from the coordinator secret (so a database
//! write alone cannot forge one) and is pulled by agents that opted in.

use crate::permissions::{require, Permission};
use crate::policy_explain::device_subject;
use crate::posture::{PostureContext, CAP_SSH_USERS};
use crate::{
    append_audit, bearer, bump_control_revision, console_session, hash, load_acl_row, now, secret,
    specs_cover, valid_ssh_os_user, Acl, ApiError, AppState, DeviceTag, Role, Session,
};
use axum::{
    extract::{Path as UrlPath, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signer, SigningKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{AssertSqlSafe, Row};
use std::collections::BTreeSet;
use uuid::Uuid;

/// A ticket must be redeemed by the gateway within this window.
pub(crate) const TICKET_TTL_SECS: i64 = 60;
pub(crate) const MAX_SESSION_SECS: i64 = 30 * 60;
pub(crate) const IDLE_TIMEOUT_SECS: i64 = 10 * 60;
/// How often the gateway must report; a live session ends within one period
/// of a revoke, suspend or policy change.
pub(crate) const REPORT_INTERVAL_SECS: i64 = 10;
/// A redeemed session whose gateway stopped reporting counts as ended.
const REPORT_STALE_SECS: i64 = 60;
pub(crate) const MAX_JOB_TIMEOUT_SECS: i64 = 10 * 60;
pub(crate) const MAX_JOB_OUTPUT_BYTES: i64 = 64 * 1024;
/// An approved run must be claimed by its agent within this window.
const JOB_CLAIM_WINDOW_SECS: i64 = 10 * 60;
const MAX_ARGV_ITEMS: usize = 32;
const MAX_ARGV_ITEM_CHARS: usize = 256;
const SEALED_PREFIX: &str = "btsealed1:";
const LIST_LIMIT: i64 = 100;
pub(crate) const CAP_REMOTE_SSH: &str = "remote-ssh-ca";
pub(crate) const CAP_REMOTE_JOBS: &str = "remote-jobs";
pub(crate) const JOB_SIGNATURE_CONTEXT: &str = "blaktail-remote-job-v1\n";
const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "csh", "tcsh", "busybox", "env", "sudo",
    "su", "doas", "xargs",
];

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/orgs/:org_id/remote-access/settings",
            get(get_settings).put(put_settings),
        )
        .route(
            "/v1/orgs/:org_id/remote-access/host-keys",
            get(list_host_keys),
        )
        .route(
            "/v1/orgs/:org_id/remote-access/host-keys/:node_id/acknowledge",
            post(acknowledge_host_key),
        )
        .route(
            "/v1/orgs/:org_id/remote-access/sessions",
            get(list_sessions).post(create_session),
        )
        .route(
            "/v1/orgs/:org_id/remote-access/sessions/:session_id/revoke",
            post(revoke_session),
        )
        .route(
            "/v1/orgs/:org_id/remote-access/users/:user_id/revoke",
            post(revoke_user_sessions),
        )
        .route(
            "/v1/orgs/:org_id/remote-jobs/templates",
            get(list_templates).post(create_template),
        )
        .route(
            "/v1/orgs/:org_id/remote-jobs/templates/:template_id",
            delete(disable_template),
        )
        .route(
            "/v1/orgs/:org_id/remote-jobs/runs",
            get(list_runs).post(request_run),
        )
        .route(
            "/v1/orgs/:org_id/remote-jobs/runs/:run_id/approve",
            post(approve_run),
        )
        .route(
            "/v1/orgs/:org_id/remote-jobs/runs/:run_id/reject",
            post(reject_run),
        )
        .route(
            "/v1/orgs/:org_id/remote-jobs/runs/:run_id/cancel",
            post(cancel_run),
        )
        .route("/v1/nodes/:node_id/ssh-host-key", put(report_host_key))
        .route(
            "/v1/nodes/:node_id/remote-sessions/redeem",
            post(redeem_ticket),
        )
        .route(
            "/v1/nodes/:node_id/remote-sessions/:session_id/report",
            post(report_session),
        )
        .route("/v1/nodes/:node_id/remote-jobs", get(pending_jobs))
        .route("/v1/nodes/:node_id/remote-jobs/:run_id", get(job_state))
        .route(
            "/v1/nodes/:node_id/remote-jobs/:run_id/claim",
            post(claim_job),
        )
        .route(
            "/v1/nodes/:node_id/remote-jobs/:run_id/result",
            post(job_result),
        )
}

// ---------------------------------------------------------------------------
// Keys

fn derived_key(master: &[u8], label: &[u8], org_id: &str) -> [u8; 32] {
    Sha256::new()
        .chain_update(label)
        .chain_update(master)
        .chain_update(org_id.as_bytes())
        .finalize()
        .into()
}

fn seal(master: &[u8], org_id: &str, plaintext: &[u8]) -> Result<String, ApiError> {
    let cipher = ChaCha20Poly1305::new_from_slice(&derived_key(
        master,
        b"blaktail-remote-ssh-ca-seal-v1",
        org_id,
    ))
    .map_err(|_| ApiError::CorruptData)?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| ApiError::CorruptData)?;
    let mut packed = nonce.to_vec();
    packed.extend(ciphertext);
    Ok(format!("{SEALED_PREFIX}{}", STANDARD.encode(packed)))
}

fn open(master: &[u8], org_id: &str, sealed: &str) -> Result<Vec<u8>, ApiError> {
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
    ChaCha20Poly1305::new_from_slice(&derived_key(
        master,
        b"blaktail-remote-ssh-ca-seal-v1",
        org_id,
    ))
    .map_err(|_| ApiError::CorruptData)?
    .decrypt(Nonce::from_slice(nonce), ciphertext)
    .map_err(|_| ApiError::CorruptData)
}

/// Per-organisation job signing key, derived from the coordinator secret so
/// it is never stored and a database write alone cannot sign a job.
pub(crate) fn job_signing_key(master: &[u8], org_id: &str) -> SigningKey {
    SigningKey::from_bytes(&derived_key(
        master,
        b"blaktail-remote-job-signing-v1",
        org_id,
    ))
}

pub(crate) fn job_public_key(master: &[u8], org_id: &str) -> String {
    STANDARD.encode(job_signing_key(master, org_id).verifying_key().as_bytes())
}

fn new_ca(master: &[u8], org_id: &str) -> Result<(String, String), ApiError> {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let keypair = ssh_key::private::Ed25519Keypair::from_seed(&seed);
    seed.fill(0);
    let private = ssh_key::PrivateKey::from(keypair);
    let public = private
        .public_key()
        .to_openssh()
        .map_err(|_| ApiError::CorruptData)?;
    let pem = private
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|_| ApiError::CorruptData)?;
    Ok((public, seal(master, org_id, pem.as_bytes())?))
}

/// Parses an OpenSSH Ed25519 public key and returns it without its comment
/// plus its SHA-256 fingerprint.
pub(crate) fn normalise_ed25519_key(value: &str) -> Result<(String, String), ApiError> {
    let key = ssh_key::PublicKey::from_openssh(value.trim())
        .map_err(|_| ApiError::BadRequest("SSH host key is not an OpenSSH public key".into()))?;
    if key.algorithm() != ssh_key::Algorithm::Ed25519 {
        return Err(ApiError::BadRequest(
            "SSH host key must be ssh-ed25519".into(),
        ));
    }
    let key = ssh_key::PublicKey::new(key.key_data().clone(), "");
    let fingerprint = key.fingerprint(ssh_key::HashAlg::Sha256).to_string();
    let text = key.to_openssh().map_err(|_| ApiError::CorruptData)?;
    Ok((text.trim().to_owned(), fingerprint))
}

pub(crate) struct CertificateRequest<'a> {
    pub(crate) session_id: Uuid,
    pub(crate) user_id: &'a str,
    pub(crate) os_user: &'a str,
    pub(crate) public_key: &'a str,
    pub(crate) source_addresses: &'a [String],
    pub(crate) valid_before: i64,
}

/// Signs a session-only user certificate: one principal, the gateway's
/// overlay address as `source-address`, and only `permit-pty`.
pub(crate) fn sign_user_certificate(
    ca_pem: &[u8],
    request: &CertificateRequest<'_>,
) -> Result<(String, u64), ApiError> {
    let ca = ssh_key::PrivateKey::from_openssh(ca_pem).map_err(|_| ApiError::CorruptData)?;
    let subject = ssh_key::PublicKey::from_openssh(request.public_key.trim()).map_err(|_| {
        ApiError::BadRequest("session key must be an OpenSSH Ed25519 public key".into())
    })?;
    if subject.algorithm() != ssh_key::Algorithm::Ed25519 {
        return Err(ApiError::BadRequest(
            "session key must be ssh-ed25519".into(),
        ));
    }
    if request.source_addresses.is_empty() {
        return Err(ApiError::Conflict(
            "the gateway has no overlay address".into(),
        ));
    }
    let mut nonce = vec![0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let serial = OsRng.next_u64();
    let valid_after = (now() - 30).max(0) as u64;
    let mut builder = ssh_key::certificate::Builder::new(
        nonce,
        subject.key_data().clone(),
        valid_after,
        request.valid_before.max(0) as u64,
    )
    .map_err(|_| ApiError::CorruptData)?;
    let failed = |_| ApiError::CorruptData;
    builder
        .serial(serial)
        .map_err(failed)?
        .cert_type(ssh_key::certificate::CertType::User)
        .map_err(failed)?
        .key_id(format!(
            "blaktail-session:{}:{}",
            request.session_id, request.user_id
        ))
        .map_err(failed)?
        .valid_principal(request.os_user)
        .map_err(failed)?
        .critical_option("source-address", request.source_addresses.join(","))
        .map_err(failed)?
        .extension("permit-pty", "")
        .map_err(failed)?;
    let certificate = builder.sign(&ca).map_err(failed)?;
    Ok((
        certificate
            .to_openssh()
            .map_err(|_| ApiError::CorruptData)?,
        serial,
    ))
}

// ---------------------------------------------------------------------------
// Node helpers

#[derive(Clone)]
pub(crate) struct NodeStatus {
    pub(crate) name: String,
    pub(crate) addresses: Vec<String>,
    pub(crate) suspended: bool,
    pub(crate) credential_expires_at: i64,
    pub(crate) capabilities: Vec<String>,
    pub(crate) last_seen_at: Option<i64>,
}

impl NodeStatus {
    fn inactive_reason(&self) -> Option<&'static str> {
        if self.suspended {
            Some("suspended")
        } else if self.credential_expires_at <= now() {
            Some("credential_expired")
        } else {
            None
        }
    }

    fn has(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|value| value == capability)
    }

    /// Overlay host addresses without prefix length.
    pub(crate) fn host_addresses(&self) -> Vec<String> {
        self.addresses
            .iter()
            .filter_map(|address| {
                let (ip, prefix) = address.split_once('/').unwrap_or((address, ""));
                let host = match prefix {
                    "" => true,
                    "32" => !ip.contains(':'),
                    "128" => ip.contains(':'),
                    _ => false,
                };
                host.then(|| ip.to_owned())
            })
            .collect()
    }
}

/// Loads one live (not revoked or deleted) node of the organisation.
async fn node_status(
    pool: &sqlx::AnyPool,
    org_id: &str,
    node_id: Uuid,
) -> Result<Option<NodeStatus>, ApiError> {
    let Some(row) = sqlx::query(
        "SELECT name,allowed_ips_json,CASE WHEN suspended_at IS NULL THEN 0 ELSE 1 END,credential_expires_at,capabilities_json,last_seen_at FROM nodes WHERE id=$1 AND org_id=$2 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(node_id.to_string())
    .bind(org_id)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };
    Ok(Some(NodeStatus {
        name: row.try_get(0)?,
        addresses: serde_json::from_str(&row.try_get::<String, _>(1)?).unwrap_or_default(),
        suspended: row.try_get::<i64, _>(2)? != 0,
        credential_expires_at: row.try_get(3)?,
        capabilities: serde_json::from_str(&row.try_get::<String, _>(4).unwrap_or_default())
            .unwrap_or_default(),
        last_seen_at: row.try_get(5)?,
    }))
}

/// Authenticates a node token and returns the node's organisation.
async fn authenticate_node(
    s: &AppState,
    node_id: Uuid,
    headers: &HeaderMap,
) -> Result<String, ApiError> {
    let row = sqlx::query(
        "SELECT org_id,credential_expires_at,CASE WHEN suspended_at IS NULL THEN 0 ELSE 1 END FROM nodes WHERE id=$1 AND token_hash=$2 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(node_id.to_string())
    .bind(bearer(headers)?)
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

// ---------------------------------------------------------------------------
// Settings

struct SettingsRow {
    gateway_node_id: Option<Uuid>,
    gateway_url: String,
    ca_public_key: String,
    ca_private_sealed: String,
    updated_at: i64,
    updated_by: String,
}

async fn load_settings(
    pool: &sqlx::AnyPool,
    org_id: &str,
) -> Result<Option<SettingsRow>, ApiError> {
    let Some(row) = sqlx::query(
        "SELECT gateway_node_id,gateway_url,ca_public_key,ca_private_sealed,updated_at,updated_by FROM remote_access_settings WHERE org_id=$1",
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };
    Ok(Some(SettingsRow {
        gateway_node_id: row
            .try_get::<Option<String>, _>(0)?
            .and_then(|id| Uuid::parse_str(&id).ok()),
        gateway_url: row.try_get(1)?,
        ca_public_key: row.try_get(2)?,
        ca_private_sealed: row.try_get(3)?,
        updated_at: row.try_get(4)?,
        updated_by: row.try_get(5)?,
    }))
}

/// What a device agent needs: the SSH user CA and gateway addresses (to
/// trust the CA only for connections from the gateway) and the job key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AgentView {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) user_ca: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) gateway_addresses: Vec<String>,
    pub(crate) job_signing_key: String,
}

pub(crate) async fn agent_view(
    s: &AppState,
    org_id: &str,
    node_id: Uuid,
) -> Result<AgentView, ApiError> {
    let mut view = AgentView {
        job_signing_key: job_public_key(&s.auth_hmac_secret, org_id),
        ..AgentView::default()
    };
    let Some(settings) = load_settings(&s.store.pool, org_id).await? else {
        return Ok(view);
    };
    let Some(gateway_id) = settings.gateway_node_id.filter(|id| *id != node_id) else {
        return Ok(view);
    };
    if let Some(gateway) = node_status(&s.store.pool, org_id, gateway_id).await? {
        if gateway.inactive_reason().is_none() {
            view.user_ca = settings.ca_public_key;
            view.gateway_addresses = gateway.host_addresses();
        }
    }
    Ok(view)
}

#[derive(Serialize)]
struct SettingsView {
    configured: bool,
    gateway_node_id: Option<Uuid>,
    gateway_name: Option<String>,
    gateway_state: &'static str,
    gateway_url: String,
    ca_public_key: String,
    updated_at: Option<i64>,
    updated_by: String,
    ticket_ttl_seconds: i64,
    max_session_seconds: i64,
    idle_timeout_seconds: i64,
}

async fn settings_view(s: &AppState, org_id: &str) -> Result<SettingsView, ApiError> {
    let settings = load_settings(&s.store.pool, org_id).await?;
    let mut view = SettingsView {
        configured: false,
        gateway_node_id: None,
        gateway_name: None,
        gateway_state: "not_configured",
        gateway_url: String::new(),
        ca_public_key: String::new(),
        updated_at: None,
        updated_by: String::new(),
        ticket_ttl_seconds: TICKET_TTL_SECS,
        max_session_seconds: MAX_SESSION_SECS,
        idle_timeout_seconds: IDLE_TIMEOUT_SECS,
    };
    if let Some(settings) = settings {
        view.configured = settings.gateway_node_id.is_some() && !settings.gateway_url.is_empty();
        view.gateway_node_id = settings.gateway_node_id;
        view.gateway_url = settings.gateway_url;
        view.ca_public_key = settings.ca_public_key;
        view.updated_at = Some(settings.updated_at);
        view.updated_by = settings.updated_by;
        if let Some(id) = settings.gateway_node_id {
            view.gateway_state = match node_status(&s.store.pool, org_id, id).await? {
                None => "removed",
                Some(node) => {
                    view.gateway_name = Some(node.name.clone());
                    match node.inactive_reason() {
                        Some(reason) => reason,
                        None if node
                            .last_seen_at
                            .is_some_and(|seen| now() - seen <= crate::NODE_ONLINE_SECS) =>
                        {
                            "online"
                        }
                        None => "offline",
                    }
                }
            };
        }
    }
    Ok(view)
}

async fn get_settings(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<SettingsView>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewNetwork)?;
    Ok(Json(settings_view(&s, &org_id.to_string()).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsInput {
    gateway_node_id: Option<Uuid>,
    #[serde(default)]
    gateway_url: String,
}

fn validate_gateway_url(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    let parsed = url::Url::parse(value)
        .map_err(|_| ApiError::BadRequest("gateway URL is not a valid URL".into()))?;
    let local = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1"));
    let secure = parsed.scheme() == "wss" || (parsed.scheme() == "ws" && local);
    if !secure
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || value.len() > 200
    {
        return Err(ApiError::BadRequest(
            "gateway URL must be a wss:// URL without credentials, query or fragment".into(),
        ));
    }
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}

async fn put_settings(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<SettingsInput>,
) -> Result<Json<SettingsView>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    // Owner-only: the gateway becomes a path into every device that trusts
    // the organisation CA.
    require(&session, Permission::ManageSecurity)?;
    let org = org_id.to_string();
    let gateway_url = validate_gateway_url(&input.gateway_url)?;
    if let Some(id) = input.gateway_node_id {
        let node = node_status(&s.store.pool, &org, id)
            .await?
            .ok_or(ApiError::NotFound)?;
        if let Some(reason) = node.inactive_reason() {
            return Err(ApiError::Conflict(format!(
                "the gateway device is {}",
                reason.replace('_', " ")
            )));
        }
    }
    let existing = load_settings(&s.store.pool, &org).await?;
    let mut tx = s.store.pool.begin().await?;
    let created_ca = existing.is_none();
    match existing {
        Some(_) => {
            sqlx::query(
                "UPDATE remote_access_settings SET gateway_node_id=$1,gateway_url=$2,updated_at=$3,updated_by=$4 WHERE org_id=$5",
            )
            .bind(input.gateway_node_id.map(|id| id.to_string()))
            .bind(&gateway_url)
            .bind(now())
            .bind(&session.user_id)
            .bind(&org)
            .execute(&mut *tx)
            .await?;
        }
        None => {
            let (public, sealed) = new_ca(&s.auth_hmac_secret, &org)?;
            sqlx::query(
                "INSERT INTO remote_access_settings(org_id,gateway_node_id,gateway_url,ca_public_key,ca_private_sealed,updated_at,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7)",
            )
            .bind(&org)
            .bind(input.gateway_node_id.map(|id| id.to_string()))
            .bind(&gateway_url)
            .bind(public)
            .bind(sealed)
            .bind(now())
            .bind(&session.user_id)
            .execute(&mut *tx)
            .await?;
        }
    }
    append_audit(
        &mut tx,
        org_id,
        &session,
        "remote_access.settings_updated",
        "organisation",
        Some(&org),
        &serde_json::json!({
            "gateway_node_id": input.gateway_node_id,
            "gateway_url": gateway_url,
            "ssh_ca_created": created_ca,
        }),
    )
    .await?;
    // Agents learn the CA and gateway address from their next peer map.
    bump_control_revision(&mut tx, &org).await?;
    tx.commit().await?;
    Ok(Json(settings_view(&s, &org).await?))
}

// ---------------------------------------------------------------------------
// Host keys

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostKeyReport {
    public_key: String,
}

#[derive(Serialize)]
struct HostKeyReportResult {
    state: &'static str,
    fingerprint: String,
}

async fn report_host_key(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<HostKeyReport>,
) -> Result<Json<HostKeyReportResult>, ApiError> {
    let org = authenticate_node(&s, node_id, &headers).await?;
    if input.public_key.len() > 1024 {
        return Err(ApiError::BadRequest("SSH host key is too long".into()));
    }
    let (key, fingerprint) = normalise_ed25519_key(&input.public_key)?;
    let mut tx = s.store.pool.begin().await?;
    let existing = sqlx::query(
        "SELECT public_key,pending_key FROM remote_host_keys WHERE node_id=$1 AND org_id=$2",
    )
    .bind(node_id.to_string())
    .bind(&org)
    .fetch_optional(&mut *tx)
    .await?;
    let state = match existing {
        None => {
            sqlx::query(
                "INSERT INTO remote_host_keys(node_id,org_id,public_key,fingerprint,reported_at) VALUES($1,$2,$3,$4,$5)",
            )
            .bind(node_id.to_string())
            .bind(&org)
            .bind(&key)
            .bind(&fingerprint)
            .bind(now())
            .execute(&mut *tx)
            .await?;
            "pinned"
        }
        Some(row) => {
            let pinned: String = row.try_get(0)?;
            let pending: Option<String> = row.try_get(1)?;
            if pinned == key {
                sqlx::query(
                    "UPDATE remote_host_keys SET reported_at=$1,pending_key=NULL,pending_fingerprint=NULL,pending_reported_at=NULL WHERE node_id=$2",
                )
                .bind(now())
                .bind(node_id.to_string())
                .execute(&mut *tx)
                .await?;
                "pinned"
            } else {
                if pending.as_deref() != Some(key.as_str()) {
                    sqlx::query(
                        "UPDATE remote_host_keys SET pending_key=$1,pending_fingerprint=$2,pending_reported_at=$3 WHERE node_id=$4",
                    )
                    .bind(&key)
                    .bind(&fingerprint)
                    .bind(now())
                    .bind(node_id.to_string())
                    .execute(&mut *tx)
                    .await?;
                    let org_uuid = Uuid::parse_str(&org).map_err(|_| ApiError::CorruptData)?;
                    append_audit(
                        &mut tx,
                        org_uuid,
                        &node_session(node_id),
                        "remote_session.host_key_changed",
                        "node",
                        Some(&node_id.to_string()),
                        &serde_json::json!({ "pending_fingerprint": fingerprint }),
                    )
                    .await?;
                }
                "pending_acknowledgement"
            }
        }
    };
    tx.commit().await?;
    Ok(Json(HostKeyReportResult { state, fingerprint }))
}

fn node_session(node_id: Uuid) -> Session {
    Session {
        user_id: format!("node:{node_id}"),
        role: Role::Member,
        name: "Device agent".into(),
        email: String::new(),
    }
}

#[derive(Serialize)]
struct HostKeyView {
    node_id: Uuid,
    fingerprint: String,
    reported_at: i64,
    pending_fingerprint: Option<String>,
    pending_reported_at: Option<i64>,
    acknowledged_at: Option<i64>,
}

async fn list_host_keys(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<HostKeyView>>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewNetwork)?;
    let rows = sqlx::query(
        "SELECT node_id,fingerprint,reported_at,pending_fingerprint,pending_reported_at,acknowledged_at FROM remote_host_keys WHERE org_id=$1 ORDER BY node_id",
    )
    .bind(org_id.to_string())
    .fetch_all(&s.store.pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(HostKeyView {
                node_id: Uuid::parse_str(&row.try_get::<String, _>(0)?)
                    .map_err(|_| ApiError::CorruptData)?,
                fingerprint: row.try_get(1)?,
                reported_at: row.try_get(2)?,
                pending_fingerprint: row.try_get(3)?,
                pending_reported_at: row.try_get(4)?,
                acknowledged_at: row.try_get(5)?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()
        .map(Json)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcknowledgeInput {
    /// The pending fingerprint the administrator compared out of band.
    fingerprint: String,
}

async fn acknowledge_host_key(
    State(s): State<AppState>,
    UrlPath((org_id, node_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<AcknowledgeInput>,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManagePeers)?;
    let mut tx = s.store.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE remote_host_keys SET public_key=pending_key,fingerprint=pending_fingerprint,reported_at=pending_reported_at,pending_key=NULL,pending_fingerprint=NULL,pending_reported_at=NULL,acknowledged_at=$1,acknowledged_by=$2 WHERE node_id=$3 AND org_id=$4 AND pending_fingerprint=$5",
    )
    .bind(now())
    .bind(&session.user_id)
    .bind(node_id.to_string())
    .bind(org_id.to_string())
    .bind(input.fingerprint.trim())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::Conflict(
            "no pending host key with that fingerprint".into(),
        ));
    }
    append_audit(
        &mut tx,
        org_id,
        &session,
        "remote_session.host_key_acknowledged",
        "node",
        Some(&node_id.to_string()),
        &serde_json::json!({ "fingerprint": input.fingerprint.trim() }),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Session policy

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SessionKind {
    Ssh,
    Rdp,
}

impl SessionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
        }
    }

    fn port(self) -> u16 {
        match self {
            Self::Ssh => 22,
            Self::Rdp => 3389,
        }
    }
}

fn valid_rdp_user(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 64
        && user
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '\\' | '@'))
}

/// Why a path is refused. The message is safe to show and to audit.
struct Denial(String);

impl Denial {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

struct Path {
    gateway: NodeStatus,
    target: NodeStatus,
    host_key: Option<String>,
}

/// Re-runs the coordinator's own policy compiler for gateway → target. The
/// result matches what both agents enforce, so a browser session can never
/// reach a port or OS user that an ordinary device on the gateway's tags
/// could not.
async fn check_path(
    s: &AppState,
    org_id: Uuid,
    gateway_id: Uuid,
    target_id: Uuid,
    kind: SessionKind,
    os_user: &str,
) -> Result<Result<Path, Denial>, ApiError> {
    let org = org_id.to_string();
    let Some(target) = node_status(&s.store.pool, &org, target_id).await? else {
        return Err(ApiError::NotFound);
    };
    let Some(gateway) = node_status(&s.store.pool, &org, gateway_id).await? else {
        return Ok(Err(Denial::new("the remote access gateway was removed")));
    };
    if gateway_id == target_id {
        return Ok(Err(Denial::new(
            "the gateway cannot open a session to itself",
        )));
    }
    if let Some(reason) = target.inactive_reason() {
        return Ok(Err(Denial::new(format!(
            "the device is {}",
            reason.replace('_', " ")
        ))));
    }
    if let Some(reason) = gateway.inactive_reason() {
        return Ok(Err(Denial::new(format!(
            "the gateway is {}",
            reason.replace('_', " ")
        ))));
    }
    let acl: Acl = serde_json::from_str(&load_acl_row(&s.store, org_id).await?.json)
        .map_err(|_| ApiError::CorruptData)?;
    let ctx = PostureContext::load(&s.store.pool, &org).await?;
    let (Some(gateway_facts), Some(target_facts)) =
        (ctx.facts.get(&gateway_id), ctx.facts.get(&target_id))
    else {
        return Ok(Err(Denial::new("the device or gateway is not active")));
    };
    let gateway_subject = device_subject(gateway_facts, &ctx);
    let target_subject = device_subject(target_facts, &ctx);
    if !acl.allows(&gateway_subject, &target_subject)
        || !acl.allows(&target_subject, &gateway_subject)
    {
        return Ok(Err(Denial::new(
            "access policy does not pair the gateway with this device",
        )));
    }
    let ingress =
        acl.peer_ingress_for(&gateway_subject, &target_subject, target.has(CAP_SSH_USERS));
    let port = kind.port();
    let allowed = ingress.tcp.iter().cloned().collect::<BTreeSet<_>>();
    let denied = ingress.deny_tcp.iter().cloned().collect::<BTreeSet<_>>();
    if specs_cover(&denied, port) || !(ingress.all || specs_cover(&allowed, port)) {
        return Ok(Err(Denial::new(format!(
            "access policy does not let the gateway reach TCP {port} on this device"
        ))));
    }
    let mut host_key = None;
    if kind == SessionKind::Ssh {
        if !acl.allows_ssh(&gateway_subject, &target_subject, os_user) {
            return Ok(Err(Denial::new(format!(
                "no SSH rule lets the gateway log in to this device as {os_user}"
            ))));
        }
        if !target.has(CAP_REMOTE_SSH) {
            return Ok(Err(Denial::new(
                "this device has not installed the organisation SSH CA (opt-in sshd drop-in)",
            )));
        }
        let row = sqlx::query(
            "SELECT public_key,pending_key FROM remote_host_keys WHERE node_id=$1 AND org_id=$2",
        )
        .bind(target_id.to_string())
        .bind(&org)
        .fetch_optional(&s.store.pool)
        .await?;
        match row {
            None => {
                return Ok(Err(Denial::new(
                    "this device has not reported an SSH host key",
                )))
            }
            Some(row) => {
                if row.try_get::<Option<String>, _>(1)?.is_some() {
                    return Ok(Err(Denial::new(
                        "this device reported a new SSH host key; an administrator must acknowledge it",
                    )));
                }
                host_key = Some(row.try_get::<String, _>(0)?);
            }
        }
    }
    Ok(Ok(Path {
        gateway,
        target,
        host_key,
    }))
}

// ---------------------------------------------------------------------------
// Console: sessions

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSession {
    kind: SessionKind,
    target_node_id: Uuid,
    os_user: String,
    reason: String,
    #[serde(default)]
    duration_minutes: Option<i64>,
}

#[derive(Serialize)]
struct IssuedSession {
    session_id: Uuid,
    kind: SessionKind,
    ticket: String,
    gateway_url: String,
    ticket_expires_at: i64,
    max_end_at: i64,
    idle_timeout_seconds: i64,
    target_name: String,
    os_user: String,
}

fn validate_reason(reason: &str) -> Result<String, ApiError> {
    let reason = reason.trim();
    if reason.chars().count() < 4
        || reason.chars().count() > 200
        || reason.chars().any(char::is_control)
    {
        return Err(ApiError::BadRequest(
            "give an access reason of 4 to 200 characters".into(),
        ));
    }
    Ok(reason.to_owned())
}

async fn audit_denial(
    s: &AppState,
    org_id: Uuid,
    session: &Session,
    target: Uuid,
    details: serde_json::Value,
) -> Result<(), ApiError> {
    let mut connection = s.store.pool.acquire().await?;
    append_audit(
        &mut connection,
        org_id,
        session,
        "remote_session.denied",
        "node",
        Some(&target.to_string()),
        &details,
    )
    .await
}

async fn create_session(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<CreateSession>,
) -> Result<(StatusCode, Json<IssuedSession>), ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::UseRemoteSessions)?;
    let org = org_id.to_string();
    let reason = validate_reason(&input.reason)?;
    let os_user = input.os_user.trim().to_owned();
    let valid_user = match input.kind {
        SessionKind::Ssh => os_user != "*" && valid_ssh_os_user(&os_user),
        SessionKind::Rdp => valid_rdp_user(&os_user),
    };
    if !valid_user {
        return Err(ApiError::BadRequest("OS user name is not valid".into()));
    }
    let duration = input.duration_minutes.unwrap_or(MAX_SESSION_SECS / 60);
    if !(1..=MAX_SESSION_SECS / 60).contains(&duration) {
        return Err(ApiError::BadRequest(
            "session length must be 1 to 30 minutes".into(),
        ));
    }
    let settings = load_settings(&s.store.pool, &org).await?;
    let (Some(gateway_id), Some(settings)) = (
        settings.as_ref().and_then(|row| row.gateway_node_id),
        settings.as_ref(),
    ) else {
        return Err(ApiError::Conflict(
            "browser remote access is not set up for this organisation".into(),
        ));
    };
    if settings.gateway_url.is_empty() {
        return Err(ApiError::Conflict(
            "browser remote access has no gateway URL".into(),
        ));
    }
    let path = match check_path(
        &s,
        org_id,
        gateway_id,
        input.target_node_id,
        input.kind,
        &os_user,
    )
    .await?
    {
        Ok(path) => path,
        Err(Denial(message)) => {
            audit_denial(
                &s,
                org_id,
                &session,
                input.target_node_id,
                serde_json::json!({
                    "kind": input.kind.as_str(),
                    "os_user": os_user,
                    "reason": reason,
                    "denied_because": message,
                }),
            )
            .await?;
            return Err(ApiError::Conflict(message));
        }
    };
    let issued_at = now();
    let mut tx = s.store.pool.begin().await?;
    let live: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM remote_sessions WHERE org_id=$1 AND user_id=$2 AND target_node_id=$3 AND revoked_at IS NULL AND ended_at IS NULL AND ((redeemed_at IS NULL AND ticket_expires_at>$4) OR (redeemed_at IS NOT NULL AND max_end_at>$4 AND COALESCE(last_report_at,redeemed_at)>$5))",
    )
    .bind(&org)
    .bind(&session.user_id)
    .bind(input.target_node_id.to_string())
    .bind(issued_at)
    .bind(issued_at - REPORT_STALE_SECS)
    .fetch_one(&mut *tx)
    .await?;
    if live > 0 {
        return Err(ApiError::Conflict(
            "you already have a session open to this device; end it first".into(),
        ));
    }
    let id = Uuid::new_v4();
    let ticket = secret("btrs");
    let ticket_expires_at = issued_at + TICKET_TTL_SECS;
    let max_end_at = issued_at + duration * 60;
    sqlx::query(
        "INSERT INTO remote_sessions(id,org_id,kind,user_id,user_name,user_email,user_role,gateway_node_id,target_node_id,os_user,reason,ticket_hash,created_at,ticket_expires_at,max_end_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
    )
    .bind(id.to_string())
    .bind(&org)
    .bind(input.kind.as_str())
    .bind(&session.user_id)
    .bind(&session.name)
    .bind(&session.email)
    .bind(session.role.as_str())
    .bind(gateway_id.to_string())
    .bind(input.target_node_id.to_string())
    .bind(&os_user)
    .bind(&reason)
    .bind(hash(&ticket))
    .bind(issued_at)
    .bind(ticket_expires_at)
    .bind(max_end_at)
    .execute(&mut *tx)
    .await?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "remote_session.issued",
        "node",
        Some(&input.target_node_id.to_string()),
        &serde_json::json!({
            "session_id": id,
            "kind": input.kind.as_str(),
            "target_name": path.target.name,
            "gateway_node_id": gateway_id,
            "os_user": os_user,
            "reason": reason,
            "ticket_expires_at": ticket_expires_at,
            "max_end_at": max_end_at,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(IssuedSession {
            session_id: id,
            kind: input.kind,
            ticket,
            gateway_url: settings.gateway_url.clone(),
            ticket_expires_at,
            max_end_at,
            idle_timeout_seconds: IDLE_TIMEOUT_SECS,
            target_name: path.target.name,
            os_user,
        }),
    ))
}

#[derive(Serialize)]
struct SessionView {
    id: Uuid,
    kind: String,
    status: &'static str,
    user_id: String,
    user_name: String,
    target_node_id: Uuid,
    gateway_node_id: Uuid,
    os_user: String,
    reason: String,
    created_at: i64,
    redeemed_at: Option<i64>,
    ended_at: Option<i64>,
    end_reason: Option<String>,
    max_end_at: i64,
    revoked_at: Option<i64>,
    bytes_to_target: i64,
    bytes_from_target: i64,
}

fn session_status(
    redeemed_at: Option<i64>,
    ended_at: Option<i64>,
    revoked_at: Option<i64>,
    ticket_expires_at: i64,
    max_end_at: i64,
    last_report_at: Option<i64>,
    at: i64,
) -> &'static str {
    if ended_at.is_some() {
        "ended"
    } else if revoked_at.is_some() {
        "revoked"
    } else if let Some(redeemed) = redeemed_at {
        if max_end_at <= at || last_report_at.unwrap_or(redeemed) <= at - REPORT_STALE_SECS {
            "ended"
        } else {
            "active"
        }
    } else if ticket_expires_at <= at {
        "expired"
    } else {
        "issued"
    }
}

async fn list_sessions(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<SessionView>>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::UseRemoteSessions)?;
    let rows = sqlx::query(
        "SELECT id,kind,user_id,user_name,target_node_id,gateway_node_id,os_user,reason,created_at,redeemed_at,ended_at,end_reason,max_end_at,revoked_at,bytes_to_target,bytes_from_target,ticket_expires_at,last_report_at FROM remote_sessions WHERE org_id=$1 ORDER BY created_at DESC LIMIT $2",
    )
    .bind(org_id.to_string())
    .bind(LIST_LIMIT)
    .fetch_all(&s.store.pool)
    .await?;
    let at = now();
    rows.into_iter()
        .map(|row| {
            let parse = |value: String| Uuid::parse_str(&value).map_err(|_| ApiError::CorruptData);
            let redeemed_at: Option<i64> = row.try_get(9)?;
            let ended_at: Option<i64> = row.try_get(10)?;
            let max_end_at: i64 = row.try_get(12)?;
            let revoked_at: Option<i64> = row.try_get(13)?;
            Ok(SessionView {
                id: parse(row.try_get(0)?)?,
                kind: row.try_get(1)?,
                status: session_status(
                    redeemed_at,
                    ended_at,
                    revoked_at,
                    row.try_get(16)?,
                    max_end_at,
                    row.try_get(17)?,
                    at,
                ),
                user_id: row.try_get(2)?,
                user_name: row.try_get(3)?,
                target_node_id: parse(row.try_get(4)?)?,
                gateway_node_id: parse(row.try_get(5)?)?,
                os_user: row.try_get(6)?,
                reason: row.try_get(7)?,
                created_at: row.try_get(8)?,
                redeemed_at,
                ended_at,
                end_reason: row.try_get(11)?,
                max_end_at,
                revoked_at,
                bytes_to_target: row.try_get(14)?,
                bytes_from_target: row.try_get(15)?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()
        .map(Json)
}

async fn revoke_session(
    State(s): State<AppState>,
    UrlPath((org_id, session_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::UseRemoteSessions)?;
    let mut tx = s.store.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE remote_sessions SET revoked_at=$1,revoked_by=$2 WHERE id=$3 AND org_id=$4 AND revoked_at IS NULL AND ended_at IS NULL",
    )
    .bind(now())
    .bind(&session.user_id)
    .bind(session_id.to_string())
    .bind(org_id.to_string())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::NotFound);
    }
    append_audit(
        &mut tx,
        org_id,
        &session,
        "remote_session.revoked",
        "remote_session",
        Some(&session_id.to_string()),
        &serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct RevokedCount {
    revoked: u64,
}

/// The console's service assertion action for directory deprovisioning.
pub(crate) const REVOKE_USER_ACTION: &str = "remote_access.revoke_user";

/// Called by the console when a person is suspended, removed or loses the
/// remote-session permission, so their open sessions end at the gateway's
/// next report. SCIM and IdP role sync have no person behind them, so they
/// send a service assertion scoped to this one action.
async fn revoke_user_sessions(
    State(s): State<AppState>,
    UrlPath((org_id, user_id)): UrlPath<(Uuid, String)>,
    headers: HeaderMap,
) -> Result<Json<RevokedCount>, ApiError> {
    let claims = crate::verified_console_assertion(&s, &headers, org_id).await?;
    let session = if claims.role == "service" {
        if claims.action.as_deref() != Some(REVOKE_USER_ACTION)
            || !claims.user_id.starts_with("system:")
        {
            return Err(ApiError::Forbidden);
        }
        // Read-only role, used only to attribute the audit row.
        Session {
            user_id: claims.user_id,
            role: Role::Auditor,
            name: claims.name,
            email: claims.email,
        }
    } else {
        if claims.action.is_some() {
            return Err(ApiError::Unauthorized);
        }
        let session = Session {
            role: claims.role.parse().map_err(|_| ApiError::Unauthorized)?,
            user_id: claims.user_id,
            name: claims.name,
            email: claims.email,
        };
        require(&session, Permission::ManageSecurity)?;
        session
    };
    let mut tx = s.store.pool.begin().await?;
    let revoked = sqlx::query(
        "UPDATE remote_sessions SET revoked_at=$1,revoked_by=$2 WHERE org_id=$3 AND user_id=$4 AND revoked_at IS NULL AND ended_at IS NULL",
    )
    .bind(now())
    .bind(&session.user_id)
    .bind(org_id.to_string())
    .bind(&user_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if revoked > 0 {
        append_audit(
            &mut tx,
            org_id,
            &session,
            "remote_session.revoked",
            "user",
            Some(&user_id),
            &serde_json::json!({ "sessions": revoked }),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Json(RevokedCount { revoked }))
}

// ---------------------------------------------------------------------------
// Gateway: redeem and report

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemInput {
    ticket: String,
    /// The gateway's ephemeral OpenSSH Ed25519 public key (SSH only).
    #[serde(default)]
    public_key: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct RedeemedSession {
    pub(crate) session_id: Uuid,
    pub(crate) kind: SessionKind,
    pub(crate) target_node_id: Uuid,
    pub(crate) target_name: String,
    pub(crate) target_address: String,
    pub(crate) port: u16,
    pub(crate) os_user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) host_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) certificate: Option<String>,
    pub(crate) max_end_at: i64,
    pub(crate) idle_timeout_seconds: i64,
    pub(crate) report_interval_seconds: i64,
}

struct SessionRow {
    id: Uuid,
    org_id: Uuid,
    kind: SessionKind,
    actor: Session,
    target_node_id: Uuid,
    os_user: String,
    max_end_at: i64,
    redeemed_at: Option<i64>,
    ended_at: Option<i64>,
    revoked_at: Option<i64>,
    created_at: i64,
}

const SESSION_COLUMNS: &str = "id,org_id,kind,user_id,user_name,user_email,user_role,gateway_node_id,target_node_id,os_user,max_end_at,redeemed_at,ended_at,revoked_at,created_at";

fn session_row(row: &sqlx::any::AnyRow) -> Result<SessionRow, ApiError> {
    let parse = |value: String| Uuid::parse_str(&value).map_err(|_| ApiError::CorruptData);
    Ok(SessionRow {
        id: parse(row.try_get(0)?)?,
        org_id: parse(row.try_get(1)?)?,
        kind: match row.try_get::<String, _>(2)?.as_str() {
            "ssh" => SessionKind::Ssh,
            "rdp" => SessionKind::Rdp,
            _ => return Err(ApiError::CorruptData),
        },
        actor: Session {
            user_id: row.try_get(3)?,
            name: row.try_get(4)?,
            email: row.try_get(5)?,
            role: row
                .try_get::<String, _>(6)?
                .parse()
                .map_err(|_| ApiError::CorruptData)?,
        },
        target_node_id: parse(row.try_get(8)?)?,
        os_user: row.try_get(9)?,
        max_end_at: row.try_get(10)?,
        redeemed_at: row.try_get(11)?,
        ended_at: row.try_get(12)?,
        revoked_at: row.try_get(13)?,
        created_at: row.try_get(14)?,
    })
}

/// Marks a session ended once and audits it with metadata only.
async fn end_session(
    s: &AppState,
    row: &SessionRow,
    reason: &str,
    bytes: (i64, i64),
) -> Result<(), ApiError> {
    let at = now();
    let mut tx = s.store.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE remote_sessions SET ended_at=$1,end_reason=$2,bytes_to_target=$3,bytes_from_target=$4,last_report_at=$1 WHERE id=$5 AND ended_at IS NULL",
    )
    .bind(at)
    .bind(reason)
    .bind(bytes.0)
    .bind(bytes.1)
    .bind(row.id.to_string())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed > 0 {
        let action = if reason == "host_key_mismatch" {
            "remote_session.host_key_mismatch"
        } else {
            "remote_session.ended"
        };
        append_audit(
            &mut tx,
            row.org_id,
            &row.actor,
            action,
            "node",
            Some(&row.target_node_id.to_string()),
            &serde_json::json!({
                "session_id": row.id,
                "kind": row.kind.as_str(),
                "os_user": row.os_user,
                "end_reason": reason,
                "started_at": row.redeemed_at,
                "duration_seconds": row.redeemed_at.map(|started| at - started),
                "bytes_to_target": bytes.0,
                "bytes_from_target": bytes.1,
            }),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn redeem_ticket(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<RedeemInput>,
) -> Result<Json<RedeemedSession>, ApiError> {
    let org = authenticate_node(&s, node_id, &headers).await?;
    let at = now();
    // Single use: only one redeem can flip redeemed_at, and only for this
    // gateway, inside the ticket window, before any revoke.
    let changed = sqlx::query(
        "UPDATE remote_sessions SET redeemed_at=$1,last_report_at=$1 WHERE ticket_hash=$2 AND org_id=$3 AND gateway_node_id=$4 AND redeemed_at IS NULL AND revoked_at IS NULL AND ended_at IS NULL AND ticket_expires_at>$1",
    )
    .bind(at)
    .bind(hash(input.ticket.trim()))
    .bind(&org)
    .bind(node_id.to_string())
    .execute(&s.store.pool)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::Gone);
    }
    let row = sqlx::query(AssertSqlSafe(format!(
        "SELECT {SESSION_COLUMNS} FROM remote_sessions WHERE ticket_hash=$1"
    )))
    .bind(hash(input.ticket.trim()))
    .fetch_one(&s.store.pool)
    .await?;
    let row = session_row(&row)?;
    // The gateway must still be the configured one: a gateway swapped out
    // after issue cannot redeem the old organisation's tickets.
    let settings = load_settings(&s.store.pool, &org)
        .await?
        .ok_or(ApiError::Forbidden)?;
    if settings.gateway_node_id != Some(node_id) {
        end_session(&s, &row, "gateway_changed", (0, 0)).await?;
        return Err(ApiError::Forbidden);
    }
    let path = match check_path(
        &s,
        row.org_id,
        node_id,
        row.target_node_id,
        row.kind,
        &row.os_user,
    )
    .await
    {
        Ok(Ok(path)) => path,
        Ok(Err(Denial(message))) => {
            end_session(&s, &row, "policy", (0, 0)).await?;
            return Err(ApiError::Conflict(message));
        }
        Err(ApiError::NotFound) => {
            end_session(&s, &row, "target_removed", (0, 0)).await?;
            return Err(ApiError::Gone);
        }
        Err(error) => return Err(error),
    };
    // The ticket is spent: any failure from here must end and audit the
    // session rather than leave it redeemed with nothing running.
    let prepared = async {
        let target_address = path
            .target
            .host_addresses()
            .into_iter()
            .find(|address| !address.contains(':'))
            .ok_or_else(|| ApiError::Conflict("the device has no overlay IPv4 address".into()))?;
        let certificate = match row.kind {
            SessionKind::Ssh => {
                let public_key = input.public_key.as_deref().ok_or_else(|| {
                    ApiError::BadRequest("an SSH session needs a public key".into())
                })?;
                let pem = open(&s.auth_hmac_secret, &org, &settings.ca_private_sealed)?;
                let (certificate, serial) = sign_user_certificate(
                    &pem,
                    &CertificateRequest {
                        session_id: row.id,
                        user_id: &row.actor.user_id,
                        os_user: &row.os_user,
                        public_key,
                        source_addresses: &path.gateway.host_addresses(),
                        valid_before: row.max_end_at,
                    },
                )?;
                sqlx::query("UPDATE remote_sessions SET cert_serial=$1 WHERE id=$2")
                    .bind(serial.to_string())
                    .bind(row.id.to_string())
                    .execute(&s.store.pool)
                    .await?;
                Some(certificate)
            }
            SessionKind::Rdp => None,
        };
        Ok::<_, ApiError>((target_address, certificate))
    }
    .await;
    let (target_address, certificate) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            end_session(&s, &row, "error", (0, 0)).await?;
            return Err(error);
        }
    };
    let mut tx = s.store.pool.begin().await?;
    append_audit(
        &mut tx,
        row.org_id,
        &row.actor,
        "remote_session.started",
        "node",
        Some(&row.target_node_id.to_string()),
        &serde_json::json!({
            "session_id": row.id,
            "kind": row.kind.as_str(),
            "target_name": path.target.name,
            "gateway_node_id": node_id,
            "os_user": row.os_user,
            "issued_at": row.created_at,
            "max_end_at": row.max_end_at,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(RedeemedSession {
        session_id: row.id,
        kind: row.kind,
        target_node_id: row.target_node_id,
        target_name: path.target.name,
        target_address,
        port: row.kind.port(),
        os_user: row.os_user,
        host_key: path.host_key,
        certificate,
        max_end_at: row.max_end_at,
        idle_timeout_seconds: IDLE_TIMEOUT_SECS,
        report_interval_seconds: REPORT_INTERVAL_SECS,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionReport {
    #[serde(default)]
    bytes_to_target: i64,
    #[serde(default)]
    bytes_from_target: i64,
    /// Set when the gateway has ended the session itself.
    #[serde(default)]
    ended: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ReportDecision {
    pub(crate) action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
}

const GATEWAY_END_REASONS: &[&str] = &[
    "user_closed",
    "idle_timeout",
    "max_duration",
    "target_closed",
    "host_key_mismatch",
    "connect_failed",
    "auth_failed",
    "gateway_shutdown",
    "error",
];

async fn report_session(
    State(s): State<AppState>,
    UrlPath((node_id, session_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<SessionReport>,
) -> Result<Json<ReportDecision>, ApiError> {
    let org = authenticate_node(&s, node_id, &headers).await?;
    let row = sqlx::query(AssertSqlSafe(format!(
        "SELECT {SESSION_COLUMNS} FROM remote_sessions WHERE id=$1 AND org_id=$2 AND gateway_node_id=$3"
    )))
    .bind(session_id.to_string())
    .bind(&org)
    .bind(node_id.to_string())
    .fetch_optional(&s.store.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let row = session_row(&row)?;
    if row.redeemed_at.is_none() {
        return Err(ApiError::NotFound);
    }
    let bytes = (input.bytes_to_target.max(0), input.bytes_from_target.max(0));
    let terminate = |reason: &str| ReportDecision {
        action: "terminate".into(),
        reason: Some(reason.into()),
    };
    if let Some(reason) = input.ended.as_deref() {
        if !GATEWAY_END_REASONS.contains(&reason) {
            return Err(ApiError::BadRequest("unknown end reason".into()));
        }
        end_session(&s, &row, reason, bytes).await?;
        return Ok(Json(terminate(reason)));
    }
    if row.ended_at.is_some() {
        return Ok(Json(terminate("ended")));
    }
    let reason = if row.revoked_at.is_some() {
        Some("revoked".to_owned())
    } else if row.max_end_at <= now() {
        Some("max_duration".to_owned())
    } else if load_settings(&s.store.pool, &org)
        .await?
        .and_then(|settings| settings.gateway_node_id)
        != Some(node_id)
    {
        // Clearing or swapping the organisation's gateway ends live sessions
        // on the old one, not just new redeems.
        Some("gateway_changed".to_owned())
    } else {
        match check_path(
            &s,
            row.org_id,
            node_id,
            row.target_node_id,
            row.kind,
            &row.os_user,
        )
        .await
        {
            Ok(Ok(_)) => None,
            Ok(Err(Denial(message))) => Some(format!("policy: {message}")),
            Err(ApiError::NotFound) => Some("target_removed".to_owned()),
            Err(error) => return Err(error),
        }
    };
    if let Some(reason) = reason {
        end_session(&s, &row, &reason, bytes).await?;
        return Ok(Json(terminate(&reason)));
    }
    sqlx::query(
        "UPDATE remote_sessions SET last_report_at=$1,bytes_to_target=$2,bytes_from_target=$3 WHERE id=$4 AND ended_at IS NULL",
    )
    .bind(now())
    .bind(bytes.0)
    .bind(bytes.1)
    .bind(row.id.to_string())
    .execute(&s.store.pool)
    .await?;
    Ok(Json(ReportDecision {
        action: "continue".into(),
        reason: None,
    }))
}

// ---------------------------------------------------------------------------
// Remote jobs: templates

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetSelector {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<DeviceTag>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    node_ids: Vec<Uuid>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TemplateInput {
    name: String,
    argv: Vec<String>,
    timeout_secs: i64,
    output_cap_bytes: i64,
    target: TargetSelector,
}

#[derive(Serialize)]
struct TemplateView {
    id: Uuid,
    name: String,
    argv: Vec<String>,
    timeout_secs: i64,
    output_cap_bytes: i64,
    target: TargetSelector,
    created_at: i64,
    created_by: String,
}

/// A template is a fixed program and arguments, never a shell string: the
/// agent executes argv directly with no shell, so no request can inject.
pub(crate) fn validate_argv(argv: &[String]) -> Result<(), ApiError> {
    if argv.is_empty() || argv.len() > MAX_ARGV_ITEMS {
        return Err(ApiError::BadRequest(format!(
            "a job needs 1 to {MAX_ARGV_ITEMS} arguments"
        )));
    }
    if argv
        .iter()
        .any(|item| item.len() > MAX_ARGV_ITEM_CHARS || item.contains('\0'))
    {
        return Err(ApiError::BadRequest(format!(
            "each argument must be at most {MAX_ARGV_ITEM_CHARS} bytes with no NUL"
        )));
    }
    let program = &argv[0];
    if !program.starts_with('/')
        || program.contains("/../")
        || program.ends_with("/..")
        || program
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(ApiError::BadRequest(
            "the program must be an absolute path".into(),
        ));
    }
    let base = program.rsplit('/').next().unwrap_or_default();
    if SHELLS.contains(&base) || base.starts_with("python") || base.starts_with("perl") {
        return Err(ApiError::BadRequest(
            "a job cannot start a shell or interpreter; name the program directly".into(),
        ));
    }
    Ok(())
}

fn valid_template_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ' '))
}

async fn create_template(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<TemplateInput>,
) -> Result<(StatusCode, Json<TemplateView>), ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageRemoteJobs)?;
    let name = input.name.trim().to_owned();
    if !valid_template_name(&name) {
        return Err(ApiError::BadRequest(
            "template name must be 1-64 letters, digits, spaces, dots, hyphens or underscores"
                .into(),
        ));
    }
    validate_argv(&input.argv)?;
    if !(1..=MAX_JOB_TIMEOUT_SECS).contains(&input.timeout_secs) {
        return Err(ApiError::BadRequest(
            "timeout must be 1 to 600 seconds".into(),
        ));
    }
    if !(1..=MAX_JOB_OUTPUT_BYTES).contains(&input.output_cap_bytes) {
        return Err(ApiError::BadRequest(
            "output cap must be 1 to 65536 bytes".into(),
        ));
    }
    let mut target = input.target;
    target.tags = crate::canonical_tags(target.tags);
    target.node_ids.sort();
    target.node_ids.dedup();
    if target.tags.is_empty() && target.node_ids.is_empty() {
        return Err(ApiError::BadRequest(
            "choose at least one target tag or device".into(),
        ));
    }
    if target.node_ids.len() > 64 {
        return Err(ApiError::BadRequest("at most 64 target devices".into()));
    }
    let id = Uuid::new_v4();
    let created_at = now();
    let mut tx = s.store.pool.begin().await?;
    sqlx::query(
        "INSERT INTO remote_job_templates(id,org_id,name,argv_json,timeout_secs,output_cap_bytes,target_json,created_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(id.to_string())
    .bind(org_id.to_string())
    .bind(&name)
    .bind(serde_json::to_string(&input.argv).map_err(|_| ApiError::CorruptData)?)
    .bind(input.timeout_secs)
    .bind(input.output_cap_bytes)
    .bind(serde_json::to_string(&target).map_err(|_| ApiError::CorruptData)?)
    .bind(created_at)
    .bind(&session.user_id)
    .execute(&mut *tx)
    .await
    .map_err(crate::conflict("a job template with that name already exists"))?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "remote_job.template_created",
        "remote_job_template",
        Some(&id.to_string()),
        &serde_json::json!({
            "name": name,
            "argv": input.argv,
            "timeout_secs": input.timeout_secs,
            "output_cap_bytes": input.output_cap_bytes,
            "target": target,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(TemplateView {
            id,
            name,
            argv: input.argv,
            timeout_secs: input.timeout_secs,
            output_cap_bytes: input.output_cap_bytes,
            target,
            created_at,
            created_by: session.user_id,
        }),
    ))
}

struct TemplateRow {
    id: Uuid,
    name: String,
    argv: Vec<String>,
    timeout_secs: i64,
    output_cap_bytes: i64,
    target: TargetSelector,
    created_at: i64,
    created_by: String,
}

async fn load_templates(
    pool: &sqlx::AnyPool,
    org_id: &str,
    template_id: Option<Uuid>,
) -> Result<Vec<TemplateRow>, ApiError> {
    let rows = sqlx::query(
        "SELECT id,name,argv_json,timeout_secs,output_cap_bytes,target_json,created_at,created_by FROM remote_job_templates WHERE org_id=$1 AND disabled_at IS NULL AND ($2='' OR id=$2) ORDER BY name",
    )
    .bind(org_id)
    .bind(template_id.map(|id| id.to_string()).unwrap_or_default())
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(TemplateRow {
                id: Uuid::parse_str(&row.try_get::<String, _>(0)?)
                    .map_err(|_| ApiError::CorruptData)?,
                name: row.try_get(1)?,
                argv: serde_json::from_str(&row.try_get::<String, _>(2)?)
                    .map_err(|_| ApiError::CorruptData)?,
                timeout_secs: row.try_get(3)?,
                output_cap_bytes: row.try_get(4)?,
                target: serde_json::from_str(&row.try_get::<String, _>(5)?)
                    .map_err(|_| ApiError::CorruptData)?,
                created_at: row.try_get(6)?,
                created_by: row.try_get(7)?,
            })
        })
        .collect()
}

async fn list_templates(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<TemplateView>>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::UseRemoteSessions)?;
    Ok(Json(
        load_templates(&s.store.pool, &org_id.to_string(), None)
            .await?
            .into_iter()
            .map(|row| TemplateView {
                id: row.id,
                name: row.name,
                argv: row.argv,
                timeout_secs: row.timeout_secs,
                output_cap_bytes: row.output_cap_bytes,
                target: row.target,
                created_at: row.created_at,
                created_by: row.created_by,
            })
            .collect(),
    ))
}

async fn disable_template(
    State(s): State<AppState>,
    UrlPath((org_id, template_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageRemoteJobs)?;
    let mut tx = s.store.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE remote_job_templates SET disabled_at=$1 WHERE id=$2 AND org_id=$3 AND disabled_at IS NULL",
    )
    .bind(now())
    .bind(template_id.to_string())
    .bind(org_id.to_string())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::NotFound);
    }
    append_audit(
        &mut tx,
        org_id,
        &session,
        "remote_job.template_disabled",
        "remote_job_template",
        Some(&template_id.to_string()),
        &serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Remote jobs: runs

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunRequest {
    template_id: Uuid,
    node_id: Uuid,
    reason: String,
}

#[derive(Serialize)]
struct RunView {
    id: Uuid,
    template_id: Uuid,
    template_name: String,
    node_id: Uuid,
    argv: Vec<String>,
    timeout_secs: i64,
    output_cap_bytes: i64,
    reason: String,
    status: String,
    requested_by: String,
    requested_at: i64,
    decided_by: Option<String>,
    decided_at: Option<i64>,
    claimed_at: Option<i64>,
    cancel_requested_at: Option<i64>,
    finished_at: Option<i64>,
    exit_code: Option<i64>,
    output: Option<String>,
    output_truncated: bool,
}

const RUN_COLUMNS: &str = "id,template_id,template_name,node_id,argv_json,timeout_secs,output_cap_bytes,reason,status,requested_by,requested_at,decided_by,decided_at,claimed_at,cancel_requested_at,finished_at,exit_code,output,output_truncated,claim_expires_at";

fn run_view(row: &sqlx::any::AnyRow) -> Result<RunView, ApiError> {
    let parse = |value: String| Uuid::parse_str(&value).map_err(|_| ApiError::CorruptData);
    let mut status: String = row.try_get(8)?;
    let claim_expires_at: Option<i64> = row.try_get(19)?;
    if status == "approved" && claim_expires_at.is_some_and(|deadline| deadline <= now()) {
        status = "expired".into();
    }
    Ok(RunView {
        id: parse(row.try_get(0)?)?,
        template_id: parse(row.try_get(1)?)?,
        template_name: row.try_get(2)?,
        node_id: parse(row.try_get(3)?)?,
        argv: serde_json::from_str(&row.try_get::<String, _>(4)?)
            .map_err(|_| ApiError::CorruptData)?,
        timeout_secs: row.try_get(5)?,
        output_cap_bytes: row.try_get(6)?,
        reason: row.try_get(7)?,
        status,
        requested_by: row.try_get(9)?,
        requested_at: row.try_get(10)?,
        decided_by: row.try_get(11)?,
        decided_at: row.try_get(12)?,
        claimed_at: row.try_get(13)?,
        cancel_requested_at: row.try_get(14)?,
        finished_at: row.try_get(15)?,
        exit_code: row.try_get(16)?,
        output: row.try_get(17)?,
        output_truncated: row.try_get::<i64, _>(18)? != 0,
    })
}

async fn load_run(pool: &sqlx::AnyPool, org_id: &str, run_id: Uuid) -> Result<RunView, ApiError> {
    let row = sqlx::query(AssertSqlSafe(format!(
        "SELECT {RUN_COLUMNS} FROM remote_job_runs WHERE id=$1 AND org_id=$2"
    )))
    .bind(run_id.to_string())
    .bind(org_id)
    .fetch_optional(pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    run_view(&row)
}

async fn list_runs(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<RunView>>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::UseRemoteSessions)?;
    let rows = sqlx::query(AssertSqlSafe(format!(
        "SELECT {RUN_COLUMNS} FROM remote_job_runs WHERE org_id=$1 ORDER BY requested_at DESC LIMIT $2"
    )))
    .bind(org_id.to_string())
    .bind(LIST_LIMIT)
    .fetch_all(&s.store.pool)
    .await?;
    rows.iter()
        .map(run_view)
        .collect::<Result<Vec<_>, _>>()
        .map(Json)
}

async fn request_run(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<RunRequest>,
) -> Result<(StatusCode, Json<RunView>), ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::UseRemoteSessions)?;
    let org = org_id.to_string();
    let reason = validate_reason(&input.reason)?;
    let template = load_templates(&s.store.pool, &org, Some(input.template_id))
        .await?
        .into_iter()
        .next()
        .ok_or(ApiError::NotFound)?;
    let node = node_status(&s.store.pool, &org, input.node_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if let Some(reason) = node.inactive_reason() {
        return Err(ApiError::Conflict(format!(
            "the device is {}",
            reason.replace('_', " ")
        )));
    }
    let tags: Vec<DeviceTag> =
        sqlx::query_scalar::<_, String>("SELECT tags_json FROM nodes WHERE id=$1 AND org_id=$2")
            .bind(input.node_id.to_string())
            .bind(&org)
            .fetch_one(&s.store.pool)
            .await
            .map(|json| serde_json::from_str(&json).unwrap_or_default())?;
    let selected = template.target.node_ids.contains(&input.node_id)
        || template.target.tags.iter().any(|tag| tags.contains(tag));
    if !selected {
        return Err(ApiError::Conflict(
            "this device is outside the template's targets".into(),
        ));
    }
    if !node.has(CAP_REMOTE_JOBS) {
        return Err(ApiError::Conflict(
            "this device has not opted in to remote jobs (blaktaild --allow-remote-jobs)".into(),
        ));
    }
    let id = Uuid::new_v4();
    let mut tx = s.store.pool.begin().await?;
    sqlx::query(
        "INSERT INTO remote_job_runs(id,org_id,template_id,template_name,node_id,argv_json,timeout_secs,output_cap_bytes,reason,status,requested_by,requested_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending_approval',$10,$11)",
    )
    .bind(id.to_string())
    .bind(&org)
    .bind(template.id.to_string())
    .bind(&template.name)
    .bind(input.node_id.to_string())
    .bind(serde_json::to_string(&template.argv).map_err(|_| ApiError::CorruptData)?)
    .bind(template.timeout_secs)
    .bind(template.output_cap_bytes)
    .bind(&reason)
    .bind(&session.user_id)
    .bind(now())
    .execute(&mut *tx)
    .await?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "remote_job.requested",
        "remote_job_run",
        Some(&id.to_string()),
        &serde_json::json!({
            "template_id": template.id,
            "template_name": template.name,
            "node_id": input.node_id,
            "argv": template.argv,
            "reason": reason,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(load_run(&s.store.pool, &org, id).await?),
    ))
}

/// The exact bytes an agent verifies. The agent parses this payload after
/// verifying it, so nothing outside the signature reaches the executor.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct SignedJob {
    pub(crate) run_id: Uuid,
    pub(crate) org_id: Uuid,
    pub(crate) node_id: Uuid,
    pub(crate) argv: Vec<String>,
    pub(crate) timeout_secs: i64,
    pub(crate) output_cap_bytes: i64,
    pub(crate) expires_at: i64,
}

pub(crate) fn sign_job(master: &[u8], job: &SignedJob) -> Result<(String, String), ApiError> {
    let payload = serde_json::to_string(job).map_err(|_| ApiError::CorruptData)?;
    let key = job_signing_key(master, &job.org_id.to_string());
    let signature = key.sign(format!("{JOB_SIGNATURE_CONTEXT}{payload}").as_bytes());
    Ok((payload, STANDARD.encode(signature.to_bytes())))
}

async fn approve_run(
    State(s): State<AppState>,
    UrlPath((org_id, run_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<RunView>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageRemoteJobs)?;
    let org = org_id.to_string();
    let run = load_run(&s.store.pool, &org, run_id).await?;
    if run.status != "pending_approval" {
        return Err(ApiError::Conflict(format!("the run is {}", run.status)));
    }
    // A template disabled after the request can no longer be approved.
    if load_templates(&s.store.pool, &org, Some(run.template_id))
        .await?
        .is_empty()
    {
        return Err(ApiError::Conflict("the job template was disabled".into()));
    }
    let expires_at = now() + JOB_CLAIM_WINDOW_SECS;
    let (payload, signature) = sign_job(
        &s.auth_hmac_secret,
        &SignedJob {
            run_id,
            org_id,
            node_id: run.node_id,
            argv: run.argv.clone(),
            timeout_secs: run.timeout_secs,
            output_cap_bytes: run.output_cap_bytes,
            expires_at,
        },
    )?;
    let mut tx = s.store.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE remote_job_runs SET status='approved',decided_by=$1,decided_at=$2,claim_expires_at=$3,signature=$4 WHERE id=$5 AND org_id=$6 AND status='pending_approval'",
    )
    .bind(&session.user_id)
    .bind(now())
    .bind(expires_at)
    .bind(format!("{signature}.{payload}"))
    .bind(run_id.to_string())
    .bind(&org)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::Conflict("the run changed; reload".into()));
    }
    append_audit(
        &mut tx,
        org_id,
        &session,
        "remote_job.approved",
        "remote_job_run",
        Some(&run_id.to_string()),
        &serde_json::json!({
            "node_id": run.node_id,
            "argv": run.argv,
            "claim_expires_at": expires_at,
            "payload_sha256": format!("{:x}", Sha256::digest(payload.as_bytes())),
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(load_run(&s.store.pool, &org, run_id).await?))
}

async fn reject_run(
    State(s): State<AppState>,
    UrlPath((org_id, run_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<RunView>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageRemoteJobs)?;
    let org = org_id.to_string();
    let mut tx = s.store.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE remote_job_runs SET status='rejected',decided_by=$1,decided_at=$2 WHERE id=$3 AND org_id=$4 AND status='pending_approval'",
    )
    .bind(&session.user_id)
    .bind(now())
    .bind(run_id.to_string())
    .bind(&org)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::Conflict(
            "only a pending run can be rejected".into(),
        ));
    }
    append_audit(
        &mut tx,
        org_id,
        &session,
        "remote_job.rejected",
        "remote_job_run",
        Some(&run_id.to_string()),
        &serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(load_run(&s.store.pool, &org, run_id).await?))
}

async fn cancel_run(
    State(s): State<AppState>,
    UrlPath((org_id, run_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<RunView>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::UseRemoteSessions)?;
    let org = org_id.to_string();
    let at = now();
    let mut tx = s.store.pool.begin().await?;
    // Not yet claimed: cancel outright. Running: the agent kills it at its
    // next check and reports `cancelled`.
    let queued = sqlx::query(
        "UPDATE remote_job_runs SET status='cancelled',cancel_requested_at=$1,finished_at=$1,decided_by=COALESCE(decided_by,$2) WHERE id=$3 AND org_id=$4 AND status IN ('pending_approval','approved')",
    )
    .bind(at)
    .bind(&session.user_id)
    .bind(run_id.to_string())
    .bind(&org)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    let running = if queued == 0 {
        sqlx::query(
            "UPDATE remote_job_runs SET cancel_requested_at=$1 WHERE id=$2 AND org_id=$3 AND status='running' AND cancel_requested_at IS NULL",
        )
        .bind(at)
        .bind(run_id.to_string())
        .bind(&org)
        .execute(&mut *tx)
        .await?
        .rows_affected()
    } else {
        0
    };
    if queued == 0 && running == 0 {
        return Err(ApiError::Conflict("the run has already finished".into()));
    }
    append_audit(
        &mut tx,
        org_id,
        &session,
        "remote_job.cancel_requested",
        "remote_job_run",
        Some(&run_id.to_string()),
        &serde_json::json!({ "was_running": running > 0 }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(load_run(&s.store.pool, &org, run_id).await?))
}

// ---------------------------------------------------------------------------
// Remote jobs: agent

#[derive(Serialize, Deserialize)]
pub(crate) struct AgentJob {
    pub(crate) run_id: Uuid,
    pub(crate) payload: String,
    pub(crate) signature: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct AgentJobs {
    pub(crate) jobs: Vec<AgentJob>,
}

async fn pending_jobs(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<AgentJobs>, ApiError> {
    let org = authenticate_node(&s, node_id, &headers).await?;
    let rows = sqlx::query(
        "SELECT id,signature FROM remote_job_runs WHERE org_id=$1 AND node_id=$2 AND status='approved' AND claim_expires_at>$3 ORDER BY decided_at LIMIT 10",
    )
    .bind(&org)
    .bind(node_id.to_string())
    .bind(now())
    .fetch_all(&s.store.pool)
    .await?;
    let jobs = rows
        .into_iter()
        .map(|row| {
            let packed: String = row.try_get(1)?;
            let (signature, payload) = packed.split_once('.').ok_or(ApiError::CorruptData)?;
            Ok(AgentJob {
                run_id: Uuid::parse_str(&row.try_get::<String, _>(0)?)
                    .map_err(|_| ApiError::CorruptData)?,
                payload: payload.to_owned(),
                signature: signature.to_owned(),
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(AgentJobs { jobs }))
}

#[derive(Serialize, Deserialize)]
pub(crate) struct JobState {
    pub(crate) status: String,
    pub(crate) cancel: bool,
}

async fn job_state(
    State(s): State<AppState>,
    UrlPath((node_id, run_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<JobState>, ApiError> {
    let org = authenticate_node(&s, node_id, &headers).await?;
    let row = sqlx::query(
        "SELECT status,cancel_requested_at FROM remote_job_runs WHERE id=$1 AND org_id=$2 AND node_id=$3",
    )
    .bind(run_id.to_string())
    .bind(&org)
    .bind(node_id.to_string())
    .fetch_optional(&s.store.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let status: String = row.try_get(0)?;
    let cancel = row.try_get::<Option<i64>, _>(1)?.is_some() || status == "cancelled";
    Ok(Json(JobState { status, cancel }))
}

async fn run_actor(pool: &sqlx::AnyPool, org: &str, run_id: Uuid) -> Result<String, ApiError> {
    Ok(
        sqlx::query_scalar("SELECT requested_by FROM remote_job_runs WHERE id=$1 AND org_id=$2")
            .bind(run_id.to_string())
            .bind(org)
            .fetch_one(pool)
            .await?,
    )
}

async fn claim_job(
    State(s): State<AppState>,
    UrlPath((node_id, run_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let org = authenticate_node(&s, node_id, &headers).await?;
    let requested_by = run_actor(&s.store.pool, &org, run_id)
        .await
        .map_err(|_| ApiError::Gone)?;
    let mut tx = s.store.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE remote_job_runs SET status='running',claimed_at=$1 WHERE id=$2 AND org_id=$3 AND node_id=$4 AND status='approved' AND claim_expires_at>$1",
    )
    .bind(now())
    .bind(run_id.to_string())
    .bind(&org)
    .bind(node_id.to_string())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::Gone);
    }
    let org_uuid = Uuid::parse_str(&org).map_err(|_| ApiError::CorruptData)?;
    let mut actor = node_session(node_id);
    actor.name = format!("Device agent (requested by {requested_by})");
    append_audit(
        &mut tx,
        org_uuid,
        &actor,
        "remote_job.started",
        "remote_job_run",
        Some(&run_id.to_string()),
        &serde_json::json!({ "node_id": node_id }),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JobResult {
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) exit_code: Option<i64>,
    #[serde(default)]
    pub(crate) output: String,
    #[serde(default)]
    pub(crate) output_truncated: bool,
}

const JOB_END_STATES: &[&str] = &[
    "succeeded",
    "failed",
    "timed_out",
    "output_capped",
    "cancelled",
    "error",
];

async fn job_result(
    State(s): State<AppState>,
    UrlPath((node_id, run_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<JobResult>,
) -> Result<StatusCode, ApiError> {
    let org = authenticate_node(&s, node_id, &headers).await?;
    if !JOB_END_STATES.contains(&input.status.as_str()) {
        return Err(ApiError::BadRequest("unknown job status".into()));
    }
    let cap: i64 = sqlx::query_scalar(
        "SELECT output_cap_bytes FROM remote_job_runs WHERE id=$1 AND org_id=$2 AND node_id=$3 AND status='running'",
    )
    .bind(run_id.to_string())
    .bind(&org)
    .bind(node_id.to_string())
    .fetch_optional(&s.store.pool)
    .await?
    .ok_or(ApiError::Conflict("the run is not running on this device".into()))?;
    if input.output.len() as i64 > cap {
        return Err(ApiError::BadRequest(
            "job output exceeds the template's cap".into(),
        ));
    }
    let output_sha256 = format!("{:x}", Sha256::digest(input.output.as_bytes()));
    let mut tx = s.store.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE remote_job_runs SET status=$1,exit_code=$2,output=$3,output_truncated=$4,finished_at=$5 WHERE id=$6 AND org_id=$7 AND node_id=$8 AND status='running'",
    )
    .bind(&input.status)
    .bind(input.exit_code)
    .bind(&input.output)
    .bind(i64::from(input.output_truncated))
    .bind(now())
    .bind(run_id.to_string())
    .bind(&org)
    .bind(node_id.to_string())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::Conflict(
            "the run is not running on this device".into(),
        ));
    }
    let org_uuid = Uuid::parse_str(&org).map_err(|_| ApiError::CorruptData)?;
    // The audit row carries the output digest, so the stored output is
    // covered by the tamper-evident chain without copying it into the log.
    append_audit(
        &mut tx,
        org_uuid,
        &node_session(node_id),
        "remote_job.finished",
        "remote_job_run",
        Some(&run_id.to_string()),
        &serde_json::json!({
            "status": input.status,
            "exit_code": input.exit_code,
            "output_bytes": input.output.len(),
            "output_truncated": input.output_truncated,
            "output_sha256": output_sha256,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn argv_rejects_shells_relative_paths_and_nul() {
        for argv in [
            vec![],
            vec!["uptime".to_string()],
            vec!["/bin/sh".into(), "-c".into(), "id".into()],
            vec!["/usr/bin/env".into(), "id".into()],
            vec!["/usr/bin/python3".into(), "-c".into(), "print(1)".into()],
            vec!["/usr/bin/../bin/sh".into()],
            vec!["/usr/bin/id".into(), "a\0b".into()],
        ] {
            assert!(validate_argv(&argv).is_err(), "{argv:?}");
        }
        validate_argv(&["/usr/bin/uptime".into()]).unwrap();
        validate_argv(&["/usr/bin/systemctl".into(), "status".into(), "ssh".into()]).unwrap();
    }

    #[test]
    fn certificate_is_bound_to_one_user_and_the_gateway() {
        let master = b"unit-test-master-secret-32-bytes!!";
        let (ca_public, sealed) = new_ca(master, "org").unwrap();
        let pem = open(master, "org", &sealed).unwrap();
        assert!(open(master, "other-org", &sealed).is_err());
        let subject =
            ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[7u8; 32]));
        let (certificate, _) = sign_user_certificate(
            &pem,
            &CertificateRequest {
                session_id: Uuid::nil(),
                user_id: "person",
                os_user: "deploy",
                public_key: &subject.public_key().to_openssh().unwrap(),
                source_addresses: &["100.64.0.9".into()],
                valid_before: now() + 600,
            },
        )
        .unwrap();
        let parsed = ssh_key::Certificate::from_openssh(&certificate).unwrap();
        assert_eq!(parsed.valid_principals(), ["deploy".to_string()]);
        assert_eq!(
            parsed
                .critical_options()
                .get("source-address")
                .map(String::as_str),
            Some("100.64.0.9")
        );
        assert!(parsed.extensions().contains_key("permit-pty"));
        assert!(!parsed.extensions().contains_key("permit-port-forwarding"));
        assert!(!parsed.extensions().contains_key("permit-agent-forwarding"));
        let ca = ssh_key::PublicKey::from_openssh(&ca_public).unwrap();
        parsed
            .validate([&ca.fingerprint(ssh_key::HashAlg::Sha256)])
            .unwrap();
    }

    #[test]
    fn signed_jobs_verify_and_tampering_fails() {
        let master = b"unit-test-master-secret-32-bytes!!";
        let org = Uuid::from_u128(1);
        let job = SignedJob {
            run_id: Uuid::from_u128(2),
            org_id: org,
            node_id: Uuid::from_u128(3),
            argv: vec!["/usr/bin/uptime".into()],
            timeout_secs: 30,
            output_cap_bytes: 1024,
            expires_at: 1,
        };
        let (payload, signature) = sign_job(master, &job).unwrap();
        let key = ed25519_dalek::VerifyingKey::from_bytes(
            &STANDARD
                .decode(job_public_key(master, &org.to_string()))
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let signature =
            ed25519_dalek::Signature::from_slice(&STANDARD.decode(signature).unwrap()).unwrap();
        key.verify_strict(
            format!("{JOB_SIGNATURE_CONTEXT}{payload}").as_bytes(),
            &signature,
        )
        .unwrap();
        let tampered = payload.replace("uptime", "reboot");
        assert!(key
            .verify_strict(
                format!("{JOB_SIGNATURE_CONTEXT}{tampered}").as_bytes(),
                &signature
            )
            .is_err());
        assert_ne!(
            job_public_key(master, &org.to_string()),
            job_public_key(master, &Uuid::from_u128(9).to_string())
        );
    }
}
