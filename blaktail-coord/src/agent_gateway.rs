//! Agent network (draft 24, ADR 0008): an organisation-run AI model gateway.
//!
//! The coordinator holds providers, agent keys and their policies. The
//! `blaktail-agentgw` process runs on an enrolled node that reports the
//! `agent-gateway` capability and that an owner or admin designated as a
//! gateway (a reported capability alone is never enough, because the gateway
//! receives provider credentials and vouches for the caller's address). It
//! asks the coordinator to authorise every
//! request: key, node binding, size, model allowlist, offshore policy and the
//! daily quota are all decided here, so several gateways share one quota and a
//! revoked key stops working on the next request.
//!
//! Sensitive fields: provider credentials are sealed with the coordinator
//! secret and only ever leave in an authorisation grant to a gateway node;
//! agent keys are stored as SHA-256 hashes; prompt and response content is
//! stored only for keys an owner switched to full logging, sealed, and purged
//! after at most 30 days.

use crate::{
    append_audit, bearer, console_session, designations, hash, now,
    permissions::{require, Permission},
    private_services::{open_key, seal_key},
    ApiError, AppState, Role,
};
use axum::{
    extract::{Path as UrlPath, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::{any::AnyRow, AnyConnection, Row};
use std::net::IpAddr;
use uuid::Uuid;

pub(crate) const CAP_AGENT_GATEWAY: &str = "agent-gateway";
/// The gateway refuses bodies above this before asking the coordinator.
pub(crate) const MAX_REQUEST_BYTES: i64 = 4 * 1024 * 1024;
const MAX_PROVIDERS: i64 = 32;
const MAX_KEYS: i64 = 256;
const MAX_MODELS: usize = 32;
const MAX_PATTERNS: usize = 16;
const MAX_PATTERN_LEN: usize = 256;
const MAX_CREDENTIAL: usize = 4096;
const MAX_CONTENT_CHARS: usize = 256 * 1024;
const MAX_FULL_RETENTION_DAYS: i64 = 30;
const METADATA_RETENTION_DAYS: i64 = 90;
/// Output tokens reserved when a request sets no `max_tokens`; the gateway
/// forwards the granted allowance so the provider cannot exceed it.
const DEFAULT_OUTPUT_TOKENS: i64 = 4096;
/// A reservation the gateway never finalised is closed as abandoned.
const PENDING_TIMEOUT_SECS: i64 = 15 * 60;
const KEY_PREFIX: &str = "btak_";
const RESIDENCIES: &[&str] = &["onshore", "offshore"];
const LOGGING_MODES: &[&str] = &["off", "metadata", "full"];
pub(crate) const ICIP_WARNING: &str = "Full logging stores prompts and responses. Prompts can contain Indigenous Cultural and Intellectual Property (ICIP); only enable it with the consent of the knowledge holders, and keep retention as short as possible.";

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/orgs/:org_id/agents", get(overview))
        .route("/v1/orgs/:org_id/agents/settings", put(put_settings))
        .route("/v1/orgs/:org_id/agents/providers", post(create_provider))
        .route(
            "/v1/orgs/:org_id/agents/providers/:provider_id",
            axum::routing::patch(update_provider).delete(delete_provider),
        )
        .route("/v1/orgs/:org_id/agents/keys", post(create_key))
        .route(
            "/v1/orgs/:org_id/agents/keys/:key_id",
            put(update_key).delete(revoke_key),
        )
        .route(
            "/v1/orgs/:org_id/agents/gateways/:node_id",
            put(designate_gateway),
        )
        .route("/v1/orgs/:org_id/agents/usage", get(usage))
        .route(
            "/v1/orgs/:org_id/agents/requests/:request_id/content",
            get(request_content),
        )
        .route(
            "/v1/nodes/:node_id/agent-gateway/authorize",
            post(authorize),
        )
        .route("/v1/nodes/:node_id/agent-gateway/models", post(models))
        .route("/v1/nodes/:node_id/agent-gateway/usage", post(ingest_usage))
}

// ---------------------------------------------------------------- views

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Settings {
    pub(crate) allow_offshore: bool,
    updated_at: Option<i64>,
    updated_by: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ProviderView {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    kind: String,
    base_url: String,
    data_location: String,
    residency: String,
    pub(crate) has_credential: bool,
    models: Vec<String>,
    enabled: bool,
    /// Offshore while the organisation forbids offshore providers.
    pub(crate) blocked_by_policy: bool,
    pub(crate) revision: i64,
    created_at: i64,
    updated_at: i64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Policy {
    #[serde(default)]
    bound_node_id: Option<Uuid>,
    #[serde(default)]
    allowed_provider_ids: Vec<Uuid>,
    /// Empty means every model the allowed providers declare.
    #[serde(default)]
    allowed_models: Vec<String>,
    #[serde(default = "default_requests")]
    daily_request_quota: i64,
    #[serde(default = "default_tokens")]
    daily_token_quota: i64,
    #[serde(default = "default_request_bytes")]
    max_request_bytes: i64,
    #[serde(default = "default_logging")]
    logging_mode: String,
    /// Days full prompt content is kept; only meaningful for `full`.
    #[serde(default)]
    log_retention_days: i64,
    #[serde(default)]
    redact_patterns: Vec<String>,
}

fn default_requests() -> i64 {
    1_000
}
fn default_tokens() -> i64 {
    1_000_000
}
fn default_request_bytes() -> i64 {
    256 * 1024
}
fn default_logging() -> String {
    "off".into()
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct Today {
    pub(crate) requests: i64,
    pub(crate) tokens: i64,
    pub(crate) denied: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct KeyView {
    pub(crate) id: Uuid,
    name: String,
    key_prefix: String,
    pub(crate) policy: Policy,
    pub(crate) revision: i64,
    created_by: String,
    created_at: i64,
    updated_at: i64,
    last_used_at: Option<i64>,
    pub(crate) revoked_at: Option<i64>,
    pub(crate) today: Today,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct GatewayNode {
    pub(crate) id: String,
    name: String,
    last_seen_at: Option<i64>,
    /// Reports the `agent-gateway` capability.
    pub(crate) capable: bool,
    /// Designated by an owner or admin; only capable and designated devices
    /// can act as a gateway.
    pub(crate) designated: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Overview {
    pub(crate) settings: Settings,
    pub(crate) providers: Vec<ProviderView>,
    pub(crate) keys: Vec<KeyView>,
    pub(crate) gateways: Vec<GatewayNode>,
    icip_warning: String,
    day: String,
}

// ---------------------------------------------------------------- helpers

fn day_of(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .unwrap_or_default()
        .format("%Y-%m-%d")
        .to_string()
}

fn json_col<T: serde::de::DeserializeOwned>(row: &AnyRow, index: usize) -> Result<T, ApiError> {
    serde_json::from_str(&row.try_get::<String, _>(index)?).map_err(|_| ApiError::CorruptData)
}

fn to_json<T: Serialize>(value: &T) -> Result<String, ApiError> {
    serde_json::to_string(value).map_err(|_| ApiError::CorruptData)
}

fn bad(message: impl Into<String>) -> ApiError {
    ApiError::BadRequest(message.into())
}

fn printable(value: &str, field: &str, max: usize) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > max || value.chars().any(char::is_control) {
        return Err(bad(format!(
            "{field} must be 1 to {max} printable characters"
        )));
    }
    Ok(value.to_owned())
}

fn check_name(name: &str) -> Result<String, ApiError> {
    let name = name.trim().to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 48
        || name.starts_with('-')
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(bad(
            "name must be 1 to 48 lowercase letters, digits or hyphens",
        ));
    }
    Ok(name)
}

fn check_models(models: &[String], allow_empty: bool) -> Result<Vec<String>, ApiError> {
    let mut out = Vec::new();
    for model in models {
        let model = model.trim();
        if model.is_empty()
            || model.len() > 128
            || !model
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._:/-@".contains(c))
        {
            return Err(bad(format!(
                "model id {model:?} must be 1 to 128 letters, digits or ._:/-@"
            )));
        }
        if !out.iter().any(|m| m == model) {
            out.push(model.to_owned());
        }
    }
    if out.len() > MAX_MODELS {
        return Err(bad(format!("at most {MAX_MODELS} models")));
    }
    if out.is_empty() && !allow_empty {
        return Err(bad("declare at least one model id this provider serves"));
    }
    Ok(out)
}

fn check_residency(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if RESIDENCIES.contains(&value) {
        Ok(value.to_owned())
    } else {
        Err(bad("residency must be onshore or offshore"))
    }
}

/// Whether an IPv4 provider address is private; refuses link-local
/// (including 169.254.169.254), metadata and unspecified addresses.
fn ipv4_private(ip: std::net::Ipv4Addr) -> Result<bool, ApiError> {
    if ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip == std::net::Ipv4Addr::new(100, 100, 100, 200)
    {
        return Err(bad(
            "link-local, metadata and unspecified addresses cannot be providers",
        ));
    }
    Ok(ip.is_loopback()
        || ip.is_private()
        || (ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64))
}

/// Upstream URL rules. Self-hosted providers on private addresses are the
/// point, so private ranges are allowed; cloud metadata endpoints never are,
/// and an offshore provider or a credential crossing a public network needs
/// TLS.
fn check_base_url(value: &str, residency: &str, has_credential: bool) -> Result<String, ApiError> {
    let url = url::Url::parse(value.trim()).map_err(|_| bad("base URL is not a valid URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(bad("base URL must use http or https"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(bad(
            "put credentials in the credential field, never in the URL",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(bad("base URL must not have a query or fragment"));
    }
    let host = url.host().ok_or_else(|| bad("base URL needs a host"))?;
    let private = match &host {
        url::Host::Domain(domain) => {
            let domain = domain.to_ascii_lowercase();
            if domain == "metadata.google.internal" || domain.ends_with(".metadata.google.internal")
            {
                return Err(bad("cloud metadata endpoints cannot be providers"));
            }
            domain == "localhost" || domain.ends_with(".internal") || domain.ends_with(".blaktail")
        }
        url::Host::Ipv4(ip) => ipv4_private(*ip)?,
        // An IPv4-mapped literal must not bypass the IPv4 rules.
        url::Host::Ipv6(ip) => match ip.to_ipv4_mapped() {
            Some(v4) => ipv4_private(v4)?,
            None => {
                let first = ip.segments()[0];
                let metadata = std::net::Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254);
                if (first & 0xffc0) == 0xfe80 || ip.is_unspecified() || *ip == metadata {
                    return Err(bad(
                        "link-local, metadata and unspecified addresses cannot be providers",
                    ));
                }
                ip.is_loopback() || (first & 0xfe00) == 0xfc00
            }
        },
    };
    if url.scheme() == "http" {
        if residency == "offshore" {
            return Err(bad("offshore providers must use https"));
        }
        if has_credential && !private {
            return Err(bad(
                "a credential may only be sent over http to a private or loopback address; use https",
            ));
        }
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn check_credential(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_CREDENTIAL || value.chars().any(char::is_control) {
        return Err(bad(format!(
            "credential must be 1 to {MAX_CREDENTIAL} printable characters"
        )));
    }
    Ok(value.to_owned())
}

pub(crate) fn compile_pattern(pattern: &str) -> Result<regex::Regex, String> {
    regex::RegexBuilder::new(pattern)
        .size_limit(1 << 20)
        .dfa_size_limit(1 << 20)
        .build()
        .map_err(|error| format!("redaction pattern {pattern:?} is invalid: {error}"))
}

async fn org_exists(conn: &mut AnyConnection, org_id: Uuid) -> Result<(), ApiError> {
    sqlx::query_scalar::<_, String>("SELECT id FROM orgs WHERE id=$1")
        .bind(org_id.to_string())
        .fetch_optional(&mut *conn)
        .await?
        .map(|_| ())
        .ok_or(ApiError::NotFound)
}

async fn load_settings(conn: &mut AnyConnection, org_id: &str) -> Result<Settings, ApiError> {
    let row = sqlx::query(
        "SELECT allow_offshore,updated_at,updated_by FROM agent_settings WHERE org_id=$1",
    )
    .bind(org_id)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(match row {
        Some(row) => Settings {
            allow_offshore: row.try_get::<i64, _>(0)? != 0,
            updated_at: Some(row.try_get(1)?),
            updated_by: Some(row.try_get(2)?),
        },
        None => Settings {
            allow_offshore: false,
            updated_at: None,
            updated_by: None,
        },
    })
}

const PROVIDER_COLUMNS: &str = "id,name,kind,base_url,data_location,residency,sealed_credential,models_json,enabled,revision,created_at,updated_at";

fn provider_from_row(row: &AnyRow, allow_offshore: bool) -> Result<ProviderView, ApiError> {
    let residency: String = row.try_get(5)?;
    Ok(ProviderView {
        id: row
            .try_get::<String, _>(0)?
            .parse()
            .map_err(|_| ApiError::CorruptData)?,
        name: row.try_get(1)?,
        kind: row.try_get(2)?,
        base_url: row.try_get(3)?,
        data_location: row.try_get(4)?,
        blocked_by_policy: residency == "offshore" && !allow_offshore,
        residency,
        has_credential: row.try_get::<Option<String>, _>(6)?.is_some(),
        models: json_col(row, 7)?,
        enabled: row.try_get::<i64, _>(8)? != 0,
        revision: row.try_get(9)?,
        created_at: row.try_get(10)?,
        updated_at: row.try_get(11)?,
    })
}

async fn load_providers(
    conn: &mut AnyConnection,
    org_id: &str,
    allow_offshore: bool,
) -> Result<Vec<ProviderView>, ApiError> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {PROVIDER_COLUMNS} FROM agent_providers WHERE org_id=$1 ORDER BY name"
    )))
    .bind(org_id)
    .fetch_all(&mut *conn)
    .await?
    .iter()
    .map(|row| provider_from_row(row, allow_offshore))
    .collect()
}

const KEY_COLUMNS: &str = "k.id,k.name,k.key_prefix,k.bound_node_id,k.allowed_providers_json,k.allowed_models_json,k.daily_request_quota,k.daily_token_quota,k.max_request_bytes,k.logging_mode,k.log_retention_days,k.redact_patterns_json,k.revision,k.created_by,k.created_at,k.updated_at,k.last_used_at,k.revoked_at,COALESCE(q.requests,0),COALESCE(q.tokens,0),COALESCE(q.denied,0)";

fn key_from_row(row: &AnyRow) -> Result<KeyView, ApiError> {
    let bound: Option<String> = row.try_get(3)?;
    Ok(KeyView {
        id: row
            .try_get::<String, _>(0)?
            .parse()
            .map_err(|_| ApiError::CorruptData)?,
        name: row.try_get(1)?,
        key_prefix: row.try_get(2)?,
        policy: Policy {
            bound_node_id: bound
                .map(|id| id.parse().map_err(|_| ApiError::CorruptData))
                .transpose()?,
            allowed_provider_ids: json_col(row, 4)?,
            allowed_models: json_col(row, 5)?,
            daily_request_quota: row.try_get(6)?,
            daily_token_quota: row.try_get(7)?,
            max_request_bytes: row.try_get(8)?,
            logging_mode: row.try_get(9)?,
            log_retention_days: row.try_get(10)?,
            redact_patterns: json_col(row, 11)?,
        },
        revision: row.try_get(12)?,
        created_by: row.try_get(13)?,
        created_at: row.try_get(14)?,
        updated_at: row.try_get(15)?,
        last_used_at: row.try_get(16)?,
        revoked_at: row.try_get(17)?,
        today: Today {
            requests: row.try_get(18)?,
            tokens: row.try_get(19)?,
            denied: row.try_get(20)?,
        },
    })
}

async fn load_keys(conn: &mut AnyConnection, org_id: &str) -> Result<Vec<KeyView>, ApiError> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {KEY_COLUMNS} FROM agent_keys k LEFT JOIN agent_quota_days q ON q.key_id=k.id AND q.day=$2 WHERE k.org_id=$1 ORDER BY k.revoked_at IS NOT NULL, k.name, k.created_at"
    )))
    .bind(org_id)
    .bind(day_of(now()))
    .fetch_all(&mut *conn)
    .await?
    .iter()
    .map(key_from_row)
    .collect()
}

async fn load_key(
    conn: &mut AnyConnection,
    org_id: Uuid,
    key_id: Uuid,
) -> Result<KeyView, ApiError> {
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {KEY_COLUMNS} FROM agent_keys k LEFT JOIN agent_quota_days q ON q.key_id=k.id AND q.day=$3 WHERE k.org_id=$1 AND k.id=$2"
    )))
    .bind(org_id.to_string())
    .bind(key_id.to_string())
    .bind(day_of(now()))
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(ApiError::NotFound)?;
    key_from_row(&row)
}

/// Retention: expired metadata rows go, expired content is dropped from rows
/// that remain, and reservations a gateway never closed become abandoned.
async fn purge(conn: &mut AnyConnection, org_id: &str) -> Result<(), ApiError> {
    let current = now();
    sqlx::query(
        "DELETE FROM agent_requests WHERE org_id=$1 AND expires_at IS NOT NULL AND expires_at<=$2",
    )
    .bind(org_id)
    .bind(current)
    .execute(&mut *conn)
    .await?;
    sqlx::query("UPDATE agent_requests SET sealed_content=NULL,content_expires_at=NULL WHERE org_id=$1 AND content_expires_at IS NOT NULL AND content_expires_at<=$2")
        .bind(org_id)
        .bind(current)
        .execute(&mut *conn)
        .await?;
    sqlx::query("UPDATE agent_requests SET status='abandoned',finished_at=$2,expires_at=$3 WHERE org_id=$1 AND status='pending' AND started_at<=$4")
        .bind(org_id)
        .bind(current)
        .bind(current + METADATA_RETENTION_DAYS * 86_400)
        .bind(current - PENDING_TIMEOUT_SECS)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------- console

async fn overview(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Overview>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewAgentUsage)?;
    let mut conn = s.store.pool.acquire().await?;
    org_exists(&mut conn, org_id).await?;
    let org = org_id.to_string();
    let settings = load_settings(&mut conn, &org).await?;
    let providers = load_providers(&mut conn, &org, settings.allow_offshore).await?;
    let keys = load_keys(&mut conn, &org).await?;
    let designated = designations::designated(&mut conn, &org, designations::AGENT_GATEWAY).await?;
    let gateways = sqlx::query(
        "SELECT id,COALESCE(NULLIF(TRIM(display_name),''),name),last_seen_at,capabilities_json FROM nodes WHERE org_id=$1 AND revoked_at IS NULL AND deleted_at IS NULL ORDER BY name",
    )
    .bind(&org)
    .fetch_all(&mut *conn)
    .await?
    .iter()
    .filter_map(|row| {
        let capabilities: Vec<String> = json_col(row, 3).unwrap_or_default();
        let id: String = row.try_get(0).ok()?;
        let capable = capabilities.iter().any(|c| c == CAP_AGENT_GATEWAY);
        let is_designated = designated.contains(&id);
        (capable || is_designated).then_some(())?;
        Some(GatewayNode {
            id,
            name: row.try_get(1).ok()?,
            last_seen_at: row.try_get(2).ok()?,
            capable,
            designated: is_designated,
        })
    })
    .collect();
    Ok(Json(Overview {
        settings,
        providers,
        keys,
        gateways,
        icip_warning: ICIP_WARNING.into(),
        day: day_of(now()),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsInput {
    allow_offshore: bool,
}

async fn put_settings(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<SettingsInput>,
) -> Result<Json<Settings>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageAgentGateway)?;
    // Sending data offshore is a sovereignty decision, not routine admin work.
    if session.role != Role::Owner {
        return Err(ApiError::Forbidden);
    }
    let mut tx = s.store.pool.begin().await?;
    org_exists(&mut tx, org_id).await?;
    let org = org_id.to_string();
    let before = load_settings(&mut tx, &org).await?;
    let current = now();
    sqlx::query(
        "INSERT INTO agent_settings(org_id,allow_offshore,updated_by,updated_at) VALUES($1,$2,$3,$4) ON CONFLICT(org_id) DO UPDATE SET allow_offshore=$2,updated_by=$3,updated_at=$4",
    )
    .bind(&org)
    .bind(i64::from(input.allow_offshore))
    .bind(&session.user_id)
    .bind(current)
    .execute(&mut *tx)
    .await?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "agent.settings.updated",
        "agent_settings",
        None,
        &serde_json::json!({
            "allow_offshore": {"from": before.allow_offshore, "to": input.allow_offshore},
        }),
    )
    .await?;
    let settings = load_settings(&mut tx, &org).await?;
    tx.commit().await?;
    Ok(Json(settings))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DesignationInput {
    designated: bool,
}

/// Designates (or releases) a device as an AI gateway for this organisation.
async fn designate_gateway(
    State(s): State<AppState>,
    UrlPath((org_id, node_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<DesignationInput>,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageAgentGateway)?;
    let mut tx = s.store.pool.begin().await?;
    designations::set(
        &mut tx,
        org_id,
        &session,
        node_id,
        designations::AGENT_GATEWAY,
        input.designated,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderInput {
    name: String,
    #[serde(default = "default_kind")]
    kind: String,
    base_url: String,
    data_location: String,
    residency: String,
    #[serde(default)]
    credential: Option<String>,
    models: Vec<String>,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_kind() -> String {
    "openai_compatible".into()
}
fn default_true() -> bool {
    true
}

async fn create_provider(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<ProviderInput>,
) -> Result<(StatusCode, Json<ProviderView>), ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageAgentGateway)?;
    let name = check_name(&input.name)?;
    if input.kind != "openai_compatible" {
        return Err(bad(
            "kind must be openai_compatible (OpenAI-compatible APIs, including Ollama and vLLM)",
        ));
    }
    let residency = check_residency(&input.residency)?;
    let data_location = printable(&input.data_location, "data location", 80)?;
    let credential = input
        .credential
        .as_deref()
        .filter(|c| !c.trim().is_empty())
        .map(check_credential)
        .transpose()?;
    let base_url = check_base_url(&input.base_url, &residency, credential.is_some())?;
    let models = check_models(&input.models, false)?;
    let sealed = credential
        .as_deref()
        .map(|c| seal_key(&s.auth_hmac_secret, c))
        .transpose()?;
    let mut tx = s.store.pool.begin().await?;
    org_exists(&mut tx, org_id).await?;
    let org = org_id.to_string();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_providers WHERE org_id=$1")
        .bind(&org)
        .fetch_one(&mut *tx)
        .await?;
    if count >= MAX_PROVIDERS {
        return Err(bad(format!(
            "organisations are limited to {MAX_PROVIDERS} providers"
        )));
    }
    let id = Uuid::new_v4();
    let current = now();
    sqlx::query(
        "INSERT INTO agent_providers(id,org_id,name,kind,base_url,data_location,residency,sealed_credential,models_json,enabled,revision,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,$11,$11)",
    )
    .bind(id.to_string())
    .bind(&org)
    .bind(&name)
    .bind(&input.kind)
    .bind(&base_url)
    .bind(&data_location)
    .bind(&residency)
    .bind(sealed)
    .bind(to_json(&models)?)
    .bind(i64::from(input.enabled))
    .bind(current)
    .execute(&mut *tx)
    .await
    .map_err(crate::conflict("a provider with that name already exists"))?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "agent.provider.created",
        "agent_provider",
        Some(&id.to_string()),
        &serde_json::json!({
            "name": name,
            "base_url": base_url,
            "data_location": data_location,
            "residency": residency,
            "models": models,
            "enabled": input.enabled,
            "has_credential": credential.is_some(),
        }),
    )
    .await?;
    let settings = load_settings(&mut tx, &org).await?;
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {PROVIDER_COLUMNS} FROM agent_providers WHERE id=$1"
    )))
    .bind(id.to_string())
    .fetch_one(&mut *tx)
    .await?;
    let view = provider_from_row(&row, settings.allow_offshore)?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(view)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderPatch {
    revision: i64,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    data_location: Option<String>,
    #[serde(default)]
    residency: Option<String>,
    #[serde(default)]
    models: Option<Vec<String>>,
    /// Replaces the stored credential; it is never returned.
    #[serde(default)]
    credential: Option<String>,
    #[serde(default)]
    clear_credential: bool,
}

async fn update_provider(
    State(s): State<AppState>,
    UrlPath((org_id, provider_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<ProviderPatch>,
) -> Result<Json<ProviderView>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageAgentGateway)?;
    let mut tx = s.store.pool.begin().await?;
    let org = org_id.to_string();
    let settings = load_settings(&mut tx, &org).await?;
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {PROVIDER_COLUMNS} FROM agent_providers WHERE id=$1 AND org_id=$2"
    )))
    .bind(provider_id.to_string())
    .bind(&org)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let current_sealed: Option<String> = row.try_get(6)?;
    let before = provider_from_row(&row, settings.allow_offshore)?;
    if before.revision != input.revision {
        return Err(ApiError::PreconditionFailed);
    }
    let residency = match &input.residency {
        Some(value) => check_residency(value)?,
        None => before.residency.clone(),
    };
    let data_location = match &input.data_location {
        Some(value) => printable(value, "data location", 80)?,
        None => before.data_location.clone(),
    };
    let new_credential = input
        .credential
        .as_deref()
        .filter(|c| !c.trim().is_empty())
        .map(check_credential)
        .transpose()?;
    if input.clear_credential && new_credential.is_some() {
        return Err(bad("send either a new credential or clear_credential"));
    }
    let sealed = if input.clear_credential {
        None
    } else if let Some(credential) = &new_credential {
        Some(seal_key(&s.auth_hmac_secret, credential)?)
    } else {
        current_sealed
    };
    let base_url = check_base_url(
        input.base_url.as_deref().unwrap_or(&before.base_url),
        &residency,
        sealed.is_some(),
    )?;
    let models = match &input.models {
        Some(models) => check_models(models, false)?,
        None => before.models.clone(),
    };
    let enabled = input.enabled.unwrap_or(before.enabled);
    sqlx::query(
        "UPDATE agent_providers SET base_url=$1,data_location=$2,residency=$3,sealed_credential=$4,models_json=$5,enabled=$6,revision=revision+1,updated_at=$7 WHERE id=$8 AND org_id=$9 AND revision=$10",
    )
    .bind(&base_url)
    .bind(&data_location)
    .bind(&residency)
    .bind(&sealed)
    .bind(to_json(&models)?)
    .bind(i64::from(enabled))
    .bind(now())
    .bind(provider_id.to_string())
    .bind(&org)
    .bind(input.revision)
    .execute(&mut *tx)
    .await?
    .rows_affected()
    .eq(&1)
    .then_some(())
    .ok_or(ApiError::PreconditionFailed)?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "agent.provider.updated",
        "agent_provider",
        Some(&provider_id.to_string()),
        &serde_json::json!({
            "name": before.name,
            "base_url": base_url,
            "data_location": data_location,
            "residency": {"from": before.residency, "to": residency},
            "models": models,
            "enabled": enabled,
            "credential_replaced": new_credential.is_some(),
            "credential_cleared": input.clear_credential,
        }),
    )
    .await?;
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {PROVIDER_COLUMNS} FROM agent_providers WHERE id=$1"
    )))
    .bind(provider_id.to_string())
    .fetch_one(&mut *tx)
    .await?;
    let view = provider_from_row(&row, settings.allow_offshore)?;
    tx.commit().await?;
    Ok(Json(view))
}

async fn delete_provider(
    State(s): State<AppState>,
    UrlPath((org_id, provider_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageAgentGateway)?;
    let mut tx = s.store.pool.begin().await?;
    let name: String =
        sqlx::query_scalar("SELECT name FROM agent_providers WHERE id=$1 AND org_id=$2")
            .bind(provider_id.to_string())
            .bind(org_id.to_string())
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ApiError::NotFound)?;
    sqlx::query("DELETE FROM agent_providers WHERE id=$1 AND org_id=$2")
        .bind(provider_id.to_string())
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "agent.provider.deleted",
        "agent_provider",
        Some(&provider_id.to_string()),
        &serde_json::json!({"name": name}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Validates a key policy against the organisation. Full logging is an owner
/// decision with an explicit ICIP acknowledgement and at most 30 days.
async fn check_policy(
    conn: &mut AnyConnection,
    org_id: &str,
    role: Role,
    policy: &Policy,
    previous: Option<&Policy>,
    acknowledge_icip: bool,
) -> Result<Policy, ApiError> {
    let mut out = policy.clone();
    if !LOGGING_MODES.contains(&policy.logging_mode.as_str()) {
        return Err(bad("logging_mode must be off, metadata or full"));
    }
    if !(1..=1_000_000).contains(&policy.daily_request_quota) {
        return Err(bad("daily request quota must be 1 to 1000000"));
    }
    if !(1..=1_000_000_000).contains(&policy.daily_token_quota) {
        return Err(bad("daily token quota must be 1 to 1000000000"));
    }
    if !(1..=MAX_REQUEST_BYTES).contains(&policy.max_request_bytes) {
        return Err(bad(format!(
            "max request size must be 1 to {MAX_REQUEST_BYTES} bytes"
        )));
    }
    if policy.logging_mode == "full" {
        if !(1..=MAX_FULL_RETENTION_DAYS).contains(&policy.log_retention_days) {
            return Err(bad(format!(
                "full logging needs a retention of 1 to {MAX_FULL_RETENTION_DAYS} days"
            )));
        }
        let changed = previous.is_none_or(|before| {
            before.logging_mode != "full" || before.log_retention_days != policy.log_retention_days
        });
        if changed {
            if role != Role::Owner {
                return Err(ApiError::Forbidden);
            }
            if !acknowledge_icip {
                return Err(bad(format!(
                    "acknowledge the ICIP warning to enable full logging: {ICIP_WARNING}"
                )));
            }
        }
    } else {
        out.log_retention_days = 0;
    }
    out.allowed_models = check_models(&policy.allowed_models, true)?;
    if policy.redact_patterns.len() > MAX_PATTERNS {
        return Err(bad(format!("at most {MAX_PATTERNS} redaction patterns")));
    }
    for pattern in &policy.redact_patterns {
        if pattern.is_empty() || pattern.len() > MAX_PATTERN_LEN {
            return Err(bad(format!(
                "redaction patterns must be 1 to {MAX_PATTERN_LEN} characters"
            )));
        }
        compile_pattern(pattern).map_err(ApiError::BadRequest)?;
    }
    let mut providers = policy.allowed_provider_ids.clone();
    providers.sort();
    providers.dedup();
    for provider in &providers {
        sqlx::query_scalar::<_, String>("SELECT id FROM agent_providers WHERE id=$1 AND org_id=$2")
            .bind(provider.to_string())
            .bind(org_id)
            .fetch_optional(&mut *conn)
            .await?
            .ok_or_else(|| bad(format!("provider {provider} does not exist")))?;
    }
    out.allowed_provider_ids = providers;
    if let Some(node) = policy.bound_node_id {
        sqlx::query_scalar::<_, String>(
            "SELECT id FROM nodes WHERE id=$1 AND org_id=$2 AND revoked_at IS NULL AND deleted_at IS NULL",
        )
        .bind(node.to_string())
        .bind(org_id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| bad("the bound device is not an active device in this organisation"))?;
    }
    Ok(out)
}

fn policy_audit(policy: &Policy) -> serde_json::Value {
    serde_json::json!({
        "bound_node_id": policy.bound_node_id,
        "allowed_provider_ids": policy.allowed_provider_ids,
        "allowed_models": policy.allowed_models,
        "daily_request_quota": policy.daily_request_quota,
        "daily_token_quota": policy.daily_token_quota,
        "max_request_bytes": policy.max_request_bytes,
        "logging_mode": policy.logging_mode,
        "log_retention_days": policy.log_retention_days,
        "redact_pattern_count": policy.redact_patterns.len(),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyCreate {
    name: String,
    #[serde(default)]
    policy: Policy,
    #[serde(default)]
    acknowledge_icip: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CreatedKey {
    pub(crate) key: KeyView,
    /// Shown once; only its hash is stored.
    pub(crate) secret: String,
}

async fn create_key(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<KeyCreate>,
) -> Result<(StatusCode, Json<CreatedKey>), ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageAgentGateway)?;
    let name = check_name(&input.name)?;
    let mut tx = s.store.pool.begin().await?;
    org_exists(&mut tx, org_id).await?;
    let org = org_id.to_string();
    let policy = check_policy(
        &mut tx,
        &org,
        session.role,
        &input.policy,
        None,
        input.acknowledge_icip,
    )
    .await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM agent_keys WHERE org_id=$1 AND revoked_at IS NULL",
    )
    .bind(&org)
    .fetch_one(&mut *tx)
    .await?;
    if count >= MAX_KEYS {
        return Err(bad(format!(
            "organisations are limited to {MAX_KEYS} active agent keys"
        )));
    }
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let secret = format!("{KEY_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw));
    let id = Uuid::new_v4();
    let current = now();
    sqlx::query(
        "INSERT INTO agent_keys(id,org_id,name,key_prefix,key_hash,bound_node_id,allowed_providers_json,allowed_models_json,daily_request_quota,daily_token_quota,max_request_bytes,logging_mode,log_retention_days,redact_patterns_json,revision,created_by,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,1,$15,$16,$16)",
    )
    .bind(id.to_string())
    .bind(&org)
    .bind(&name)
    .bind(&secret[..12])
    .bind(hash(&secret))
    .bind(policy.bound_node_id.map(|n| n.to_string()))
    .bind(to_json(&policy.allowed_provider_ids)?)
    .bind(to_json(&policy.allowed_models)?)
    .bind(policy.daily_request_quota)
    .bind(policy.daily_token_quota)
    .bind(policy.max_request_bytes)
    .bind(&policy.logging_mode)
    .bind(policy.log_retention_days)
    .bind(to_json(&policy.redact_patterns)?)
    .bind(&session.user_id)
    .bind(current)
    .execute(&mut *tx)
    .await?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "agent.key.created",
        "agent_key",
        Some(&id.to_string()),
        &serde_json::json!({
            "name": name,
            "key_prefix": &secret[..12],
            "policy": policy_audit(&policy),
            "icip_acknowledged": policy.logging_mode == "full",
        }),
    )
    .await?;
    let key = load_key(&mut tx, org_id, id).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(CreatedKey { key, secret })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyUpdate {
    revision: i64,
    policy: Policy,
    #[serde(default)]
    acknowledge_icip: bool,
}

async fn update_key(
    State(s): State<AppState>,
    UrlPath((org_id, key_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<KeyUpdate>,
) -> Result<Json<KeyView>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageAgentGateway)?;
    let mut tx = s.store.pool.begin().await?;
    let org = org_id.to_string();
    let before = load_key(&mut tx, org_id, key_id).await?;
    if before.revoked_at.is_some() {
        return Err(ApiError::Conflict("this key is revoked".into()));
    }
    if before.revision != input.revision {
        return Err(ApiError::PreconditionFailed);
    }
    let policy = check_policy(
        &mut tx,
        &org,
        session.role,
        &input.policy,
        Some(&before.policy),
        input.acknowledge_icip,
    )
    .await?;
    let updated = sqlx::query(
        "UPDATE agent_keys SET bound_node_id=$1,allowed_providers_json=$2,allowed_models_json=$3,daily_request_quota=$4,daily_token_quota=$5,max_request_bytes=$6,logging_mode=$7,log_retention_days=$8,redact_patterns_json=$9,revision=revision+1,updated_at=$10 WHERE id=$11 AND org_id=$12 AND revision=$13 AND revoked_at IS NULL",
    )
    .bind(policy.bound_node_id.map(|n| n.to_string()))
    .bind(to_json(&policy.allowed_provider_ids)?)
    .bind(to_json(&policy.allowed_models)?)
    .bind(policy.daily_request_quota)
    .bind(policy.daily_token_quota)
    .bind(policy.max_request_bytes)
    .bind(&policy.logging_mode)
    .bind(policy.log_retention_days)
    .bind(to_json(&policy.redact_patterns)?)
    .bind(now())
    .bind(key_id.to_string())
    .bind(&org)
    .bind(input.revision)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if updated != 1 {
        return Err(ApiError::PreconditionFailed);
    }
    if policy.logging_mode != "full" {
        // Leaving full logging deletes stored content now, not at expiry.
        sqlx::query("UPDATE agent_requests SET sealed_content=NULL,content_expires_at=NULL WHERE org_id=$1 AND key_id=$2")
            .bind(&org)
            .bind(key_id.to_string())
            .execute(&mut *tx)
            .await?;
    }
    append_audit(
        &mut tx,
        org_id,
        &session,
        "agent.key.policy_updated",
        "agent_key",
        Some(&key_id.to_string()),
        &serde_json::json!({
            "from": policy_audit(&before.policy),
            "to": policy_audit(&policy),
        }),
    )
    .await?;
    let key = load_key(&mut tx, org_id, key_id).await?;
    tx.commit().await?;
    Ok(Json(key))
}

async fn revoke_key(
    State(s): State<AppState>,
    UrlPath((org_id, key_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageAgentGateway)?;
    let mut tx = s.store.pool.begin().await?;
    let before = load_key(&mut tx, org_id, key_id).await?;
    if before.revoked_at.is_none() {
        sqlx::query("UPDATE agent_keys SET revoked_at=$1,updated_at=$1,revision=revision+1 WHERE id=$2 AND org_id=$3 AND revoked_at IS NULL")
            .bind(now())
            .bind(key_id.to_string())
            .bind(org_id.to_string())
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE agent_requests SET sealed_content=NULL,content_expires_at=NULL WHERE org_id=$1 AND key_id=$2")
            .bind(org_id.to_string())
            .bind(key_id.to_string())
            .execute(&mut *tx)
            .await?;
        append_audit(
            &mut tx,
            org_id,
            &session,
            "agent.key.revoked",
            "agent_key",
            Some(&key_id.to_string()),
            &serde_json::json!({"name": before.name, "key_prefix": before.key_prefix}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct UsageQuery {
    #[serde(default)]
    days: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct UsageDay {
    pub(crate) day: String,
    pub(crate) key_id: String,
    pub(crate) key_name: Option<String>,
    pub(crate) model: String,
    pub(crate) requests: i64,
    pub(crate) errors: i64,
    pub(crate) prompt_tokens: i64,
    pub(crate) completion_tokens: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RequestRecord {
    pub(crate) id: String,
    key_id: String,
    pub(crate) model: String,
    provider_id: String,
    caller_node_id: Option<String>,
    pub(crate) status: String,
    http_status: Option<i64>,
    request_bytes: i64,
    pub(crate) prompt_tokens: i64,
    pub(crate) completion_tokens: i64,
    usage_estimated: bool,
    latency_ms: Option<i64>,
    started_at: i64,
    pub(crate) has_content: bool,
    content_expires_at: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Usage {
    pub(crate) days: Vec<UsageDay>,
    pub(crate) recent: Vec<RequestRecord>,
}

async fn usage(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    Query(query): Query<UsageQuery>,
    headers: HeaderMap,
) -> Result<Json<Usage>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewAgentUsage)?;
    let days = query.days.unwrap_or(14).clamp(1, 90);
    let mut conn = s.store.pool.acquire().await?;
    let org = org_id.to_string();
    purge(&mut conn, &org).await?;
    let since = day_of(now() - (days - 1) * 86_400);
    let days = sqlx::query(
        "SELECT u.day,u.key_id,k.name,u.model,u.requests,u.errors,u.prompt_tokens,u.completion_tokens FROM agent_usage_days u LEFT JOIN agent_keys k ON k.id=u.key_id AND k.org_id=u.org_id WHERE u.org_id=$1 AND u.day>=$2 ORDER BY u.day DESC, k.name, u.model",
    )
    .bind(&org)
    .bind(&since)
    .fetch_all(&mut *conn)
    .await?
    .iter()
    .map(|row| {
        Ok(UsageDay {
            day: row.try_get(0)?,
            key_id: row.try_get(1)?,
            key_name: row.try_get(2)?,
            model: row.try_get(3)?,
            requests: row.try_get(4)?,
            errors: row.try_get(5)?,
            prompt_tokens: row.try_get(6)?,
            completion_tokens: row.try_get(7)?,
        })
    })
    .collect::<Result<Vec<_>, ApiError>>()?;
    let recent = sqlx::query(
        "SELECT id,key_id,model,provider_id,caller_node_id,status,http_status,request_bytes,prompt_tokens,completion_tokens,usage_estimated,latency_ms,started_at,CASE WHEN sealed_content IS NULL THEN 0 ELSE 1 END,content_expires_at FROM agent_requests WHERE org_id=$1 ORDER BY started_at DESC, id LIMIT 100",
    )
    .bind(&org)
    .fetch_all(&mut *conn)
    .await?
    .iter()
    .map(|row| {
        Ok(RequestRecord {
            id: row.try_get(0)?,
            key_id: row.try_get(1)?,
            model: row.try_get(2)?,
            provider_id: row.try_get(3)?,
            caller_node_id: row.try_get(4)?,
            status: row.try_get(5)?,
            http_status: row.try_get(6)?,
            request_bytes: row.try_get(7)?,
            prompt_tokens: row.try_get(8)?,
            completion_tokens: row.try_get(9)?,
            usage_estimated: row.try_get::<i64, _>(10)? != 0,
            latency_ms: row.try_get(11)?,
            started_at: row.try_get(12)?,
            has_content: row.try_get::<i64, _>(13)? != 0,
            content_expires_at: row.try_get(14)?,
        })
    })
    .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(Usage { days, recent }))
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Content {
    pub(crate) request: String,
    pub(crate) response: String,
    expires_at: i64,
}

/// Reading stored prompts is owner-only and always audited.
async fn request_content(
    State(s): State<AppState>,
    UrlPath((org_id, request_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<Content>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageAgentGateway)?;
    if session.role != Role::Owner {
        return Err(ApiError::Forbidden);
    }
    let mut tx = s.store.pool.begin().await?;
    purge(&mut tx, &org_id.to_string()).await?;
    let row = sqlx::query(
        "SELECT sealed_content,content_expires_at,key_id FROM agent_requests WHERE id=$1 AND org_id=$2 AND sealed_content IS NOT NULL",
    )
    .bind(request_id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let stored: StoredContent = serde_json::from_str(&open_key(
        &s.auth_hmac_secret,
        &row.try_get::<String, _>(0)?,
    )?)
    .map_err(|_| ApiError::CorruptData)?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "agent.request_content.viewed",
        "agent_request",
        Some(&request_id.to_string()),
        &serde_json::json!({"key_id": row.try_get::<String, _>(2)?}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(Content {
        request: stored.request,
        response: stored.response,
        expires_at: row.try_get(1)?,
    }))
}

// ---------------------------------------------------------------- gateway

/// Authenticates the gateway node: node token, active, not suspended or
/// expired, the `agent-gateway` capability and an owner/admin designation.
/// Every gateway endpoint goes through here, so the caller address a gateway
/// reports (`client_ip`) is only ever trusted from a designated device.
async fn gateway_org(s: &AppState, node_id: Uuid, headers: &HeaderMap) -> Result<String, ApiError> {
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
    let capabilities: Vec<String> = json_col(&row, 2).unwrap_or_default();
    if !capabilities.iter().any(|c| c == CAP_AGENT_GATEWAY) {
        return Err(ApiError::Forbidden);
    }
    let org: String = row.try_get(0)?;
    let mut conn = s.store.pool.acquire().await?;
    if !designations::is_designated(&mut conn, &org, node_id, designations::AGENT_GATEWAY).await? {
        return Err(ApiError::Forbidden);
    }
    Ok(org)
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Denial {
    pub(crate) status: u16,
    pub(crate) code: String,
    pub(crate) message: String,
}

fn deny(status: u16, code: &str, message: impl Into<String>) -> Denial {
    Denial {
        status,
        code: code.into(),
        message: message.into(),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct UpstreamGrant {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) base_url: String,
    pub(crate) credential: Option<String>,
    pub(crate) data_location: String,
    pub(crate) residency: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Grant {
    pub(crate) request_id: Uuid,
    pub(crate) key_id: Uuid,
    pub(crate) model: String,
    pub(crate) provider: UpstreamGrant,
    pub(crate) logging_mode: String,
    pub(crate) redact_patterns: Vec<String>,
    /// Output tokens reserved for this request; the gateway clamps the
    /// forwarded `max_tokens` to it.
    pub(crate) max_tokens: i64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct Decision {
    pub(crate) allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) denial: Option<Denial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) grant: Option<Grant>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizeInput {
    api_key: String,
    model: String,
    #[serde(default)]
    client_ip: Option<String>,
    request_bytes: i64,
    /// The client's requested output limit, if any.
    #[serde(default)]
    max_tokens: Option<i64>,
}

struct ActiveKey {
    id: String,
    policy: Policy,
}

async fn find_key(
    conn: &mut AnyConnection,
    org: &str,
    api_key: &str,
) -> Result<Option<ActiveKey>, ApiError> {
    if !api_key.starts_with(KEY_PREFIX) || api_key.len() > 128 {
        return Ok(None);
    }
    // Scoped to the gateway's organisation: another org's key is unknown here.
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {KEY_COLUMNS} FROM agent_keys k LEFT JOIN agent_quota_days q ON q.key_id=k.id AND q.day=$3 WHERE k.org_id=$1 AND k.key_hash=$2 AND k.revoked_at IS NULL"
    )))
    .bind(org)
    .bind(hash(api_key))
    .bind(day_of(now()))
    .fetch_optional(&mut *conn)
    .await?;
    Ok(match row {
        Some(row) => {
            let key = key_from_row(&row)?;
            Some(ActiveKey {
                id: key.id.to_string(),
                policy: key.policy,
            })
        }
        None => None,
    })
}

/// Maps a caller's overlay source address to an active node in the org.
async fn caller_node(
    conn: &mut AnyConnection,
    org: &str,
    client_ip: Option<&str>,
) -> Result<Option<(String, bool)>, ApiError> {
    let Some(ip) = client_ip.and_then(|ip| ip.trim().parse::<IpAddr>().ok()) else {
        return Ok(None);
    };
    let rows = sqlx::query(
        "SELECT id,allowed_ips_json,CASE WHEN suspended_at IS NULL THEN 0 ELSE 1 END FROM nodes WHERE org_id=$1 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(org)
    .fetch_all(&mut *conn)
    .await?;
    for row in rows {
        let addresses: Vec<String> = json_col(&row, 1).unwrap_or_default();
        let matches = addresses.iter().any(|address| {
            let (host, len) = address.split_once('/').unwrap_or((address, ""));
            matches!(len, "" | "32" | "128") && host.parse::<IpAddr>().ok() == Some(ip)
        });
        if matches {
            return Ok(Some((row.try_get(0)?, row.try_get::<i64, _>(2)? != 0)));
        }
    }
    Ok(None)
}

struct Chosen {
    row: AnyRow,
}

/// Picks the provider for `model` among the key's allowed providers,
/// preferring onshore ones; offshore only when the organisation allows it.
async fn choose_provider(
    conn: &mut AnyConnection,
    org: &str,
    policy: &Policy,
    model: &str,
    allow_offshore: bool,
) -> Result<Result<Chosen, Denial>, ApiError> {
    if !policy.allowed_models.is_empty() && !policy.allowed_models.iter().any(|m| m == model) {
        return Ok(Err(deny(
            403,
            "model_not_allowed",
            format!("this agent key may not use model {model:?}"),
        )));
    }
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {PROVIDER_COLUMNS} FROM agent_providers WHERE org_id=$1 AND enabled=1 ORDER BY CASE WHEN residency='onshore' THEN 0 ELSE 1 END, name"
    )))
    .bind(org)
    .fetch_all(&mut *conn)
    .await?;
    let mut served_elsewhere = false;
    let mut offshore_blocked = false;
    for row in rows {
        let view = provider_from_row(&row, allow_offshore)?;
        if !view.models.iter().any(|m| m == model) {
            continue;
        }
        if !policy.allowed_provider_ids.contains(&view.id) {
            served_elsewhere = true;
            continue;
        }
        if view.blocked_by_policy {
            offshore_blocked = true;
            continue;
        }
        return Ok(Ok(Chosen { row }));
    }
    Ok(Err(if offshore_blocked {
        deny(
            403,
            "offshore_forbidden",
            "this model is only available from an offshore provider and the organisation forbids offshore providers",
        )
    } else if served_elsewhere {
        deny(
            403,
            "model_not_allowed",
            format!("this agent key may not use any provider serving {model:?}"),
        )
    } else {
        deny(
            404,
            "model_not_found",
            format!("no enabled provider serves {model:?}"),
        )
    }))
}

async fn count_denial(conn: &mut AnyConnection, org: &str, key_id: &str) -> Result<(), ApiError> {
    let day = day_of(now());
    sqlx::query("INSERT INTO agent_quota_days(key_id,day,org_id) VALUES($1,$2,$3) ON CONFLICT(key_id,day) DO NOTHING")
        .bind(key_id)
        .bind(&day)
        .bind(org)
        .execute(&mut *conn)
        .await?;
    sqlx::query("UPDATE agent_quota_days SET denied=denied+1 WHERE key_id=$1 AND day=$2")
        .bind(key_id)
        .bind(&day)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn authorize(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<AuthorizeInput>,
) -> Result<Json<Decision>, ApiError> {
    let org = gateway_org(&s, node_id, &headers).await?;
    let mut tx = s.store.pool.begin().await?;
    purge(&mut tx, &org).await?;
    let Some(key) = find_key(&mut tx, &org, input.api_key.trim()).await? else {
        return Ok(Json(Decision {
            denial: Some(deny(401, "invalid_api_key", "unknown or revoked agent key")),
            ..Decision::default()
        }));
    };
    let decision = decide(&s, &mut tx, &org, node_id, &key, &input).await?;
    if let Err(denial) = &decision {
        count_denial(&mut tx, &org, &key.id).await?;
        tx.commit().await?;
        return Ok(Json(Decision {
            denial: Some(deny(denial.status, &denial.code, denial.message.clone())),
            ..Decision::default()
        }));
    }
    tx.commit().await?;
    Ok(Json(Decision {
        allowed: true,
        grant: decision.ok(),
        denial: None,
    }))
}

async fn decide(
    s: &AppState,
    tx: &mut AnyConnection,
    org: &str,
    gateway: Uuid,
    key: &ActiveKey,
    input: &AuthorizeInput,
) -> Result<Result<Grant, Denial>, ApiError> {
    let caller = caller_node(tx, org, input.client_ip.as_deref()).await?;
    if let Some((_, true)) = caller {
        return Ok(Err(deny(
            403,
            "caller_suspended",
            "the calling device is suspended",
        )));
    }
    if let Some(bound) = key.policy.bound_node_id {
        if caller.as_ref().map(|(id, _)| id.as_str()) != Some(bound.to_string().as_str()) {
            return Ok(Err(deny(
                403,
                "node_binding",
                "this agent key is bound to another device",
            )));
        }
    }
    if input.request_bytes < 0 || input.request_bytes > key.policy.max_request_bytes {
        return Ok(Err(deny(
            413,
            "request_too_large",
            format!(
                "request body exceeds this key's limit of {} bytes",
                key.policy.max_request_bytes
            ),
        )));
    }
    let model = input.model.trim();
    if check_models(&[model.to_owned()], false).is_err() {
        return Ok(Err(deny(
            400,
            "invalid_model",
            "model id is missing or invalid",
        )));
    }
    let settings = load_settings(tx, org).await?;
    let chosen = match choose_provider(tx, org, &key.policy, model, settings.allow_offshore).await?
    {
        Ok(chosen) => chosen,
        Err(denial) => return Ok(Err(denial)),
    };
    let current = now();
    let day = day_of(current);
    sqlx::query("INSERT INTO agent_quota_days(key_id,day,org_id) VALUES($1,$2,$3) ON CONFLICT(key_id,day) DO NOTHING")
        .bind(&key.id)
        .bind(&day)
        .bind(org)
        .execute(&mut *tx)
        .await?;
    // Tokens are reserved up front (prompt estimate plus the output
    // allowance) and settled when usage arrives, so concurrent requests
    // cannot together overrun the daily token quota.
    let used: i64 =
        sqlx::query_scalar("SELECT tokens FROM agent_quota_days WHERE key_id=$1 AND day=$2")
            .bind(&key.id)
            .bind(&day)
            .fetch_one(&mut *tx)
            .await?;
    let prompt_estimate = (input.request_bytes + 3) / 4;
    let output = input
        .max_tokens
        .filter(|tokens| *tokens > 0)
        .unwrap_or(DEFAULT_OUTPUT_TOKENS)
        .min(key.policy.daily_token_quota - used - prompt_estimate);
    let reserve = prompt_estimate + output;
    // The conditional increment is the quota check, so concurrent requests
    // can never exceed the daily request or token quota.
    let reserved = if output < 1 {
        0
    } else {
        sqlx::query(
            "UPDATE agent_quota_days SET requests=requests+1,tokens=tokens+$5 WHERE key_id=$1 AND day=$2 AND requests<$3 AND tokens+$5<=$4",
        )
        .bind(&key.id)
        .bind(&day)
        .bind(key.policy.daily_request_quota)
        .bind(key.policy.daily_token_quota)
        .bind(reserve)
        .execute(&mut *tx)
        .await?
        .rows_affected()
    };
    if reserved != 1 {
        return Ok(Err(deny(
            429,
            "quota_exceeded",
            "this agent key has used its daily request or token quota (resets at 00:00 UTC)",
        )));
    }
    let provider = provider_from_row(&chosen.row, settings.allow_offshore)?;
    let credential = chosen
        .row
        .try_get::<Option<String>, _>(6)?
        .map(|sealed| open_key(&s.auth_hmac_secret, &sealed))
        .transpose()?;
    let request_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agent_requests(id,org_id,key_id,provider_id,model,gateway_node_id,caller_node_id,day,logging_mode,status,request_bytes,started_at,reserved_tokens) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',$10,$11,$12)",
    )
    .bind(request_id.to_string())
    .bind(org)
    .bind(&key.id)
    .bind(provider.id.to_string())
    .bind(model)
    .bind(gateway.to_string())
    .bind(caller.map(|(id, _)| id))
    .bind(&day)
    .bind(&key.policy.logging_mode)
    .bind(input.request_bytes)
    .bind(current)
    .bind(reserve)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE agent_keys SET last_used_at=$1 WHERE id=$2")
        .bind(current)
        .bind(&key.id)
        .execute(&mut *tx)
        .await?;
    Ok(Ok(Grant {
        request_id,
        key_id: key.id.parse().map_err(|_| ApiError::CorruptData)?,
        model: model.to_owned(),
        provider: UpstreamGrant {
            id: provider.id,
            name: provider.name,
            kind: provider.kind,
            base_url: provider.base_url,
            credential,
            data_location: provider.data_location,
            residency: provider.residency,
        },
        logging_mode: key.policy.logging_mode.clone(),
        redact_patterns: key.policy.redact_patterns.clone(),
        max_tokens: output,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelsInput {
    api_key: String,
    #[serde(default)]
    client_ip: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ModelEntry {
    pub(crate) id: String,
    pub(crate) provider: String,
    pub(crate) data_location: String,
    pub(crate) residency: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct ModelList {
    pub(crate) allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) denial: Option<Denial>,
    #[serde(default)]
    pub(crate) models: Vec<ModelEntry>,
}

/// The models a key could use right now (allowlist and offshore policy
/// applied; quotas are not reserved).
async fn models(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<ModelsInput>,
) -> Result<Json<ModelList>, ApiError> {
    let org = gateway_org(&s, node_id, &headers).await?;
    let mut conn = s.store.pool.acquire().await?;
    let Some(key) = find_key(&mut conn, &org, input.api_key.trim()).await? else {
        return Ok(Json(ModelList {
            denial: Some(deny(401, "invalid_api_key", "unknown or revoked agent key")),
            ..ModelList::default()
        }));
    };
    if let Some(bound) = key.policy.bound_node_id {
        let caller = caller_node(&mut conn, &org, input.client_ip.as_deref()).await?;
        if caller.map(|(id, _)| id) != Some(bound.to_string()) {
            return Ok(Json(ModelList {
                denial: Some(deny(
                    403,
                    "node_binding",
                    "this agent key is bound to another device",
                )),
                ..ModelList::default()
            }));
        }
    }
    let settings = load_settings(&mut conn, &org).await?;
    let mut models = Vec::new();
    for provider in load_providers(&mut conn, &org, settings.allow_offshore).await? {
        if !provider.enabled
            || provider.blocked_by_policy
            || !key.policy.allowed_provider_ids.contains(&provider.id)
        {
            continue;
        }
        for model in &provider.models {
            let allowed =
                key.policy.allowed_models.is_empty() || key.policy.allowed_models.contains(model);
            if allowed && !models.iter().any(|m: &ModelEntry| &m.id == model) {
                models.push(ModelEntry {
                    id: model.clone(),
                    provider: provider.name.clone(),
                    data_location: provider.data_location.clone(),
                    residency: provider.residency.clone(),
                });
            }
        }
    }
    Ok(Json(ModelList {
        allowed: true,
        denial: None,
        models,
    }))
}

#[derive(Deserialize, Serialize)]
struct StoredContent {
    request: String,
    response: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UsageInput {
    request_id: Uuid,
    /// `ok` or `error`.
    status: String,
    #[serde(default)]
    http_status: Option<u16>,
    #[serde(default)]
    prompt_tokens: i64,
    #[serde(default)]
    completion_tokens: i64,
    #[serde(default)]
    usage_estimated: bool,
    #[serde(default)]
    latency_ms: Option<i64>,
    /// Sent only for keys in full logging mode; ignored otherwise.
    #[serde(default)]
    request_content: Option<String>,
    #[serde(default)]
    response_content: Option<String>,
}

async fn ingest_usage(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<UsageInput>,
) -> Result<StatusCode, ApiError> {
    let org = gateway_org(&s, node_id, &headers).await?;
    if !matches!(input.status.as_str(), "ok" | "error") {
        return Err(bad("status must be ok or error"));
    }
    let cap = 100_000_000;
    if !(0..=cap).contains(&input.prompt_tokens) || !(0..=cap).contains(&input.completion_tokens) {
        return Err(bad("token counts are out of range"));
    }
    let mut tx = s.store.pool.begin().await?;
    // Only the gateway that reserved the request may close it, once.
    let row = sqlx::query(
        "SELECT r.key_id,r.model,r.day,r.status,k.logging_mode,k.log_retention_days,r.reserved_tokens FROM agent_requests r JOIN agent_keys k ON k.id=r.key_id WHERE r.id=$1 AND r.org_id=$2 AND r.gateway_node_id=$3",
    )
    .bind(input.request_id.to_string())
    .bind(&org)
    .bind(node_id.to_string())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let key_id: String = row.try_get(0)?;
    let model: String = row.try_get(1)?;
    let day: String = row.try_get(2)?;
    if row.try_get::<String, _>(3)? != "pending" {
        return Err(ApiError::Conflict(
            "usage for this request was already recorded".into(),
        ));
    }
    // The key's current mode wins: switching logging off stops storage at once.
    let mode: String = row.try_get(4)?;
    let retention: i64 = row.try_get(5)?;
    let reserved: i64 = row.try_get(6)?;
    let tokens = input.prompt_tokens + input.completion_tokens;
    // Settle the reservation: release what was not used, charge any overrun.
    sqlx::query("UPDATE agent_quota_days SET tokens=tokens+$1 WHERE key_id=$2 AND day=$3")
        .bind(tokens - reserved)
        .bind(&key_id)
        .bind(&day)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO agent_usage_days(org_id,key_id,model,day) VALUES($1,$2,$3,$4) ON CONFLICT(org_id,key_id,model,day) DO NOTHING")
        .bind(&org)
        .bind(&key_id)
        .bind(&model)
        .bind(&day)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE agent_usage_days SET requests=requests+1,errors=errors+$1,prompt_tokens=prompt_tokens+$2,completion_tokens=completion_tokens+$3 WHERE org_id=$4 AND key_id=$5 AND model=$6 AND day=$7")
        .bind(i64::from(input.status == "error"))
        .bind(input.prompt_tokens)
        .bind(input.completion_tokens)
        .bind(&org)
        .bind(&key_id)
        .bind(&model)
        .bind(&day)
        .execute(&mut *tx)
        .await?;
    let current = now();
    if mode == "off" {
        sqlx::query("DELETE FROM agent_requests WHERE id=$1")
            .bind(input.request_id.to_string())
            .execute(&mut *tx)
            .await?;
    } else {
        let content = if mode == "full" {
            match (&input.request_content, &input.response_content) {
                (Some(request), response) => {
                    let stored = StoredContent {
                        request: request.chars().take(MAX_CONTENT_CHARS).collect(),
                        response: response
                            .as_deref()
                            .unwrap_or_default()
                            .chars()
                            .take(MAX_CONTENT_CHARS)
                            .collect(),
                    };
                    let sealed = seal_key(&s.auth_hmac_secret, &to_json(&stored)?)?;
                    Some((
                        sealed,
                        current + retention.min(MAX_FULL_RETENTION_DAYS) * 86_400,
                    ))
                }
                _ => None,
            }
        } else {
            None
        };
        sqlx::query(
            "UPDATE agent_requests SET status=$1,http_status=$2,prompt_tokens=$3,completion_tokens=$4,usage_estimated=$5,latency_ms=$6,finished_at=$7,expires_at=$8,sealed_content=$9,content_expires_at=$10 WHERE id=$11",
        )
        .bind(&input.status)
        .bind(input.http_status.map(i64::from))
        .bind(input.prompt_tokens)
        .bind(input.completion_tokens)
        .bind(i64::from(input.usage_estimated))
        .bind(input.latency_ms)
        .bind(current)
        .bind(current + METADATA_RETENTION_DAYS * 86_400)
        .bind(content.as_ref().map(|(sealed, _)| sealed.clone()))
        .bind(content.map(|(_, expires)| expires))
        .bind(input.request_id.to_string())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests;
