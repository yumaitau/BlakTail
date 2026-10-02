use crate::permissions::{require, Permission};
use crate::{hash, now, secret, ApiError, AppState, Session};
use axum::{
    extract::{Path as UrlPath, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::net::lookup_host;
use tracing::warn;
use url::Url;
use uuid::Uuid;

const WEBHOOK_SECRET_PREFIX: &str = "btw";
const SEALED_SECRET_PREFIX: &str = "bte1.";
const MAX_DESTINATIONS: i64 = 8;
const MAX_ATTEMPTS: i64 = 8;
const MAX_CONSOLE_EVENT_PAYLOAD: usize = 4_096;
const ALLOWED_CONSOLE_EVENTS: &[&str] = &["membership.updated"];
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(200);

fn webhook_seal_key(master: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"blaktail-webhook-secret-v1");
    hasher.update(master);
    hasher.finalize().into()
}

fn seal_signing_secret(master: &[u8], plaintext: &str) -> Result<String, ApiError> {
    let cipher = ChaCha20Poly1305::new_from_slice(&webhook_seal_key(master))
        .map_err(|_| ApiError::BadRequest("webhook sealing key is invalid".into()))?;
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| ApiError::CorruptData)?;
    let mut packed = nonce_bytes.to_vec();
    packed.extend(ciphertext);
    Ok(format!("{SEALED_SECRET_PREFIX}{}", STANDARD.encode(packed)))
}

fn open_signing_secret(master: &[u8], stored: &str) -> Result<String, ApiError> {
    if stored.starts_with("btw_") {
        return Ok(stored.to_owned());
    }
    let packed = stored
        .strip_prefix(SEALED_SECRET_PREFIX)
        .ok_or(ApiError::CorruptData)?;
    let raw = STANDARD.decode(packed).map_err(|_| ApiError::CorruptData)?;
    if raw.len() <= 12 {
        return Err(ApiError::CorruptData);
    }
    let (nonce_bytes, ciphertext) = raw.split_at(12);
    let cipher = ChaCha20Poly1305::new_from_slice(&webhook_seal_key(master))
        .map_err(|_| ApiError::CorruptData)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| ApiError::CorruptData)?;
    String::from_utf8(plaintext).map_err(|_| ApiError::CorruptData)
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct WebhookDestination {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub secret_prefix: String,
    pub enabled: bool,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateWebhook {
    name: String,
    url: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsoleWebhookEvent {
    event_type: String,
    payload: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct WebhookDelivery {
    pub id: Uuid,
    pub destination_id: Uuid,
    pub event_id: String,
    pub event_type: String,
    pub created_at: i64,
    pub attempts: i64,
    pub last_error: Option<String>,
    pub delivered_at: Option<i64>,
    pub dead_lettered_at: Option<i64>,
}

pub(crate) async fn enqueue(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: Uuid,
    event_type: &str,
    payload: &serde_json::Value,
) -> Result<(), ApiError> {
    let event_id = Uuid::new_v4().to_string();
    let created_at = now();
    let destinations = sqlx::query(
        "SELECT id FROM webhook_destinations WHERE org_id=$1 AND enabled=1 ORDER BY created_at,id",
    )
    .bind(org_id.to_string())
    .fetch_all(&mut **tx)
    .await?;
    for row in destinations {
        let destination_id: String = row.try_get(0)?;
        sqlx::query(
            "INSERT INTO webhook_outbox(id,org_id,destination_id,event_id,event_type,payload_json,created_at,next_attempt_at,attempts)
             VALUES($1,$2,$3,$4,$5,$6,$7,$7,0)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(org_id.to_string())
        .bind(destination_id)
        .bind(&event_id)
        .bind(event_type)
        .bind(payload.to_string())
        .bind(created_at)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

pub(crate) async fn delivery_loop(state: AppState) {
    loop {
        if let Err(error) = deliver_due(&state).await {
            warn!(%error, "webhook delivery poll failed");
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn deliver_due(state: &AppState) -> Result<(), ApiError> {
    let rows = sqlx::query(
        "SELECT o.id,o.org_id,o.destination_id,o.event_id,o.event_type,o.payload_json,o.attempts,d.url,d.signing_secret
         FROM webhook_outbox o
         JOIN webhook_destinations d ON d.id=o.destination_id
         WHERE o.delivered_at IS NULL AND o.dead_lettered_at IS NULL AND o.next_attempt_at<=$1 AND d.enabled=1
         ORDER BY o.next_attempt_at,o.id
         LIMIT 16",
    )
    .bind(now())
    .fetch_all(&state.store.pool)
    .await?;
    for row in rows {
        let id: String = row.try_get(0)?;
        let org_id: String = row.try_get(1)?;
        let destination_id: String = row.try_get(2)?;
        let event_id: String = row.try_get(3)?;
        let event_type: String = row.try_get(4)?;
        let payload: String = row.try_get(5)?;
        let attempts: i64 = row.try_get(6)?;
        let url: String = row.try_get(7)?;
        let stored_secret: String = row.try_get(8)?;
        let signing_secret = match open_signing_secret(&state.auth_hmac_secret, &stored_secret) {
            Ok(secret) => secret,
            Err(error) => {
                warn!(%error, delivery_id = %id, "webhook signing secret could not be opened");
                continue;
            }
        };
        match deliver_one(DeliveryJob {
            delivery_id: &id,
            org_id: &org_id,
            destination_id: &destination_id,
            event_id: &event_id,
            event_type: &event_type,
            payload: &payload,
            url: &url,
            signing_secret: &signing_secret,
        })
        .await
        {
            Ok(()) => {
                sqlx::query(
                    "UPDATE webhook_outbox SET delivered_at=$1,last_error=NULL WHERE id=$2",
                )
                .bind(now())
                .bind(&id)
                .execute(&state.store.pool)
                .await?;
            }
            Err(error) => {
                let next_attempts = attempts + 1;
                let dead = next_attempts >= MAX_ATTEMPTS;
                let backoff = 1_i64 << attempts.min(7);
                sqlx::query(
                    "UPDATE webhook_outbox SET attempts=$1,next_attempt_at=$2,last_error=$3,dead_lettered_at=$4 WHERE id=$5",
                )
                .bind(next_attempts)
                .bind(now() + backoff)
                .bind(error.to_string())
                .bind(if dead { Some(now()) } else { None })
                .bind(&id)
                .execute(&state.store.pool)
                .await?;
            }
        }
    }
    Ok(())
}

struct DeliveryJob<'a> {
    delivery_id: &'a str,
    org_id: &'a str,
    destination_id: &'a str,
    event_id: &'a str,
    event_type: &'a str,
    payload: &'a str,
    url: &'a str,
    signing_secret: &'a str,
}

async fn deliver_one(job: DeliveryJob<'_>) -> Result<(), ApiError> {
    let parsed = validate_destination_url(job.url, cfg!(test))?;
    revalidate_resolved_ips(&parsed).await?;
    let timestamp = now();
    let signature = sign_payload(job.signing_secret, timestamp, job.payload);
    let client = reqwest::Client::builder()
        .timeout(DELIVERY_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let response = client
        .post(parsed)
        .header("content-type", "application/json")
        .header("x-blaktail-event", job.event_type)
        .header("x-blaktail-delivery", job.delivery_id)
        .header("x-blaktail-event-id", job.event_id)
        .header("x-blaktail-organisation", job.org_id)
        .header("x-blaktail-destination", job.destination_id)
        .header(
            "x-blaktail-signature",
            format!("t={timestamp},v1={signature}"),
        )
        .body(job.payload.to_owned())
        .send()
        .await
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    if status.as_u16() == 429 {
        return Err(ApiError::TooManyRequests);
    }
    Err(ApiError::BadRequest(format!(
        "destination returned {}",
        status.as_u16()
    )))
}

fn sign_payload(secret: &str, timestamp: i64, payload: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(format!("{timestamp}.{payload}").as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn validate_destination_url(raw: &str, allow_private: bool) -> Result<Url, ApiError> {
    let url = Url::parse(raw).map_err(|_| ApiError::BadRequest("webhook URL is invalid".into()))?;
    if url.scheme() != "https" && !(allow_private && url.scheme() == "http") {
        return Err(ApiError::BadRequest("webhook URL must be https".into()));
    }
    if url.username() != "" || url.password().is_some() {
        return Err(ApiError::BadRequest(
            "webhook URL cannot include credentials".into(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| ApiError::BadRequest("webhook URL must include a host".into()))?;
    if is_blocked_hostname(host) {
        return Err(ApiError::BadRequest(
            "webhook URL host is not allowed".into(),
        ));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_blocked_ip(ip, allow_private) {
            return Err(ApiError::BadRequest(
                "webhook URL target is not allowed".into(),
            ));
        }
    }
    Ok(url)
}

async fn revalidate_resolved_ips(url: &Url) -> Result<(), ApiError> {
    let host = url
        .host_str()
        .ok_or_else(|| ApiError::BadRequest("webhook URL must include a host".into()))?;
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs = lookup_host((host, port))
        .await
        .map_err(|_| ApiError::BadRequest("webhook URL host could not be resolved".into()))?;
    let mut any = false;
    for addr in addrs {
        any = true;
        if is_blocked_ip(addr.ip(), cfg!(test)) {
            return Err(ApiError::BadRequest(
                "webhook URL resolved to a blocked address".into(),
            ));
        }
        let _unused: SocketAddr = addr;
    }
    if !any {
        return Err(ApiError::BadRequest(
            "webhook URL host could not be resolved".into(),
        ));
    }
    Ok(())
}

fn is_blocked_hostname(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "localhost"
        || host == "metadata"
        || host == "metadata.google.internal"
        || host.ends_with(".localhost")
        || host.ends_with(".internal")
        || host.ends_with(".local")
}

fn is_blocked_ip(ip: IpAddr, allow_private: bool) -> bool {
    if is_metadata_ip(ip) {
        return true;
    }
    if allow_private {
        return false;
    }
    match ip {
        IpAddr::V4(value) => {
            value.is_loopback()
                || value.is_private()
                || value.is_link_local()
                || value.is_unspecified()
                || value.is_broadcast()
                || value.octets()[0] == 0
        }
        IpAddr::V6(value) => {
            value.is_loopback()
                || value.is_unique_local()
                || value.is_unicast_link_local()
                || value.is_unspecified()
        }
    }
}

fn is_metadata_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => value.octets() == [169, 254, 169, 254],
        IpAddr::V6(_) => false,
    }
}

pub(crate) async fn list_destinations(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<crate::admin::Envelope<Vec<WebhookDestination>>>, ApiError> {
    let (org_id, caller) = crate::admin::authenticate_org_header(&s, &headers).await?;
    crate::admin::require_scope(&caller, crate::admin::Scope::WebhooksRead)?;
    Ok(Json(crate::admin::Envelope {
        data: load_destinations(&s, org_id).await?,
        next_cursor: None,
    }))
}

pub(crate) async fn list_destinations_console(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<WebhookDestination>>, ApiError> {
    let session = crate::console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageIntegrations)?;
    Ok(Json(load_destinations(&s, org_id).await?))
}

async fn load_destinations(
    state: &AppState,
    org_id: Uuid,
) -> Result<Vec<WebhookDestination>, ApiError> {
    let rows = sqlx::query(
        "SELECT id,name,url,secret_prefix,enabled,created_at FROM webhook_destinations WHERE org_id=$1 ORDER BY created_at,id",
    )
    .bind(org_id.to_string())
    .fetch_all(&state.store.pool)
    .await?;
    let mut destinations = Vec::new();
    for row in rows {
        destinations.push(WebhookDestination {
            id: Uuid::parse_str(&row.try_get::<String, _>(0)?)
                .map_err(|_| ApiError::CorruptData)?,
            name: row.try_get(1)?,
            url: row.try_get(2)?,
            secret_prefix: row.try_get(3)?,
            enabled: row.try_get::<i64, _>(4)? != 0,
            created_at: row.try_get(5)?,
            secret: None,
        });
    }
    Ok(destinations)
}

pub(crate) async fn create_destination(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateWebhook>,
) -> Result<(StatusCode, Json<WebhookDestination>), ApiError> {
    let (org_id, caller) = crate::admin::authenticate_org_header(&s, &headers).await?;
    crate::admin::require_scope(&caller, crate::admin::Scope::WebhooksWrite)?;
    insert_destination(&s, org_id, &caller.session, input).await
}

pub(crate) async fn enqueue_console_event(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<ConsoleWebhookEvent>,
) -> Result<StatusCode, ApiError> {
    let session = crate::console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageSecurity)?;
    if !ALLOWED_CONSOLE_EVENTS.contains(&input.event_type.as_str()) {
        return Err(ApiError::BadRequest("event type is not allowed".into()));
    }
    if !input.payload.is_object() {
        return Err(ApiError::BadRequest("payload must be an object".into()));
    }
    let membership_id = input
        .payload
        .get("membership_id")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .trim();
    if membership_id.is_empty() {
        return Err(ApiError::BadRequest("membership_id is required".into()));
    }
    let encoded = input.payload.to_string();
    if encoded.len() > MAX_CONSOLE_EVENT_PAYLOAD {
        return Err(ApiError::BadRequest("payload is too large".into()));
    }
    let mut tx = s.store.pool.begin().await?;
    enqueue(&mut tx, org_id, &input.event_type, &input.payload).await?;
    crate::append_audit(
        &mut tx,
        org_id,
        &session,
        "webhook.event_enqueued",
        "webhook_event",
        Some(membership_id),
        &serde_json::json!({"event_type": input.event_type}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::ACCEPTED)
}

pub(crate) async fn create_destination_console(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<CreateWebhook>,
) -> Result<(StatusCode, Json<WebhookDestination>), ApiError> {
    let session = crate::console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageIntegrations)?;
    insert_destination(&s, org_id, &session, input).await
}

async fn insert_destination(
    state: &AppState,
    org_id: Uuid,
    session: &Session,
    input: CreateWebhook,
) -> Result<(StatusCode, Json<WebhookDestination>), ApiError> {
    let name = input.name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(ApiError::BadRequest(
            "webhook name must be 1-64 characters".into(),
        ));
    }
    let url = validate_destination_url(&input.url, cfg!(test))?;
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM webhook_destinations WHERE org_id=$1 AND enabled=1",
    )
    .bind(org_id.to_string())
    .fetch_one(&state.store.pool)
    .await?;
    if count >= MAX_DESTINATIONS {
        return Err(ApiError::BadRequest(
            "organisations are limited to 8 webhook destinations".into(),
        ));
    }
    let id = Uuid::new_v4();
    let signing_secret = secret(WEBHOOK_SECRET_PREFIX);
    let sealed = seal_signing_secret(&state.auth_hmac_secret, &signing_secret)?;
    let prefix: String = signing_secret.chars().take(11).collect();
    let created_at = now();
    let mut tx = state.store.pool.begin().await?;
    sqlx::query(
        "INSERT INTO webhook_destinations(id,org_id,name,url,signing_secret,secret_hash,secret_prefix,enabled,created_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,1,$8)",
    )
    .bind(id.to_string())
    .bind(org_id.to_string())
    .bind(name)
    .bind(url.as_str())
    .bind(&sealed)
    .bind(hash(&signing_secret))
    .bind(&prefix)
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|error| {
        if error.to_string().contains("UNIQUE") || error.to_string().contains("unique") {
            ApiError::Conflict("webhook name already exists".into())
        } else {
            ApiError::Database(error)
        }
    })?;
    crate::append_audit(
        &mut tx,
        org_id,
        session,
        "webhook.created",
        "webhook",
        Some(&id.to_string()),
        &serde_json::json!({"name": name, "url_host": url.host_str()}),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(WebhookDestination {
            id,
            name: name.to_owned(),
            url: url.to_string(),
            secret_prefix: prefix,
            enabled: true,
            created_at,
            secret: Some(signing_secret),
        }),
    ))
}

pub(crate) async fn delete_destination(
    State(s): State<AppState>,
    UrlPath(destination_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (org_id, caller) = crate::admin::authenticate_org_header(&s, &headers).await?;
    crate::admin::require_scope(&caller, crate::admin::Scope::WebhooksWrite)?;
    disable_destination(&s, org_id, &caller.session, destination_id).await
}

pub(crate) async fn delete_destination_console(
    State(s): State<AppState>,
    UrlPath((org_id, destination_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let session = crate::console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageIntegrations)?;
    disable_destination(&s, org_id, &session, destination_id).await
}

async fn disable_destination(
    state: &AppState,
    org_id: Uuid,
    session: &Session,
    destination_id: Uuid,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.store.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE webhook_destinations SET enabled=0 WHERE id=$1 AND org_id=$2 AND enabled=1",
    )
    .bind(destination_id.to_string())
    .bind(org_id.to_string())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::NotFound);
    }
    crate::append_audit(
        &mut tx,
        org_id,
        session,
        "webhook.disabled",
        "webhook",
        Some(&destination_id.to_string()),
        &serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn list_deliveries(
    State(s): State<AppState>,
    UrlPath(destination_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<crate::admin::Envelope<Vec<WebhookDelivery>>>, ApiError> {
    let (org_id, caller) = crate::admin::authenticate_org_header(&s, &headers).await?;
    crate::admin::require_scope(&caller, crate::admin::Scope::WebhooksRead)?;
    Ok(Json(crate::admin::Envelope {
        data: load_deliveries(&s, org_id, destination_id).await?,
        next_cursor: None,
    }))
}

pub(crate) async fn list_deliveries_console(
    State(s): State<AppState>,
    UrlPath((org_id, destination_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<Vec<WebhookDelivery>>, ApiError> {
    let session = crate::console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageIntegrations)?;
    Ok(Json(load_deliveries(&s, org_id, destination_id).await?))
}

async fn load_deliveries(
    state: &AppState,
    org_id: Uuid,
    destination_id: Uuid,
) -> Result<Vec<WebhookDelivery>, ApiError> {
    let exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM webhook_destinations WHERE id=$1 AND org_id=$2")
            .bind(destination_id.to_string())
            .bind(org_id.to_string())
            .fetch_optional(&state.store.pool)
            .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound);
    }
    let rows = sqlx::query(
        "SELECT id,destination_id,event_id,event_type,created_at,attempts,last_error,delivered_at,dead_lettered_at
         FROM webhook_outbox WHERE org_id=$1 AND destination_id=$2 ORDER BY created_at DESC,id DESC LIMIT 50",
    )
    .bind(org_id.to_string())
    .bind(destination_id.to_string())
    .fetch_all(&state.store.pool)
    .await?;
    let mut deliveries = Vec::new();
    for row in rows {
        deliveries.push(WebhookDelivery {
            id: Uuid::parse_str(&row.try_get::<String, _>(0)?)
                .map_err(|_| ApiError::CorruptData)?,
            destination_id: Uuid::parse_str(&row.try_get::<String, _>(1)?)
                .map_err(|_| ApiError::CorruptData)?,
            event_id: row.try_get(2)?,
            event_type: row.try_get(3)?,
            created_at: row.try_get(4)?,
            attempts: row.try_get(5)?,
            last_error: row.try_get(6)?,
            delivered_at: row.try_get(7)?,
            dead_lettered_at: row.try_get(8)?,
        });
    }
    Ok(deliveries)
}

pub(crate) async fn replay_delivery(
    State(s): State<AppState>,
    UrlPath(delivery_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (org_id, caller) = crate::admin::authenticate_org_header(&s, &headers).await?;
    crate::admin::require_scope(&caller, crate::admin::Scope::WebhooksWrite)?;
    reset_delivery(&s, org_id, &caller.session, delivery_id).await
}

pub(crate) async fn replay_delivery_console(
    State(s): State<AppState>,
    UrlPath((org_id, delivery_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let session = crate::console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageIntegrations)?;
    reset_delivery(&s, org_id, &session, delivery_id).await
}

async fn reset_delivery(
    state: &AppState,
    org_id: Uuid,
    session: &Session,
    delivery_id: Uuid,
) -> Result<StatusCode, ApiError> {
    let mut tx = state.store.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE webhook_outbox SET attempts=0,next_attempt_at=$1,dead_lettered_at=NULL,last_error=NULL
         WHERE id=$2 AND org_id=$3 AND delivered_at IS NULL",
    )
    .bind(now())
    .bind(delivery_id.to_string())
    .bind(org_id.to_string())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::NotFound);
    }
    crate::append_audit(
        &mut tx,
        org_id,
        session,
        "webhook.replayed",
        "webhook_delivery",
        Some(&delivery_id.to_string()),
        &serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_urls_reject_private_and_metadata_targets() {
        assert!(validate_destination_url("http://example.com/hook", false).is_err());
        assert!(validate_destination_url("https://127.0.0.1/hook", false).is_err());
        assert!(validate_destination_url("https://10.0.0.5/hook", false).is_err());
        assert!(validate_destination_url("https://169.254.169.254/latest", true).is_err());
        assert!(validate_destination_url("https://localhost/hook", true).is_err());
        assert!(validate_destination_url("https://example.com/hook", false).is_ok());
        assert!(validate_destination_url("http://127.0.0.1:9/hook", true).is_ok());
    }

    #[test]
    fn webhook_signature_covers_timestamp_and_body() {
        let first = sign_payload("btw_secret", 10, "{\"ok\":true}");
        let second = sign_payload("btw_secret", 10, "{\"ok\":true}");
        let other = sign_payload("btw_secret", 11, "{\"ok\":true}");
        assert_eq!(first, second);
        assert_ne!(first, other);
    }

    #[test]
    fn webhook_signing_secret_seals_and_opens() {
        let master = b"test-only-hmac-secret-at-least-32-bytes";
        let sealed = seal_signing_secret(master, "btw_shown-once").unwrap();
        assert!(sealed.starts_with("bte1."));
        assert!(!sealed.contains("btw_shown-once"));
        assert_eq!(
            open_signing_secret(master, &sealed).unwrap(),
            "btw_shown-once"
        );
        assert_eq!(
            open_signing_secret(master, "btw_legacy-plaintext").unwrap(),
            "btw_legacy-plaintext"
        );
        assert!(open_signing_secret(b"other-master-key-at-least-32-bytes!!", &sealed).is_err());
    }
}
