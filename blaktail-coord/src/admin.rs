use crate::{
    append_audit, bearer_value, bump_control_revision, conflict, console_session, hash,
    load_audit_events, load_nodes, load_org_dns, load_org_dns_tx, load_previous_dns_tx, now,
    publish_org_dns, secret, tombstone_node, ApiError, AppState, AuditQuery, NodeListQuery, Role,
    Session, Store, ADMIN_API_MAX_BODY_BYTES, ADMIN_API_RATE_LIMIT, ADMIN_API_RATE_WINDOW_SECS,
};
use axum::{
    extract::{DefaultBodyLimit, Form, Path as UrlPath, Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

const API_PREFIX: &str = "bta";
const ACCESS_PREFIX: &str = "bto";
const ACCESS_TOKEN_TTL_SECS: i64 = 3600;
const DEFAULT_TOKEN_TTL_SECS: i64 = 90 * 24 * 60 * 60;
const MAX_TOKEN_TTL_SECS: i64 = 365 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Scope {
    #[serde(rename = "devices:read")]
    DevicesRead,
    #[serde(rename = "devices:write")]
    DevicesWrite,
    #[serde(rename = "keys:write")]
    KeysWrite,
    #[serde(rename = "routes:write")]
    RoutesWrite,
    #[serde(rename = "policy:write")]
    PolicyWrite,
    #[serde(rename = "dns:write")]
    DnsWrite,
    #[serde(rename = "audit:read")]
    AuditRead,
    #[serde(rename = "status:read")]
    StatusRead,
    #[serde(rename = "webhooks:read")]
    WebhooksRead,
    #[serde(rename = "webhooks:write")]
    WebhooksWrite,
}

impl Scope {
    fn as_str(self) -> &'static str {
        match self {
            Self::DevicesRead => "devices:read",
            Self::DevicesWrite => "devices:write",
            Self::KeysWrite => "keys:write",
            Self::RoutesWrite => "routes:write",
            Self::PolicyWrite => "policy:write",
            Self::DnsWrite => "dns:write",
            Self::AuditRead => "audit:read",
            Self::StatusRead => "status:read",
            Self::WebhooksRead => "webhooks:read",
            Self::WebhooksWrite => "webhooks:write",
        }
    }
}

#[derive(Clone)]
pub(crate) struct ApiCaller {
    pub(crate) session: Session,
    client_id: Option<String>,
    scopes: Vec<Scope>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateApiClient {
    name: String,
    #[serde(default)]
    scopes: Vec<Scope>,
    #[serde(default)]
    expires_in_seconds: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ApiClientCreated {
    pub id: Uuid,
    pub name: String,
    pub token: String,
    pub token_prefix: String,
    pub scopes: Vec<Scope>,
    pub expires_at: Option<i64>,
}

#[derive(Serialize)]
pub(crate) struct ApiClientRecord {
    id: Uuid,
    name: String,
    token_prefix: String,
    scopes: Vec<Scope>,
    created_at: i64,
    last_used_at: Option<i64>,
    expires_at: Option<i64>,
    revoked: bool,
}

#[derive(Serialize)]
pub(crate) struct Envelope<T: Serialize> {
    pub(crate) data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) next_cursor: Option<String>,
}

pub(crate) fn api_routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/status", get(api_status))
        .route("/api/v1/devices", get(api_list_devices))
        .route(
            "/api/v1/devices/:node_id",
            get(api_get_device).delete(api_delete_device),
        )
        .route(
            "/api/v1/devices/:node_id/friendly-name",
            put(api_rename_device),
        )
        .route(
            "/api/v1/devices/:node_id/tombstone",
            post(api_tombstone_device),
        )
        .route("/api/v1/keys", post(api_mint_key))
        .route("/api/v1/devices/:node_id/routes", put(api_approve_routes))
        .route("/api/v1/policy", get(api_get_policy).put(api_put_policy))
        .route("/api/v1/dns", get(api_get_dns).put(api_put_dns))
        .route(
            "/api/v1/wireguard-only-peers",
            get(api_list_wg_only).post(api_create_wg_only),
        )
        .route(
            "/api/v1/wireguard-only-peers/:peer_id",
            get(api_get_wg_only).delete(api_revoke_wg_only),
        )
        .route(
            "/api/v1/wireguard-only-peers/:peer_id/rotate",
            post(api_rotate_wg_only),
        )
        .route("/api/v1/audit", get(api_list_audit))
        .route(
            "/api/v1/webhooks",
            get(crate::webhooks::list_destinations).post(crate::webhooks::create_destination),
        )
        .route(
            "/api/v1/webhooks/:destination_id",
            axum::routing::delete(crate::webhooks::delete_destination),
        )
        .route(
            "/api/v1/webhooks/:destination_id/deliveries",
            get(crate::webhooks::list_deliveries),
        )
        .route(
            "/api/v1/webhooks/deliveries/:delivery_id/replay",
            post(crate::webhooks::replay_delivery),
        )
        .route(
            "/api/v1/network-resources",
            get(crate::resources::api_list).post(crate::resources::api_create),
        )
        .route(
            "/api/v1/network-resources/:resource_id",
            get(crate::resources::api_get)
                .put(crate::resources::api_update)
                .delete(crate::resources::api_delete),
        )
        .layer(DefaultBodyLimit::max(ADMIN_API_MAX_BODY_BYTES))
}

pub(crate) fn require_scope(caller: &ApiCaller, scope: Scope) -> Result<(), ApiError> {
    if caller.client_id.is_none() {
        if scope_is_write(scope) && caller.session.role == Role::Member {
            return Err(ApiError::Forbidden);
        }
        return Ok(());
    }
    if caller.scopes.contains(&scope)
        || (scope == Scope::DevicesRead && caller.scopes.contains(&Scope::DevicesWrite))
        || (scope == Scope::WebhooksRead && caller.scopes.contains(&Scope::WebhooksWrite))
    {
        return Ok(());
    }
    Err(ApiError::Forbidden)
}

fn scope_is_write(scope: Scope) -> bool {
    matches!(
        scope,
        Scope::DevicesWrite
            | Scope::KeysWrite
            | Scope::RoutesWrite
            | Scope::PolicyWrite
            | Scope::DnsWrite
            | Scope::WebhooksWrite
    )
}

async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    org_id: Uuid,
) -> Result<ApiCaller, ApiError> {
    let token = bearer_value(headers)?;
    if token.starts_with(&format!("{ACCESS_PREFIX}_")) {
        return access_token_session(state, token, org_id).await;
    }
    if token.starts_with(&format!("{API_PREFIX}_")) {
        return api_token_session(state, token, org_id).await;
    }
    let session = console_session(state, headers, org_id).await?;
    Ok(ApiCaller {
        session,
        client_id: None,
        scopes: Vec::new(),
    })
}

pub(crate) async fn authenticate_org_header(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(Uuid, ApiCaller), ApiError> {
    let org_id = headers
        .get("x-blaktail-organisation")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value.trim()).ok())
        .ok_or(ApiError::Unauthorized)?;
    let caller = authenticate(state, headers, org_id).await?;
    Ok((org_id, caller))
}

async fn api_token_session(
    state: &AppState,
    token: &str,
    org_id: Uuid,
) -> Result<ApiCaller, ApiError> {
    let current_time = now();
    let row = sqlx::query(
        "SELECT id,name,scopes_json,expires_at FROM api_clients WHERE token_hash=$1 AND org_id=$2 AND revoked_at IS NULL",
    )
    .bind(hash(token))
    .bind(org_id.to_string())
    .fetch_optional(&state.store.pool)
    .await?
    .ok_or(ApiError::Unauthorized)?;
    let client_id: String = row.try_get(0)?;
    let name: String = row.try_get(1)?;
    let scopes: Vec<Scope> =
        serde_json::from_str(&row.try_get::<String, _>(2)?).map_err(|_| ApiError::CorruptData)?;
    let expires_at: Option<i64> = row.try_get(3)?;
    if expires_at.is_some_and(|expires| expires <= current_time) {
        return Err(ApiError::Unauthorized);
    }
    sqlx::query("UPDATE api_clients SET last_used_at=$1 WHERE id=$2")
        .bind(current_time)
        .bind(&client_id)
        .execute(&state.store.pool)
        .await?;
    if !state.api_rate.allow(
        &client_id,
        current_time,
        ADMIN_API_RATE_LIMIT,
        ADMIN_API_RATE_WINDOW_SECS,
    ) {
        return Err(ApiError::TooManyRequests);
    }
    Ok(ApiCaller {
        session: Session {
            user_id: format!("api:{client_id}"),
            role: Role::Admin,
            name,
            email: String::new(),
        },
        client_id: Some(client_id),
        scopes,
    })
}

async fn access_token_session(
    state: &AppState,
    token: &str,
    org_id: Uuid,
) -> Result<ApiCaller, ApiError> {
    let current_time = now();
    let row = sqlx::query(
        "SELECT t.api_client_id, c.name, t.scopes_json, t.expires_at, c.revoked_at, c.expires_at
         FROM oauth_access_tokens t
         JOIN api_clients c ON c.id = t.api_client_id AND c.org_id = t.org_id
         WHERE t.token_hash=$1 AND t.org_id=$2",
    )
    .bind(hash(token))
    .bind(org_id.to_string())
    .fetch_optional(&state.store.pool)
    .await?
    .ok_or(ApiError::Unauthorized)?;
    let client_id: String = row.try_get(0)?;
    let name: String = row.try_get(1)?;
    let scopes: Vec<Scope> =
        serde_json::from_str(&row.try_get::<String, _>(2)?).map_err(|_| ApiError::CorruptData)?;
    let access_expires_at: i64 = row.try_get(3)?;
    let revoked_at: Option<i64> = row.try_get(4)?;
    let client_expires_at: Option<i64> = row.try_get(5)?;
    if revoked_at.is_some()
        || access_expires_at <= current_time
        || client_expires_at.is_some_and(|expires| expires <= current_time)
    {
        return Err(ApiError::Unauthorized);
    }
    sqlx::query("UPDATE oauth_access_tokens SET last_used_at=$1 WHERE token_hash=$2")
        .bind(current_time)
        .bind(hash(token))
        .execute(&state.store.pool)
        .await?;
    sqlx::query("UPDATE api_clients SET last_used_at=$1 WHERE id=$2")
        .bind(current_time)
        .bind(&client_id)
        .execute(&state.store.pool)
        .await?;
    if !state.api_rate.allow(
        &client_id,
        current_time,
        ADMIN_API_RATE_LIMIT,
        ADMIN_API_RATE_WINDOW_SECS,
    ) {
        return Err(ApiError::TooManyRequests);
    }
    Ok(ApiCaller {
        session: Session {
            user_id: format!("api:{client_id}"),
            role: Role::Admin,
            name,
            email: String::new(),
        },
        client_id: Some(client_id),
        scopes,
    })
}

fn normalise_client_name(name: &str) -> Result<String, ApiError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "name must be 1-64 characters without control characters".into(),
        ));
    }
    Ok(name.to_owned())
}

pub(crate) async fn create_api_client(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<CreateApiClient>,
) -> Result<(StatusCode, Json<ApiClientCreated>), ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    if session.role != Role::Owner {
        return Err(ApiError::Forbidden);
    }
    insert_api_client(&s.store, org_id, &session, input).await
}

async fn insert_api_client(
    store: &Store,
    org_id: Uuid,
    session: &Session,
    input: CreateApiClient,
) -> Result<(StatusCode, Json<ApiClientCreated>), ApiError> {
    let name = normalise_client_name(&input.name)?;
    let scopes = if input.scopes.is_empty() {
        vec![Scope::StatusRead]
    } else {
        let mut scopes = input.scopes;
        scopes.sort_by_key(|scope| scope.as_str());
        scopes.dedup();
        scopes
    };
    let expires_at = match input.expires_in_seconds {
        Some(seconds) if (60..=MAX_TOKEN_TTL_SECS).contains(&seconds) => Some(now() + seconds),
        Some(_) => {
            return Err(ApiError::BadRequest(format!(
                "expires_in_seconds must be between 60 and {MAX_TOKEN_TTL_SECS}"
            )))
        }
        None => Some(now() + DEFAULT_TOKEN_TTL_SECS),
    };
    let token = secret(API_PREFIX);
    let token_prefix = token.chars().take(11).collect::<String>();
    let id = Uuid::new_v4();
    let mut tx = store.pool.begin().await?;
    sqlx::query(
        "INSERT INTO api_clients(id,org_id,name,token_hash,token_prefix,scopes_json,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(id.to_string())
    .bind(org_id.to_string())
    .bind(&name)
    .bind(hash(&token))
    .bind(&token_prefix)
    .bind(serde_json::to_string(&scopes).unwrap())
    .bind(now())
    .bind(expires_at)
    .execute(&mut *tx)
    .await
    .map_err(conflict("automation client name already exists"))?;
    append_audit(
        &mut tx,
        org_id,
        session,
        "api_client.created",
        "api_client",
        Some(&id.to_string()),
        &serde_json::json!({
            "name": name,
            "scopes": scopes,
            "token_prefix": token_prefix,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(ApiClientCreated {
            id,
            name,
            token,
            token_prefix,
            scopes,
            expires_at,
        }),
    ))
}

pub(crate) async fn list_api_clients(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<ApiClientRecord>>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    if session.role == Role::Member {
        return Err(ApiError::Forbidden);
    }
    Ok(Json(load_api_clients(&s.store, org_id).await?))
}

async fn load_api_clients(store: &Store, org_id: Uuid) -> Result<Vec<ApiClientRecord>, ApiError> {
    let rows = sqlx::query(
        "SELECT id,name,token_prefix,scopes_json,created_at,last_used_at,expires_at,CASE WHEN revoked_at IS NOT NULL THEN 1 ELSE 0 END FROM api_clients WHERE org_id=$1 ORDER BY name",
    )
    .bind(org_id.to_string())
    .fetch_all(&store.pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok::<_, ApiError>(ApiClientRecord {
                id: Uuid::parse_str(&row.try_get::<String, _>(0)?)
                    .map_err(|_| ApiError::CorruptData)?,
                name: row.try_get(1)?,
                token_prefix: row.try_get(2)?,
                scopes: serde_json::from_str(&row.try_get::<String, _>(3)?)
                    .map_err(|_| ApiError::CorruptData)?,
                created_at: row.try_get(4)?,
                last_used_at: row.try_get(5)?,
                expires_at: row.try_get(6)?,
                revoked: row.try_get::<i64, _>(7)? != 0,
            })
        })
        .collect()
}

pub(crate) async fn revoke_api_client(
    State(s): State<AppState>,
    UrlPath((org_id, client_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    if session.role != Role::Owner {
        return Err(ApiError::Forbidden);
    }
    let mut tx = s.store.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE api_clients SET revoked_at=$1,token_hash=$2 WHERE id=$3 AND org_id=$4 AND revoked_at IS NULL",
    )
    .bind(now())
    .bind(format!("revoked:{}", hash(&client_id.to_string())))
    .bind(client_id.to_string())
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
        "api_client.revoked",
        "api_client",
        Some(&client_id.to_string()),
        &serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub(crate) struct OAuthTokenRequest {
    #[serde(default)]
    grant_type: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    client_secret: String,
    #[serde(default)]
    scope: String,
}

#[derive(Serialize)]
pub(crate) struct OAuthTokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    scope: String,
    organisation_id: Uuid,
}

pub(crate) struct OAuthError {
    status: StatusCode,
    error: &'static str,
    description: &'static str,
}

impl OAuthError {
    fn invalid_request(description: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_request",
            description,
        }
    }

    fn invalid_client() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error: "invalid_client",
            description: "client authentication failed",
        }
    }

    fn unsupported_grant_type() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "unsupported_grant_type",
            description: "only client_credentials is supported",
        }
    }

    fn invalid_scope() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_scope",
            description: "requested scope is not granted to this client",
        }
    }

    fn server_error() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: "server_error",
            description: "token service failed",
        }
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> axum::response::Response {
        let mut response = (
            self.status,
            Json(serde_json::json!({
                "error": self.error,
                "error_description": self.description,
            })),
        )
            .into_response();
        if self.status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Basic realm=\"BlakTail\""),
            );
        }
        response
    }
}

fn basic_client_auth(headers: &HeaderMap) -> Result<Option<(String, String)>, OAuthError> {
    let Some(value) = headers.get(AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| OAuthError::invalid_client())?;
    let Some(encoded) = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))
    else {
        return Ok(None);
    };
    let decoded = STANDARD
        .decode(encoded.trim())
        .map_err(|_| OAuthError::invalid_client())?;
    let decoded = String::from_utf8(decoded).map_err(|_| OAuthError::invalid_client())?;
    let (id, secret) = decoded
        .split_once(':')
        .ok_or_else(OAuthError::invalid_client)?;
    if id.is_empty() || secret.is_empty() {
        return Err(OAuthError::invalid_client());
    }
    Ok(Some((id.to_owned(), secret.to_owned())))
}

fn parse_requested_scopes(value: &str) -> Result<Vec<Scope>, OAuthError> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    value
        .split_whitespace()
        .map(|part| {
            serde_json::from_value(serde_json::Value::String(part.to_string()))
                .map_err(|_| OAuthError::invalid_scope())
        })
        .collect()
}

pub(crate) async fn oauth_token(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(input): Form<OAuthTokenRequest>,
) -> Result<Json<OAuthTokenResponse>, OAuthError> {
    if input.grant_type != "client_credentials" {
        return Err(OAuthError::unsupported_grant_type());
    }
    let (client_id, client_secret) = match basic_client_auth(&headers)? {
        Some(credentials) => credentials,
        None => {
            if input.client_id.is_empty() || input.client_secret.is_empty() {
                return Err(OAuthError::invalid_request(
                    "client_id and client_secret are required",
                ));
            }
            (input.client_id, input.client_secret)
        }
    };
    let client_id = Uuid::parse_str(client_id.trim()).map_err(|_| OAuthError::invalid_client())?;
    if !client_secret.starts_with(&format!("{API_PREFIX}_")) {
        return Err(OAuthError::invalid_client());
    }
    let current_time = now();
    let row = sqlx::query(
        "SELECT org_id,name,scopes_json,expires_at FROM api_clients WHERE id=$1 AND token_hash=$2 AND revoked_at IS NULL",
    )
    .bind(client_id.to_string())
    .bind(hash(&client_secret))
    .fetch_optional(&s.store.pool)
    .await
    .map_err(|_| OAuthError::server_error())?
    .ok_or_else(OAuthError::invalid_client)?;
    let org_id = Uuid::parse_str(
        &row.try_get::<String, _>(0)
            .map_err(|_| OAuthError::server_error())?,
    )
    .map_err(|_| OAuthError::server_error())?;
    let name: String = row.try_get(1).map_err(|_| OAuthError::server_error())?;
    let scopes: Vec<Scope> = serde_json::from_str(
        &row.try_get::<String, _>(2)
            .map_err(|_| OAuthError::server_error())?,
    )
    .map_err(|_| OAuthError::server_error())?;
    let client_expires_at: Option<i64> = row.try_get(3).map_err(|_| OAuthError::server_error())?;
    if client_expires_at.is_some_and(|expires| expires <= current_time) {
        return Err(OAuthError::invalid_client());
    }
    let requested = parse_requested_scopes(&input.scope)?;
    if requested.iter().any(|scope| !scopes.contains(scope)) {
        return Err(OAuthError::invalid_scope());
    }
    if !s.api_rate.allow(
        &client_id.to_string(),
        current_time,
        ADMIN_API_RATE_LIMIT,
        ADMIN_API_RATE_WINDOW_SECS,
    ) {
        return Err(OAuthError {
            status: StatusCode::TOO_MANY_REQUESTS,
            error: "temporarily_unavailable",
            description: "client is rate limited",
        });
    }
    let access_expires_at = client_expires_at
        .unwrap_or(current_time + ACCESS_TOKEN_TTL_SECS)
        .min(current_time + ACCESS_TOKEN_TTL_SECS);
    if access_expires_at <= current_time {
        return Err(OAuthError::invalid_client());
    }
    let access_token = secret(ACCESS_PREFIX);
    let token_prefix = access_token.chars().take(11).collect::<String>();
    let token_id = Uuid::new_v4();
    let mut tx = s
        .store
        .pool
        .begin()
        .await
        .map_err(|_| OAuthError::server_error())?;
    sqlx::query("DELETE FROM oauth_access_tokens WHERE api_client_id=$1 AND expires_at<=$2")
        .bind(client_id.to_string())
        .bind(current_time)
        .execute(&mut *tx)
        .await
        .map_err(|_| OAuthError::server_error())?;
    sqlx::query(
        "INSERT INTO oauth_access_tokens(id,org_id,api_client_id,token_hash,token_prefix,scopes_json,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(token_id.to_string())
    .bind(org_id.to_string())
    .bind(client_id.to_string())
    .bind(hash(&access_token))
    .bind(&token_prefix)
    .bind(serde_json::to_string(&scopes).unwrap())
    .bind(current_time)
    .bind(access_expires_at)
    .execute(&mut *tx)
    .await
    .map_err(|_| OAuthError::server_error())?;
    sqlx::query("UPDATE api_clients SET last_used_at=$1 WHERE id=$2")
        .bind(current_time)
        .bind(client_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| OAuthError::server_error())?;
    append_audit(
        &mut tx,
        org_id,
        &Session {
            user_id: format!("api:{client_id}"),
            role: Role::Admin,
            name,
            email: String::new(),
        },
        "oauth.access_token_issued",
        "oauth_access_token",
        Some(&token_id.to_string()),
        &serde_json::json!({
            "api_client_id": client_id,
            "token_prefix": token_prefix,
            "expires_at": access_expires_at,
        }),
    )
    .await
    .map_err(|_| OAuthError::server_error())?;
    tx.commit().await.map_err(|_| OAuthError::server_error())?;
    Ok(Json(OAuthTokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: access_expires_at - current_time,
        scope: scopes
            .iter()
            .map(|scope| scope.as_str())
            .collect::<Vec<_>>()
            .join(" "),
        organisation_id: org_id,
    }))
}

async fn api_status(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::StatusRead)?;
    s.store
        .readiness()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    Ok(Json(serde_json::json!({
        "status": "ready",
        "api": "v1",
        "organisation_id": org_id,
        "schema_version": crate::CURRENT_SCHEMA_VERSION,
    })))
}

async fn api_list_devices(
    State(s): State<AppState>,
    Query(query): Query<NodeListQuery>,
    headers: HeaderMap,
) -> Result<Json<Envelope<Vec<crate::NodeRow>>>, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::DevicesRead)?;
    let nodes = load_nodes(&s.store, org_id, &query).await?;
    let next_cursor = nodes.last().map(|node| node.id.to_string());
    Ok(Json(Envelope {
        data: nodes,
        next_cursor,
    }))
}

async fn api_get_device(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Envelope<crate::NodeRow>>, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::DevicesRead)?;
    let query = NodeListQuery {
        include_deleted: Some(true),
        ..NodeListQuery::default()
    };
    let node = load_nodes(&s.store, org_id, &query)
        .await?
        .into_iter()
        .find(|node| node.id == node_id)
        .ok_or(ApiError::NotFound)?;
    Ok(Json(Envelope {
        data: node,
        next_cursor: None,
    }))
}

async fn api_delete_device(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::DevicesWrite)?;
    let mut tx = s.store.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE nodes SET revoked_at=$1 WHERE id=$2 AND org_id=$3 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(now())
    .bind(node_id.to_string())
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
        &caller.session,
        "node.revoked",
        "node",
        Some(&node_id.to_string()),
        &serde_json::json!({"via":"admin_api"}),
    )
    .await?;
    crate::webhooks::enqueue(
        &mut tx,
        org_id,
        "device.revoked",
        &serde_json::json!({ "device_id": node_id }),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FriendlyNameBody {
    friendly_name: String,
}

async fn api_rename_device(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(body): Json<FriendlyNameBody>,
) -> Result<StatusCode, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::DevicesWrite)?;
    rename_device(&s, org_id, node_id, &caller.session, &body.friendly_name).await
}

async fn rename_device(
    state: &AppState,
    org_id: Uuid,
    node_id: Uuid,
    session: &Session,
    friendly_name: &str,
) -> Result<StatusCode, ApiError> {
    if session.role == Role::Member && !session.user_id.starts_with("api:") {
        return Err(ApiError::Forbidden);
    }
    let value = friendly_name.trim();
    let friendly_name = if value.is_empty() {
        None
    } else {
        if value.chars().count() > 64 || value.chars().any(char::is_control) {
            return Err(ApiError::BadRequest(
                "friendly_name must be at most 64 characters".into(),
            ));
        }
        Some(value.to_owned())
    };
    let mut tx = state.store.pool.begin().await?;
    let current = sqlx::query(
        "SELECT name,display_name FROM nodes WHERE id=$1 AND org_id=$2 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(node_id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&mut *tx)
    .await?
    .map(|row| {
        Ok::<_, sqlx::Error>((
            row.try_get::<String, _>(0)?,
            row.try_get::<Option<String>, _>(1)?,
        ))
    })
    .transpose()?;
    let (technical_name, previous) = current.ok_or(ApiError::NotFound)?;
    if previous == friendly_name {
        return Ok(StatusCode::NO_CONTENT);
    }
    sqlx::query("UPDATE nodes SET display_name=$1 WHERE id=$2 AND org_id=$3")
        .bind(&friendly_name)
        .bind(node_id.to_string())
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await?;
    append_audit(
        &mut tx,
        org_id,
        session,
        "node.friendly_name_updated",
        "node",
        Some(&node_id.to_string()),
        &serde_json::json!({
            "friendly_name": friendly_name,
            "previous_friendly_name": previous,
            "technical_name": technical_name,
        }),
    )
    .await?;
    crate::webhooks::enqueue(
        &mut tx,
        org_id,
        "device.renamed",
        &serde_json::json!({
            "device_id": node_id,
            "friendly_name": friendly_name,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn api_tombstone_device(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::DevicesWrite)?;
    tombstone_node(&s.store, org_id, node_id, &caller.session).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MintKeyBody {
    #[serde(default = "default_key_ttl")]
    expires_in_seconds: i64,
    #[serde(default = "default_true")]
    single_use: bool,
}

fn default_key_ttl() -> i64 {
    3600
}
fn default_true() -> bool {
    true
}

#[derive(Serialize)]
struct MintedKey {
    id: Uuid,
    key: String,
    expires_at: i64,
    single_use: bool,
}

pub(crate) fn idempotency_key(headers: &HeaderMap) -> Result<Option<String>, ApiError> {
    let Some(value) = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };
    let value = value.trim();
    if !(8..=128).contains(&value.len()) || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "Idempotency-Key must be 8-128 printable characters".into(),
        ));
    }
    Ok(Some(value.to_owned()))
}

async fn api_mint_key(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<MintKeyBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::KeysWrite)?;
    if !(1..=2_592_000).contains(&input.expires_in_seconds) {
        return Err(ApiError::BadRequest(
            "expires_in_seconds must be between 1 and 2592000".into(),
        ));
    }
    let actor = caller.client_id.clone().unwrap_or_else(|| "console".into());
    let request_hash = crate::hash(&format!(
        "{}:{}",
        input.expires_in_seconds, input.single_use
    ));
    if let Some(key) = idempotency_key(&headers)? {
        if let Some(row) = sqlx::query(
            "SELECT request_hash,status,body_json FROM api_idempotency WHERE org_id=$1 AND client_id=$2 AND key_hash=$3",
        )
        .bind(org_id.to_string())
        .bind(&actor)
        .bind(crate::hash(&key))
        .fetch_optional(&s.store.pool)
        .await?
        {
            let stored: String = row.try_get(0)?;
            if stored != request_hash {
                return Err(ApiError::Conflict(
                    "Idempotency-Key was reused with a different request".into(),
                ));
            }
            let status = u16::try_from(row.try_get::<i64, _>(1)?).unwrap_or(201);
            let body: String = row.try_get(2)?;
            return Ok((
                StatusCode::from_u16(status).unwrap_or(StatusCode::CREATED),
                Json(serde_json::from_str(&body).unwrap_or_default()),
            ));
        }
    }
    let key = secret("btk");
    let id = Uuid::new_v4();
    let expires_at = now() + input.expires_in_seconds;
    let mut tx = s.store.pool.begin().await?;
    let changed = sqlx::query("INSERT INTO join_keys(id,org_id,key_hash,expires_at,single_use,created_at,user_id,user_role,tags_json) SELECT $1,id,$2,$3,$4,$5,$6,$7,'[]' FROM orgs WHERE id=$8")
        .bind(id.to_string())
        .bind(hash(&key))
        .bind(expires_at)
        .bind(i64::from(input.single_use))
        .bind(now())
        .bind(&caller.session.user_id)
        .bind(caller.session.role.as_str())
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
        &caller.session,
        "join_key.minted",
        "join_key",
        Some(&id.to_string()),
        &serde_json::json!({"single_use": input.single_use, "via":"admin_api"}),
    )
    .await?;
    let body = serde_json::to_value(Envelope {
        data: MintedKey {
            id,
            key,
            expires_at,
            single_use: input.single_use,
        },
        next_cursor: None,
    })
    .unwrap_or_default();
    if let Some(idempotency) = idempotency_key(&headers)? {
        sqlx::query(
            "INSERT INTO api_idempotency(org_id,client_id,key_hash,method,path,request_hash,status,body_json,created_at) VALUES($1,$2,$3,'POST','/api/v1/keys',$4,201,$5,$6)",
        )
        .bind(org_id.to_string())
        .bind(&actor)
        .bind(crate::hash(&idempotency))
        .bind(&request_hash)
        .bind(body.to_string())
        .bind(now())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(body)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteBody {
    approved_routes: Vec<String>,
}

async fn api_approve_routes(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(body): Json<RouteBody>,
) -> Result<StatusCode, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::RoutesWrite)?;
    let mut tx = s.store.pool.begin().await?;
    let advertised: Option<String> = sqlx::query_scalar(
        "SELECT advertised_routes_json FROM nodes WHERE id=$1 AND org_id=$2 AND deleted_at IS NULL",
    )
    .bind(node_id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&mut *tx)
    .await?;
    let advertised: Vec<String> =
        serde_json::from_str(&advertised.ok_or(ApiError::NotFound)?).unwrap_or_default();
    for route in &body.approved_routes {
        if !advertised.iter().any(|advertised| advertised == route) {
            return Err(ApiError::BadRequest(format!(
                "route {route} was not advertised"
            )));
        }
    }
    crate::resources::ensure_routes_free(&mut tx, org_id, &body.approved_routes).await?;
    sqlx::query("UPDATE nodes SET approved_routes_json=$1 WHERE id=$2 AND org_id=$3")
        .bind(serde_json::to_string(&body.approved_routes).unwrap())
        .bind(node_id.to_string())
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await?;
    append_audit(
        &mut tx,
        org_id,
        &caller.session,
        "node.routes_updated",
        "node",
        Some(&node_id.to_string()),
        &serde_json::json!({"approved_routes": body.approved_routes, "via":"admin_api"}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn api_get_policy(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Envelope<serde_json::Value>>, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::DevicesRead)?;
    let document = crate::load_acl_document(&s.store, org_id).await?;
    let etag = document
        .get("etag")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    let revision = document
        .get("revision")
        .cloned()
        .unwrap_or(serde_json::json!(1));
    let has_previous = document
        .get("has_previous")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    Ok(Json(Envelope {
        data: serde_json::json!({
            "acl": document,
            "etag": etag,
            "revision": revision,
            "has_previous": has_previous,
        }),
        next_cursor: None,
    }))
}

async fn api_put_policy(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(value): Json<serde_json::Value>,
) -> Result<StatusCode, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::PolicyWrite)?;
    let mut tx = s.store.pool.begin().await?;
    let current = crate::load_acl_row_tx(&mut tx, org_id).await?;
    let expected = value
        .get("etag")
        .and_then(|value| value.as_str())
        .ok_or_else(|| ApiError::BadRequest("etag is required".into()))?;
    if expected != hash(&current.json) {
        return Err(ApiError::PreconditionFailed);
    }
    let rollback = value.get("rollback").and_then(serde_json::Value::as_bool) == Some(true);
    let next = if rollback {
        current
            .previous
            .clone()
            .ok_or_else(|| ApiError::BadRequest("no previous policy revision to restore".into()))?
    } else {
        let acl = value.get("acl").cloned().ok_or_else(|| {
            ApiError::BadRequest("acl is required unless rollback is true".into())
        })?;
        crate::storeable_acl_json(acl)?
    };
    let acl: crate::Acl = serde_json::from_str(&next).map_err(|_| ApiError::CorruptData)?;
    crate::publish_acl_tx(&mut tx, org_id, &current.json, &next, current.revision).await?;
    bump_control_revision(&mut tx, org_id.to_string()).await?;
    append_audit(
        &mut tx,
        org_id,
        &caller.session,
        if rollback {
            "acl.rolled_back"
        } else {
            "acl.updated"
        },
        "acl",
        Some(&org_id.to_string()),
        &serde_json::json!({
            "via": "admin_api",
            "defaults": acl.defaults.as_str(),
            "sha256": hash(&next),
            "revision": current.revision + 1,
        }),
    )
    .await?;
    crate::webhooks::enqueue(
        &mut tx,
        org_id,
        if rollback {
            "policy.rolled_back"
        } else {
            "policy.published"
        },
        &serde_json::json!({
            "revision": current.revision + 1,
            "defaults": acl.defaults.as_str(),
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn api_get_dns(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Envelope<crate::org_dns::OrgDnsResponse>>, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::DevicesRead)?;
    Ok(Json(Envelope {
        data: load_org_dns(&s.store, org_id).await?,
        next_cursor: None,
    }))
}

async fn api_put_dns(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(value): Json<serde_json::Value>,
) -> Result<Json<Envelope<crate::org_dns::OrgDnsResponse>>, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::DnsWrite)?;
    let mut tx = s.store.pool.begin().await?;
    let current = load_org_dns_tx(&mut tx, org_id).await?;
    if let Some(expected) = value.get("etag").and_then(|value| value.as_str()) {
        if expected != current.etag {
            return Err(ApiError::PreconditionFailed);
        }
    }
    let rollback = value
        .get("rollback")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let next = if rollback {
        load_previous_dns_tx(&mut tx, org_id).await?
    } else {
        let settings = value.get("dns").cloned().ok_or_else(|| {
            ApiError::BadRequest("dns is required unless rollback is true".into())
        })?;
        crate::org_dns::parse_settings(&settings.to_string())?
    };
    publish_org_dns(&mut tx, org_id, &current, &next).await?;
    append_audit(
        &mut tx,
        org_id,
        &caller.session,
        if rollback {
            "dns.rolled_back"
        } else {
            "dns.updated"
        },
        "dns",
        Some(&org_id.to_string()),
        &serde_json::json!({
            "via": "admin_api",
            "revision": current.revision + 1,
            "managed": next.managed,
        }),
    )
    .await?;
    crate::webhooks::enqueue(
        &mut tx,
        org_id,
        if rollback {
            "dns.rolled_back"
        } else {
            "dns.published"
        },
        &serde_json::json!({
            "revision": current.revision + 1,
            "managed": next.managed,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(Envelope {
        data: load_org_dns(&s.store, org_id).await?,
        next_cursor: None,
    }))
}

async fn api_list_audit(
    State(s): State<AppState>,
    Query(query): Query<AuditQuery>,
    headers: HeaderMap,
) -> Result<Json<Envelope<Vec<crate::AuditEvent>>>, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::AuditRead)?;
    crate::purge_expired_audit(&s.store, org_id).await?;
    let events = load_audit_events(&s.store, org_id, &query).await?;
    let next_cursor = events
        .last()
        .map(|event| format!("{}:{}", event.created_at, event.id));
    Ok(Json(Envelope {
        data: events,
        next_cursor,
    }))
}

async fn api_list_wg_only(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Envelope<Vec<crate::wg_only::WireGuardOnlyPeer>>>, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::DevicesRead)?;
    Ok(Json(Envelope {
        data: crate::wg_only::list_for_org(&s, org_id).await?,
        next_cursor: None,
    }))
}

async fn api_create_wg_only(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<crate::wg_only::CreateWireGuardOnlyPeer>,
) -> Result<(StatusCode, Json<crate::wg_only::WireGuardOnlyPeer>), ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::DevicesWrite)?;
    Ok((
        StatusCode::CREATED,
        Json(crate::wg_only::create_for_org(&s, org_id, &caller.session, input).await?),
    ))
}

async fn api_get_wg_only(
    State(s): State<AppState>,
    UrlPath(peer_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<crate::wg_only::WireGuardOnlyPeer>, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::DevicesRead)?;
    Ok(Json(
        crate::wg_only::get_for_org(&s, org_id, peer_id).await?,
    ))
}

async fn api_revoke_wg_only(
    State(s): State<AppState>,
    UrlPath(peer_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::DevicesWrite)?;
    crate::wg_only::revoke_for_org(&s, org_id, peer_id, &caller.session).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn api_rotate_wg_only(
    State(s): State<AppState>,
    UrlPath(peer_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<crate::wg_only::RotateWireGuardOnlyPeer>,
) -> Result<Json<crate::wg_only::WireGuardOnlyPeer>, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::DevicesWrite)?;
    Ok(Json(
        crate::wg_only::rotate_for_org(&s, org_id, peer_id, &caller.session, input).await?,
    ))
}
