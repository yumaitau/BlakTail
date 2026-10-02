//! Service-user (automation API client) lifecycle beyond create/revoke:
//! secret rotation and reversible suspension. A service user is never a
//! console identity: it has no Better Auth account, its `bta_`/`bto_`
//! secrets are only accepted by `/api/v1` and `/oauth/token`, and its audit
//! rows carry `api:<client id>` with actor role `api_client`.

use crate::admin::{
    ApiClientCreated, Scope, API_PREFIX, DEFAULT_TOKEN_TTL_SECS, MAX_TOKEN_TTL_SECS,
};
use crate::permissions::{require, Permission};
use crate::{append_audit, console_session, hash, now, secret, ApiError, AppState};
use axum::{
    extract::{Path as UrlPath, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/orgs/:org_id/api-clients/:client_id/rotate",
            post(rotate_api_client),
        )
        .route(
            "/v1/orgs/:org_id/api-clients/:client_id/suspend",
            post(suspend_api_client),
        )
        .route(
            "/v1/orgs/:org_id/api-clients/:client_id/resume",
            post(resume_api_client),
        )
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct RotateApiClient {
    #[serde(default)]
    expires_in_seconds: Option<i64>,
}

/// Issue a new client secret. The old secret and every OAuth access token
/// minted from it stop working in the same transaction.
async fn rotate_api_client(
    State(s): State<AppState>,
    UrlPath((org_id, client_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    body: Option<Json<RotateApiClient>>,
) -> Result<Json<ApiClientCreated>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageApiClients)?;
    let input = body.map(|Json(input)| input).unwrap_or_default();
    let lifetime = input.expires_in_seconds.unwrap_or(DEFAULT_TOKEN_TTL_SECS);
    if !(60..=MAX_TOKEN_TTL_SECS).contains(&lifetime) {
        return Err(ApiError::BadRequest(format!(
            "expires_in_seconds must be between 60 and {MAX_TOKEN_TTL_SECS}"
        )));
    }
    let current_time = now();
    let expires_at = current_time + lifetime;
    let token = secret(API_PREFIX);
    let token_prefix = token.chars().take(11).collect::<String>();
    let mut tx = s.store.pool.begin().await?;
    let row = sqlx::query(
        "SELECT name,scopes_json FROM api_clients WHERE id=$1 AND org_id=$2 AND revoked_at IS NULL",
    )
    .bind(client_id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let name: String = row.try_get(0)?;
    let scopes: Vec<Scope> =
        serde_json::from_str(&row.try_get::<String, _>(1)?).map_err(|_| ApiError::CorruptData)?;
    sqlx::query(
        "UPDATE api_clients SET token_hash=$1,token_prefix=$2,expires_at=$3,rotated_at=$4 WHERE id=$5 AND org_id=$6 AND revoked_at IS NULL",
    )
    .bind(hash(&token))
    .bind(&token_prefix)
    .bind(expires_at)
    .bind(current_time)
    .bind(client_id.to_string())
    .bind(org_id.to_string())
    .execute(&mut *tx)
    .await?;
    let invalidated = sqlx::query("DELETE FROM oauth_access_tokens WHERE api_client_id=$1")
        .bind(client_id.to_string())
        .execute(&mut *tx)
        .await?
        .rows_affected();
    append_audit(
        &mut tx,
        org_id,
        &session,
        "api_client.rotated",
        "api_client",
        Some(&client_id.to_string()),
        &serde_json::json!({
            "token_prefix": token_prefix,
            "expires_at": expires_at,
            "access_tokens_invalidated": invalidated,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(ApiClientCreated {
        id: client_id,
        name,
        token,
        token_prefix,
        scopes,
        expires_at: Some(expires_at),
    }))
}

async fn suspend_api_client(
    State(s): State<AppState>,
    UrlPath((org_id, client_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    set_suspended(&s, org_id, client_id, &headers, true).await
}

async fn resume_api_client(
    State(s): State<AppState>,
    UrlPath((org_id, client_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    set_suspended(&s, org_id, client_id, &headers, false).await
}

async fn set_suspended(
    s: &AppState,
    org_id: Uuid,
    client_id: Uuid,
    headers: &HeaderMap,
    suspend: bool,
) -> Result<StatusCode, ApiError> {
    let session = console_session(s, headers, org_id).await?;
    require(&session, Permission::ManageApiClients)?;
    let mut tx = s.store.pool.begin().await?;
    let changed = if suspend {
        sqlx::query(
            "UPDATE api_clients SET suspended_at=$1 WHERE id=$2 AND org_id=$3 AND revoked_at IS NULL AND suspended_at IS NULL",
        )
        .bind(now())
    } else {
        sqlx::query(
            "UPDATE api_clients SET suspended_at=NULL WHERE id=$1 AND org_id=$2 AND revoked_at IS NULL AND suspended_at IS NOT NULL",
        )
    };
    let changed = changed
        .bind(client_id.to_string())
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if changed == 0 {
        let exists: Option<String> = sqlx::query_scalar(
            "SELECT id FROM api_clients WHERE id=$1 AND org_id=$2 AND revoked_at IS NULL",
        )
        .bind(client_id.to_string())
        .bind(org_id.to_string())
        .fetch_optional(&mut *tx)
        .await?;
        return match exists {
            Some(_) => Ok(StatusCode::NO_CONTENT),
            None => Err(ApiError::NotFound),
        };
    }
    append_audit(
        &mut tx,
        org_id,
        &session,
        if suspend {
            "api_client.suspended"
        } else {
            "api_client.resumed"
        },
        "api_client",
        Some(&client_id.to_string()),
        &serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
