//! `/api/v1` operations for objects that first shipped in the console
//! (draft 22). Each handler authenticates the automation caller, checks its
//! scope, then calls the same function the console route calls, so both
//! paths share one permission check and one validator.

use crate::admin::{authenticate_org_header, require_scope, Envelope, Scope};
use crate::dns_workspace::{validate_draft, ValidateRequest, ValidateResponse};
use crate::peer_lifecycle::{list_join_keys_as, revoke_join_key_as, JoinKeySummary};
use crate::posture::{
    create_check_as, delete_check_as, list_checks_as, update_check_as, CheckView, CreateCheck,
    UpdateCheck,
};
use crate::{ApiError, AppState};
use axum::{
    extract::{Path as UrlPath, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use uuid::Uuid;

fn envelope<T: serde::Serialize>(data: T) -> Json<Envelope<T>> {
    Json(Envelope {
        data,
        next_cursor: None,
    })
}

pub(crate) async fn api_list_posture_checks(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Envelope<Vec<CheckView>>>, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::DevicesRead)?;
    let Json(checks) = list_checks_as(&s, org_id, &caller.session).await?;
    Ok(envelope(checks))
}

pub(crate) async fn api_create_posture_check(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateCheck>,
) -> Result<(StatusCode, Json<Envelope<serde_json::Value>>), ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::PolicyWrite)?;
    let (status, Json(created)) = create_check_as(&s, org_id, &caller.session, input).await?;
    Ok((status, envelope(created)))
}

pub(crate) async fn api_update_posture_check(
    State(s): State<AppState>,
    UrlPath(check_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<UpdateCheck>,
) -> Result<Json<Envelope<serde_json::Value>>, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::PolicyWrite)?;
    let Json(updated) = update_check_as(&s, org_id, &caller.session, check_id, input).await?;
    Ok(envelope(updated))
}

pub(crate) async fn api_delete_posture_check(
    State(s): State<AppState>,
    UrlPath(check_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::PolicyWrite)?;
    delete_check_as(&s, org_id, &caller.session, check_id).await
}

pub(crate) async fn api_list_join_keys(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Envelope<Vec<JoinKeySummary>>>, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::KeysRead)?;
    let Json(keys) = list_join_keys_as(&s, org_id, &caller.session).await?;
    Ok(envelope(keys))
}

pub(crate) async fn api_revoke_join_key(
    State(s): State<AppState>,
    UrlPath(key_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::KeysWrite)?;
    revoke_join_key_as(&s, org_id, &caller.session, key_id).await
}

pub(crate) async fn api_validate_dns(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ValidateRequest>,
) -> Result<Json<Envelope<ValidateResponse>>, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::DevicesRead)?;
    Ok(envelope(validate_draft(&s.store, org_id, input).await?))
}
