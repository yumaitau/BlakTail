//! Event catalogue and per-destination subscriptions on top of the signed
//! webhook outbox (draft 18). Signed HTTPS webhooks are delivered by
//! `webhooks`; email, Slack and Teams channels by `notify_channels`, on the
//! same outbox rows.
//!
//! Events come from three places: explicit `webhooks::enqueue` calls at the
//! mutation (device, policy, DNS), audit actions mapped here (so every
//! audited write that matters is one table entry, not a new call site), and
//! a periodic sweep for credentials that are about to expire.

use crate::admin::{authenticate_org_header, require_scope, Envelope, Scope};
use crate::audit_log::{redact, ChainEntry};
use crate::permissions::{require, Permission};
use crate::posture::{evaluate, load_checks, referenced_checks, NodeFacts};
use crate::{append_audit, console_session, now, webhooks, ApiError, AppState, Session, Store};
use axum::{
    extract::{Path as UrlPath, State},
    http::{HeaderMap, StatusCode},
    routing::{get, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::{AnyConnection, Row};
use uuid::Uuid;

/// Credentials expiring within this window raise `credential.expiring`.
pub(crate) const EXPIRY_WARNING_SECS: i64 = 7 * 24 * 60 * 60;
const MAX_EXPIRY_SWEEP_ROWS: i64 = 1_000;
pub(crate) const ALL_EVENTS: &str = "*";

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Severity {
    Info,
    Notice,
    Warning,
}

impl Severity {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Warning => "warning",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct EventKind {
    pub(crate) event_type: &'static str,
    pub(crate) severity: Severity,
    pub(crate) summary: &'static str,
}

const fn kind(event_type: &'static str, severity: Severity, summary: &'static str) -> EventKind {
    EventKind {
        event_type,
        severity,
        summary,
    }
}

/// Every event type a destination can receive. `docs/notifications.md`
/// mirrors this table; a test keeps every enqueue site inside it.
pub(crate) const CATALOGUE: &[EventKind] = &[
    kind(
        "device.enrolled",
        Severity::Info,
        "A device enrolled with a join key or browser approval.",
    ),
    kind(
        "join_key.used",
        Severity::Notice,
        "A join key (not a browser approval) enrolled a device.",
    ),
    kind(
        "device.renamed",
        Severity::Info,
        "A device's friendly name changed.",
    ),
    kind(
        "device.revoked",
        Severity::Warning,
        "A device credential was revoked.",
    ),
    kind("device.deleted", Severity::Warning, "A device was removed."),
    kind(
        "device.suspended",
        Severity::Warning,
        "A device was suspended and left every peer map.",
    ),
    kind(
        "device.resumed",
        Severity::Info,
        "A suspended device was resumed.",
    ),
    kind(
        "credential.expiring",
        Severity::Warning,
        "A device credential expires within seven days.",
    ),
    kind(
        "posture.failed",
        Severity::Warning,
        "A new inventory report made a device fail a posture check that policy references.",
    ),
    kind(
        "route.approved",
        Severity::Notice,
        "The subnet routes approved for a device changed.",
    ),
    kind(
        "policy.published",
        Severity::Notice,
        "A new access policy revision was published.",
    ),
    kind(
        "policy.rolled_back",
        Severity::Warning,
        "Access policy was rolled back.",
    ),
    kind(
        "dns.published",
        Severity::Notice,
        "A new DNS revision was published.",
    ),
    kind(
        "dns.rolled_back",
        Severity::Warning,
        "DNS settings were rolled back.",
    ),
    kind(
        "membership.updated",
        Severity::Info,
        "A person's membership role or status changed in the console.",
    ),
    kind(
        "membership.role_changed",
        Severity::Warning,
        "A person's organisation role changed.",
    ),
    kind(
        "service_user.suspended",
        Severity::Warning,
        "An automation client (service user) was suspended.",
    ),
    kind(
        "traffic.settings_changed",
        Severity::Notice,
        "Traffic diagnostics were turned on or off, or sampling or retention changed.",
    ),
];

pub(crate) fn find(event_type: &str) -> Option<&'static EventKind> {
    CATALOGUE.iter().find(|kind| kind.event_type == event_type)
}

/// Audit actions that also raise a catalogued event.
fn audit_event(action: &str) -> Option<&'static str> {
    match action {
        "node.routes_updated" => Some("route.approved"),
        "api_client.suspended" => Some("service_user.suspended"),
        "traffic.settings_updated" => Some("traffic.settings_changed"),
        _ => None,
    }
}

/// Called by `append_audit` inside the writer's transaction, so the event is
/// committed or rolled back with the change itself.
pub(crate) async fn enqueue_for_audit(
    connection: &mut AnyConnection,
    org_id: Uuid,
    entry: &ChainEntry,
    details: &serde_json::Value,
) -> Result<(), ApiError> {
    let Some(event_type) = audit_event(&entry.action) else {
        return Ok(());
    };
    let mut details = details.clone();
    redact(&mut details);
    webhooks::enqueue(
        connection,
        org_id,
        event_type,
        &serde_json::json!({
            "action": entry.action,
            "target_type": entry.target_type,
            "target_id": entry.target_id,
            "actor": {"user_id": entry.actor_user_id, "role": entry.actor_role},
            "details": details,
            "audit_event_id": entry.id,
        }),
    )
    .await
}

pub(crate) fn subscribed(event_types: &[String], event_type: &str) -> bool {
    event_types
        .iter()
        .any(|value| value == ALL_EVENTS || value == event_type)
}

/// Canonical subscription list: `["*"]`, or sorted catalogued types.
pub(crate) fn validate_event_types(input: &[String]) -> Result<Vec<String>, ApiError> {
    if input.is_empty() {
        return Err(ApiError::BadRequest(
            "choose at least one event type, or \"*\" for all".into(),
        ));
    }
    let mut out = Vec::new();
    for value in input {
        let value = value.trim();
        if value == ALL_EVENTS {
            return Ok(vec![ALL_EVENTS.into()]);
        }
        if find(value).is_none() {
            return Err(ApiError::BadRequest(format!(
                "unknown event type {value:?}; see the event catalogue"
            )));
        }
        out.push(value.to_owned());
    }
    out.sort();
    out.dedup();
    Ok(out)
}

// ---------------------------------------------------------------------------
// Posture regressions

/// Policy-referenced checks the device passed before a report and fails
/// after it. Time-based lapses (credential age) are not reported here.
pub(crate) async fn newly_failing_checks(
    store: &Store,
    org_id: &str,
    before: &NodeFacts,
    after: &NodeFacts,
) -> Result<Vec<String>, ApiError> {
    let checks = load_checks(&store.pool, org_id).await?;
    if checks.is_empty() {
        return Ok(Vec::new());
    }
    let org = Uuid::parse_str(org_id).map_err(|_| ApiError::CorruptData)?;
    let refs = referenced_checks(&crate::load_org_acl(store, org).await?);
    let at = now();
    Ok(checks
        .iter()
        .filter(|(name, _)| refs.contains_key(*name))
        .filter(|(name, check)| {
            evaluate(name, check.version, &check.definition, before, at).passed
                && !evaluate(name, check.version, &check.definition, after, at).passed
        })
        .map(|(name, _)| name.clone())
        .collect())
}

// ---------------------------------------------------------------------------
// Credential expiry sweep

/// Enqueues `credential.expiring` once per device credential. The event id
/// is derived from the device and its expiry, so repeated sweeps and
/// coordinator replicas never duplicate a delivery.
pub(crate) async fn enqueue_expiring_credentials(
    store: &Store,
    at: i64,
) -> Result<usize, ApiError> {
    let rows = sqlx::query(
        "SELECT id,org_id,name,credential_expires_at FROM nodes WHERE revoked_at IS NULL AND deleted_at IS NULL AND credential_expires_at>$1 AND credential_expires_at<=$2 ORDER BY credential_expires_at LIMIT $3",
    )
    .bind(at)
    .bind(at + EXPIRY_WARNING_SECS)
    .bind(MAX_EXPIRY_SWEEP_ROWS)
    .fetch_all(&store.pool)
    .await?;
    let mut enqueued = 0;
    for row in rows {
        let node_id: String = row.try_get(0)?;
        let org_id: String = row.try_get(1)?;
        let name: String = row.try_get(2)?;
        let expires_at: i64 = row.try_get(3)?;
        let org = Uuid::parse_str(&org_id).map_err(|_| ApiError::CorruptData)?;
        let mut tx = store.pool.begin().await?;
        enqueued += webhooks::enqueue_once(
            &mut tx,
            org,
            "credential.expiring",
            &format!("credential.expiring:{node_id}:{expires_at}"),
            &serde_json::json!({
                "device_id": node_id,
                "name": name,
                "credential_expires_at": expires_at,
            }),
        )
        .await?;
        tx.commit().await?;
    }
    Ok(enqueued)
}

// ---------------------------------------------------------------------------
// Routes

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/orgs/:org_id/events/catalogue", get(catalogue_console))
        .route(
            "/v1/orgs/:org_id/webhooks/:destination_id/subscriptions",
            put(subscriptions_console),
        )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SubscriptionInput {
    event_types: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SubscriptionView {
    pub(crate) destination_id: Uuid,
    pub(crate) event_types: Vec<String>,
}

pub(crate) async fn set_subscriptions(
    store: &Store,
    org_id: Uuid,
    session: &Session,
    destination_id: Uuid,
    input: SubscriptionInput,
) -> Result<SubscriptionView, ApiError> {
    require(session, Permission::ManageIntegrations)?;
    let event_types = validate_event_types(&input.event_types)?;
    let encoded = serde_json::to_string(&event_types).map_err(|_| ApiError::CorruptData)?;
    let mut tx = store.pool.begin().await?;
    let previous: String = sqlx::query_scalar(
        "SELECT event_types_json FROM webhook_destinations WHERE id=$1 AND org_id=$2",
    )
    .bind(destination_id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    sqlx::query("UPDATE webhook_destinations SET event_types_json=$1 WHERE id=$2 AND org_id=$3")
        .bind(&encoded)
        .bind(destination_id.to_string())
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await?;
    append_audit(
        &mut tx,
        org_id,
        session,
        "webhook.subscriptions_updated",
        "webhook",
        Some(&destination_id.to_string()),
        &serde_json::json!({
            "event_types": event_types,
            "previous_event_types": serde_json::from_str::<serde_json::Value>(&previous).unwrap_or_default(),
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(SubscriptionView {
        destination_id,
        event_types,
    })
}

async fn catalogue_console(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<&'static [EventKind]>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewNetwork)?;
    Ok(Json(CATALOGUE))
}

async fn subscriptions_console(
    State(s): State<AppState>,
    UrlPath((org_id, destination_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<SubscriptionInput>,
) -> Result<Json<SubscriptionView>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    Ok(Json(
        set_subscriptions(&s.store, org_id, &session, destination_id, input).await?,
    ))
}

pub(crate) async fn api_catalogue(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Envelope<&'static [EventKind]>>, ApiError> {
    let (_, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::WebhooksRead)?;
    Ok(Json(Envelope {
        data: CATALOGUE,
        next_cursor: None,
    }))
}

pub(crate) async fn api_subscriptions(
    State(s): State<AppState>,
    UrlPath(destination_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<SubscriptionInput>,
) -> Result<(StatusCode, Json<Envelope<SubscriptionView>>), ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::WebhooksWrite)?;
    let view = set_subscriptions(&s.store, org_id, &caller.session, destination_id, input).await?;
    Ok((
        StatusCode::OK,
        Json(Envelope {
            data: view,
            next_cursor: None,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscriptions_validate_against_the_catalogue() {
        assert_eq!(
            validate_event_types(&["posture.failed".into(), "device.revoked".into()]).unwrap(),
            vec!["device.revoked", "posture.failed"]
        );
        assert_eq!(
            validate_event_types(&["device.revoked".into(), "*".into()]).unwrap(),
            vec!["*"]
        );
        assert!(validate_event_types(&[]).is_err());
        assert!(validate_event_types(&["email.sent".into()]).is_err());
        assert!(subscribed(&["*".into()], "anything"));
        assert!(subscribed(&["dns.published".into()], "dns.published"));
        assert!(!subscribed(&["dns.published".into()], "policy.published"));
    }

    #[test]
    fn audit_mapped_events_are_catalogued() {
        for action in [
            "node.routes_updated",
            "api_client.suspended",
            "traffic.settings_updated",
        ] {
            let event = audit_event(action).unwrap();
            assert!(find(event).is_some(), "{event} missing from catalogue");
        }
        let mut names: Vec<_> = CATALOGUE.iter().map(|kind| kind.event_type).collect();
        let total = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), total, "duplicate catalogue entry");
    }

    #[test]
    fn every_enqueue_site_uses_a_catalogued_event() {
        let sources = [
            include_str!("lib.rs"),
            include_str!("admin.rs"),
            include_str!("webhooks.rs"),
            include_str!("posture.rs"),
            include_str!("notifications.rs"),
        ];
        let literal = regex_lite_literals(&sources);
        assert!(!literal.is_empty());
        for event in literal {
            assert!(
                find(&event).is_some(),
                "{event} is enqueued but not catalogued"
            );
        }
    }

    /// Event-shaped string literals inside each `enqueue(...)` call.
    fn regex_lite_literals(sources: &[&str]) -> Vec<String> {
        let mut found = Vec::new();
        for source in sources {
            for chunk in source.split("enqueue(").skip(1) {
                let call = chunk.split(".await").next().unwrap_or(chunk);
                let window: String = call.chars().take(300).collect();
                if let Some(start) = window.find('"') {
                    let rest = &window[start + 1..];
                    if let Some(end) = rest.find('"') {
                        let candidate = &rest[..end];
                        if candidate.contains('.')
                            && candidate
                                .chars()
                                .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_')
                        {
                            found.push(candidate.to_owned());
                        }
                    }
                }
            }
        }
        found
    }
}
