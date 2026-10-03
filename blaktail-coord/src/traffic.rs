//! Opt-in traffic diagnostics (draft 17), separate from the audit log.
//!
//! Off by default. Only an owner can turn it on. Devices upload aggregate
//! counters (bytes, packets, transport, allow/deny per time bucket and
//! service class) with their node token; the coordinator refuses uploads
//! while the organisation is opted out, rejects anything payload-shaped,
//! samples, and deletes records past the organisation's retention.

use crate::flows::{should_sample, validate_batch, validate_flow_json, FlowRecord};
use crate::permissions::{require, Permission};
use crate::{append_audit, console_session, now, ApiError, AppState, Store};
use axum::{
    body::Bytes,
    extract::{Path as UrlPath, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::BTreeMap;
use uuid::Uuid;

pub(crate) const MIN_SAMPLING_RATE: f64 = 0.01;
pub(crate) const MAX_RETENTION_DAYS: i64 = 30;
const DEFAULT_RETENTION_DAYS: i64 = 7;
/// Storage bound per organisation; uploads beyond it are refused.
pub(crate) const MAX_RECORDS_PER_ORG: i64 = 200_000;
const MAX_UPLOAD_BYTES: usize = 256 * 1024;
const UPLOADS_PER_NODE_PER_MINUTE: u32 = 12;
pub(crate) const STALE_AFTER_SECS: i64 = 2 * 60 * 60;
const MAX_SUMMARY_HOURS: i64 = 7 * 24;
const DAY_SECS: i64 = 24 * 60 * 60;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/orgs/:org_id/traffic/settings",
            get(get_settings).put(put_settings),
        )
        .route("/v1/orgs/:org_id/traffic/summary", get(summary))
        .route(
            "/v1/orgs/:org_id/traffic/records",
            axum::routing::delete(delete_records),
        )
        .route("/v1/nodes/:node_id/flows", post(ingest))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct TrafficSettings {
    pub(crate) enabled: bool,
    pub(crate) sampling_rate: f64,
    pub(crate) retention_days: i64,
    pub(crate) updated_at: Option<i64>,
    pub(crate) updated_by: String,
}

async fn load_settings(
    connection: &mut sqlx::AnyConnection,
    org_id: &str,
) -> Result<TrafficSettings, ApiError> {
    let row = sqlx::query(
        "SELECT enabled,sampling_rate,CAST(retention_days AS BIGINT),updated_at,updated_by FROM flow_settings WHERE org_id=$1",
    )
    .bind(org_id)
    .fetch_optional(&mut *connection)
    .await?;
    Ok(match row {
        Some(row) => TrafficSettings {
            enabled: row.try_get::<i64, _>(0)? != 0,
            sampling_rate: row.try_get(1)?,
            retention_days: row.try_get(2)?,
            updated_at: Some(row.try_get(3)?),
            updated_by: row.try_get(4)?,
        },
        None => TrafficSettings {
            enabled: false,
            sampling_rate: 1.0,
            retention_days: DEFAULT_RETENTION_DAYS,
            updated_at: None,
            updated_by: String::new(),
        },
    })
}

/// What a device's peer map says about reporting. Absent means off.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct AgentTraffic {
    pub(crate) enabled: bool,
    pub(crate) sampling_rate: f64,
    /// Uploads must name the device's own organisation.
    pub(crate) org_id: String,
}

pub(crate) async fn agent_view(
    pool: &sqlx::AnyPool,
    org_id: &str,
) -> Result<Option<AgentTraffic>, ApiError> {
    let mut connection = pool.acquire().await?;
    let settings = load_settings(&mut connection, org_id).await?;
    Ok(settings.enabled.then(|| AgentTraffic {
        enabled: true,
        sampling_rate: settings.sampling_rate,
        org_id: org_id.to_owned(),
    }))
}

async fn get_settings(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<TrafficSettings>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewAudit)?;
    let mut connection = s.store.pool.acquire().await?;
    Ok(Json(
        load_settings(&mut connection, &org_id.to_string()).await?,
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SettingsInput {
    enabled: bool,
    #[serde(default)]
    sampling_rate: Option<f64>,
    #[serde(default)]
    retention_days: Option<i64>,
}

async fn put_settings(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<SettingsInput>,
) -> Result<Json<TrafficSettings>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    // Owner-only: turning collection on is a privacy decision for the org.
    require(&session, Permission::ManageSecurity)?;
    let org = org_id.to_string();
    let mut tx = s.store.pool.begin().await?;
    let previous = load_settings(&mut tx, &org).await?;
    let sampling_rate = input.sampling_rate.unwrap_or(previous.sampling_rate);
    if !sampling_rate.is_finite() || !(MIN_SAMPLING_RATE..=1.0).contains(&sampling_rate) {
        return Err(ApiError::BadRequest(format!(
            "sampling_rate must be between {MIN_SAMPLING_RATE} and 1"
        )));
    }
    let retention_days = input.retention_days.unwrap_or(previous.retention_days);
    if !(1..=MAX_RETENTION_DAYS).contains(&retention_days) {
        return Err(ApiError::BadRequest(format!(
            "retention_days must be between 1 and {MAX_RETENTION_DAYS}"
        )));
    }
    let at = now();
    sqlx::query(
        "INSERT INTO flow_settings(org_id,sampling_rate,retention_days,updated_at,enabled,updated_by) VALUES($1,$2,$3,$4,$5,$6)
         ON CONFLICT (org_id) DO UPDATE SET sampling_rate=excluded.sampling_rate,retention_days=excluded.retention_days,updated_at=excluded.updated_at,enabled=excluded.enabled,updated_by=excluded.updated_by",
    )
    .bind(&org)
    .bind(sampling_rate)
    .bind(retention_days)
    .bind(at)
    .bind(i64::from(input.enabled))
    .bind(&session.user_id)
    .execute(&mut *tx)
    .await?;
    if input.enabled != previous.enabled
        || (input.enabled && sampling_rate != previous.sampling_rate)
    {
        // Agents learn the change on their next control update; the bump
        // wakes long-polls so reporting starts or stops within seconds.
        crate::bump_control_revision(&mut tx, &org).await?;
    }
    append_audit(
        &mut tx,
        org_id,
        &session,
        "traffic.settings_updated",
        "traffic_settings",
        Some(&org),
        &serde_json::json!({
            "enabled": input.enabled,
            "previous_enabled": previous.enabled,
            "sampling_rate": sampling_rate,
            "retention_days": retention_days,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(TrafficSettings {
        enabled: input.enabled,
        sampling_rate,
        retention_days,
        updated_at: Some(at),
        updated_by: session.user_id,
    }))
}

async fn delete_records(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageSecurity)?;
    let mut tx = s.store.pool.begin().await?;
    let deleted = sqlx::query("DELETE FROM flow_records WHERE org_id=$1")
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await?
        .rows_affected();
    append_audit(
        &mut tx,
        org_id,
        &session,
        "traffic.records_deleted",
        "traffic_records",
        Some(&org_id.to_string()),
        &serde_json::json!({"count": deleted}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(serde_json::json!({"deleted": deleted})))
}

// ---------------------------------------------------------------------------
// Ingest

/// Wire form of one aggregate record. Unknown fields are refused so nothing
/// beyond these counters can be smuggled into storage.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UploadRecord {
    org_id: String,
    device_id: String,
    service: String,
    start_bucket: i64,
    end_bucket: i64,
    proto: String,
    port: u16,
    bytes: u64,
    packets: u64,
    transport: crate::flows::FlowTransport,
    decision: crate::flows::FlowDecision,
    #[serde(default)]
    peer_id: Option<String>,
    #[serde(default)]
    direction: Option<crate::flows::FlowDirection>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Upload {
    records: Vec<UploadRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct UploadResult {
    pub(crate) accepted: usize,
    pub(crate) sampled_out: usize,
    pub(crate) sampling_rate: f64,
}

fn sample_draw(record: &FlowRecord) -> u64 {
    let digest = Sha256::digest(
        format!(
            "{}|{}|{}|{}|{}|{}",
            record.org_id,
            record.device_id,
            record.start_bucket,
            record.service,
            record.proto,
            record.port
        )
        .as_bytes(),
    );
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes)
}

fn label<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

async fn ingest(
    State(s): State<AppState>,
    UrlPath(node_id): UrlPath<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<UploadResult>), ApiError> {
    let token = crate::bearer(&headers)?;
    let row = sqlx::query(
        "SELECT org_id,credential_expires_at,CASE WHEN suspended_at IS NULL THEN 0 ELSE 1 END FROM nodes WHERE id=$1 AND token_hash=$2 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(node_id.to_string())
    .bind(token)
    .fetch_optional(&s.store.pool)
    .await?
    .ok_or(ApiError::Unauthorized)?;
    let org_id: String = row.try_get(0)?;
    if row.try_get::<i64, _>(1)? <= now() {
        return Err(ApiError::CredentialExpired);
    }
    if row.try_get::<i64, _>(2)? != 0 {
        return Err(ApiError::Suspended);
    }
    if !s.api_rate.allow(
        &format!("flows:{node_id}"),
        now(),
        UPLOADS_PER_NODE_PER_MINUTE,
        60,
    ) {
        return Err(ApiError::Conflict(
            "traffic uploads are limited to 12 a minute per device".into(),
        ));
    }
    {
        let mut connection = s.store.pool.acquire().await?;
        if !load_settings(&mut connection, &org_id).await?.enabled {
            return Err(disabled());
        }
    }
    if body.len() > MAX_UPLOAD_BYTES {
        return Err(ApiError::BadRequest("traffic upload is too large".into()));
    }
    let raw: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| ApiError::BadRequest("traffic upload must be JSON".into()))?;
    validate_flow_json(&raw).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let upload: Upload = serde_json::from_value(raw)
        .map_err(|error| ApiError::BadRequest(format!("invalid traffic upload: {error}")))?;
    let records: Vec<FlowRecord> = upload
        .records
        .into_iter()
        .map(|record| FlowRecord {
            org_id: record.org_id,
            device_id: record.device_id,
            service: record.service,
            start_bucket: record.start_bucket,
            end_bucket: record.end_bucket,
            proto: record.proto,
            port: record.port,
            bytes: record.bytes,
            packets: record.packets,
            transport: record.transport,
            decision: record.decision,
            peer_id: record.peer_id,
            direction: record.direction,
        })
        .collect();
    validate_batch(&records).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let device = node_id.to_string();
    if records
        .iter()
        .any(|record| record.org_id != org_id || record.device_id != device)
    {
        // A device may only report its own counters in its own organisation.
        return Err(ApiError::Forbidden);
    }
    let peers: std::collections::BTreeSet<&str> = records
        .iter()
        .filter_map(|record| record.peer_id.as_deref())
        .collect();
    for peer in peers {
        // A peer must be a device of the same organisation (deleted or
        // revoked ones still count: their history stays attributable).
        let known: Option<String> =
            sqlx::query_scalar("SELECT id FROM nodes WHERE id=$1 AND org_id=$2")
                .bind(peer)
                .bind(&org_id)
                .fetch_optional(&s.store.pool)
                .await?;
        if known.is_none() {
            return Err(ApiError::Forbidden);
        }
    }

    let mut tx = s.store.pool.begin().await?;
    // Re-read inside the write so turning collection off stops ingestion
    // from the next request, even one that raced the toggle.
    let settings = load_settings(&mut tx, &org_id).await?;
    if !settings.enabled {
        return Err(disabled());
    }
    let at = now();
    sqlx::query("DELETE FROM flow_records WHERE org_id=$1 AND created_at<$2")
        .bind(&org_id)
        .bind(at - settings.retention_days * DAY_SECS)
        .execute(&mut *tx)
        .await?;
    let sampled: Vec<&FlowRecord> = records
        .iter()
        .filter(|record| should_sample(settings.sampling_rate, sample_draw(record)))
        .collect();
    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM flow_records WHERE org_id=$1")
        .bind(&org_id)
        .fetch_one(&mut *tx)
        .await?;
    if stored + sampled.len() as i64 > MAX_RECORDS_PER_ORG {
        return Err(ApiError::Conflict(
            "traffic storage limit reached; lower the sampling rate or retention".into(),
        ));
    }
    for record in &sampled {
        sqlx::query(
            "INSERT INTO flow_records(id,org_id,device_id,service,start_bucket,end_bucket,proto,port,bytes,packets,transport,decision,created_at,peer_id,direction) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&org_id)
        .bind(&device)
        .bind(&record.service)
        .bind(record.start_bucket)
        .bind(record.end_bucket)
        .bind(&record.proto)
        .bind(i32::from(record.port))
        .bind(i64::try_from(record.bytes).unwrap_or(i64::MAX))
        .bind(i64::try_from(record.packets).unwrap_or(i64::MAX))
        .bind(label(&record.transport))
        .bind(label(&record.decision))
        .bind(at)
        .bind(record.peer_id.as_deref())
        .bind(record.direction.as_ref().map(label))
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(UploadResult {
            accepted: sampled.len(),
            sampled_out: records.len() - sampled.len(),
            sampling_rate: settings.sampling_rate,
        }),
    ))
}

fn disabled() -> ApiError {
    ApiError::Conflict("traffic diagnostics are turned off for this organisation".into())
}

/// Deletes records older than each organisation's retention.
pub(crate) async fn purge_expired(store: &Store) -> Result<u64, ApiError> {
    Ok(sqlx::query(
        "DELETE FROM flow_records WHERE created_at < $1 - COALESCE((SELECT CAST(f.retention_days AS BIGINT) FROM flow_settings f WHERE f.org_id=flow_records.org_id),$2)*$3",
    )
    .bind(now())
    .bind(DEFAULT_RETENTION_DAYS)
    .bind(DAY_SECS)
    .execute(&store.pool)
    .await?
    .rows_affected())
}

// ---------------------------------------------------------------------------
// Summary

#[derive(Default, Deserialize)]
pub(crate) struct SummaryQuery {
    #[serde(default)]
    hours: Option<i64>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub(crate) struct Counter {
    pub(crate) bytes: i64,
    pub(crate) packets: i64,
    pub(crate) records: i64,
}

impl Counter {
    fn add(&mut self, bytes: i64, packets: i64, records: i64) {
        self.bytes = self.bytes.saturating_add(bytes);
        self.packets = self.packets.saturating_add(packets);
        self.records = self.records.saturating_add(records);
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub(crate) struct Bucket {
    pub(crate) start: i64,
    pub(crate) allowed: Counter,
    pub(crate) denied: Counter,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Confidence {
    /// Every record is reported by a device; the coordinator sees no traffic.
    pub(crate) source: String,
    pub(crate) level: String,
    pub(crate) sampling_rate: f64,
    pub(crate) reporting_devices: i64,
    pub(crate) active_devices: i64,
    pub(crate) detail: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct TrafficSummary {
    pub(crate) settings: TrafficSettings,
    /// `disabled`, `no_data`, `stale` or `current`.
    pub(crate) state: String,
    pub(crate) window_hours: i64,
    pub(crate) generated_at: i64,
    pub(crate) last_received_at: Option<i64>,
    pub(crate) allowed: Counter,
    pub(crate) denied: Counter,
    pub(crate) by_transport: BTreeMap<String, Counter>,
    pub(crate) by_service: BTreeMap<String, Counter>,
    /// `inbound` (a peer started the flow), `outbound`, or `unknown` for
    /// records that do not say.
    #[serde(default)]
    pub(crate) by_direction: BTreeMap<String, Counter>,
    pub(crate) buckets: Vec<Bucket>,
    pub(crate) confidence: Confidence,
}

pub(crate) fn traffic_state(enabled: bool, last_received_at: Option<i64>, at: i64) -> &'static str {
    match (enabled, last_received_at) {
        (false, _) => "disabled",
        (true, None) => "no_data",
        (true, Some(last)) if at - last > STALE_AFTER_SECS => "stale",
        (true, Some(_)) => "current",
    }
}

fn confidence(rate: f64, reporting: i64, active: i64) -> Confidence {
    let level = if reporting == 0 {
        "none"
    } else if rate >= 1.0 && reporting >= active {
        "high"
    } else if reporting * 2 >= active {
        "partial"
    } else {
        "low"
    };
    let detail = if reporting == 0 {
        "No device has reported traffic in this window. Agents report only while diagnostics are on, about once a minute; Android phones and agents older than this release do not report, so an empty view does not mean there was no traffic.".to_owned()
    } else {
        format!(
            "{reporting} of {active} active devices reported. Counts are device-reported aggregates sampled at {:.0}%, so totals are a lower bound.",
            rate * 100.0
        )
    };
    Confidence {
        source: "agent_reported".into(),
        level: level.into(),
        sampling_rate: rate,
        reporting_devices: reporting,
        active_devices: active,
        detail,
    }
}

async fn summary(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Query(query): Query<SummaryQuery>,
) -> Result<Json<TrafficSummary>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewAudit)?;
    let window_hours = query.hours.unwrap_or(24);
    if !(1..=MAX_SUMMARY_HOURS).contains(&window_hours) {
        return Err(ApiError::BadRequest(format!(
            "hours must be between 1 and {MAX_SUMMARY_HOURS}"
        )));
    }
    let org = org_id.to_string();
    let at = now();
    let since = at - window_hours * 3600;
    let settings = {
        let mut connection = s.store.pool.acquire().await?;
        load_settings(&mut connection, &org).await?
    };
    let rows = sqlx::query(
        "SELECT (start_bucket/3600)*3600,decision,transport,service,CAST(COALESCE(SUM(bytes),0) AS BIGINT),CAST(COALESCE(SUM(packets),0) AS BIGINT),COUNT(*),COALESCE(direction,'unknown') FROM flow_records WHERE org_id=$1 AND start_bucket>=$2 GROUP BY (start_bucket/3600)*3600,decision,transport,service,COALESCE(direction,'unknown')",
    )
    .bind(&org)
    .bind(since)
    .fetch_all(&s.store.pool)
    .await?;
    let mut allowed = Counter::default();
    let mut denied = Counter::default();
    let mut by_transport: BTreeMap<String, Counter> = BTreeMap::new();
    let mut by_service: BTreeMap<String, Counter> = BTreeMap::new();
    let mut by_direction: BTreeMap<String, Counter> = BTreeMap::new();
    let mut buckets: BTreeMap<i64, Bucket> = BTreeMap::new();
    for row in rows {
        let start: i64 = row.try_get(0)?;
        let decision: String = row.try_get(1)?;
        let transport: String = row.try_get(2)?;
        let service: String = row.try_get(3)?;
        let bytes: i64 = row.try_get(4)?;
        let packets: i64 = row.try_get(5)?;
        let records: i64 = row.try_get(6)?;
        let direction: String = row.try_get(7)?;
        let bucket = buckets.entry(start).or_insert_with(|| Bucket {
            start,
            ..Bucket::default()
        });
        if decision == "denied" {
            denied.add(bytes, packets, records);
            bucket.denied.add(bytes, packets, records);
        } else {
            allowed.add(bytes, packets, records);
            bucket.allowed.add(bytes, packets, records);
        }
        by_transport
            .entry(transport)
            .or_default()
            .add(bytes, packets, records);
        by_service
            .entry(service)
            .or_default()
            .add(bytes, packets, records);
        by_direction
            .entry(direction)
            .or_default()
            .add(bytes, packets, records);
    }
    let reporting = sqlx::query(
        "SELECT COUNT(DISTINCT device_id),MAX(created_at) FROM flow_records WHERE org_id=$1 AND start_bucket>=$2",
    )
    .bind(&org)
    .bind(since)
    .fetch_one(&s.store.pool)
    .await?;
    let reporting_devices: i64 = reporting.try_get(0)?;
    let last_received_at: Option<i64> = reporting.try_get(1)?;
    let active_devices: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM nodes WHERE org_id=$1 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(&org)
    .fetch_one(&s.store.pool)
    .await?;
    Ok(Json(TrafficSummary {
        state: traffic_state(settings.enabled, last_received_at, at).into(),
        confidence: confidence(settings.sampling_rate, reporting_devices, active_devices),
        settings,
        window_hours,
        generated_at: at,
        last_received_at,
        allowed,
        denied,
        by_transport,
        by_service,
        by_direction,
        buckets: buckets.into_values().collect(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_reports_disabled_empty_and_stale_honestly() {
        assert_eq!(traffic_state(false, Some(100), 100), "disabled");
        assert_eq!(traffic_state(true, None, 100), "no_data");
        assert_eq!(traffic_state(true, Some(0), STALE_AFTER_SECS + 1), "stale");
        assert_eq!(traffic_state(true, Some(10), 20), "current");
    }

    #[test]
    fn confidence_levels_follow_coverage_and_sampling() {
        assert_eq!(confidence(1.0, 0, 4).level, "none");
        assert_eq!(confidence(1.0, 4, 4).level, "high");
        assert_eq!(confidence(0.5, 4, 4).level, "partial");
        assert_eq!(confidence(1.0, 1, 4).level, "low");
    }
}
