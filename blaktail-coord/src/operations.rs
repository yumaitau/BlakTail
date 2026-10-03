//! Protected operator health view (draft 23). Owner and auditor sessions read
//! component versions, schema state, relay reachability as this coordinator
//! sees it, webhook outbox depth, credential expiry counts and the operator's
//! last backup proof. Public `/livez` and `/readyz` stay narrow; this view
//! never returns key material, tokens, webhook URLs or relay secrets.

use crate::permissions::{require, Permission};
use crate::{console_session, now, ApiError, AppState, DatabaseBackend, CURRENT_SCHEMA_VERSION};
use axum::{
    extract::{Path as UrlPath, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};
use uuid::Uuid;

/// Bounds the work one health request can trigger.
const MAX_PROBED_RELAYS: usize = 16;
const RELAY_PROBE_TIMEOUT: Duration = Duration::from_millis(1_500);
const PROBE_CAPABILITY_SECS: u64 = 60;
const NODE_EXPIRY_WARNING_SECS: i64 = 14 * 86_400;
const CERT_EXPIRY_WARNING_SECS: i64 = 30 * 86_400;
const BACKUP_PROOF_ENV: &str = "BLAKTAIL_BACKUP_PROOF_FILE";
const MAX_BACKUP_PROOF_BYTES: u64 = 4 * 1024;

/// One advertised relay with the Australian region it is declared in.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct RelayEntry {
    pub(crate) endpoint: String,
    pub(crate) region: String,
    /// Approved `wss://` fallback served by the same relay (ADR 0004).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) wss: Option<String>,
}

/// Parses `coordinator.relays` in configured (priority) order. Untagged
/// entries inherit the coordinator's region; any entry whose region is not an
/// approved Australian identifier is dropped, so agents are never handed an
/// offshore fallback even if configuration validation was bypassed.
pub(crate) fn relay_directory(entries: &[String], coordinator_region: &str) -> Vec<RelayEntry> {
    let mut directory: Vec<RelayEntry> = Vec::new();
    for entry in entries {
        let (endpoint, region) = blaktail_config::split_relay_entry(entry);
        let region = region
            .unwrap_or(coordinator_region)
            .trim()
            .to_ascii_lowercase();
        if endpoint.is_empty() {
            continue;
        }
        if !blaktail_config::is_australian_region(&region) {
            tracing::error!(%endpoint, %region, "refusing to advertise a relay outside Australia");
            continue;
        }
        if directory.iter().any(|known| known.endpoint == endpoint) {
            continue;
        }
        directory.push(RelayEntry {
            endpoint: endpoint.to_owned(),
            region,
            wss: approved_wss(entry),
        });
    }
    directory
}

/// The entry's WSS fallback if it passes the HTTPS fallback origin policy
/// (`https_fallback::approved_endpoint`: TLS, `.au` host, no credentials).
/// A rejected URL drops only the fallback, never the UDP relay.
fn approved_wss(entry: &str) -> Option<String> {
    let url = blaktail_config::relay_entry_wss(entry)?;
    let as_https = url
        .strip_prefix("wss://")
        .map(|rest| format!("https://{rest}"));
    match as_https
        .as_deref()
        .map(crate::https_fallback::approved_endpoint)
    {
        Some(Ok(())) => Some(url.to_owned()),
        _ => {
            tracing::error!(%url, "refusing to advertise a relay WSS fallback outside approved AU HTTPS origins");
            None
        }
    }
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/v1/orgs/:org_id/operations/health", get(operations_health))
}

#[derive(Serialize)]
struct OperationsHealth {
    generated_at: i64,
    coordinator: CoordinatorComponent,
    schema: SchemaState,
    relays: Vec<RelayHealth>,
    webhooks: WebhookOutbox,
    expiry: ExpiryCounts,
    backup: BackupProof,
}

#[derive(Serialize)]
struct CoordinatorComponent {
    version: &'static str,
    region: String,
    database_backend: &'static str,
}

#[derive(Serialize)]
struct SchemaState {
    applied_version: i64,
    supported_version: i64,
    latest_migration: &'static str,
    status: &'static str,
}

#[derive(Serialize)]
struct RelayHealth {
    endpoint: String,
    region: String,
    /// "reachable", "unreachable", "unresolved", "not_probed".
    status: &'static str,
    round_trip_ms: Option<u64>,
}

#[derive(Serialize)]
struct WebhookOutbox {
    pending: i64,
    due_now: i64,
    dead_letters: i64,
    oldest_pending_age_seconds: Option<i64>,
}

#[derive(Serialize)]
struct ExpiryCounts {
    node_credentials_expired: i64,
    node_credentials_expiring_14_days: i64,
    service_certificates_expiring_30_days: i64,
    service_ca_expiring_30_days: i64,
    api_clients_expiring_14_days: i64,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub(crate) struct BackupProof {
    /// "recorded", "not_recorded" or "unreadable".
    status: &'static str,
    completed_at: Option<i64>,
    restore_verified_at: Option<i64>,
    label: Option<String>,
}

async fn operations_health(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<OperationsHealth>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewOperations)?;
    let current_time = now();
    let pool = &s.store.pool;
    let org = org_id.to_string();

    let applied_version = crate::schema_version(pool, s.store.backend)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let latest_migration = crate::MIGRATIONS
        .iter()
        .find(|migration| migration.version == applied_version)
        .map_or("unknown", |migration| migration.name);
    let schema = SchemaState {
        applied_version,
        supported_version: CURRENT_SCHEMA_VERSION,
        latest_migration,
        status: match applied_version.cmp(&CURRENT_SCHEMA_VERSION) {
            std::cmp::Ordering::Equal => "current",
            std::cmp::Ordering::Less => "behind",
            std::cmp::Ordering::Greater => "ahead",
        },
    };

    let count = |sql: &'static str, bind: i64| {
        let org = org.clone();
        async move {
            sqlx::query_scalar::<_, i64>(sql)
                .bind(org)
                .bind(bind)
                .fetch_one(pool)
                .await
        }
    };
    let webhooks = WebhookOutbox {
        pending: count(
            "SELECT COUNT(*) FROM webhook_outbox WHERE org_id=$1 AND delivered_at IS NULL AND dead_lettered_at IS NULL AND created_at<=$2",
            current_time,
        )
        .await?,
        due_now: count(
            "SELECT COUNT(*) FROM webhook_outbox WHERE org_id=$1 AND delivered_at IS NULL AND dead_lettered_at IS NULL AND next_attempt_at<=$2",
            current_time,
        )
        .await?,
        dead_letters: count(
            "SELECT COUNT(*) FROM webhook_outbox WHERE org_id=$1 AND dead_lettered_at IS NOT NULL AND dead_lettered_at<=$2",
            current_time,
        )
        .await?,
        oldest_pending_age_seconds: sqlx::query_scalar::<_, Option<i64>>(
            "SELECT MIN(created_at) FROM webhook_outbox WHERE org_id=$1 AND delivered_at IS NULL AND dead_lettered_at IS NULL",
        )
        .bind(&org)
        .fetch_one(pool)
        .await?
        .map(|oldest| (current_time - oldest).max(0)),
    };

    let expiry = ExpiryCounts {
        node_credentials_expired: count(
            "SELECT COUNT(*) FROM nodes WHERE org_id=$1 AND revoked_at IS NULL AND deleted_at IS NULL AND credential_expires_at>0 AND credential_expires_at<=$2",
            current_time,
        )
        .await?,
        node_credentials_expiring_14_days: count(
            "SELECT COUNT(*) FROM nodes WHERE org_id=$1 AND revoked_at IS NULL AND deleted_at IS NULL AND credential_expires_at>$2 AND credential_expires_at<=$2+1209600",
            current_time,
        )
        .await?,
        service_certificates_expiring_30_days: count(
            "SELECT COUNT(*) FROM service_certificates WHERE org_id=$1 AND revoked_at IS NULL AND not_after<=$2",
            current_time + CERT_EXPIRY_WARNING_SECS,
        )
        .await?,
        service_ca_expiring_30_days: count(
            "SELECT COUNT(*) FROM service_cas WHERE org_id=$1 AND not_after<=$2",
            current_time + CERT_EXPIRY_WARNING_SECS,
        )
        .await?,
        api_clients_expiring_14_days: count(
            "SELECT COUNT(*) FROM api_clients WHERE org_id=$1 AND revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at<=$2",
            current_time + NODE_EXPIRY_WARNING_SECS,
        )
        .await?,
    };

    let relays = probe_relays(&s).await;
    let backup = read_backup_proof(std::env::var_os(BACKUP_PROOF_ENV).as_deref().map(Path::new));

    Ok(Json(OperationsHealth {
        generated_at: current_time,
        coordinator: CoordinatorComponent {
            version: env!("CARGO_PKG_VERSION"),
            region: s.region.as_str().to_owned(),
            database_backend: match s.store.backend {
                DatabaseBackend::Sqlite => "sqlite",
                DatabaseBackend::Postgres => "postgres",
            },
        },
        schema,
        relays,
        webhooks,
        expiry,
        backup,
    }))
}

/// Authenticated REGISTER+PING to each advertised relay with a throwaway
/// probe identity and a sixty-second capability. Proves the relay is up,
/// shares this coordinator's relay secret and is reachable from here; it
/// does not prove reachability from any agent's network.
async fn probe_relays(s: &AppState) -> Vec<RelayHealth> {
    let mut probes = tokio::task::JoinSet::new();
    for (index, relay) in s.relay_directory.iter().enumerate() {
        if index >= MAX_PROBED_RELAYS || s.relay_auth_secret.is_empty() {
            continue;
        }
        let endpoint = relay.endpoint.clone();
        let secret = s.relay_auth_secret.clone();
        probes.spawn(async move {
            let Some(address) = tokio::net::lookup_host(&endpoint)
                .await
                .ok()
                .and_then(|mut addresses| addresses.next())
            else {
                return (index, "unresolved", None);
            };
            let probe_id = *Uuid::new_v4().as_bytes();
            let expires_at = now().max(0) as u64 + PROBE_CAPABILITY_SECS;
            let token = blaktail_relay::mint_token(&secret, &probe_id, expires_at);
            let started = std::time::Instant::now();
            match blaktail_relay::probe(address, &probe_id, expires_at, &token, RELAY_PROBE_TIMEOUT)
                .await
            {
                Ok(_) => (
                    index,
                    "reachable",
                    Some(started.elapsed().as_millis() as u64),
                ),
                Err(_) => (index, "unreachable", None),
            }
        });
    }
    let mut results: Vec<RelayHealth> = s
        .relay_directory
        .iter()
        .map(|relay| RelayHealth {
            endpoint: relay.endpoint.clone(),
            region: relay.region.clone(),
            status: "not_probed",
            round_trip_ms: None,
        })
        .collect();
    while let Some(Ok((index, status, round_trip_ms))) = probes.join_next().await {
        results[index].status = status;
        results[index].round_trip_ms = round_trip_ms;
    }
    results
}

#[derive(Deserialize)]
struct BackupMarker {
    completed_at: i64,
    #[serde(default)]
    restore_verified_at: Option<i64>,
    #[serde(default)]
    label: Option<String>,
}

/// Reads the operator-written backup marker. Only timestamps and a short
/// printable label are returned; locations, bucket names and keys are not.
pub(crate) fn read_backup_proof(path: Option<&Path>) -> BackupProof {
    let empty = |status| BackupProof {
        status,
        completed_at: None,
        restore_verified_at: None,
        label: None,
    };
    let Some(path) = path else {
        return empty("not_recorded");
    };
    let Ok(metadata) = std::fs::metadata(path) else {
        return empty("not_recorded");
    };
    if !metadata.is_file() || metadata.len() > MAX_BACKUP_PROOF_BYTES {
        return empty("unreadable");
    }
    let Some(marker) = std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<BackupMarker>(&bytes).ok())
        .filter(|marker| marker.completed_at > 0)
    else {
        return empty("unreadable");
    };
    BackupProof {
        status: "recorded",
        completed_at: Some(marker.completed_at),
        restore_verified_at: marker.restore_verified_at.filter(|at| *at > 0),
        label: marker
            .label
            .map(|label| {
                label
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || " ._-".contains(*c))
                    .take(80)
                    .collect::<String>()
            })
            .filter(|label| !label.trim().is_empty()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_directory_keeps_order_and_drops_offshore_entries() {
        let entries = vec![
            "relay-a.example:3478#australiaeast".to_owned(),
            "relay-b.example:3478".to_owned(),
            "relay-c.example:3478#us-east-1".to_owned(),
            "relay-b.example:3478#ap-southeast-2".to_owned(),
        ];
        assert_eq!(
            relay_directory(&entries, "ap-southeast-2"),
            vec![
                RelayEntry {
                    endpoint: "relay-a.example:3478".into(),
                    region: "australiaeast".into(),
                    wss: None,
                },
                RelayEntry {
                    endpoint: "relay-b.example:3478".into(),
                    region: "ap-southeast-2".into(),
                    wss: None,
                },
            ]
        );
        // An offshore coordinator region never vouches for untagged relays.
        assert!(relay_directory(&entries[1..2], "us-east-1").is_empty());
    }

    #[test]
    fn relay_directory_hands_out_only_approved_wss_fallbacks() {
        let entries = vec![
            "relay-a.example:3478#australiaeast;wss=wss://relay-a.example.org.au/v1/relay"
                .to_owned(),
            "relay-b.example:3478;wss=wss://relay-b.example.com/v1/relay".to_owned(),
            "relay-c.example:3478;wss=wss://user:pw@relay-c.example.au/v1/relay".to_owned(),
            "relay-d.example:3478#us-east-1;wss=wss://relay-d.example.au/v1/relay".to_owned(),
        ];
        let directory = relay_directory(&entries, "ap-southeast-2");
        assert_eq!(
            directory
                .iter()
                .map(|entry| (entry.endpoint.as_str(), entry.wss.as_deref()))
                .collect::<Vec<_>>(),
            vec![
                (
                    "relay-a.example:3478",
                    Some("wss://relay-a.example.org.au/v1/relay")
                ),
                // Non-AU and credential-bearing URLs drop the fallback only.
                ("relay-b.example:3478", None),
                ("relay-c.example:3478", None),
            ]
        );
        let json = serde_json::to_value(&directory).unwrap();
        assert!(json[1].get("wss").is_none());
    }

    #[test]
    fn backup_proof_reports_only_timestamps_and_a_safe_label() {
        assert_eq!(read_backup_proof(None).status, "not_recorded");
        let dir = std::env::temp_dir().join(format!("blaktail-backup-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("last-backup.json");
        assert_eq!(read_backup_proof(Some(&marker)).status, "not_recorded");
        std::fs::write(&marker, "not json").unwrap();
        assert_eq!(read_backup_proof(Some(&marker)).status, "unreadable");
        std::fs::write(
            &marker,
            r#"{"completed_at":1790000000,"restore_verified_at":1790003600,"label":"nightly <script>s3://bucket?key=secret","location":"s3://private"}"#,
        )
        .unwrap();
        let proof = read_backup_proof(Some(&marker));
        assert_eq!(proof.status, "recorded");
        assert_eq!(proof.completed_at, Some(1_790_000_000));
        assert_eq!(proof.restore_verified_at, Some(1_790_003_600));
        let label = proof.label.unwrap();
        assert!(!label.contains(['<', '?', '=', ':', '/']));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
