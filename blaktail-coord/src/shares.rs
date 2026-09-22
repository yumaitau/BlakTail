use crate::{ApiError, Store};
use serde::{Deserialize, Serialize};
use sqlx::{AnyPool, Row};
use std::collections::BTreeSet;
use uuid::Uuid;

pub const DEFAULT_SHARE_PORT: u16 = 5647;
const MAX_SHARES: usize = 4;
const MAX_LABEL_LEN: usize = 32;
const MAX_PATH_LEN: usize = 512;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeShare {
    pub label: String,
    pub path: String,
    #[serde(default = "default_share_port")]
    pub port: u16,
    #[serde(default = "default_true")]
    pub read_only: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishedShare {
    pub node_id: Uuid,
    pub dns_name: String,
    pub label: String,
    pub port: u16,
    pub read_only: bool,
}

fn default_share_port() -> u16 {
    DEFAULT_SHARE_PORT
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareUpdate {
    pub shares: Vec<NodeShare>,
}

pub fn parse_shares(json: &str) -> Vec<NodeShare> {
    if json.trim().is_empty() {
        return Vec::new();
    }
    serde_json::from_str(json).unwrap_or_default()
}

pub fn canonicalise(shares: Vec<NodeShare>) -> Result<Vec<NodeShare>, ApiError> {
    if shares.len() > MAX_SHARES {
        return Err(ApiError::BadRequest(format!(
            "a node may publish at most {MAX_SHARES} shares"
        )));
    }
    let mut canonical = Vec::new();
    let mut labels = BTreeSet::new();
    let mut ports = BTreeSet::new();
    for share in shares {
        let label = canonical_label(&share.label)?;
        if !labels.insert(label.clone()) {
            return Err(ApiError::BadRequest(format!(
                "duplicate share label {label}"
            )));
        }
        if !(1024..=65535).contains(&share.port) {
            return Err(ApiError::BadRequest(
                "share port must be between 1024 and 65535".into(),
            ));
        }
        let path = share.path.trim();
        if path.is_empty()
            || path.len() > MAX_PATH_LEN
            || !path.starts_with('/')
            || path.contains('\0')
            || path.split('/').any(|part| part == "..")
        {
            return Err(ApiError::BadRequest(
                "share path must be an absolute directory without parent segments".into(),
            ));
        }
        ports.insert(share.port);
        canonical.push(NodeShare {
            label,
            path: path.to_owned(),
            port: share.port,
            read_only: share.read_only,
            enabled: share.enabled,
        });
    }
    if ports.len() > 1 {
        return Err(ApiError::BadRequest(
            "all shares on a node must use the same TCP port".into(),
        ));
    }
    Ok(canonical)
}

pub fn published(node_id: Uuid, dns_name: &str, shares: &[NodeShare]) -> Vec<PublishedShare> {
    shares
        .iter()
        .filter(|share| share.enabled)
        .map(|share| PublishedShare {
            node_id,
            dns_name: dns_name.to_owned(),
            label: share.label.clone(),
            port: share.port,
            read_only: share.read_only,
        })
        .collect()
}

pub fn grant_share_ports(
    tcp: &mut Vec<String>,
    deny_tcp: &[String],
    all: bool,
    shares: &[NodeShare],
) {
    if all {
        return;
    }
    for share in shares.iter().filter(|share| share.enabled) {
        let port = share.port.to_string();
        if deny_tcp.iter().any(|denied| denied == &port) {
            continue;
        }
        if !tcp.iter().any(|existing| existing == &port) {
            tcp.push(port);
        }
    }
}

pub async fn load_published(
    pool: &AnyPool,
    org_id: &str,
    node_ids: &BTreeSet<Uuid>,
) -> Result<Vec<PublishedShare>, ApiError> {
    if node_ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        "SELECT id,dns_name,shares_json FROM nodes WHERE org_id=$1 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;
    let mut published_shares = Vec::new();
    for row in rows {
        let id =
            Uuid::parse_str(&row.try_get::<String, _>(0)?).map_err(|_| ApiError::CorruptData)?;
        if !node_ids.contains(&id) {
            continue;
        }
        let dns_name: String = row.try_get(1)?;
        let shares = parse_shares(&row.try_get::<String, _>(2).unwrap_or_else(|_| "[]".into()));
        published_shares.extend(published(id, &dns_name, &shares));
    }
    Ok(published_shares)
}

pub async fn dns_applied_counts(
    store: &Store,
    org_id: Uuid,
    revision: i64,
) -> Result<(i64, i64), ApiError> {
    let enrolled: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM nodes WHERE org_id=$1 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(org_id.to_string())
    .fetch_one(&store.pool)
    .await?;
    let applied: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM nodes WHERE org_id=$1 AND revoked_at IS NULL AND deleted_at IS NULL AND dns_applied_revision=$2",
    )
    .bind(org_id.to_string())
    .bind(revision)
    .fetch_one(&store.pool)
    .await?;
    Ok((applied.max(0), enrolled.max(0)))
}

fn canonical_label(label: &str) -> Result<String, ApiError> {
    let label = label.trim().to_ascii_lowercase();
    if label.is_empty()
        || label.len() > MAX_LABEL_LEN
        || label.starts_with('-')
        || label.ends_with('-')
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(ApiError::BadRequest(
            "share name must be 1-32 letters, digits, or hyphens".into(),
        ));
    }
    Ok(label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalise_normalises_and_rejects_escapes() {
        let shares = canonicalise(vec![NodeShare {
            label: "Files".into(),
            path: "/srv/shared".into(),
            port: DEFAULT_SHARE_PORT,
            read_only: true,
            enabled: true,
        }])
        .unwrap();
        assert_eq!(shares[0].label, "files");
        assert!(canonicalise(vec![NodeShare {
            label: "files".into(),
            path: "/srv/../etc".into(),
            port: DEFAULT_SHARE_PORT,
            read_only: true,
            enabled: true,
        }])
        .is_err());
        let writable = canonicalise(vec![NodeShare {
            label: "files".into(),
            path: "/srv/shared".into(),
            port: DEFAULT_SHARE_PORT,
            read_only: false,
            enabled: true,
        }])
        .unwrap();
        assert!(!writable[0].read_only);
    }
}
