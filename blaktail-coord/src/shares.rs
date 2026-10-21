use crate::{ApiError, Store};
use serde::{Deserialize, Serialize};
use sqlx::{AnyPool, Row};
use std::collections::{BTreeMap, BTreeSet};
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
    /// `ro` or `rw` once a drive policy is in force. Absent means the
    /// pre-policy rule: the share's own read-only flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
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
        if !acceptable_share_path(path) {
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
            access: None,
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
    if !valid_share_label(&label) {
        return Err(ApiError::BadRequest(
            "share name must be 1-32 letters, digits, hyphens, underscores, parentheses, or spaces"
                .into(),
        ));
    }
    Ok(label)
}

fn valid_share_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL_LEN
        && !label.starts_with('-')
        && !label.ends_with('-')
        && !label.starts_with(' ')
        && !label.ends_with(' ')
        && label.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'(' | b')' | b' ')
        })
}

/// Unix absolute path, or a Windows drive path including the `\\?\` canonical form.
fn acceptable_share_path(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_PATH_LEN || path.contains('\0') {
        return false;
    }
    let stripped = path
        .strip_prefix(r"\\?\")
        .or_else(|| path.strip_prefix("//?/"))
        .unwrap_or(path);
    let unix = stripped.starts_with('/');
    let windows = stripped.len() >= 3
        && stripped.as_bytes()[0].is_ascii_alphabetic()
        && stripped.as_bytes()[1] == b':'
        && matches!(stripped.as_bytes()[2], b'\\' | b'/');
    if !unix && !windows {
        return false;
    }
    !stripped
        .split(['/', '\\'])
        .any(|part| part == ".." || part.contains('\0'))
}

/// Who may publish folders, who may open the local browser, and which
/// shares each source may read or write. Absent on an organisation means
/// the earlier rule: any peer the network policy can already reach.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrivePolicy {
    /// `*`, a role (`owner`, `admin`, `member`, `network_admin`, `auditor`),
    /// `tag:office`, or `group:name`.
    #[serde(default)]
    pub share: Vec<String>,
    #[serde(default)]
    pub access: Vec<String>,
    #[serde(default)]
    pub grants: Vec<DriveGrant>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriveGrant {
    #[serde(default)]
    pub src_roles: Vec<String>,
    #[serde(default)]
    pub src_tags: Vec<String>,
    #[serde(default)]
    pub src_groups: Vec<String>,
    #[serde(default)]
    pub dst_roles: Vec<String>,
    #[serde(default)]
    pub dst_tags: Vec<String>,
    #[serde(default)]
    pub dst_groups: Vec<String>,
    /// Source and destination must be the same person.
    #[serde(default)]
    pub same_user: bool,
    pub shares: Vec<String>,
    /// `ro` or `rw`.
    pub access: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DriveView {
    pub access: bool,
    pub share: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local: Vec<DriveGrantShare>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callers: Vec<DriveCaller>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DriveGrantShare {
    pub label: String,
    pub access: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DriveCaller {
    pub address: String,
    pub label: String,
    pub access: String,
}

#[derive(Clone, Debug)]
pub struct DriveActor {
    pub role: String,
    pub tags: Vec<String>,
    pub user_id: String,
    pub email: String,
}

const DRIVE_ROLES: &[&str] = &["owner", "admin", "member", "network_admin", "auditor"];
const DRIVE_TAGS: &[&str] = &["office", "ranger", "store"];

pub fn validate_policy(
    policy: &DrivePolicy,
    groups: &BTreeMap<String, Vec<String>>,
) -> Result<(), ApiError> {
    if policy.share.is_empty() || policy.access.is_empty() {
        return Err(ApiError::BadRequest(
            "drive policy must say who can share and who can access shared folders".into(),
        ));
    }
    if policy.grants.len() > 64 {
        return Err(ApiError::BadRequest(
            "drive policy is limited to 64 grants".into(),
        ));
    }
    for selector in policy.share.iter().chain(policy.access.iter()) {
        check_actor_selector(selector, groups)?;
    }
    for grant in &policy.grants {
        let selected = !grant.src_roles.is_empty()
            || !grant.src_tags.is_empty()
            || !grant.src_groups.is_empty()
            || !grant.dst_roles.is_empty()
            || !grant.dst_tags.is_empty()
            || !grant.dst_groups.is_empty()
            || grant.same_user;
        if !selected {
            return Err(ApiError::BadRequest(
                "drive grant must select a source, a destination, or the same person".into(),
            ));
        }
        if grant.shares.is_empty() || grant.shares.len() > 32 {
            return Err(ApiError::BadRequest(
                "drive grant must name 1-32 shares, or *".into(),
            ));
        }
        for name in &grant.shares {
            if name != "*" {
                canonical_label(name)?;
            }
        }
        if grant.access != "ro" && grant.access != "rw" {
            return Err(ApiError::BadRequest(
                "drive grant access must be ro or rw".into(),
            ));
        }
        for name in grant.src_groups.iter().chain(grant.dst_groups.iter()) {
            if !groups.contains_key(name) {
                return Err(ApiError::BadRequest(format!(
                    "drive grant refers to unknown group {name}"
                )));
            }
        }
        for role in grant.src_roles.iter().chain(grant.dst_roles.iter()) {
            if !DRIVE_ROLES.contains(&role.as_str()) {
                return Err(ApiError::BadRequest(format!(
                    "drive grant role {role} is not a known role"
                )));
            }
        }
        for tag in grant.src_tags.iter().chain(grant.dst_tags.iter()) {
            if !DRIVE_TAGS.contains(&tag.as_str()) {
                return Err(ApiError::BadRequest(format!(
                    "drive grant tag {tag} is not a known tag"
                )));
            }
        }
    }
    Ok(())
}

fn check_actor_selector(
    selector: &str,
    groups: &BTreeMap<String, Vec<String>>,
) -> Result<(), ApiError> {
    let selector = selector.trim();
    if selector == "*" || DRIVE_ROLES.contains(&selector) {
        return Ok(());
    }
    if let Some(tag) = selector.strip_prefix("tag:") {
        if DRIVE_TAGS.contains(&tag) {
            return Ok(());
        }
        return Err(ApiError::BadRequest(format!(
            "drive selector {selector} is not a known tag"
        )));
    }
    if let Some(group) = selector.strip_prefix("group:") {
        if groups.contains_key(group) {
            return Ok(());
        }
        return Err(ApiError::BadRequest(format!(
            "drive selector {selector} is not a known group"
        )));
    }
    Err(ApiError::BadRequest(format!(
        "drive selector {selector} must be *, a role, tag:name, or group:name"
    )))
}

pub fn actor_permitted(
    selectors: &[String],
    actor: &DriveActor,
    groups: &BTreeMap<String, Vec<String>>,
) -> bool {
    selectors.iter().any(|selector| {
        let selector = selector.trim();
        if selector == "*" {
            return true;
        }
        if let Some(tag) = selector.strip_prefix("tag:") {
            return actor
                .tags
                .iter()
                .any(|have| have.eq_ignore_ascii_case(tag.trim()));
        }
        if let Some(group) = selector.strip_prefix("group:") {
            return groups
                .get(group.trim())
                .is_some_and(|members| actor_in_group(actor, members));
        }
        selector.eq_ignore_ascii_case(actor.role.trim())
    })
}

fn actor_in_group(actor: &DriveActor, members: &[String]) -> bool {
    members.iter().any(|member| {
        let member = member.trim();
        if member.is_empty() {
            return false;
        }
        (!actor.user_id.is_empty() && member.eq_ignore_ascii_case(actor.user_id.trim()))
            || (!actor.email.is_empty() && member.eq_ignore_ascii_case(actor.email.trim()))
    })
}

/// `Some("ro"|"rw")` when a grant matches. `None` when this source may not
/// see the share. A read-only share caps `rw` at `ro`.
pub fn grant_access(
    policy: &DrivePolicy,
    groups: &BTreeMap<String, Vec<String>>,
    source: &DriveActor,
    destination: &DriveActor,
    label: &str,
    read_only: bool,
) -> Option<&'static str> {
    let mut writable = false;
    let mut readable = false;
    for grant in &policy.grants {
        if !grant_matches(grant, groups, source, destination, label) {
            continue;
        }
        readable = true;
        writable |= grant.access == "rw";
    }
    if !readable {
        return None;
    }
    if writable && !read_only {
        Some("rw")
    } else {
        Some("ro")
    }
}

fn grant_matches(
    grant: &DriveGrant,
    groups: &BTreeMap<String, Vec<String>>,
    source: &DriveActor,
    destination: &DriveActor,
    label: &str,
) -> bool {
    if grant.same_user
        && (source.user_id.is_empty()
            || !source
                .user_id
                .eq_ignore_ascii_case(destination.user_id.trim()))
    {
        return false;
    }
    if !side_matches(
        &grant.src_roles,
        &grant.src_tags,
        &grant.src_groups,
        source,
        groups,
    ) || !side_matches(
        &grant.dst_roles,
        &grant.dst_tags,
        &grant.dst_groups,
        destination,
        groups,
    ) {
        return false;
    }
    grant.shares.iter().any(|name| {
        name == "*"
            || canonical_label(name)
                .ok()
                .is_some_and(|canonical| canonical == label)
    })
}

fn side_matches(
    roles: &[String],
    tags: &[String],
    group_names: &[String],
    actor: &DriveActor,
    groups: &BTreeMap<String, Vec<String>>,
) -> bool {
    (roles.is_empty()
        || roles
            .iter()
            .any(|role| role.eq_ignore_ascii_case(&actor.role)))
        && (tags.is_empty()
            || tags
                .iter()
                .any(|tag| actor.tags.iter().any(|have| have.eq_ignore_ascii_case(tag))))
        && (group_names.is_empty()
            || group_names.iter().any(|name| {
                groups
                    .get(name)
                    .is_some_and(|members| actor_in_group(actor, members))
            }))
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
        let spaced = canonicalise(vec![NodeShare {
            label: " Company Docs ".into(),
            path: r"C:\Shared\Docs".into(),
            port: DEFAULT_SHARE_PORT,
            read_only: true,
            enabled: true,
        }])
        .unwrap();
        assert_eq!(spaced[0].label, "company docs");
        assert!(canonicalise(vec![NodeShare {
            label: "bad/name".into(),
            path: "/srv/shared".into(),
            port: DEFAULT_SHARE_PORT,
            read_only: true,
            enabled: true,
        }])
        .is_err());
    }

    #[test]
    fn drive_grant_caps_read_only_and_same_user() {
        let policy = DrivePolicy {
            share: vec!["*".into()],
            access: vec!["*".into()],
            grants: vec![
                DriveGrant {
                    src_roles: vec![],
                    src_tags: vec![],
                    src_groups: vec![],
                    dst_roles: vec![],
                    dst_tags: vec!["store".into()],
                    dst_groups: vec![],
                    same_user: false,
                    shares: vec!["company-docs".into()],
                    access: "ro".into(),
                },
                DriveGrant {
                    src_roles: vec![],
                    src_tags: vec![],
                    src_groups: vec![],
                    dst_roles: vec![],
                    dst_tags: vec![],
                    dst_groups: vec![],
                    same_user: true,
                    shares: vec!["*".into()],
                    access: "rw".into(),
                },
            ],
        };
        let groups = BTreeMap::new();
        validate_policy(&policy, &groups).unwrap();
        let member = DriveActor {
            role: "member".into(),
            tags: vec!["office".into()],
            user_id: "alice".into(),
            email: String::new(),
        };
        let store = DriveActor {
            role: "member".into(),
            tags: vec!["store".into()],
            user_id: "bob".into(),
            email: String::new(),
        };
        assert_eq!(
            grant_access(&policy, &groups, &member, &store, "company-docs", false),
            Some("ro")
        );
        assert_eq!(
            grant_access(&policy, &groups, &member, &store, "other", false),
            None
        );
        assert_eq!(
            grant_access(&policy, &groups, &member, &member, "notes", true),
            Some("ro")
        );
        assert_eq!(
            grant_access(&policy, &groups, &member, &store, "notes", false),
            None
        );
        let mut wide = policy.clone();
        wide.grants[1].access = "rw".into();
        assert_eq!(
            grant_access(&wide, &groups, &member, &member, "notes", false),
            Some("rw")
        );
    }
}
