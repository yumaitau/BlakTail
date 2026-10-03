//! Versioned per-organisation posture checks (draft 08).
//!
//! Policy `allow` rules and SSH `allow`/`check` rules name checks in
//! `posture`. The peer-map compiler evaluates them against coordinator
//! observed state and agent-reported inventory for the source device. The
//! inventory is self-reported by the device's own node token: it is a
//! hygiene signal, not attestation, and the API says so.

use crate::{
    append_audit, bump_control_revision, canonical_capabilities, console_session,
    normalise_inventory_text, now,
    permissions::{require, Permission},
    valid_acl_group_name, Acl, ApiError, AppState, DeviceTag, Role, Session, Store, Subject,
};
use axum::{
    extract::{Path as UrlPath, State},
    http::{HeaderMap, StatusCode},
    routing::{get, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use uuid::Uuid;

/// Destination installs the inbound overlay filter compiled from `ingress`.
pub(crate) const CAP_ACL_FILTER: &str = "acl-filter";
/// Destination verified that sshd enforces per-source `AllowUsers` /
/// `DenyUsers`. Without it the coordinator keeps user-limited SSH closed.
pub(crate) const CAP_SSH_USERS: &str = "ssh-users";

const MAX_CHECKS_PER_ORG: i64 = 32;
const MIN_AGE_SECS: i64 = 60;
const MAX_AGE_SECS: i64 = 365 * 24 * 60 * 60;
const OS_FAMILIES: &[&str] = &["linux", "macos", "ios", "android", "windows"];
pub(crate) const SELF_REPORTED_NOTICE: &str = "Operating system, OS version, agent version and capabilities are reported by the device itself. They are hygiene signals, not attestation, and must not be treated as compliance evidence.";

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum MissingData {
    #[default]
    Fail,
    Pass,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PostureDefinition {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) min_agent_version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) os_families: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) min_os_versions: BTreeMap<String, String>,
    /// Maximum seconds since the device credential was last issued
    /// (enrolment or `reauth`), observed by the coordinator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_credential_age_secs: Option<i64>,
    /// Agent-reported inventory older than this counts as missing data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_report_age_secs: Option<i64>,
    /// Device must be active: not revoked, removed or credential-expired.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) require_approved_peer: bool,
    /// What a check does when the data it needs is missing or stale.
    #[serde(default)]
    pub(crate) on_missing_data: MissingData,
    /// Signal from one of this organisation's MDM/EDR integrations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) integration: Option<crate::posture_integrations::IntegrationRequirement>,
}

impl PostureDefinition {
    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        let bad = |message: &str| Err(ApiError::BadRequest(message.into()));
        if self.description.chars().count() > 200 || self.description.chars().any(char::is_control)
        {
            return bad("posture description must be at most 200 printable characters");
        }
        if self.min_agent_version.is_none()
            && self.os_families.is_empty()
            && self.min_os_versions.is_empty()
            && self.max_credential_age_secs.is_none()
            && !self.require_approved_peer
            && self.integration.is_none()
        {
            return bad("posture check must set at least one requirement");
        }
        if let Some(requirement) = &self.integration {
            requirement.validate()?;
        }
        if let Some(version) = &self.min_agent_version {
            if parse_version(version).is_none() {
                return bad("min_agent_version must look like 1.2.3");
            }
        }
        for family in self.os_families.iter().chain(self.min_os_versions.keys()) {
            if !OS_FAMILIES.contains(&family.as_str()) {
                return Err(ApiError::BadRequest(format!(
                    "unknown OS family {family:?}; use one of {}",
                    OS_FAMILIES.join(", ")
                )));
            }
        }
        if self
            .min_os_versions
            .values()
            .any(|v| parse_version(v).is_none())
        {
            return bad("min_os_versions values must look like 14.2");
        }
        for age in [self.max_credential_age_secs, self.max_report_age_secs]
            .into_iter()
            .flatten()
        {
            if !(MIN_AGE_SECS..=MAX_AGE_SECS).contains(&age) {
                return bad("posture ages must be 60-31536000 seconds");
            }
        }
        Ok(())
    }
}

/// Parses `1.2.3`, `v14.2` or `0.1.0-beta` into numeric components.
pub(crate) fn parse_version(value: &str) -> Option<Vec<u64>> {
    let value = value.trim().trim_start_matches('v');
    let core = value.split(['-', '+', ' ']).next()?;
    let parts = core
        .split('.')
        .map(|part| part.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;
    (!parts.is_empty() && parts.len() <= 4).then_some(parts)
}

fn version_at_least(found: &[u64], minimum: &[u64]) -> bool {
    let len = found.len().max(minimum.len());
    let pad = |v: &[u64]| {
        let mut v = v.to_vec();
        v.resize(len, 0);
        v
    };
    pad(found) >= pad(minimum)
}

#[derive(Clone, Debug)]
pub(crate) struct NodeFacts {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) display_name: Option<String>,
    pub(crate) user_id: String,
    pub(crate) role: Role,
    pub(crate) tags: Vec<DeviceTag>,
    pub(crate) os: Option<String>,
    pub(crate) os_version: Option<String>,
    pub(crate) agent_version: Option<String>,
    pub(crate) capabilities: Vec<String>,
    pub(crate) created_at: i64,
    pub(crate) credential_issued_at: Option<i64>,
    pub(crate) credential_expires_at: i64,
    pub(crate) inventory_reported_at: Option<i64>,
    /// This organisation's integration signals, keyed by integration id.
    pub(crate) integrations: BTreeMap<String, crate::posture_integrations::IntegrationFact>,
}

impl NodeFacts {
    pub(crate) fn issued_at(&self) -> i64 {
        self.credential_issued_at.unwrap_or(self.created_at)
    }
    fn reported_at(&self) -> i64 {
        self.inventory_reported_at.unwrap_or(self.created_at)
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Reason {
    pub(crate) text: String,
    /// `agent_reported` (not attested), `coordinator_observed` or
    /// `provider_reported` (an MDM/EDR integration).
    pub(crate) source: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Assessment {
    pub(crate) check: String,
    pub(crate) version: i64,
    pub(crate) passed: bool,
    pub(crate) missing_data: bool,
    pub(crate) reasons: Vec<Reason>,
    /// When a passing result will next lapse without any new event.
    pub(crate) expires_at: Option<i64>,
}

const AGENT: &str = "agent_reported";
const COORD: &str = "coordinator_observed";

pub(crate) fn evaluate(
    name: &str,
    version: i64,
    def: &PostureDefinition,
    facts: &NodeFacts,
    now: i64,
) -> Assessment {
    let mut failures = Vec::new();
    let mut missing = Vec::new();
    let mut passes = Vec::new();
    let mut deadline: Option<i64> = None;
    let mut lapse = |at: i64| deadline = Some(deadline.map_or(at, |d| d.min(at)));

    if def.require_approved_peer {
        if facts.credential_expires_at <= now {
            failures.push(Reason {
                text: "device credential has expired".into(),
                source: COORD,
            });
        } else {
            passes.push(Reason {
                text: "device is active with an unexpired credential".into(),
                source: COORD,
            });
            lapse(facts.credential_expires_at);
        }
    }
    if let Some(max) = def.max_credential_age_secs {
        let age = now.saturating_sub(facts.issued_at());
        if age > max {
            failures.push(Reason {
                text: format!("credential last issued {age}s ago; check allows {max}s"),
                source: COORD,
            });
        } else {
            passes.push(Reason {
                text: format!("credential issued {age}s ago (limit {max}s)"),
                source: COORD,
            });
            lapse(facts.issued_at() + max);
        }
    }
    if let Some(requirement) = &def.integration {
        let outcome = crate::posture_integrations::assess(
            requirement,
            facts
                .integrations
                .get(&requirement.integration_id.to_string()),
            now,
        );
        let reason = Reason {
            text: outcome.reason,
            source: crate::posture_integrations::PROVIDER_SOURCE,
        };
        if outcome.passed {
            passes.push(reason);
            if let Some(at) = outcome.lapse {
                lapse(at);
            }
        } else {
            failures.push(reason);
        }
    }
    let stale = def.max_report_age_secs.and_then(|max| {
        let age = now.saturating_sub(facts.reported_at());
        if age > max {
            Some(format!(
                "agent inventory last reported {age}s ago, older than {max}s"
            ))
        } else {
            lapse(facts.reported_at() + max);
            None
        }
    });
    let reported = |value: &Option<String>, label: &str, missing: &mut Vec<Reason>| {
        if let Some(reason) = &stale {
            missing.push(Reason {
                text: format!("{label}: {reason}"),
                source: AGENT,
            });
            return None;
        }
        match value.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
            Some(value) => Some(value.to_ascii_lowercase()),
            None => {
                missing.push(Reason {
                    text: format!("{label} was not reported"),
                    source: AGENT,
                });
                None
            }
        }
    };
    let needs_os = !def.os_families.is_empty() || !def.min_os_versions.is_empty();
    let os = if needs_os {
        reported(&facts.os, "operating system", &mut missing)
    } else {
        None
    };
    if let Some(os) = &os {
        if !def.os_families.is_empty() {
            if def.os_families.iter().any(|family| family == os) {
                passes.push(Reason {
                    text: format!("operating system {os} is allowed"),
                    source: AGENT,
                });
            } else {
                failures.push(Reason {
                    text: format!(
                        "operating system {os} is not one of {}",
                        def.os_families.join(", ")
                    ),
                    source: AGENT,
                });
            }
        }
        if let Some(minimum) = def.min_os_versions.get(os) {
            match reported(&facts.os_version, "OS version", &mut missing)
                .as_deref()
                .and_then(parse_version)
            {
                Some(found)
                    if version_at_least(&found, &parse_version(minimum).unwrap_or_default()) =>
                {
                    passes.push(Reason {
                        text: format!("{os} version meets {minimum}"),
                        source: AGENT,
                    })
                }
                Some(_) => failures.push(Reason {
                    text: format!(
                        "{os} version {} is older than {minimum}",
                        facts.os_version.as_deref().unwrap_or_default()
                    ),
                    source: AGENT,
                }),
                None if stale.is_none() && facts.os_version.is_some() => missing.push(Reason {
                    text: format!(
                        "OS version {:?} is not a comparable version",
                        facts.os_version.as_deref().unwrap_or_default()
                    ),
                    source: AGENT,
                }),
                None => {}
            }
        }
    }
    if let Some(minimum) = &def.min_agent_version {
        if let Some(found) = reported(&facts.agent_version, "agent version", &mut missing) {
            match parse_version(&found) {
                Some(parts)
                    if version_at_least(&parts, &parse_version(minimum).unwrap_or_default()) =>
                {
                    passes.push(Reason {
                        text: format!("agent {found} meets {minimum}"),
                        source: AGENT,
                    })
                }
                Some(_) => failures.push(Reason {
                    text: format!("agent {found} is older than {minimum}"),
                    source: AGENT,
                }),
                None => missing.push(Reason {
                    text: format!("agent version {found:?} is not a comparable version"),
                    source: AGENT,
                }),
            }
        }
    }

    let missing_data = !missing.is_empty();
    let passed = failures.is_empty() && (!missing_data || def.on_missing_data == MissingData::Pass);
    let mut reasons = failures;
    if missing_data {
        let policy = match def.on_missing_data {
            MissingData::Fail => "check fails closed on missing data",
            MissingData::Pass => "check is configured to pass on missing data",
        };
        reasons.extend(missing.into_iter().map(|reason| Reason {
            text: format!("{} ({policy})", reason.text),
            source: reason.source,
        }));
    }
    if passed {
        reasons.extend(passes);
    }
    Assessment {
        check: name.into(),
        version,
        passed,
        missing_data,
        reasons,
        expires_at: if passed { deadline } else { None },
    }
}

#[derive(Clone, Debug)]
pub(crate) struct StoredCheck {
    pub(crate) id: String,
    pub(crate) version: i64,
    pub(crate) definition: PostureDefinition,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
}

/// One organisation's checks and active-node facts, loaded once per compile.
pub(crate) struct PostureContext {
    pub(crate) checks: BTreeMap<String, StoredCheck>,
    pub(crate) facts: HashMap<Uuid, NodeFacts>,
    pub(crate) now: i64,
}

pub(crate) async fn load_checks(
    pool: &sqlx::AnyPool,
    org_id: &str,
) -> Result<BTreeMap<String, StoredCheck>, ApiError> {
    let rows = sqlx::query(
        "SELECT id,name,version,definition_json,created_at,updated_at FROM posture_checks WHERE org_id=$1 ORDER BY name",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            let name: String = row.try_get(1)?;
            let definition: PostureDefinition = serde_json::from_str(&row.try_get::<String, _>(3)?)
                .map_err(|_| ApiError::CorruptData)?;
            Ok((
                name,
                StoredCheck {
                    id: row.try_get(0)?,
                    version: row.try_get(2)?,
                    definition,
                    created_at: row.try_get(4)?,
                    updated_at: row.try_get(5)?,
                },
            ))
        })
        .collect()
}

pub(crate) async fn load_facts(
    pool: &sqlx::AnyPool,
    org_id: &str,
    node_id: Option<Uuid>,
) -> Result<Vec<NodeFacts>, ApiError> {
    let rows = sqlx::query(
        "SELECT id,name,display_name,user_id,user_role,tags_json,os,os_version,agent_version,capabilities_json,CAST(created_at AS BIGINT),credential_issued_at,credential_expires_at,inventory_reported_at FROM nodes WHERE org_id=$1 AND ($2='' OR id=$2) AND revoked_at IS NULL AND deleted_at IS NULL ORDER BY name",
    )
    .bind(org_id)
    .bind(node_id.map(|id| id.to_string()).unwrap_or_default())
    .fetch_all(pool)
    .await?;
    let mut facts = rows
        .into_iter()
        .map(|row| {
            Ok(NodeFacts {
                id: Uuid::parse_str(&row.try_get::<String, _>(0)?)
                    .map_err(|_| ApiError::CorruptData)?,
                name: row.try_get(1)?,
                display_name: row.try_get(2)?,
                user_id: row.try_get(3)?,
                role: row
                    .try_get::<String, _>(4)?
                    .parse()
                    .map_err(|_| ApiError::CorruptData)?,
                tags: serde_json::from_str(&row.try_get::<String, _>(5)?).unwrap_or_default(),
                os: row.try_get(6)?,
                os_version: row.try_get(7)?,
                agent_version: row.try_get(8)?,
                capabilities: serde_json::from_str(&row.try_get::<String, _>(9)?)
                    .unwrap_or_default(),
                created_at: row.try_get(10)?,
                credential_issued_at: row.try_get(11)?,
                credential_expires_at: row.try_get(12)?,
                inventory_reported_at: row.try_get(13)?,
                integrations: BTreeMap::new(),
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    crate::posture_integrations::attach(pool, org_id, &mut facts).await?;
    Ok(facts)
}

impl PostureContext {
    pub(crate) async fn load(pool: &sqlx::AnyPool, org_id: &str) -> Result<Self, ApiError> {
        Ok(Self {
            checks: load_checks(pool, org_id).await?,
            facts: load_facts(pool, org_id, None)
                .await?
                .into_iter()
                .map(|facts| (facts.id, facts))
                .collect(),
            now: now(),
        })
    }

    pub(crate) fn assess(&self, facts: &NodeFacts) -> Vec<Assessment> {
        self.checks
            .iter()
            .map(|(name, check)| evaluate(name, check.version, &check.definition, facts, self.now))
            .collect()
    }

    /// Fills the posture and authentication facts of a device subject. A
    /// node outside this organisation's active set passes nothing.
    pub(crate) fn apply(&self, node_id: Uuid, subject: &mut Subject) {
        let Some(facts) = self.facts.get(&node_id) else {
            return;
        };
        subject.authenticated_at = Some(facts.issued_at());
        subject.passed_posture = self
            .assess(facts)
            .into_iter()
            .filter(|assessment| assessment.passed)
            .map(|assessment| assessment.check)
            .collect();
    }

    /// Earliest future moment a compiled grant may lapse purely with time.
    pub(crate) fn next_deadline(&self, acl: &Acl) -> Option<i64> {
        let check_periods: BTreeSet<i64> = acl
            .ssh
            .iter()
            .filter(|rule| rule.action == crate::AclSshAction::Check)
            .map(|rule| {
                rule.check_period_secs
                    .unwrap_or(crate::DEFAULT_SSH_CHECK_PERIOD_SECS) as i64
            })
            .collect();
        let referenced = referenced_checks(acl);
        self.facts
            .values()
            .flat_map(|facts| {
                let mut times = Vec::new();
                for (name, check) in &self.checks {
                    if referenced.contains_key(name) {
                        let result =
                            evaluate(name, check.version, &check.definition, facts, self.now);
                        times.extend(result.expires_at);
                    }
                }
                times.extend(
                    check_periods
                        .iter()
                        .map(|period| facts.issued_at() + period),
                );
                times
            })
            .filter(|at| *at > self.now)
            .min()
    }
}

/// Map of posture check name to the policy locations that reference it.
pub(crate) fn referenced_checks(acl: &Acl) -> BTreeMap<String, Vec<String>> {
    let mut refs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (index, rule) in acl.rules.iter().enumerate() {
        for name in &rule.posture {
            refs.entry(name.clone())
                .or_default()
                .push(format!("rules[{index}]"));
        }
    }
    for (index, rule) in acl.ssh.iter().enumerate() {
        for name in &rule.posture {
            refs.entry(name.clone())
                .or_default()
                .push(format!("ssh[{index}]"));
        }
    }
    refs
}

/// Records inventory the node reports while polling and returns its current
/// capabilities. Any change bumps the control revision so other peers'
/// compiled grants follow.
pub(crate) async fn record_report(
    store: &Store,
    org_id: &str,
    node_id: Uuid,
    capabilities: Option<&str>,
    agent_version: Option<String>,
    os_version: Option<String>,
) -> Result<Vec<String>, ApiError> {
    let row = sqlx::query(
        "SELECT capabilities_json,agent_version,os_version,inventory_reported_at FROM nodes WHERE id=$1 AND org_id=$2",
    )
    .bind(node_id.to_string())
    .bind(org_id)
    .fetch_optional(&store.pool)
    .await?
    .ok_or(ApiError::Unauthorized)?;
    let current: Vec<String> =
        serde_json::from_str(&row.try_get::<String, _>(0)?).unwrap_or_default();
    let current_agent: Option<String> = row.try_get(1)?;
    let current_os: Option<String> = row.try_get(2)?;
    let reported_at: Option<i64> = row.try_get(3)?;
    if capabilities.is_none() && agent_version.is_none() && os_version.is_none() {
        return Ok(current);
    }
    let next_caps = capabilities
        .map(|value| {
            canonical_capabilities(value.split(',').map(str::to_owned).collect::<Vec<_>>())
        })
        .unwrap_or_else(|| current.clone());
    let next_agent = normalise_inventory_text(agent_version).or(current_agent.clone());
    let next_os = normalise_inventory_text(os_version).or(current_os.clone());
    let changed = next_caps != current || next_agent != current_agent || next_os != current_os;
    // Refresh the freshness stamp at most once a minute when nothing changed.
    if !changed && reported_at.is_some_and(|at| now() - at < 60) {
        return Ok(current);
    }
    let failing = if changed {
        match load_facts(&store.pool, org_id, Some(node_id))
            .await?
            .into_iter()
            .next()
        {
            Some(before) => {
                let mut after = before.clone();
                after.capabilities = next_caps.clone();
                after.agent_version = next_agent.clone();
                after.os_version = next_os.clone();
                after.inventory_reported_at = Some(now());
                crate::notifications::newly_failing_checks(store, org_id, &before, &after).await?
            }
            None => Vec::new(),
        }
    } else {
        Vec::new()
    };
    let mut tx = store.pool.begin().await?;
    sqlx::query(
        "UPDATE nodes SET capabilities_json=$1,agent_version=$2,os_version=$3,inventory_reported_at=$4 WHERE id=$5 AND org_id=$6",
    )
    .bind(serde_json::to_string(&next_caps).map_err(|_| ApiError::CorruptData)?)
    .bind(&next_agent)
    .bind(&next_os)
    .bind(now())
    .bind(node_id.to_string())
    .bind(org_id)
    .execute(&mut *tx)
    .await?;
    if changed {
        bump_control_revision(&mut tx, org_id).await?;
    }
    if !failing.is_empty() {
        crate::webhooks::enqueue(
            &mut tx,
            Uuid::parse_str(org_id).map_err(|_| ApiError::CorruptData)?,
            "posture.failed",
            &serde_json::json!({
                "device_id": node_id,
                "checks": failing,
                "source": "agent_reported",
            }),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(next_caps)
}

/// Lowers the organisation's next posture re-evaluation time.
pub(crate) async fn record_deadline(
    pool: &sqlx::AnyPool,
    org_id: &str,
    deadline: Option<i64>,
) -> Result<(), ApiError> {
    if let Some(at) = deadline {
        sqlx::query(
            "UPDATE orgs SET posture_next_eval_at=$1 WHERE id=$2 AND (posture_next_eval_at IS NULL OR posture_next_eval_at>$1)",
        )
        .bind(at)
        .bind(org_id)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// When a time-based posture or SSH check lapses, bump the control revision
/// once so every agent recompiles. Returns whether it fired.
pub(crate) async fn due(pool: &sqlx::AnyPool, org_id: &str) -> Result<bool, ApiError> {
    // Long-polls call this every 200 ms; read first so idle orgs never write.
    let next: Option<i64> = sqlx::query_scalar("SELECT posture_next_eval_at FROM orgs WHERE id=$1")
        .bind(org_id)
        .fetch_optional(pool)
        .await?
        .flatten();
    if next.is_none_or(|at| at > now()) {
        return Ok(false);
    }
    let fired = sqlx::query(
        "UPDATE orgs SET posture_next_eval_at=NULL,control_revision=control_revision+1 WHERE id=$1 AND posture_next_eval_at IS NOT NULL AND posture_next_eval_at<=$2",
    )
    .bind(org_id)
    .bind(now())
    .execute(pool)
    .await?
    .rows_affected();
    Ok(fired > 0)
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Enforcement {
    /// `enforced`, `unknown` or `not_enforced` for the inbound port filter.
    pub(crate) packet_filter: &'static str,
    pub(crate) ssh_users: bool,
    pub(crate) detail: String,
}

/// Where policy is enforced on a destination, from what it reported.
pub(crate) fn enforcement_profile(os: Option<&str>, capabilities: &[String]) -> Enforcement {
    let has = |cap: &str| capabilities.iter().any(|value| value == cap);
    let ssh_users = has(CAP_SSH_USERS);
    if has(CAP_ACL_FILTER) {
        return Enforcement {
            packet_filter: "enforced",
            ssh_users,
            detail: if ssh_users {
                "The agent filters inbound overlay traffic and has verified sshd per-user limits."
                    .into()
            } else {
                "The agent filters inbound overlay traffic. Per-user SSH limits are not verified (only the Linux agent with a verified sshd drop-in can), so user-limited SSH stays closed.".into()
            },
        };
    }
    match os.map(str::to_ascii_lowercase).as_deref() {
        Some("linux") => Enforcement {
            packet_filter: "unknown",
            ssh_users,
            detail: "This Linux agent has not reported filter support. Older agents may filter, but BlakTail cannot confirm it; treat ports as not enforced on this device until the agent is upgraded.".into(),
        },
        _ => Enforcement {
            packet_filter: "not_enforced",
            ssh_users,
            detail: "This client does not install an inbound packet filter. Any paired peer can reach any port; policy only decides which peers are paired.".into(),
        },
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateCheck {
    name: String,
    definition: PostureDefinition,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateCheck {
    /// The version the editor loaded; a mismatch returns 412.
    version: i64,
    definition: PostureDefinition,
}

#[derive(Serialize)]
pub(crate) struct CheckView {
    id: String,
    name: String,
    version: i64,
    definition: PostureDefinition,
    created_at: i64,
    updated_at: i64,
    referenced_by: Vec<String>,
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/orgs/:org_id/posture-checks",
            get(list_checks).post(create_check),
        )
        .route(
            "/v1/orgs/:org_id/posture-checks/:check_id",
            put(update_check).delete(delete_check),
        )
        .route(
            "/v1/orgs/:org_id/posture-assessments",
            get(list_assessments),
        )
        .route(
            "/v1/orgs/:org_id/nodes/:node_id/posture",
            get(node_assessment),
        )
}

async fn published_acl(store: &Store, org_id: Uuid) -> Result<Acl, ApiError> {
    crate::load_org_acl(store, org_id).await
}

async fn list_checks(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<CheckView>>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    list_checks_as(&s, org_id, &session).await
}

/// Console and `/api/v1/posture-checks` share these functions, so both apply
/// the same permission check and validation.
pub(crate) async fn list_checks_as(
    s: &AppState,
    org_id: Uuid,
    session: &Session,
) -> Result<Json<Vec<CheckView>>, ApiError> {
    require(session, Permission::ViewNetwork)?;
    let refs = referenced_checks(&published_acl(&s.store, org_id).await?);
    let checks = load_checks(&s.store.pool, &org_id.to_string()).await?;
    Ok(Json(
        checks
            .into_iter()
            .map(|(name, check)| CheckView {
                referenced_by: refs.get(&name).cloned().unwrap_or_default(),
                id: check.id,
                name,
                version: check.version,
                definition: check.definition,
                created_at: check.created_at,
                updated_at: check.updated_at,
            })
            .collect(),
    ))
}

async fn create_check(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<CreateCheck>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    create_check_as(&s, org_id, &session, input).await
}

pub(crate) async fn create_check_as(
    s: &AppState,
    org_id: Uuid,
    session: &Session,
    input: CreateCheck,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    require(session, Permission::ManagePolicy)?;
    if !valid_acl_group_name(&input.name) {
        return Err(ApiError::BadRequest(
            "posture check name must be 1-32 lowercase letters, digits, or hyphens".into(),
        ));
    }
    input.definition.validate()?;
    let mut tx = s.store.pool.begin().await?;
    if let Some(requirement) = &input.definition.integration {
        crate::posture_integrations::ensure_in_org(&mut tx, org_id, requirement.integration_id)
            .await?;
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM posture_checks WHERE org_id=$1")
        .bind(org_id.to_string())
        .fetch_one(&mut *tx)
        .await?;
    if count >= MAX_CHECKS_PER_ORG {
        return Err(ApiError::BadRequest(
            "organisations are limited to 32 posture checks".into(),
        ));
    }
    let id = Uuid::new_v4().to_string();
    let at = now();
    sqlx::query("INSERT INTO posture_checks(id,org_id,name,version,definition_json,created_at,updated_at) VALUES($1,$2,$3,1,$4,$5,$5)")
        .bind(&id)
        .bind(org_id.to_string())
        .bind(&input.name)
        .bind(serde_json::to_string(&input.definition).map_err(|_| ApiError::CorruptData)?)
        .bind(at)
        .execute(&mut *tx)
        .await
        .map_err(crate::conflict("posture check name already exists"))?;
    bump_control_revision(&mut tx, org_id.to_string()).await?;
    append_audit(
        &mut tx,
        org_id,
        session,
        "posture_check.created",
        "posture_check",
        Some(&id),
        &serde_json::json!({"name": input.name, "version": 1, "definition": input.definition}),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({"id": id, "name": input.name, "version": 1})),
    ))
}

async fn update_check(
    State(s): State<AppState>,
    UrlPath((org_id, check_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<UpdateCheck>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    update_check_as(&s, org_id, &session, check_id, input).await
}

pub(crate) async fn update_check_as(
    s: &AppState,
    org_id: Uuid,
    session: &Session,
    check_id: Uuid,
    input: UpdateCheck,
) -> Result<Json<serde_json::Value>, ApiError> {
    require(session, Permission::ManagePolicy)?;
    input.definition.validate()?;
    let mut tx = s.store.pool.begin().await?;
    if let Some(requirement) = &input.definition.integration {
        crate::posture_integrations::ensure_in_org(&mut tx, org_id, requirement.integration_id)
            .await?;
    }
    let row = sqlx::query(
        "SELECT name,version,definition_json FROM posture_checks WHERE id=$1 AND org_id=$2",
    )
    .bind(check_id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let name: String = row.try_get(0)?;
    let version: i64 = row.try_get(1)?;
    let previous: String = row.try_get(2)?;
    if version != input.version {
        return Err(ApiError::PreconditionFailed);
    }
    let changed = sqlx::query(
        "UPDATE posture_checks SET definition_json=$1,version=version+1,updated_at=$2 WHERE id=$3 AND org_id=$4 AND version=$5",
    )
    .bind(serde_json::to_string(&input.definition).map_err(|_| ApiError::CorruptData)?)
    .bind(now())
    .bind(check_id.to_string())
    .bind(org_id.to_string())
    .bind(version)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::PreconditionFailed);
    }
    bump_control_revision(&mut tx, org_id.to_string()).await?;
    append_audit(
        &mut tx,
        org_id,
        session,
        "posture_check.updated",
        "posture_check",
        Some(&check_id.to_string()),
        &serde_json::json!({
            "name": name,
            "version": version + 1,
            "definition": input.definition,
            "previous_definition": serde_json::from_str::<serde_json::Value>(&previous).unwrap_or_default(),
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        serde_json::json!({"id": check_id, "name": name, "version": version + 1}),
    ))
}

async fn delete_check(
    State(s): State<AppState>,
    UrlPath((org_id, check_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    delete_check_as(&s, org_id, &session, check_id).await
}

pub(crate) async fn delete_check_as(
    s: &AppState,
    org_id: Uuid,
    session: &Session,
    check_id: Uuid,
) -> Result<StatusCode, ApiError> {
    require(session, Permission::ManagePolicy)?;
    let mut tx = s.store.pool.begin().await?;
    let name: String =
        sqlx::query_scalar("SELECT name FROM posture_checks WHERE id=$1 AND org_id=$2")
            .bind(check_id.to_string())
            .bind(org_id.to_string())
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ApiError::NotFound)?;
    let acl_json = crate::load_acl_row_tx(&mut tx, org_id).await?.json;
    let acl: Acl = serde_json::from_str(&acl_json).map_err(|_| ApiError::CorruptData)?;
    if let Some(places) = referenced_checks(&acl).get(&name) {
        return Err(ApiError::Conflict(format!(
            "posture check {name} is referenced by {}; remove it from policy first",
            places.join(", ")
        )));
    }
    sqlx::query("DELETE FROM posture_checks WHERE id=$1 AND org_id=$2")
        .bind(check_id.to_string())
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await?;
    bump_control_revision(&mut tx, org_id.to_string()).await?;
    append_audit(
        &mut tx,
        org_id,
        session,
        "posture_check.deleted",
        "posture_check",
        Some(&check_id.to_string()),
        &serde_json::json!({"name": name}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct DeviceAssessment {
    node_id: Uuid,
    name: String,
    display_name: Option<String>,
    os: Option<String>,
    os_version: Option<String>,
    agent_version: Option<String>,
    capabilities: Vec<String>,
    inventory_reported_at: i64,
    credential_issued_at: i64,
    enforcement: Enforcement,
    assessments: Vec<AssessmentView>,
    /// Vendor signals for this device and where they came from.
    integrations: Vec<crate::posture_integrations::IntegrationFact>,
}

#[derive(Serialize)]
struct AssessmentView {
    #[serde(flatten)]
    assessment: Assessment,
    /// Policy locations whose grant this device loses while failing.
    affected_rules: Vec<String>,
}

#[derive(Serialize)]
struct AssessmentReport {
    evaluated_at: i64,
    notice: &'static str,
    devices: Vec<DeviceAssessment>,
}

fn device_assessment(
    ctx: &PostureContext,
    refs: &BTreeMap<String, Vec<String>>,
    facts: &NodeFacts,
) -> DeviceAssessment {
    DeviceAssessment {
        node_id: facts.id,
        name: facts.name.clone(),
        display_name: facts.display_name.clone(),
        os: facts.os.clone(),
        os_version: facts.os_version.clone(),
        agent_version: facts.agent_version.clone(),
        capabilities: facts.capabilities.clone(),
        inventory_reported_at: facts.reported_at(),
        credential_issued_at: facts.issued_at(),
        enforcement: enforcement_profile(facts.os.as_deref(), &facts.capabilities),
        integrations: facts.integrations.values().cloned().collect(),
        assessments: ctx
            .assess(facts)
            .into_iter()
            .map(|assessment| AssessmentView {
                affected_rules: refs.get(&assessment.check).cloned().unwrap_or_default(),
                assessment,
            })
            .collect(),
    }
}

async fn list_assessments(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<AssessmentReport>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewNetwork)?;
    let ctx = PostureContext::load(&s.store.pool, &org_id.to_string()).await?;
    let refs = referenced_checks(&published_acl(&s.store, org_id).await?);
    let mut devices: Vec<_> = ctx
        .facts
        .values()
        .map(|facts| device_assessment(&ctx, &refs, facts))
        .collect();
    devices.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Json(AssessmentReport {
        evaluated_at: ctx.now,
        notice: SELF_REPORTED_NOTICE,
        devices,
    }))
}

async fn node_assessment(
    State(s): State<AppState>,
    UrlPath((org_id, node_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<AssessmentReport>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewNetwork)?;
    let ctx = PostureContext::load(&s.store.pool, &org_id.to_string()).await?;
    let facts = ctx.facts.get(&node_id).ok_or(ApiError::NotFound)?;
    let refs = referenced_checks(&published_acl(&s.store, org_id).await?);
    Ok(Json(AssessmentReport {
        evaluated_at: ctx.now,
        notice: SELF_REPORTED_NOTICE,
        devices: vec![device_assessment(&ctx, &refs, facts)],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> NodeFacts {
        NodeFacts {
            id: Uuid::nil(),
            name: "store-1".into(),
            display_name: None,
            user_id: "owner-1".into(),
            role: Role::Member,
            tags: vec![],
            os: Some("linux".into()),
            os_version: Some("24.04".into()),
            agent_version: Some("0.2.1".into()),
            capabilities: vec![],
            created_at: 1_000,
            credential_issued_at: Some(5_000),
            credential_expires_at: 100_000,
            inventory_reported_at: Some(9_000),
            integrations: BTreeMap::new(),
        }
    }

    fn def(value: serde_json::Value) -> PostureDefinition {
        let def: PostureDefinition = serde_json::from_value(value).unwrap();
        def.validate().unwrap();
        def
    }

    #[test]
    fn versions_compare_numerically() {
        assert!(version_at_least(
            &parse_version("0.10.0").unwrap(),
            &parse_version("0.9").unwrap()
        ));
        assert!(!version_at_least(
            &parse_version("v1.2").unwrap(),
            &parse_version("1.2.1").unwrap()
        ));
        assert!(parse_version("aarch64").is_none());
        assert_eq!(parse_version("14.2-beta"), Some(vec![14, 2]));
    }

    #[test]
    fn agent_version_and_os_family_gate() {
        let check = def(serde_json::json!({"min_agent_version":"0.2.0","os_families":["linux"]}));
        assert!(evaluate("base", 1, &check, &facts(), 10_000).passed);
        let mut old = facts();
        old.agent_version = Some("0.1.9".into());
        let result = evaluate("base", 1, &check, &old, 10_000);
        assert!(!result.passed);
        assert!(result.reasons[0].text.contains("older than 0.2.0"));
        assert_eq!(result.reasons[0].source, "agent_reported");
        let mut mac = facts();
        mac.os = Some("macos".into());
        assert!(!evaluate("base", 1, &check, &mac, 10_000).passed);
    }

    #[test]
    fn missing_or_stale_data_fails_closed_unless_configured() {
        let strict =
            def(serde_json::json!({"min_os_versions":{"linux":"22.04"},"max_report_age_secs":600}));
        let mut arch = facts();
        arch.os_version = Some("aarch64".into());
        let result = evaluate("os", 1, &strict, &arch, 9_100);
        assert!(!result.passed && result.missing_data);
        assert!(evaluate("os", 1, &strict, &facts(), 9_100).passed);
        // Inventory reported at 9000 goes stale after 9600.
        let stale = evaluate("os", 1, &strict, &facts(), 9_700);
        assert!(!stale.passed && stale.missing_data);
        let lenient =
            def(serde_json::json!({"min_os_versions":{"linux":"22.04"},"on_missing_data":"pass"}));
        assert!(evaluate("os", 1, &lenient, &arch, 9_100).passed);
    }

    #[test]
    fn credential_age_is_coordinator_observed_and_sets_deadline() {
        let check =
            def(serde_json::json!({"max_credential_age_secs":3600,"require_approved_peer":true}));
        let fresh = evaluate("auth", 1, &check, &facts(), 6_000);
        assert!(fresh.passed);
        assert_eq!(fresh.expires_at, Some(8_600));
        let old = evaluate("auth", 1, &check, &facts(), 9_000);
        assert!(!old.passed);
        assert_eq!(old.reasons[0].source, "coordinator_observed");
        let expired = evaluate("auth", 1, &check, &facts(), 200_000);
        assert!(expired.reasons.iter().any(|r| r.text.contains("expired")));
    }

    #[test]
    fn definitions_reject_empty_and_unknown_values() {
        let empty: PostureDefinition = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(empty.validate().is_err());
        let bad: PostureDefinition =
            serde_json::from_value(serde_json::json!({"os_families":["solaris"]})).unwrap();
        assert!(bad.validate().is_err());
        assert!(
            serde_json::from_value::<PostureDefinition>(serde_json::json!({"attested": true}))
                .is_err()
        );
    }

    #[test]
    fn enforcement_profile_is_honest_about_clients() {
        assert_eq!(
            enforcement_profile(Some("linux"), &[CAP_ACL_FILTER.into()]).packet_filter,
            "enforced"
        );
        assert_eq!(
            enforcement_profile(Some("linux"), &[]).packet_filter,
            "unknown"
        );
        assert_eq!(
            enforcement_profile(Some("ios"), &[]).packet_filter,
            "not_enforced"
        );
        assert_eq!(
            enforcement_profile(Some("macos"), &[CAP_SSH_USERS.into()]).packet_filter,
            "not_enforced"
        );
        // Userspace dataplanes report the filter once their hook is active;
        // the OS alone never decides it.
        for os in ["ios", "android", "windows", "macos"] {
            let profile = enforcement_profile(Some(os), &[CAP_ACL_FILTER.into()]);
            assert_eq!(profile.packet_filter, "enforced", "{os}");
            assert!(!profile.ssh_users);
        }
    }
}
