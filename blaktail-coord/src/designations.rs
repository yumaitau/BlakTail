//! Owner/admin designation of the devices allowed to act in a privileged role
//! (AI gateway, public ingress). A device's reported capability says it runs
//! the software; only a designation lets it receive provider credentials or
//! public routes. Both are checked on every node-token request.

use crate::{append_audit, now, ApiError, Session};
use sqlx::AnyConnection;
use std::collections::BTreeSet;
use uuid::Uuid;

pub(crate) const AGENT_GATEWAY: &str = "agent-gateway";
pub(crate) const PUBLIC_INGRESS: &str = "public-ingress";

pub(crate) async fn is_designated(
    conn: &mut AnyConnection,
    org_id: &str,
    node_id: Uuid,
    role: &str,
) -> Result<bool, ApiError> {
    Ok(sqlx::query_scalar::<_, String>(
        "SELECT node_id FROM node_designations WHERE org_id=$1 AND node_id=$2 AND role=$3",
    )
    .bind(org_id)
    .bind(node_id.to_string())
    .bind(role)
    .fetch_optional(&mut *conn)
    .await?
    .is_some())
}

pub(crate) async fn designated(
    conn: &mut AnyConnection,
    org_id: &str,
    role: &str,
) -> Result<BTreeSet<String>, ApiError> {
    Ok(sqlx::query_scalar::<_, String>(
        "SELECT node_id FROM node_designations WHERE org_id=$1 AND role=$2",
    )
    .bind(org_id)
    .bind(role)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .collect())
}

/// Designates or releases an active device of the organisation, audited.
/// Returns whether anything changed.
pub(crate) async fn set(
    conn: &mut AnyConnection,
    org_id: Uuid,
    session: &Session,
    node_id: Uuid,
    role: &str,
    designate: bool,
) -> Result<bool, ApiError> {
    let org = org_id.to_string();
    // Scoped to this organisation: another org's device is not found.
    let name: String = sqlx::query_scalar(
        "SELECT COALESCE(NULLIF(TRIM(display_name),''),name) FROM nodes WHERE id=$1 AND org_id=$2 AND revoked_at IS NULL AND deleted_at IS NULL",
    )
    .bind(node_id.to_string())
    .bind(&org)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(ApiError::NotFound)?;
    let changed = if designate {
        sqlx::query(
            "INSERT INTO node_designations(org_id,node_id,role,designated_by,designated_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(org_id,node_id,role) DO NOTHING",
        )
        .bind(&org)
        .bind(node_id.to_string())
        .bind(role)
        .bind(&session.user_id)
        .bind(now())
        .execute(&mut *conn)
        .await?
        .rows_affected()
    } else {
        sqlx::query("DELETE FROM node_designations WHERE org_id=$1 AND node_id=$2 AND role=$3")
            .bind(&org)
            .bind(node_id.to_string())
            .bind(role)
            .execute(&mut *conn)
            .await?
            .rows_affected()
    } != 0;
    if changed {
        append_audit(
            conn,
            org_id,
            session,
            if designate {
                "node.role.designated"
            } else {
                "node.role.released"
            },
            "node",
            Some(&node_id.to_string()),
            &serde_json::json!({"role": role, "node_name": name}),
        )
        .await?;
    }
    Ok(changed)
}
