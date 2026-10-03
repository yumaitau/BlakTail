//! Administrative audit timeline (draft 17): filtered keyset pagination,
//! read-time redaction, permissioned and audited export, and a per-org hash
//! chain over coordinator audit rows with a verify endpoint.
//!
//! The chain makes silent edits and deletions inside the retained window
//! detectable by anyone who can read it; it is not a signature and does not
//! stop a database administrator who rewrites every later row and the head.

use crate::admin::{authenticate_org_header, require_scope, Scope};
use crate::permissions::{require, Permission};
use crate::{
    append_audit, console_session, hash, ApiError, AppState, AuditEvent, AuditQuery, Session, Store,
};
use axum::{
    extract::{Path as UrlPath, Query, State},
    http::{header, HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::{AnyConnection, AssertSqlSafe, Row};
use uuid::Uuid;

/// Upper bound on one export so a request cannot pin the database.
pub(crate) const MAX_EXPORT_ROWS: usize = 10_000;
const MAX_FILTER_CHARS: usize = 200;
const REDACTED: &str = "[redacted]";
const VERIFY_BATCH: i64 = 1_000;
const MAX_REPORTED_PROBLEMS: usize = 20;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/orgs/:org_id/audit/export", get(export_console))
        .route("/v1/orgs/:org_id/audit/verify", get(verify_console))
}

// ---------------------------------------------------------------------------
// Hash chain

pub(crate) struct ChainEntry {
    pub(crate) org_id: String,
    pub(crate) id: String,
    pub(crate) actor_user_id: String,
    pub(crate) actor_name: String,
    pub(crate) actor_email: String,
    pub(crate) actor_role: String,
    pub(crate) action: String,
    pub(crate) target_type: String,
    pub(crate) target_id: Option<String>,
    pub(crate) details_json: String,
    pub(crate) created_at: i64,
}

pub(crate) fn chain_hash(prev_hash: Option<&str>, seq: i64, entry: &ChainEntry) -> String {
    let material = serde_json::json!([
        "blaktail-audit-v1",
        entry.org_id,
        seq,
        prev_hash.unwrap_or(""),
        entry.id,
        entry.actor_user_id,
        entry.actor_name,
        entry.actor_email,
        entry.actor_role,
        entry.action,
        entry.target_type,
        entry.target_id,
        entry.details_json,
        entry.created_at,
    ]);
    hash(&material.to_string())
}

/// Appends one row to the organisation's chain. Bumping the org sequence
/// first takes the org row lock, so concurrent writers in one organisation
/// serialise and cannot fork the chain.
pub(crate) async fn insert_chained(
    connection: &mut AnyConnection,
    entry: &ChainEntry,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE orgs SET audit_chain_seq=audit_chain_seq+1 WHERE id=$1")
        .bind(&entry.org_id)
        .execute(&mut *connection)
        .await?;
    let row = sqlx::query("SELECT audit_chain_seq,audit_chain_head FROM orgs WHERE id=$1")
        .bind(&entry.org_id)
        .fetch_optional(&mut *connection)
        .await?
        .ok_or(ApiError::NotFound)?;
    let seq: i64 = row.try_get(0)?;
    let prev_hash: Option<String> = row.try_get(1)?;
    let entry_hash = chain_hash(prev_hash.as_deref(), seq, entry);
    sqlx::query(
        "INSERT INTO audit_events(id,org_id,actor_user_id,actor_name,actor_email,actor_role,action,target_type,target_id,details_json,created_at,chain_seq,prev_hash,entry_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(&entry.id)
    .bind(&entry.org_id)
    .bind(&entry.actor_user_id)
    .bind(&entry.actor_name)
    .bind(&entry.actor_email)
    .bind(&entry.actor_role)
    .bind(&entry.action)
    .bind(&entry.target_type)
    .bind(entry.target_id.as_deref())
    .bind(&entry.details_json)
    .bind(entry.created_at)
    .bind(seq)
    .bind(prev_hash.as_deref())
    .bind(&entry_hash)
    .execute(&mut *connection)
    .await?;
    sqlx::query("UPDATE orgs SET audit_chain_head=$1 WHERE id=$2")
        .bind(&entry_hash)
        .bind(&entry.org_id)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ChainReport {
    pub(crate) intact: bool,
    pub(crate) chained_events: i64,
    pub(crate) unchained_events: i64,
    pub(crate) first_seq: Option<i64>,
    pub(crate) last_seq: Option<i64>,
    pub(crate) head_seq: i64,
    pub(crate) problems: Vec<String>,
    pub(crate) note: String,
}

pub(crate) async fn verify_chain(store: &Store, org_id: Uuid) -> Result<ChainReport, ApiError> {
    let org = org_id.to_string();
    let head = sqlx::query("SELECT audit_chain_seq,audit_chain_head FROM orgs WHERE id=$1")
        .bind(&org)
        .fetch_optional(&store.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    let head_seq: i64 = head.try_get(0)?;
    let head_hash: Option<String> = head.try_get(1)?;
    let unchained_events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE org_id=$1 AND chain_seq IS NULL",
    )
    .bind(&org)
    .fetch_one(&store.pool)
    .await?;
    let mut problems = Vec::new();
    let note = |problems: &mut Vec<String>, text: String| {
        if problems.len() < MAX_REPORTED_PROBLEMS {
            problems.push(text);
        }
    };
    let mut chained_events = 0;
    let mut first_seq = None;
    let mut previous: Option<(i64, String)> = None;
    loop {
        let after = previous.as_ref().map_or(-1, |(seq, _)| *seq);
        let rows = sqlx::query(
            "SELECT id,actor_user_id,actor_name,actor_email,actor_role,action,target_type,target_id,details_json,created_at,chain_seq,prev_hash,entry_hash FROM audit_events WHERE org_id=$1 AND chain_seq IS NOT NULL AND chain_seq>$2 ORDER BY chain_seq LIMIT $3",
        )
        .bind(&org)
        .bind(after)
        .bind(VERIFY_BATCH)
        .fetch_all(&store.pool)
        .await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            let entry = ChainEntry {
                org_id: org.clone(),
                id: row.try_get(0)?,
                actor_user_id: row.try_get(1)?,
                actor_name: row.try_get(2)?,
                actor_email: row.try_get(3)?,
                actor_role: row.try_get(4)?,
                action: row.try_get(5)?,
                target_type: row.try_get(6)?,
                target_id: row.try_get(7)?,
                details_json: row.try_get(8)?,
                created_at: row.try_get(9)?,
            };
            let seq: i64 = row.try_get(10)?;
            let prev_hash: Option<String> = row.try_get(11)?;
            let entry_hash: String = row.try_get(12)?;
            if chain_hash(prev_hash.as_deref(), seq, &entry) != entry_hash {
                note(
                    &mut problems,
                    format!("event {seq} does not match its recorded hash"),
                );
            }
            match &previous {
                Some((last_seq, last_hash)) => {
                    if seq != last_seq + 1 {
                        note(
                            &mut problems,
                            format!("events {} to {} are missing", last_seq + 1, seq - 1),
                        );
                    }
                    if prev_hash.as_deref() != Some(last_hash.as_str()) {
                        note(
                            &mut problems,
                            format!("event {seq} does not link to event {last_seq}"),
                        );
                    }
                }
                None => first_seq = Some(seq),
            }
            chained_events += 1;
            previous = Some((seq, entry_hash));
        }
    }
    let last_seq = previous.as_ref().map(|(seq, _)| *seq);
    if let Some((seq, last_hash)) = &previous {
        if *seq != head_seq || head_hash.as_deref() != Some(last_hash.as_str()) {
            note(
                &mut problems,
                format!("the newest retained event is {seq} but the organisation head is {head_seq}; later events were removed or altered"),
            );
        }
    }
    let note_text = if chained_events == 0 && head_seq > 0 {
        "No chained events remain inside the retention window."
    } else {
        "The oldest retained event anchors the chain; events older than the retention window are deleted by design."
    };
    Ok(ChainReport {
        intact: problems.is_empty(),
        chained_events,
        unchained_events,
        first_seq,
        last_seq,
        head_seq,
        problems,
        note: note_text.into(),
    })
}

// ---------------------------------------------------------------------------
// Filtered listing

enum Arg {
    Text(String),
    Int(i64),
}

fn clean_filter(value: &Option<String>, field: &str) -> Result<Option<String>, ApiError> {
    let Some(value) = value.as_deref().map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    if value.chars().count() > MAX_FILTER_CHARS || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field} filter must be at most {MAX_FILTER_CHARS} printable characters"
        )));
    }
    Ok(Some(value.to_owned()))
}

fn like_prefix(prefix: &str) -> String {
    let mut pattern = String::with_capacity(prefix.len() + 1);
    for ch in prefix.chars() {
        if matches!(ch, '!' | '%' | '_') {
            pattern.push('!');
        }
        pattern.push(ch);
    }
    pattern.push('%');
    pattern
}

pub(crate) async fn query_events(
    store: &Store,
    org_id: Uuid,
    query: &AuditQuery,
    limit: i64,
) -> Result<Vec<AuditEvent>, ApiError> {
    let mut sql = String::from(
        "SELECT id,actor_user_id,actor_name,actor_email,actor_role,action,target_type,target_id,details_json,created_at FROM audit_events WHERE org_id=$1",
    );
    let mut args = vec![Arg::Text(org_id.to_string())];
    let push = |args: &mut Vec<Arg>, arg: Arg| {
        args.push(arg);
        args.len()
    };
    if let Some(cursor) = query
        .before
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        let (created_at, id) = cursor
            .split_once(':')
            .ok_or_else(|| ApiError::BadRequest("before must be created_at:id".into()))?;
        let created_at = created_at
            .parse::<i64>()
            .map_err(|_| ApiError::BadRequest("before created_at is invalid".into()))?;
        if id.is_empty() {
            return Err(ApiError::BadRequest("before id is required".into()));
        }
        let t = push(&mut args, Arg::Int(created_at));
        let i = push(&mut args, Arg::Text(id.to_owned()));
        sql.push_str(&format!(
            " AND (created_at<${t} OR (created_at=${t} AND id<${i}))"
        ));
    }
    if let Some(actor) = clean_filter(&query.actor, "actor")? {
        let n = push(&mut args, Arg::Text(actor));
        sql.push_str(&format!(
            " AND (actor_user_id=${n} OR LOWER(actor_email)=LOWER(${n}) OR actor_name=${n})"
        ));
    }
    if let Some(action) = clean_filter(&query.action, "action")? {
        if let Some(prefix) = action
            .strip_suffix('*')
            .or_else(|| action.ends_with('.').then_some(action.as_str()))
        {
            let n = push(&mut args, Arg::Text(like_prefix(prefix)));
            sql.push_str(&format!(" AND action LIKE ${n} ESCAPE '!'"));
        } else {
            let n = push(&mut args, Arg::Text(action));
            sql.push_str(&format!(" AND action=${n}"));
        }
    }
    if let Some(target_type) = clean_filter(&query.target_type, "target_type")? {
        let n = push(&mut args, Arg::Text(target_type));
        sql.push_str(&format!(" AND target_type=${n}"));
    }
    if let Some(target_id) = clean_filter(&query.target_id, "target_id")? {
        let n = push(&mut args, Arg::Text(target_id));
        sql.push_str(&format!(" AND target_id=${n}"));
    }
    if let (Some(since), Some(until)) = (query.since, query.until) {
        if since >= until {
            return Err(ApiError::BadRequest("since must be before until".into()));
        }
    }
    if let Some(since) = query.since {
        let n = push(&mut args, Arg::Int(since));
        sql.push_str(&format!(" AND created_at>=${n}"));
    }
    if let Some(until) = query.until {
        let n = push(&mut args, Arg::Int(until));
        sql.push_str(&format!(" AND created_at<${n}"));
    }
    let n = push(&mut args, Arg::Int(limit));
    sql.push_str(&format!(" ORDER BY created_at DESC,id DESC LIMIT ${n}"));
    // Only fixed fragments and numbered placeholders reach the SQL text.
    let mut statement = sqlx::query(AssertSqlSafe(sql));
    for arg in args {
        statement = match arg {
            Arg::Text(value) => statement.bind(value),
            Arg::Int(value) => statement.bind(value),
        };
    }
    let rows = statement.fetch_all(&store.pool).await?;
    rows.into_iter()
        .map(|row| {
            let details_json: String = row.try_get(8)?;
            let mut details: serde_json::Value =
                serde_json::from_str(&details_json).unwrap_or_default();
            redact(&mut details);
            Ok::<_, sqlx::Error>(AuditEvent {
                id: row.try_get(0)?,
                actor_user_id: row.try_get(1)?,
                actor_name: row.try_get(2)?,
                actor_email: row.try_get(3)?,
                actor_role: row.try_get(4)?,
                action: row.try_get(5)?,
                target_type: row.try_get(6)?,
                target_id: row.try_get(7)?,
                details,
                created_at: row.try_get(9)?,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::Database)
}

// ---------------------------------------------------------------------------
// Redaction

const SENSITIVE_KEY_MARKERS: &[&str] = &[
    "secret",
    "password",
    "passwd",
    "token",
    "private_key",
    "privatekey",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "signature",
    "psk",
];

/// Identifiers and display prefixes are designed to be shown.
fn sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    if ["_prefix", "_id", "_at", "_count", "_expires", "_ttl"]
        .iter()
        .any(|suffix| key.ends_with(suffix))
    {
        return false;
    }
    SENSITIVE_KEY_MARKERS
        .iter()
        .any(|marker| key.contains(marker))
}

/// Values that look like a BlakTail credential, a JWT or a PEM block.
fn secret_looking(value: &str) -> bool {
    let bytes = value.as_bytes();
    let blaktail_secret = value.len() >= 20
        && bytes.len() > 4
        && bytes[0] == b'b'
        && bytes[1] == b't'
        && bytes[2].is_ascii_lowercase()
        && bytes[3] == b'_';
    blaktail_secret
        || value.contains("-----BEGIN")
        || (value.starts_with("eyJ") && value.matches('.').count() == 2)
}

pub(crate) fn redact(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, nested) in map.iter_mut() {
                if sensitive_key(key) && !nested.is_null() {
                    *nested = serde_json::Value::String(REDACTED.into());
                } else {
                    redact(nested);
                }
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(redact),
        serde_json::Value::String(text) if secret_looking(text) => {
            *text = REDACTED.into();
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Export

/// Read from the same query string as the `AuditQuery` filters.
#[derive(Default, Deserialize)]
pub(crate) struct ExportFormat {
    #[serde(default)]
    format: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ExportBody {
    pub(crate) data: Vec<AuditEvent>,
    pub(crate) truncated: bool,
}

/// Collects up to `MAX_EXPORT_ROWS` matching events newest first.
async fn collect_export(
    store: &Store,
    org_id: Uuid,
    filters: &AuditQuery,
) -> Result<(Vec<AuditEvent>, bool), ApiError> {
    let mut query = filters.clone();
    query.limit = None;
    let mut events: Vec<AuditEvent> = Vec::new();
    loop {
        let page = query_events(store, org_id, &query, 200).await?;
        let full = page.len() == 200;
        if let Some(last) = page.last() {
            query.before = Some(format!("{}:{}", last.created_at, last.id));
        }
        events.extend(page);
        if events.len() > MAX_EXPORT_ROWS {
            events.truncate(MAX_EXPORT_ROWS);
            return Ok((events, true));
        }
        if !full {
            return Ok((events, false));
        }
    }
}

/// CSV cell: quoted, with formula-leading characters neutralised so a
/// spreadsheet never evaluates audit content.
fn csv_cell(value: &str) -> String {
    let guarded = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    format!("\"{}\"", guarded.replace('"', "\"\""))
}

pub(crate) fn to_csv(events: &[AuditEvent]) -> String {
    let mut out = String::from(
        "created_at,id,actor_user_id,actor_name,actor_email,actor_role,action,target_type,target_id,details\r\n",
    );
    for event in events {
        let created = chrono::DateTime::from_timestamp(event.created_at, 0)
            .map(|at| at.to_rfc3339())
            .unwrap_or_default();
        let cells = [
            created,
            event.id.clone(),
            event.actor_user_id.clone(),
            event.actor_name.clone(),
            event.actor_email.clone(),
            event.actor_role.clone(),
            event.action.clone(),
            event.target_type.clone(),
            event.target_id.clone().unwrap_or_default(),
            event.details.to_string(),
        ];
        out.push_str(
            &cells
                .iter()
                .map(|cell| csv_cell(cell))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str("\r\n");
    }
    out
}

/// Shared by the console route and `/api/v1/audit/export`: same permission,
/// same filters, same audit record.
pub(crate) async fn export(
    store: &Store,
    org_id: Uuid,
    session: &Session,
    format: ExportFormat,
    filters: AuditQuery,
) -> Result<Response, ApiError> {
    require(session, Permission::ExportAudit)?;
    let format = format.format.as_deref().unwrap_or("json");
    if !matches!(format, "json" | "csv") {
        return Err(ApiError::BadRequest("format must be json or csv".into()));
    }
    crate::purge_expired_audit(store, org_id).await?;
    let (events, truncated) = collect_export(store, org_id, &filters).await?;
    let mut filters = serde_json::to_value(&filters).unwrap_or_default();
    redact(&mut filters);
    let mut tx = store.pool.begin().await?;
    append_audit(
        &mut tx,
        org_id,
        session,
        "audit.exported",
        "audit_log",
        Some(&org_id.to_string()),
        &serde_json::json!({
            "format": format,
            "count": events.len(),
            "truncated": truncated,
            "filters": filters,
        }),
    )
    .await?;
    tx.commit().await?;
    let mut response = if format == "csv" {
        let mut response = to_csv(&events).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/csv; charset=utf-8"),
        );
        response
    } else {
        Json(ExportBody {
            data: events,
            truncated,
        })
        .into_response()
    };
    let disposition = format!("attachment; filename=\"blaktail-audit-{org_id}.{format}\"");
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, value);
    }
    response.headers_mut().insert(
        "x-blaktail-export-truncated",
        HeaderValue::from_static(if truncated { "true" } else { "false" }),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

async fn export_console(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Query(format): Query<ExportFormat>,
    Query(filters): Query<AuditQuery>,
) -> Result<Response, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    export(&s.store, org_id, &session, format, filters).await
}

async fn verify_console(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ChainReport>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ViewAudit)?;
    crate::purge_expired_audit(&s.store, org_id).await?;
    Ok(Json(verify_chain(&s.store, org_id).await?))
}

pub(crate) async fn api_export(
    State(s): State<AppState>,
    Query(format): Query<ExportFormat>,
    Query(filters): Query<AuditQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::AuditExport)?;
    export(&s.store, org_id, &caller.session, format, filters).await
}

pub(crate) async fn api_verify(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<crate::admin::Envelope<ChainReport>>, ApiError> {
    let (org_id, caller) = authenticate_org_header(&s, &headers).await?;
    require_scope(&caller, Scope::AuditRead)?;
    crate::purge_expired_audit(&s.store, org_id).await?;
    Ok(Json(crate::admin::Envelope {
        data: verify_chain(&s.store, org_id).await?,
        next_cursor: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_hides_secrets_by_key_and_shape_but_keeps_identifiers() {
        let mut value = serde_json::json!({
            "token": "anything",
            "client_secret": "x",
            "Authorization": "Bearer abc",
            "token_prefix": "bta_abcdef",
            "join_key_id": "k-1",
            "credential_expires_at": 5,
            "nested": [{"password": "hunter2"}, "btk_aaaaaaaaaaaaaaaaaaaaaaaa"],
            "note": "-----BEGIN PRIVATE KEY-----",
            "name": "laptop",
        });
        redact(&mut value);
        assert_eq!(value["token"], REDACTED);
        assert_eq!(value["client_secret"], REDACTED);
        assert_eq!(value["Authorization"], REDACTED);
        assert_eq!(value["nested"][0]["password"], REDACTED);
        assert_eq!(value["nested"][1], REDACTED);
        assert_eq!(value["note"], REDACTED);
        assert_eq!(value["token_prefix"], "bta_abcdef");
        assert_eq!(value["join_key_id"], "k-1");
        assert_eq!(value["credential_expires_at"], 5);
        assert_eq!(value["name"], "laptop");
    }

    #[test]
    fn csv_quotes_and_neutralises_formulas() {
        assert_eq!(csv_cell("plain"), "\"plain\"");
        assert_eq!(csv_cell("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_cell("=HYPERLINK(1)"), "\"'=HYPERLINK(1)\"");
        assert_eq!(csv_cell("@cmd"), "\"'@cmd\"");
    }

    #[test]
    fn like_prefix_escapes_wildcards() {
        assert_eq!(like_prefix("node."), "node.%");
        assert_eq!(like_prefix("a_b%c!"), "a!_b!%c!!%");
    }

    #[test]
    fn chain_hash_covers_every_field() {
        let entry = ChainEntry {
            org_id: "o".into(),
            id: "i".into(),
            actor_user_id: "u".into(),
            actor_name: "n".into(),
            actor_email: "e".into(),
            actor_role: "owner".into(),
            action: "a.b".into(),
            target_type: "t".into(),
            target_id: None,
            details_json: "{}".into(),
            created_at: 1,
        };
        let base = chain_hash(None, 1, &entry);
        assert_ne!(base, chain_hash(Some("x"), 1, &entry));
        assert_ne!(base, chain_hash(None, 2, &entry));
        let altered = ChainEntry {
            details_json: "{\"x\":1}".into(),
            ..entry
        };
        assert_ne!(base, chain_hash(None, 1, &altered));
    }
}
