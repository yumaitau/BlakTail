import "server-only";

import { randomUUID } from "node:crypto";
import type { AuditCursor, AuditFilters } from "./audit-view";
import type { AuditEvent } from "./coord";
import { rawSqlClient } from "./db/client";
import type { ConsoleContext } from "./session";

export async function writeConsoleAudit(event: {
  organisationId: string | null;
  actorUserId: string;
  actorEmail: string;
  actorRole: string;
  source: string;
  action: string;
  result: string;
  targetType: string;
  targetId?: string;
  details?: unknown;
}): Promise<void> {
  const sql = rawSqlClient();
  await sql`
    INSERT INTO console_audit_event (
      id, organisation_id, actor_user_id, actor_email, actor_role,
      source, action, result, target_type, target_id, details
    ) VALUES (
      ${randomUUID()}, ${event.organisationId}, ${event.actorUserId},
      ${event.actorEmail}, ${event.actorRole}, ${event.source}, ${event.action},
      ${event.result}, ${event.targetType}, ${event.targetId ?? null},
      CAST(${JSON.stringify(event.details ?? {})} AS jsonb)
    )
  `;
}

type ConsoleAuditRow = {
  id: string;
  actor_user_id: string | null;
  actor_email: string;
  actor_role: string;
  action: string;
  result: string;
  target_type: string;
  target_id: string | null;
  details: Record<string, unknown>;
  created_at: Date | string;
};

export async function listConsoleAuditEvents(
  ctx: ConsoleContext,
): Promise<AuditEvent[]> {
  const sql = rawSqlClient();
  const rows = await sql<ConsoleAuditRow[]>`
    SELECT id, actor_user_id, actor_email, actor_role, action,
      result, target_type, target_id, details, created_at
    FROM console_audit_event
    WHERE organisation_id = ${ctx.organisationId}
      OR (
        organisation_id IS NULL
        AND actor_user_id IN (
          SELECT user_id FROM person_login_identity
          WHERE person_id = ${ctx.personId}
        )
      )
    ORDER BY created_at DESC, id DESC
    LIMIT 100
  `;
  return rows.map((row) => ({
    id: `console:${row.id}`,
    actor_user_id: row.actor_user_id ?? "operator",
    actor_name: "",
    actor_email: row.actor_email,
    actor_role: row.actor_role,
    action: row.action,
    target_type: row.target_type,
    target_id: row.target_id,
    details: { ...row.details, result: row.result, source: "console" },
    created_at: Math.floor(new Date(row.created_at).getTime() / 1000),
  }));
}

function toAuditEvent(row: ConsoleAuditRow): AuditEvent {
  return {
    id: `console:${row.id}`,
    actor_user_id: row.actor_user_id ?? "operator",
    actor_name: "",
    actor_email: row.actor_email,
    actor_role: row.actor_role,
    action: row.action,
    target_type: row.target_type,
    target_id: row.target_id,
    details: { ...row.details, result: row.result, source: "console" },
    created_at: Math.floor(new Date(row.created_at).getTime() / 1000),
  };
}

/**
 * One page of console-side audit rows in merged-timeline order (whole
 * seconds descending, then id descending). See `AuditCursor`.
 */
export async function listConsoleAuditPage(
  ctx: ConsoleContext,
  filters: AuditFilters,
  cursor: AuditCursor | null,
  limit: number,
): Promise<AuditEvent[]> {
  const sql = rawSqlClient();
  const actionPrefix =
    filters.action && /[.*]$/.test(filters.action)
      ? filters.action.replace(/\*$/, "")
      : null;
  const actionExact = filters.action && !actionPrefix ? filters.action : null;
  const rows = await sql<ConsoleAuditRow[]>`
    SELECT id, actor_user_id, actor_email, actor_role, action,
      result, target_type, target_id, details, created_at
    FROM (
      SELECT *, floor(extract(epoch FROM created_at))::bigint AS sec
      FROM console_audit_event
      WHERE organisation_id = ${ctx.organisationId}
        OR (
          organisation_id IS NULL
          AND actor_user_id IN (
            SELECT user_id FROM person_login_identity
            WHERE person_id = ${ctx.personId}
          )
        )
    ) e
    WHERE (${filters.actor ?? null}::text IS NULL
        OR actor_user_id = ${filters.actor ?? null}
        OR lower(actor_email) = lower(${filters.actor ?? null}))
      AND (${actionExact}::text IS NULL OR action = ${actionExact})
      AND (${actionPrefix}::text IS NULL OR starts_with(action, ${actionPrefix}))
      AND (${filters.target_type ?? null}::text IS NULL OR target_type = ${filters.target_type ?? null})
      AND (${filters.target_id ?? null}::text IS NULL OR target_id = ${filters.target_id ?? null})
      AND (${filters.since ?? null}::bigint IS NULL OR sec >= ${filters.since ?? null})
      AND (${filters.until ?? null}::bigint IS NULL OR sec < ${filters.until ?? null})
      AND (
        ${cursor?.src ?? null}::text IS NULL
        OR (${cursor?.src ?? null} = 'c' AND sec <= ${cursor?.t ?? null}::bigint)
        OR (${cursor?.src ?? null} = 'k' AND (
          sec < ${cursor?.t ?? null}::bigint
          OR (sec = ${cursor?.t ?? null}::bigint AND id < ${cursor?.id ?? null})
        ))
      )
    ORDER BY sec DESC, id DESC
    LIMIT ${limit}
  `;
  return rows.map(toAuditEvent);
}
