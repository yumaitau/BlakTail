// Pure helpers for the audit timeline: filters, the merged cursor across the
// coordinator and console audit stores, redaction and CSV. No server-only
// imports so bun tests can load this file directly.

export type AuditEventView = {
  id: string;
  actor_user_id: string;
  actor_name: string;
  actor_email: string;
  actor_role: string;
  action: string;
  target_type: string;
  target_id: string | null;
  details: unknown;
  created_at: number;
};

export type AuditSource = "c" | "k";

export type AuditFilters = {
  actor?: string;
  action?: string;
  target_type?: string;
  target_id?: string;
  since?: number;
  until?: number;
};

/**
 * Position in the merged timeline. Order is created_at (whole seconds)
 * descending, then coordinator rows before console rows within one second,
 * then each store's own id order. Both stores filter on the same rule.
 */
export type AuditCursor = { t: number; src: AuditSource; id: string };

export const AUDIT_PAGE_SIZE = 50;
const MAX_FILTER_CHARS = 200;

export function encodeAuditCursor(cursor: AuditCursor): string {
  return `${cursor.t}~${cursor.src}~${cursor.id}`;
}

export function parseAuditCursor(value: string | undefined | null): AuditCursor | null {
  if (!value) return null;
  const match = /^(\d{1,12})~([ck])~([A-Za-z0-9-]{1,64})$/.exec(value);
  if (!match) return null;
  return { t: Number(match[1]), src: match[2] as AuditSource, id: match[3]! };
}

function cleanText(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > MAX_FILTER_CHARS) return undefined;
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) return undefined;
  return trimmed;
}

function dateToSeconds(value: unknown, endOfDay: boolean): number | undefined {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return undefined;
  const ms = Date.parse(`${value}T00:00:00Z`);
  if (Number.isNaN(ms)) return undefined;
  return Math.floor(ms / 1000) + (endOfDay ? 86_400 : 0);
}

/** Reads filters from page search params; dates are UTC calendar days. */
export function auditFiltersFromParams(
  params: Record<string, string | string[] | undefined>,
): AuditFilters {
  const one = (key: string) => {
    const value = params[key];
    return Array.isArray(value) ? value[0] : value;
  };
  const filters: AuditFilters = {
    actor: cleanText(one("actor")),
    action: cleanText(one("action")),
    target_type: cleanText(one("target_type")),
    target_id: cleanText(one("target_id")),
    since: dateToSeconds(one("from"), false),
    until: dateToSeconds(one("to"), true),
  };
  if (filters.since !== undefined && filters.until !== undefined && filters.since >= filters.until) {
    filters.until = undefined;
  }
  return filters;
}

/** Coordinator query string for one page after `cursor`. */
export function coordinatorAuditQuery(
  filters: AuditFilters,
  cursor: AuditCursor | null,
  limit: number,
): URLSearchParams {
  const query = new URLSearchParams({ limit: String(limit) });
  for (const key of ["actor", "action", "target_type", "target_id"] as const) {
    if (filters[key]) query.set(key, filters[key]!);
  }
  if (filters.since !== undefined) query.set("since", String(filters.since));
  let until = filters.until;
  if (cursor?.src === "c") {
    query.set("before", `${cursor.t}:${cursor.id}`);
  } else if (cursor?.src === "k") {
    // Every coordinator row in second t sorts before the console cursor row.
    until = until === undefined ? cursor.t : Math.min(until, cursor.t);
  }
  if (until !== undefined) query.set("until", String(until));
  return query;
}

export function sourceOf(event: AuditEventView): AuditSource {
  return event.id.startsWith("console:") ? "k" : "c";
}

export function cursorOf(event: AuditEventView): AuditCursor {
  const src = sourceOf(event);
  return {
    t: event.created_at,
    src,
    id: src === "k" ? event.id.slice("console:".length) : event.id,
  };
}

/**
 * Two-way merge of pages that are each already in timeline order. Takes at
 * most `limit` rows; there is a next page when anything fetched was left
 * over or either store returned a full page.
 */
export function mergeAuditPages(
  coordinator: AuditEventView[],
  consoleEvents: AuditEventView[],
  limit: number,
): { events: AuditEventView[]; next: string | null } {
  const events: AuditEventView[] = [];
  let i = 0;
  let j = 0;
  while (events.length < limit && (i < coordinator.length || j < consoleEvents.length)) {
    const left = coordinator[i];
    const right = consoleEvents[j];
    if (left && (!right || left.created_at >= right.created_at)) {
      events.push(left);
      i += 1;
    } else {
      events.push(right!);
      j += 1;
    }
  }
  const leftover = i < coordinator.length || j < consoleEvents.length;
  const full = coordinator.length >= limit || consoleEvents.length >= limit;
  const last = events[events.length - 1];
  return {
    events,
    next: last && (leftover || full) ? encodeAuditCursor(cursorOf(last)) : null,
  };
}

const SENSITIVE_KEY =
  /(secret|password|passwd|token|private_?key|api_?key|authorization|cookie|signature|psk)/i;
const SAFE_SUFFIX = /(_prefix|_id|_at|_count|_expires|_ttl)$/i;
export const REDACTED = "[redacted]";

function secretLooking(value: string): boolean {
  return (
    (value.length >= 20 && /^bt[a-z]_/.test(value)) ||
    value.includes("-----BEGIN") ||
    (value.startsWith("eyJ") && value.split(".").length === 3)
  );
}

/** Mirrors the coordinator's read-time redaction for console-side rows. */
export function redactDetails(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactDetails);
  if (typeof value === "string") return secretLooking(value) ? REDACTED : value;
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, nested]) => [
        key,
        SENSITIVE_KEY.test(key) && !SAFE_SUFFIX.test(key) && nested !== null
          ? REDACTED
          : redactDetails(nested),
      ]),
    );
  }
  return value;
}

function csvCell(value: string): string {
  const guarded = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return `"${guarded.replace(/"/g, '""')}"`;
}

export function auditCsv(events: AuditEventView[]): string {
  const header =
    "created_at,id,actor_user_id,actor_name,actor_email,actor_role,action,target_type,target_id,details";
  const rows = events.map((event) =>
    [
      new Date(event.created_at * 1000).toISOString(),
      event.id,
      event.actor_user_id,
      event.actor_name,
      event.actor_email,
      event.actor_role,
      event.action,
      event.target_type,
      event.target_id ?? "",
      JSON.stringify(redactDetails(event.details)),
    ]
      .map(csvCell)
      .join(","),
  );
  return [header, ...rows].join("\r\n") + "\r\n";
}
