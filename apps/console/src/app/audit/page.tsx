import Link from "next/link";
import { ConsoleShell } from "@/components/console-shell";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import {
  AUDIT_PAGE_SIZE,
  auditFiltersFromParams,
  coordinatorAuditQuery,
  mergeAuditPages,
  parseAuditCursor,
  redactDetails,
  type AuditEventView,
  type AuditFilters,
} from "@/lib/audit-view";
import { listConsoleAuditPage } from "@/lib/console-audit";
import { listAuditPage, verifyAuditChain, type ChainReport } from "@/lib/coord-events";
import { permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

type SearchParams = Record<string, string | string[] | undefined>;

function actor(event: AuditEventView) {
  return event.actor_email || event.actor_name || event.actor_user_id;
}

function nodeTone(action: string): "success" | "warning" | "danger" | undefined {
  if (/revok|delete|deny|disable|tombstone|suspend/i.test(action)) return "danger";
  if (/expir|conflict|fail|export/i.test(action)) return "warning";
  if (/approv|create|link|save|mint/i.test(action)) return "success";
  return undefined;
}

function one(params: SearchParams, key: string): string {
  const value = params[key];
  return (Array.isArray(value) ? value[0] : value) ?? "";
}

function filterQuery(params: SearchParams, extra: Record<string, string> = {}): string {
  const query = new URLSearchParams();
  for (const key of ["actor", "action", "target_type", "target_id", "from", "to"]) {
    const value = one(params, key).trim();
    if (value) query.set(key, value);
  }
  for (const [key, value] of Object.entries(extra)) query.set(key, value);
  return query.toString();
}

function hasFilters(filters: AuditFilters): boolean {
  return Object.values(filters).some((value) => value !== undefined);
}

export default async function AuditPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const ctx = await requireConsoleContext();
  const params = await searchParams;
  const filters = auditFiltersFromParams(params);
  const cursor = parseAuditCursor(one(params, "cursor"));
  let events: AuditEventView[] = [];
  let next: string | null = null;
  let error: string | null = null;
  let chain: ChainReport | null = null;
  try {
    const [coordinatorEvents, consoleEvents, report] = await Promise.all([
      listAuditPage(ctx, coordinatorAuditQuery(filters, cursor, AUDIT_PAGE_SIZE)),
      listConsoleAuditPage(ctx, filters, cursor, AUDIT_PAGE_SIZE),
      cursor ? Promise.resolve(null) : verifyAuditChain(ctx).catch(() => null),
    ]);
    ({ events, next } = mergeAuditPages(coordinatorEvents, consoleEvents, AUDIT_PAGE_SIZE));
    chain = report;
  } catch (err) {
    error = err instanceof Error ? err.message : "Could not load audit events.";
  }
  const exportDenied = permissionReason(ctx.role, "export_audit");

  return (
    <ConsoleShell ctx={ctx} current="/audit">
      <div className="stack">
        <PageHeader
          title="Audit log"
          description={`Administrative changes for ${ctx.organisationName}, newest first. Times are UTC. Network traffic is not recorded here; see Traffic.`}
        />
        <form className="panel audit-filters" method="get" action="/audit" aria-label="Filter audit events">
          <label>
            Actor
            <input name="actor" defaultValue={one(params, "actor")} maxLength={200} placeholder="email or user id" />
          </label>
          <label>
            Action
            <input name="action" defaultValue={one(params, "action")} maxLength={200} placeholder="node.* or acl.updated" />
          </label>
          <label>
            Target type
            <input name="target_type" defaultValue={one(params, "target_type")} maxLength={200} placeholder="node" />
          </label>
          <label>
            Target id
            <input name="target_id" defaultValue={one(params, "target_id")} maxLength={200} />
          </label>
          <label>
            From (UTC)
            <input type="date" name="from" defaultValue={one(params, "from")} />
          </label>
          <label>
            To (UTC, inclusive)
            <input type="date" name="to" defaultValue={one(params, "to")} />
          </label>
          <div className="row">
            <button type="submit">Apply filters</button>
            {hasFilters(filters) ? (
              <Link className="button secondary" href="/audit">
                Clear
              </Link>
            ) : null}
          </div>
        </form>

        <div className="panel stack">
          <div className="row">
            <span>
              {ctx.organisationName} · {roleLabel(ctx.role)}
            </span>
            {exportDenied ? (
              <span className="muted">Export: {exportDenied}</span>
            ) : (
              <>
                <a className="button secondary" href={`/audit/export?${filterQuery(params, { format: "csv" })}`}>
                  Export CSV
                </a>
                <a className="button secondary" href={`/audit/export?${filterQuery(params, { format: "json" })}`}>
                  Export JSON
                </a>
              </>
            )}
          </div>
          <p className="muted">
            Exports use the filters above, are capped at 10,000 coordinator events and are themselves
            recorded in this log. Secrets, tokens and passwords in event details are shown as
            [redacted].
          </p>
          {chain ? (
            <p className={chain.intact ? "muted" : "error"} role="status">
              {chain.intact
                ? `Integrity chain intact: ${chain.chained_events} coordinator events verified.`
                : `Integrity chain problem: ${chain.problems.join("; ")}`}{" "}
              {chain.unchained_events > 0
                ? `${chain.unchained_events} older or console events are not chained.`
                : ""}
            </p>
          ) : null}
        </div>

        <div className="panel">
          {error ? <p className="error">{error}</p> : null}
          {!error && events.length === 0 ? (
            <EmptyState
              title={hasFilters(filters) || cursor ? "No matching events" : "No audited changes yet"}
              body={
                hasFilters(filters) || cursor
                  ? "Nothing in the retention window matches these filters."
                  : "Approvals, invitations, and policy edits will appear here as a trail through this organisation."
              }
            />
          ) : null}
          {events.length > 0 ? (
            <ol className="audit-trail">
              {events.map((event) => (
                <li key={event.id} className="audit-event">
                  <span
                    className={["audit-node", nodeTone(event.action)].filter(Boolean).join(" ")}
                    aria-hidden="true"
                  />
                  <strong>{event.action}</strong>
                  <div>
                    {actor(event)}
                    {event.actor_role ? ` · ${event.actor_role}` : ""}
                    {event.target_type ? ` · ${event.target_type}` : ""}
                  </div>
                  <div className="muted mono">
                    {new Date(event.created_at * 1000).toISOString()}
                    {event.target_id ? ` · ${event.target_id}` : ""}
                  </div>
                  <details>
                    <summary>Details</summary>
                    <code className="mono audit-details">
                      {JSON.stringify(redactDetails(event.details), null, 2)}
                    </code>
                  </details>
                </li>
              ))}
            </ol>
          ) : null}
          <div className="row">
            {cursor ? (
              <Link className="button secondary" href={`/audit?${filterQuery(params)}`}>
                Newest
              </Link>
            ) : null}
            {next ? (
              <Link className="button secondary" href={`/audit?${filterQuery(params, { cursor: next })}`}>
                Older events
              </Link>
            ) : events.length > 0 ? (
              <span className="muted">End of the retained log.</span>
            ) : null}
          </div>
        </div>
      </div>
    </ConsoleShell>
  );
}
