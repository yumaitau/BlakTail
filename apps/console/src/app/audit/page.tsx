import { Suspense, type ReactNode } from "react";
import Link from "next/link";
import { Download } from "lucide-react";
import { errorText } from "@/lib/server-errors";
import { ConsoleShell } from "@/components/console-shell";
import {
  Alert,
  Card,
  EmptyState,
  LocalTime,
  PageHeader,
  Section,
  SkeletonTable,
} from "@/components/ui";
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
import { requireConsoleContext, type ConsoleContext } from "@/lib/session";

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

/** A labelled filter input. Server-rendered, so it can't use the client FormField. */
function FilterField({ label, children }: { label: string; children: (id: string) => ReactNode }) {
  const id = `audit-${label.toLowerCase().replace(/[^a-z]+/gu, "-")}`;
  return (
    <div className="ui-field">
      <label htmlFor={id} className="ui-field-label">
        {label}
      </label>
      {children(id)}
    </div>
  );
}

function hasFilters(filters: AuditFilters): boolean {
  return Object.values(filters).some((value) => value !== undefined);
}

export default async function AuditPage({ searchParams }: { searchParams: Promise<SearchParams> }) {
  const ctx = await requireConsoleContext();
  const params = await searchParams;
  const filters = auditFiltersFromParams(params);
  const exportDenied = permissionReason(ctx.role, "export_audit");
  const filtered = hasFilters(filters);

  return (
    <ConsoleShell ctx={ctx} current="/audit">
      <div className="stack">
        <PageHeader
          title="Audit log"
          description={`Administrative changes in ${ctx.organisationName}, newest first. Times are in your time zone; hover for UTC. Network connections aren't recorded here; see Traffic.`}
          actions={
            exportDenied ? null : (
              <>
                <a className="button secondary ui-button" href={`/audit/export?${filterQuery(params, { format: "csv" })}`}>
                  <Download aria-hidden="true" size={16} />
                  <span>Export CSV</span>
                </a>
                <a className="button secondary ui-button" href={`/audit/export?${filterQuery(params, { format: "json" })}`}>
                  <Download aria-hidden="true" size={16} />
                  <span>Export JSON</span>
                </a>
              </>
            )
          }
        />
        <p className="page-context">
          {ctx.organisationName} · {roleLabel(ctx.role)}
          {exportDenied ? "" : " · exports use the filters below, are capped at 10,000 coordinator events and are themselves audited"}
        </p>
        {exportDenied ? <Alert tone="info">Export isn&apos;t available: {exportDenied}</Alert> : null}

        <Section
          title="Filter events"
          description="Secrets, tokens and passwords in event details always show as [redacted]."
        >
          <form className="audit-filters" method="get" action="/audit" aria-label="Filter audit events">
            <FilterField label="Actor">
              {(id) => <input id={id} name="actor" defaultValue={one(params, "actor")} maxLength={200} placeholder="Email or user ID" />}
            </FilterField>
            <FilterField label="Action">
              {(id) => <input id={id} name="action" defaultValue={one(params, "action")} maxLength={200} placeholder="node.* or acl.updated" />}
            </FilterField>
            <FilterField label="Target type">
              {(id) => <input id={id} name="target_type" defaultValue={one(params, "target_type")} maxLength={200} placeholder="node" />}
            </FilterField>
            <FilterField label="Target ID">
              {(id) => <input id={id} name="target_id" defaultValue={one(params, "target_id")} maxLength={200} />}
            </FilterField>
            <FilterField label="From (UTC)">
              {(id) => <input id={id} type="date" name="from" defaultValue={one(params, "from")} />}
            </FilterField>
            <FilterField label="To (UTC, inclusive)">
              {(id) => <input id={id} type="date" name="to" defaultValue={one(params, "to")} />}
            </FilterField>
            <div className="audit-filters-actions">
              <button type="submit" className="ui-button">
                Apply filters
              </button>
              {filtered ? (
                <Link className="button secondary ui-button" href="/audit">
                  Clear
                </Link>
              ) : null}
            </div>
          </form>
        </Section>

        <Suspense
          key={filterQuery(params, { cursor: one(params, "cursor") })}
          fallback={
            <Card>
              <SkeletonTable rows={6} label="Loading audit events" />
            </Card>
          }
        >
          <AuditEvents ctx={ctx} params={params} filters={filters} />
        </Suspense>
      </div>
    </ConsoleShell>
  );
}

async function AuditEvents({
  ctx,
  params,
  filters,
}: {
  ctx: ConsoleContext;
  params: SearchParams;
  filters: AuditFilters;
}) {
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
    error = errorText(err, "Could not load audit events.");
  }
  const narrowed = hasFilters(filters) || Boolean(cursor);

  return (
    <>
      {chain ? (
        chain.intact ? (
          <Alert tone="success" title="Integrity chain intact">
            {chain.chained_events.toLocaleString("en-AU")} coordinator events verified.
            {chain.unchained_events === 1
              ? " 1 older or console event isn't chained."
              : chain.unchained_events > 1
                ? ` ${chain.unchained_events.toLocaleString("en-AU")} older or console events aren't chained.`
                : ""}
          </Alert>
        ) : (
          <Alert tone="error" title="The integrity chain has a problem">
            Some coordinator events don&apos;t match the chain, which can mean the log was changed
            outside BlakTail. Export the log and ask your operator to check the coordinator database.
            ({chain.problems.length} problem{chain.problems.length === 1 ? "" : "s"} found.)
          </Alert>
        )
      ) : null}
      <Card className="stack">
        {error ? (
          <Alert tone="error" title="Audit events couldn't be loaded">
            {error}
          </Alert>
        ) : events.length === 0 ? (
          <EmptyState
            title={narrowed ? "No matching events" : "No audited changes yet"}
            body={
              narrowed
                ? "Nothing in the retention window matches these filters. Widen the dates or clear the filters."
                : "Approvals, invitations and policy changes will appear here as they happen."
            }
            action={
              narrowed ? (
                <Link className="button secondary ui-button" href="/audit">
                  Clear filters
                </Link>
              ) : undefined
            }
          />
        ) : (
          <ol className="audit-trail" aria-label="Audit events, newest first">
            {events.map((event) => (
              <li key={event.id} className="audit-event">
                <span
                  className={["audit-node", nodeTone(event.action)].filter(Boolean).join(" ")}
                  aria-hidden="true"
                />
                <div className="audit-event-head">
                  <strong className="mono">{event.action}</strong>
                  <LocalTime className="muted" value={event.created_at} />
                </div>
                <div>
                  {actor(event)}
                  {event.actor_role ? ` · ${event.actor_role}` : ""}
                  {event.target_type ? ` · ${event.target_type}` : ""}
                </div>
                {event.target_id ? <div className="muted mono cell-break">{event.target_id}</div> : null}
                <details>
                  <summary>Details</summary>
                  <code className="mono audit-details">
                    {JSON.stringify(redactDetails(event.details), null, 2)}
                  </code>
                </details>
              </li>
            ))}
          </ol>
        )}
        {error ? null : (
          <nav className="traffic-pager" aria-label="Pages">
            <span className="muted">
              {events.length > 0 && !next ? "End of the retained log." : `${events.length} events on this page`}
            </span>
            <span className="row">
              {cursor ? (
                <Link className="button secondary ui-button" href={`/audit?${filterQuery(params)}`}>
                  Newest
                </Link>
              ) : null}
              {next ? (
                <Link className="button secondary ui-button" href={`/audit?${filterQuery(params, { cursor: next })}`}>
                  Older events
                </Link>
              ) : null}
            </span>
          </nav>
        )}
      </Card>
    </>
  );
}
