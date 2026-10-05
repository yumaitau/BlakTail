import { errorText } from "@/lib/server-errors";
import {
  auditCsv,
  auditFiltersFromParams,
  cursorOf,
  mergeAuditPages,
  redactDetails,
  type AuditCursor,
  type AuditEventView,
} from "@/lib/audit-view";
import { listConsoleAuditPage } from "@/lib/console-audit";
import { exportCoordinatorAudit } from "@/lib/coord-events";
import { permissionReason } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

export const dynamic = "force-dynamic";

const MAX_CONSOLE_ROWS = 10_000;
const PAGE = 500;

// Downloads the merged coordinator + console audit trail. The coordinator
// enforces export_audit itself and records the export as `audit.exported`.
export async function GET(request: Request): Promise<Response> {
  const ctx = await requireConsoleContext();
  const denied = permissionReason(ctx.role, "export_audit");
  if (denied) {
    return Response.json({ error: denied }, { status: 403 });
  }
  const url = new URL(request.url);
  const format = url.searchParams.get("format") === "json" ? "json" : "csv";
  const filters = auditFiltersFromParams(Object.fromEntries(url.searchParams));

  let coordinator: { data: AuditEventView[]; truncated: boolean };
  try {
    coordinator = await exportCoordinatorAudit(ctx, filters);
  } catch (error) {
    const message = errorText(error, "Export failed.");
    return Response.json({ error: message }, { status: 502 });
  }
  const consoleEvents: AuditEventView[] = [];
  let cursor: AuditCursor | null = null;
  let consoleTruncated = false;
  for (;;) {
    const page = await listConsoleAuditPage(ctx, filters, cursor, PAGE);
    consoleEvents.push(...page);
    if (page.length < PAGE) break;
    if (consoleEvents.length >= MAX_CONSOLE_ROWS) {
      consoleTruncated = true;
      break;
    }
    cursor = cursorOf(page[page.length - 1]!);
  }
  const total = coordinator.data.length + consoleEvents.length;
  const { events } = mergeAuditPages(coordinator.data, consoleEvents, total);
  const truncated = coordinator.truncated || consoleTruncated;
  const stamp = new Date().toISOString().slice(0, 10);
  const headers = new Headers({
    "cache-control": "no-store",
    "x-blaktail-export-truncated": String(truncated),
    "content-disposition": `attachment; filename="blaktail-audit-${stamp}.${format}"`,
  });
  if (format === "json") {
    headers.set("content-type", "application/json");
    const data = events.map((event) => ({ ...event, details: redactDetails(event.details) }));
    return new Response(JSON.stringify({ data, truncated }, null, 2), { headers });
  }
  headers.set("content-type", "text/csv; charset=utf-8");
  return new Response(auditCsv(events), { headers });
}
