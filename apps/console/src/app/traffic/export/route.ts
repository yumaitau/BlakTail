import { exportTrafficEvents } from "@/lib/coord-events";
import { permissionReason } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";
import { coordinatorTrafficQuery, trafficFiltersFromParams } from "@/lib/traffic-view";

export const dynamic = "force-dynamic";

// Downloads the traffic events matching the page's filters as CSV. The
// coordinator enforces export_audit itself and records the export as
// `traffic.events_exported`.
export async function GET(request: Request): Promise<Response> {
  const ctx = await requireConsoleContext();
  const denied = permissionReason(ctx.role, "export_audit");
  if (denied) {
    return Response.json({ error: denied }, { status: 403 });
  }
  const url = new URL(request.url);
  const filters = trafficFiltersFromParams(Object.fromEntries(url.searchParams));
  const query = coordinatorTrafficQuery(filters, Math.floor(Date.now() / 1000), {
    paging: false,
  });
  let upstream: Response;
  try {
    upstream = await exportTrafficEvents(ctx, query);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Export failed.";
    return Response.json({ error: message }, { status: 502 });
  }
  const stamp = new Date().toISOString().slice(0, 10);
  const headers = new Headers({
    "cache-control": "no-store",
    "content-type": "text/csv; charset=utf-8",
    "content-disposition": `attachment; filename="blaktail-traffic-events-${stamp}.csv"`,
    "x-blaktail-export-truncated":
      upstream.headers.get("x-blaktail-export-truncated") === "true" ? "true" : "false",
  });
  return new Response(upstream.body, { headers });
}
