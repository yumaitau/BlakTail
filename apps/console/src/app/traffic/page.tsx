import { Suspense } from "react";
import Link from "next/link";
import { Calendar, Download, Funnel, RefreshCw, Rows3, Search } from "lucide-react";
import { ConsoleShell } from "@/components/console-shell";
import { errorText } from "@/lib/server-errors";
import { Alert, Card, EmptyState, PageHeader, Section, SkeletonTable } from "@/components/ui";
import { TrafficEventsTable } from "@/components/traffic-events-table";
import { TrafficSettingsForm } from "@/components/traffic-settings";
import { listNodes, type CoordNode } from "@/lib/coord";
import { getTrafficSummary, listTrafficFlows, type TrafficSummary } from "@/lib/coord-events";
import { listNetworks, type NetworksOverview } from "@/lib/coord-networks";
import { permissionReason } from "@/lib/roles";
import { requireConsoleContext, type ConsoleContext } from "@/lib/session";
import {
  CONNECTION_TYPES,
  DIRECTIONS,
  EVENT_TYPES,
  PAGE_SIZES,
  PROTOCOLS,
  TIME_RANGES,
  coordinatorTrafficQuery,
  formatDate,
  formatTime,
  popoverFilterCount,
  trafficFiltersFromParams,
  trafficSearch,
  type FlowsPage,
  type TrafficFilters,
  type TrafficState,
} from "@/lib/traffic-view";

export const dynamic = "force-dynamic";

type SearchParams = Record<string, string | string[] | undefined>;

const STATE_COPY: Record<TrafficState, { badge: string; label: string }> = {
  disabled: { badge: "badge revoked", label: "Off" },
  no_data: { badge: "badge pending", label: "On, waiting for reports" },
  stale: { badge: "badge warn", label: "Reports are stale" },
  current: { badge: "badge online", label: "Receiving reports" },
};

const PROTOCOL_COPY: Record<string, string> = {
  tcp: "TCP",
  udp: "UDP",
  icmp: "ICMP",
  icmpv6: "ICMPv6",
  other: "Other IP protocols",
};
const DIRECTION_COPY: Record<string, string> = {
  inbound: "Inbound (received by the reporting device)",
  outbound: "Outbound (started by the reporting device)",
};
const EVENT_COPY: Record<string, string> = {
  start: "Connection started",
  end: "Connection ended",
  drop: "Blocked",
};
const CONNECTION_COPY: Record<string, string> = {
  p2p: "Direct",
  routed: "Through a routing peer",
  relay: "Through a relay",
};

function summaryHours(range: string): number {
  return { "1h": 1, "24h": 24, "2d": 48, "7d": 168 }[range] ?? 24;
}

function deviceName(node: CoordNode): string {
  return node.display_name || node.name;
}

function load(ctx: ConsoleContext, filters: TrafficFilters) {
  const now = Math.floor(Date.now() / 1000);
  return Promise.allSettled([
    listTrafficFlows(ctx, coordinatorTrafficQuery(filters, now)),
    getTrafficSummary(ctx, summaryHours(filters.range)),
    listNodes(ctx),
    listNetworks(ctx),
  ]);
}

export default async function TrafficPage({ searchParams }: { searchParams: Promise<SearchParams> }) {
  const ctx = await requireConsoleContext();
  const params = await searchParams;
  return (
    <ConsoleShell ctx={ctx} current="/traffic">
      <div className="stack">
        <PageHeader
          title="Traffic events"
          description={`Opt-in, per-connection events for ${ctx.organisationName}: who connected to what, on which protocol and port, through which routing peer, and which policy rule decided. Off by default. Overlay addresses and ports only — never payloads, URLs, DNS names or web data.`}
        />
        <Suspense
          key={JSON.stringify(params)}
          fallback={
            <Card>
              <SkeletonTable rows={8} label="Loading traffic events" />
            </Card>
          }
        >
          <TrafficContent ctx={ctx} params={params} />
        </Suspense>
      </div>
    </ConsoleShell>
  );
}

async function TrafficContent({ ctx, params }: { ctx: ConsoleContext; params: SearchParams }) {
  const filters = trafficFiltersFromParams(params);
  const [flowsResult, summaryResult, nodesResult, networksResult] = await load(ctx, filters);
  const page: FlowsPage | null = flowsResult.status === "fulfilled" ? flowsResult.value : null;
  const error =
    flowsResult.status === "rejected"
      ? errorText(flowsResult.reason, "Could not load traffic events.")
      : null;
  const summary: TrafficSummary | null =
    summaryResult.status === "fulfilled" ? summaryResult.value : null;
  const nodes: CoordNode[] =
    nodesResult.status === "fulfilled"
      ? [...nodesResult.value].sort((a, b) => deviceName(a).localeCompare(deviceName(b)))
      : [];
  const networks: NetworksOverview | null =
    networksResult.status === "fulfilled" ? networksResult.value : null;
  const resources = (networks?.resources ?? []).filter((resource) => resource.cidr);
  const routes = Array.from(
    new Set((networks?.device_routes ?? []).flatMap((device) => device.approved_routes)),
  ).sort();

  const settingsDenied = permissionReason(ctx.role, "manage_security");
  const exportDenied = permissionReason(ctx.role, "export_audit");
  const state = page?.state ?? summary?.state ?? null;
  const settings = page?.settings ?? summary?.settings ?? null;
  const filterCount = popoverFilterCount(filters);
  const narrowed =
    filterCount > 0 || Boolean(filters.q || filters.source || filters.destination);
  const current = trafficSearch(filters, { cursor: undefined });

  return (
    <>
        {state && settings ? (
          <section className="panel traffic-header" aria-label="Collection status">
            <div className="row">
              <span className={STATE_COPY[state].badge}>{STATE_COPY[state].label}</span>
              <span className="muted">
                Sampling {Math.round(settings.sampling_rate * 100)}% · kept {settings.retention_days}{" "}
                {settings.retention_days === 1 ? "day" : "days"}
              </span>
            </div>
            <dl className="traffic-stats">
              <div>
                <dt>Reporting devices (24 h)</dt>
                <dd>{page ? page.reporting_devices.toLocaleString("en-AU") : "–"}</dd>
              </div>
              <div>
                <dt>Last event received</dt>
                <dd>
                  {page?.last_received_at
                    ? `${formatDate(page.last_received_at)}, ${formatTime(page.last_received_at)}`
                    : "Never"}
                </dd>
              </div>
              {summary ? (
                <>
                  <div>
                    <dt>Allowed aggregates ({summaryHours(filters.range)} h)</dt>
                    <dd>{summary.allowed.records.toLocaleString("en-AU")} records</dd>
                  </div>
                  <div>
                    <dt>Denied aggregates ({summaryHours(filters.range)} h)</dt>
                    <dd>{summary.denied.records.toLocaleString("en-AU")} records</dd>
                  </div>
                </>
              ) : null}
            </dl>
            {state === "stale" ? (
              <Alert tone="warning" title="Reports are stale">
                The newest event is more than two hours old. Devices may be offline or have stopped
                reporting, so recent connections are missing.
              </Alert>
            ) : null}
          </section>
        ) : null}

        <form method="get" action="/traffic" className="traffic-toolbar" role="search" aria-label="Filter traffic events">
          <label className="traffic-search">
            <span className="visually-hidden">Search</span>
            <Search aria-hidden="true" size={16} />
            <input
              type="search"
              name="q"
              defaultValue={filters.q ?? ""}
              placeholder="Search names, addresses, ports, rules"
              maxLength={100}
            />
          </label>
          <label className="traffic-field">
            <span className="visually-hidden">Time range</span>
            <Calendar aria-hidden="true" size={16} />
            <select name="range" defaultValue={filters.range}>
              {TIME_RANGES.map((range) => (
                <option key={range.value} value={range.value}>
                  {range.label}
                </option>
              ))}
            </select>
          </label>
          <label className="traffic-field">
            <span className="visually-hidden">Source</span>
            <select name="source" defaultValue={filters.source ?? ""}>
              <option value="">All sources</option>
              <optgroup label="Devices">
                {nodes.map((node) => (
                  <option key={node.id} value={node.id}>
                    {deviceName(node)}
                  </option>
                ))}
              </optgroup>
              {resources.length > 0 ? (
                <optgroup label="Network resources">
                  {resources.map((resource) => (
                    <option key={resource.id} value={resource.id}>
                      {resource.name}
                    </option>
                  ))}
                </optgroup>
              ) : null}
            </select>
          </label>
          <label className="traffic-field">
            <span className="visually-hidden">Destination</span>
            <select name="destination" defaultValue={filters.destination ?? ""}>
              <option value="">All destinations</option>
              <optgroup label="Devices">
                {nodes.map((node) => (
                  <option key={node.id} value={node.id}>
                    {deviceName(node)}
                  </option>
                ))}
              </optgroup>
              {resources.length > 0 ? (
                <optgroup label="Network resources">
                  {resources.map((resource) => (
                    <option key={resource.id} value={resource.id}>
                      {resource.name} ({resource.cidr})
                    </option>
                  ))}
                </optgroup>
              ) : null}
              {routes.length > 0 ? (
                <optgroup label="Approved routes">
                  {routes.map((route) => (
                    <option key={route} value={route}>
                      {route}
                    </option>
                  ))}
                </optgroup>
              ) : null}
            </select>
          </label>
          <details className="traffic-popover">
            <summary className="button secondary">
              <Funnel aria-hidden="true" size={16} />
              Filter{filterCount > 0 ? ` (${filterCount})` : ""}
            </summary>
            <div className="traffic-popover-body">
              <fieldset>
                <legend>Protocol</legend>
                <select name="protocol" defaultValue={filters.protocol ?? ""} aria-label="Protocol">
                  <option value="">Any protocol</option>
                  {PROTOCOLS.map((value) => (
                    <option key={value} value={value}>
                      {PROTOCOL_COPY[value]}
                    </option>
                  ))}
                </select>
              </fieldset>
              <label>
                Port
                <input
                  type="number"
                  name="port"
                  min={0}
                  max={65535}
                  inputMode="numeric"
                  defaultValue={filters.port ?? ""}
                  placeholder="Any"
                />
              </label>
              <label>
                IP address
                <input type="text" name="ip" defaultValue={filters.ip ?? ""} placeholder="100.64.0.2" />
              </label>
              <label>
                Direction
                <select name="direction" defaultValue={filters.direction ?? ""}>
                  <option value="">Either direction</option>
                  {DIRECTIONS.map((value) => (
                    <option key={value} value={value}>
                      {DIRECTION_COPY[value]}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Event
                <select name="event_type" defaultValue={filters.event_type ?? ""}>
                  <option value="">Any event</option>
                  {EVENT_TYPES.map((value) => (
                    <option key={value} value={value}>
                      {EVENT_COPY[value]}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Connection
                <select name="connection_type" defaultValue={filters.connection_type ?? ""}>
                  <option value="">Any path</option>
                  {CONNECTION_TYPES.map((value) => (
                    <option key={value} value={value}>
                      {CONNECTION_COPY[value]}
                    </option>
                  ))}
                </select>
              </label>
              <fieldset>
                <legend>Custom range (UTC, with “Custom range” selected)</legend>
                <label>
                  From
                  <input type="datetime-local" name="from" defaultValue={filters.from ?? ""} />
                </label>
                <label>
                  To
                  <input type="datetime-local" name="to" defaultValue={filters.to ?? ""} />
                </label>
              </fieldset>
            </div>
          </details>
          <label className="traffic-field">
            <span className="visually-hidden">Rows per page</span>
            <Rows3 aria-hidden="true" size={16} />
            <select name="limit" defaultValue={String(filters.limit)}>
              {PAGE_SIZES.map((size) => (
                <option key={size} value={size}>
                  {size} rows per page
                </option>
              ))}
            </select>
          </label>
          <div className="traffic-actions">
            <button type="submit">Apply</button>
            <Link href={`/traffic${current}`} className="button secondary" aria-label="Refresh">
              <RefreshCw aria-hidden="true" size={16} />
              <span className="traffic-action-text">Refresh</span>
            </Link>
            {narrowed ? (
              <Link href="/traffic" className="button secondary">
                Clear filters
              </Link>
            ) : null}
            {exportDenied ? null : (
              <a href={`/traffic/export${current}`} className="button secondary" download>
                <Download aria-hidden="true" size={16} />
                <span className="traffic-action-text">Export CSV</span>
              </a>
            )}
          </div>
        </form>
        {exportDenied ? <Alert tone="info">CSV export isn&apos;t available: {exportDenied}</Alert> : null}

        {error ? (
          <Alert tone="error" title="Traffic events couldn't be loaded">
            {error}
          </Alert>
        ) : null}

        {page ? (
          page.flows.length === 0 ? (
            <div className="panel">
              {page.state === "disabled" ? (
                <EmptyState
                  title="Traffic events are off"
                  body="No connection events are collected for this organisation. An owner can turn collection on under Collection settings below; devices then report within about a minute."
                />
              ) : page.state === "no_data" ? (
                <EmptyState
                  title="On, but no device has reported yet"
                  body="Collection is on and no events have arrived. Linux, Windows, iOS and Android agents report per-connection events; macOS reports filter counters only. Older agents do not report, so an empty view does not mean there was no traffic."
                />
              ) : (
                <EmptyState
                  title="No traffic events match"
                  body={
                    narrowed
                      ? "Nothing in this time range matches these filters. Widen the range or clear the filters."
                      : "No events were reported in this time range."
                  }
                />
              )}
            </div>
          ) : (
            <section className="panel table-panel stack" aria-label="Traffic events">
              {page.state === "disabled" ? (
                <p className="muted" role="status">
                  Collection is off. These are events kept from before it was turned off; they are
                  deleted when the retention period ends.
                </p>
              ) : null}
              <TrafficEventsTable
                flows={page.flows}
                caption={`Traffic events, newest first. Times in UTC. ${page.flows.length} connections on this page.`}
              />
              <nav className="traffic-pager" aria-label="Pages">
                <span className="muted">
                  {page.flows.length.toLocaleString("en-AU")} connections on this page · times in UTC
                </span>
                <span className="row">
                  {filters.cursor ? (
                    <Link href={`/traffic${current}`} className="button secondary">
                      Newest
                    </Link>
                  ) : null}
                  {page.next_cursor ? (
                    <Link
                      href={`/traffic${trafficSearch(filters, { cursor: page.next_cursor })}`}
                      className="button secondary"
                    >
                      Older
                    </Link>
                  ) : null}
                </span>
              </nav>
            </section>
          )
        ) : null}

        {settings ? (
          <Section
            id="traffic-settings"
            title="Collection settings"
            description="When collection is on, each connection's overlay addresses and ports, protocol, the devices, resources or routes involved, the routing peer, the matched policy rule and byte counts are stored. Turning it on or off, exporting and deleting are audited. Events older than the retention period are deleted automatically; storage is capped at 500,000 events."
          >
            <TrafficSettingsForm
              settings={settings}
              disabledReason={
                settingsDenied ? `Only owners can change traffic collection. ${settingsDenied}` : null
              }
            />
          </Section>
        ) : null}
    </>
  );
}
