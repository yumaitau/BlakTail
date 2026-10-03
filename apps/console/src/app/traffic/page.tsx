import Link from "next/link";
import { ConsoleShell } from "@/components/console-shell";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { TrafficSettingsForm } from "@/components/traffic-settings";
import { getTrafficSummary, type TrafficCounter, type TrafficSummary } from "@/lib/coord-events";
import { permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

type SearchParams = Record<string, string | string[] | undefined>;
const WINDOWS = [6, 24, 72, 168];

function bytes(value: number): string {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function utc(seconds: number): string {
  return new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
}

const STATE_COPY: Record<TrafficSummary["state"], { badge: string; title: string; body: string }> = {
  disabled: {
    badge: "badge revoked",
    title: "Traffic diagnostics are off",
    body: "No traffic records are accepted for this organisation. Only an owner can turn collection on. Administrative changes are in the audit log, which is separate and never stands in for traffic data.",
  },
  no_data: {
    badge: "badge pending",
    title: "On, but no device has reported",
    body: "Collection is on, but no records arrived in this window. Agents report about once a minute while collection is on; Android phones and older agents do not report, so an empty view does not mean there was no traffic.",
  },
  stale: {
    badge: "badge warn",
    title: "Reports are stale",
    body: "The newest record is more than two hours old. Devices may be offline or have stopped reporting; recent traffic is missing from these figures.",
  },
  current: {
    badge: "badge online",
    title: "Receiving reports",
    body: "Figures are device-reported aggregate counters.",
  },
};

function CounterCells({ counter }: { counter: TrafficCounter }) {
  return (
    <>
      <td>{bytes(counter.bytes)}</td>
      <td>{counter.packets.toLocaleString("en-AU")}</td>
      <td>{counter.records.toLocaleString("en-AU")}</td>
    </>
  );
}

function Breakdown({ title, rows }: { title: string; rows: Record<string, TrafficCounter> }) {
  const entries = Object.entries(rows).sort((a, b) => b[1].bytes - a[1].bytes);
  if (entries.length === 0) return null;
  return (
    <div className="table-wrap">
      <table className="table">
        <caption className="muted">{title}</caption>
        <thead>
          <tr>
            <th scope="col">{title}</th>
            <th scope="col">Bytes</th>
            <th scope="col">Packets</th>
            <th scope="col">Records</th>
          </tr>
        </thead>
        <tbody>
          {entries.slice(0, 12).map(([name, counter]) => (
            <tr key={name}>
              <td className="mono">{name.replace("_", " ")}</td>
              <CounterCells counter={counter} />
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default async function TrafficPage({ searchParams }: { searchParams: Promise<SearchParams> }) {
  const ctx = await requireConsoleContext();
  const params = await searchParams;
  const requested = Number(Array.isArray(params.hours) ? params.hours[0] : params.hours);
  const hours = WINDOWS.includes(requested) ? requested : 24;
  let summary: TrafficSummary | null = null;
  let error: string | null = null;
  try {
    summary = await getTrafficSummary(ctx, hours);
  } catch (err) {
    error = err instanceof Error ? err.message : "Could not load traffic diagnostics.";
  }
  const settingsDenied = permissionReason(ctx.role, "manage_security");
  const copy = summary ? STATE_COPY[summary.state] : null;

  return (
    <ConsoleShell ctx={ctx} current="/traffic">
      <div className="stack">
        <PageHeader
          title="Traffic"
          description={`Opt-in aggregate traffic diagnostics for ${ctx.organisationName}. Off by default. No payloads, URLs, DNS questions or host names are accepted.`}
        />
        {error ? (
          <div className="panel">
            <p className="error">{error}</p>
          </div>
        ) : null}
        {summary && copy ? (
          <>
            <div className="panel stack">
              <div className="row">
                <span className={copy.badge}>{summary.state.replace("_", " ")}</span>
                <strong>{copy.title}</strong>
              </div>
              <p className="muted">{copy.body}</p>
              <p className="muted">
                Data source: {summary.confidence.source.replace("_", " ")} · confidence{" "}
                {summary.confidence.level}. {summary.confidence.detail}
              </p>
              {summary.last_received_at ? (
                <p className="muted mono">Last report received {utc(summary.last_received_at)}</p>
              ) : null}
              <nav className="filter-row" aria-label="Time window">
                {WINDOWS.map((window) => (
                  <Link
                    key={window}
                    href={`/traffic?hours=${window}`}
                    className={window === hours ? "filter-chip active" : "filter-chip"}
                    aria-current={window === hours ? "page" : undefined}
                  >
                    {window < 48 ? `${window} h` : `${window / 24} days`}
                  </Link>
                ))}
              </nav>
            </div>

            {summary.buckets.length === 0 ? (
              <div className="panel">
                <EmptyState
                  title="No traffic records in this window"
                  body="Nothing to chart. See the status above for why."
                />
              </div>
            ) : (
              <div className="panel stack">
                <div className="table-wrap">
                  <table className="table">
                    <caption className="muted">Totals, last {hours} hours (UTC)</caption>
                    <thead>
                      <tr>
                        <th scope="col">Decision</th>
                        <th scope="col">Bytes</th>
                        <th scope="col">Packets</th>
                        <th scope="col">Records</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td>Allowed</td>
                        <CounterCells counter={summary.allowed} />
                      </tr>
                      <tr>
                        <td>Denied</td>
                        <CounterCells counter={summary.denied} />
                      </tr>
                    </tbody>
                  </table>
                </div>
                <Breakdown title="Transport" rows={summary.by_transport} />
                <Breakdown title="Service class" rows={summary.by_service} />
                <Breakdown title="Who started the flow" rows={summary.by_direction ?? {}} />
                <div className="table-wrap">
                  <table className="table">
                    <caption className="muted">Hourly buckets (UTC)</caption>
                    <thead>
                      <tr>
                        <th scope="col">Hour starting</th>
                        <th scope="col">Allowed bytes</th>
                        <th scope="col">Denied bytes</th>
                        <th scope="col">Records</th>
                      </tr>
                    </thead>
                    <tbody>
                      {summary.buckets
                        .slice()
                        .reverse()
                        .map((bucket) => (
                          <tr key={bucket.start}>
                            <td className="mono">{utc(bucket.start)}</td>
                            <td>{bytes(bucket.allowed.bytes)}</td>
                            <td>{bytes(bucket.denied.bytes)}</td>
                            <td>{bucket.allowed.records + bucket.denied.records}</td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            <div className="panel stack">
              <h2>Collection settings</h2>
              <p className="muted">
                {ctx.organisationName} · {roleLabel(ctx.role)}. Turning collection on or off,
                and deleting records, is recorded in the audit log. Records older than the
                retention period are deleted automatically; storage is capped at 200,000 records.
              </p>
              <TrafficSettingsForm
                settings={summary.settings}
                disabledReason={settingsDenied ? `Only owners can change traffic collection. ${settingsDenied}` : null}
              />
            </div>
          </>
        ) : null}
      </div>
    </ConsoleShell>
  );
}
