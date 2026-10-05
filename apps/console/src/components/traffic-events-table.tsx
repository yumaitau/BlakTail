import Link from "next/link";
import { LocalTime } from "./ui/local-time";
import {
  ArrowDown,
  ArrowUp,
  ChevronDown,
  CircleQuestionMark,
  Globe,
  Laptop,
  Monitor,
  Route,
  Server,
  Share2,
  Smartphone,
  type LucideIcon,
} from "lucide-react";
import {
  endpointAddress,
  eventSentence,
  flowStatus,
  flowTotals,
  formatBytes,
  policyStep,
  portLabel,
  protocolLabel,
  type FlowEndpoint,
  type FlowEventView,
  type FlowGroup,
  type Segment,
} from "@/lib/traffic-view";

const STATUS_COPY = {
  blocked: "Blocked",
  closed: "Allowed, closed",
  open: "Allowed",
} as const;

const CONNECTION_COPY: Record<FlowEventView["connection_type"], string> = {
  p2p: "Direct (peer to peer)",
  relay: "Through a BlakTail relay",
  routed: "Through a routing peer",
};

function osIcon(os: string | null): { Icon: LucideIcon; label: string } {
  const value = (os ?? "").toLowerCase();
  if (value.includes("ios") || value.includes("android") || value.includes("iphone")) {
    return { Icon: Smartphone, label: "Phone" };
  }
  if (value.includes("mac") || value.includes("darwin") || value.includes("windows")) {
    return { Icon: Laptop, label: value.includes("windows") ? "Windows device" : "macOS device" };
  }
  if (value.includes("linux")) return { Icon: Server, label: "Linux device" };
  return { Icon: Monitor, label: "Device" };
}

function endpointIcon(endpoint: FlowEndpoint): { Icon: LucideIcon; label: string } {
  switch (endpoint.kind) {
    case "device":
      return osIcon(endpoint.os);
    case "resource":
      return { Icon: Globe, label: "Network resource" };
    case "route":
      return { Icon: Route, label: "Approved route" };
    default:
      return { Icon: CircleQuestionMark, label: "Unknown address" };
  }
}

function Sentence({ segments }: { segments: Segment[] }) {
  return (
    <>
      {segments.map((segment, index) =>
        segment.strong ? <strong key={index}>{segment.text}</strong> : <span key={index}>{segment.text}</span>,
      )}
    </>
  );
}

function EndpointCell({ endpoint }: { endpoint: FlowEndpoint }) {
  const { Icon, label } = endpointIcon(endpoint);
  const name =
    endpoint.kind === "unknown" ? "Unknown" : endpoint.name || endpoint.route || endpoint.ip;
  const href =
    endpoint.kind === "device" && endpoint.id
      ? `/devices/${encodeURIComponent(endpoint.id)}`
      : endpoint.kind === "resource" && endpoint.id
        ? `/networks/${encodeURIComponent(endpoint.id)}`
        : null;
  return (
    <div className="traffic-endpoint">
      <span className="traffic-icon" title={label}>
        <Icon aria-hidden="true" size={18} />
        <span className="visually-hidden">{label}: </span>
      </span>
      <span className="traffic-endpoint-text">
        {href ? (
          <Link href={href} className="traffic-name" title={name}>
            {name}
          </Link>
        ) : (
          <span className="traffic-name" title={name}>
            {name}
          </span>
        )}
        <span className="mono muted traffic-address">{endpointAddress(endpoint)}</span>
      </span>
    </div>
  );
}

function Timeline({ group }: { group: FlowGroup }) {
  const policy = policyStep(group);
  const [head, ...rest] = group.events;
  if (!head) return null;
  const blocked = (event: FlowEventView) => event.event_type === "drop";
  return (
    <ol className="traffic-timeline">
      <li className={blocked(head) ? "traffic-step blocked" : "traffic-step"}>
        <LocalTime value={head.at} className="muted" />
        <p>
          <Sentence segments={eventSentence(head)} />
        </p>
      </li>
      {policy ? (
        <li className={group.events.some(blocked) ? "traffic-step blocked" : "traffic-step"}>
          <p>
            {policy.lead ? `${policy.lead} ` : null}
            {policy.href ? <Link href={policy.href}>{policy.label}</Link> : <span>{policy.label}</span>}
            {policy.outcome ? ` ${policy.outcome}` : null}
            {head.rule.hint ? <span className="mono muted traffic-hint"> · device rule {head.rule.hint}</span> : null}
          </p>
        </li>
      ) : null}
      {rest.map((event) => (
        <li key={event.id} className={blocked(event) ? "traffic-step blocked" : "traffic-step"}>
          <LocalTime value={event.at} className="muted" />
          <p>
            <Sentence segments={eventSentence(event)} />
          </p>
        </li>
      ))}
      <li className="traffic-step meta">
        <dl className="traffic-facts">
          <div>
            <dt>Path</dt>
            <dd>{CONNECTION_COPY[head.connection_type]}</dd>
          </div>
          <div>
            <dt>Reported by</dt>
            <dd>{head.reporter.name}</dd>
          </div>
          <div>
            <dt>Packets</dt>
            <dd>
              {flowTotals(group.events).rx_packets.toLocaleString("en-AU")} received ·{" "}
              {flowTotals(group.events).tx_packets.toLocaleString("en-AU")} sent
            </dd>
          </div>
          <div>
            <dt>Flow</dt>
            <dd className="mono">{group.flow_id}</dd>
          </div>
        </dl>
      </li>
    </ol>
  );
}

function FlowRow({ group }: { group: FlowGroup }) {
  const head = group.events[0];
  if (!head) return null;
  const status = flowStatus(group);
  const totals = flowTotals(group.events);
  const port = portLabel(head);
  return (
    <tr className={`traffic-row ${status}`}>
      <td data-label="Time" className="traffic-time">
        <LocalTime value={group.last_at} />
      </td>
      <td data-label="Event" className="traffic-event">
        <details className="traffic-details">
          <summary>
            <span className={`traffic-dot ${status}`} aria-hidden="true" />
            <span className="traffic-summary">
              <span className="traffic-status">{STATUS_COPY[status]}</span>
              {head.aggregated ? <span className="badge pending">aggregated</span> : null}
              <span className="traffic-sentence">
                <Sentence segments={eventSentence(head)} />
              </span>
            </span>
            <ChevronDown aria-hidden="true" size={16} className="traffic-chevron" />
            <span className="visually-hidden">Show the connection timeline</span>
          </summary>
          <Timeline group={group} />
        </details>
      </td>
      <td data-label="Source">
        <EndpointCell endpoint={head.source} />
      </td>
      <td data-label="Protocol and port">
        <span className="traffic-chips">
          <span className="traffic-chip">
            <Share2 aria-hidden="true" size={14} />
            {protocolLabel(head)}
          </span>
          {port ? <span className="traffic-chip">{port}</span> : null}
        </span>
      </td>
      <td data-label="Destination">
        <EndpointCell endpoint={head.destination} />
      </td>
      <td data-label="Traffic">
        {totals.rx_bytes || totals.tx_bytes ? (
          <span className="traffic-bytes">
            <span>
              <ArrowDown aria-label="received" size={14} className="traffic-rx" />
              {formatBytes(totals.rx_bytes)}
            </span>
            <span>
              <ArrowUp aria-label="sent" size={14} className="traffic-tx" />
              {formatBytes(totals.tx_bytes)}
            </span>
          </span>
        ) : (
          <span className="muted" aria-label="no bytes reported">
            –
          </span>
        )}
      </td>
      <td data-label="Router">
        {head.router ? (
          <span className="traffic-router">
            <span className="traffic-dot open" aria-hidden="true" />
            {head.router.name}
          </span>
        ) : (
          <span className="muted" aria-label="not routed">
            –
          </span>
        )}
      </td>
    </tr>
  );
}

export function TrafficEventsTable({ flows, caption }: { flows: FlowGroup[]; caption: string }) {
  return (
    <div className="table-wrap">
      <table className="table traffic-table">
        <caption className="visually-hidden">{caption}</caption>
        <thead>
          <tr>
            <th scope="col">Time</th>
            <th scope="col">Event</th>
            <th scope="col">Source</th>
            <th scope="col">Protocol &amp; port</th>
            <th scope="col">Destination</th>
            <th scope="col">Traffic</th>
            <th scope="col">Router</th>
          </tr>
        </thead>
        <tbody>
          {flows.map((group) => (
            <FlowRow key={group.key} group={group} />
          ))}
        </tbody>
      </table>
    </div>
  );
}
