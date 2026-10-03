// Pure helpers for the per-flow traffic events page: filter parsing, the
// coordinator query, sentences, totals and formatting. No server-only
// imports so bun tests can load this file directly.

export type FlowEndpoint = {
  /** `device`, `resource`, `route` or `unknown`. */
  kind: string;
  id: string | null;
  name: string;
  ip: string;
  port: number;
  os: string | null;
  user_id: string | null;
  route: string | null;
};

export type FlowNodeRef = { id: string; name: string; os: string | null };

export type FlowRule = {
  /** `rule`, `deny_rule`, `default_same_tag`, `default_deny`, `resource`, `route` or `unknown`. */
  basis: string;
  index: number | null;
  label: string;
  hint: string | null;
};

export type FlowEventView = {
  id: string;
  flow_id: string;
  event_type: "start" | "end" | "drop";
  at: number;
  window_start: number;
  window_end: number;
  reporter: FlowNodeRef;
  direction: "inbound" | "outbound";
  protocol: string;
  protocol_number: number | null;
  icmp_type: number | null;
  icmp_code: number | null;
  icmp_name: string | null;
  source: FlowEndpoint;
  destination: FlowEndpoint;
  router: FlowNodeRef | null;
  rule: FlowRule;
  connection_type: "p2p" | "routed" | "relay";
  rx_bytes: number;
  tx_bytes: number;
  rx_packets: number;
  tx_packets: number;
  aggregated: boolean;
  received_at: number;
};

export type FlowGroup = {
  key: string;
  reporter_id: string;
  flow_id: string;
  first_at: number;
  last_at: number;
  events: FlowEventView[];
};

export type TrafficState = "disabled" | "no_data" | "stale" | "current";

export type FlowsPage = {
  flows: FlowGroup[];
  next_cursor: string | null;
  settings: {
    enabled: boolean;
    sampling_rate: number;
    retention_days: number;
    updated_at: number | null;
    updated_by: string;
  };
  state: TrafficState;
  last_received_at: number | null;
  reporting_devices: number;
  generated_at: number;
};

// ---------------------------------------------------------------------------
// Filters

export const TIME_RANGES = [
  { value: "1h", label: "Last hour", seconds: 3600 },
  { value: "24h", label: "Last 24 hours", seconds: 86_400 },
  { value: "2d", label: "Last 2 days", seconds: 2 * 86_400 },
  { value: "7d", label: "Last 7 days", seconds: 7 * 86_400 },
  { value: "custom", label: "Custom range", seconds: 0 },
] as const;
export type TimeRange = (typeof TIME_RANGES)[number]["value"];

export const PAGE_SIZES = [25, 50, 100, 200] as const;
export const PROTOCOLS = ["tcp", "udp", "icmp", "icmpv6", "other"] as const;
export const DIRECTIONS = ["inbound", "outbound"] as const;
export const EVENT_TYPES = ["start", "end", "drop"] as const;
export const CONNECTION_TYPES = ["p2p", "routed", "relay"] as const;

export type TrafficFilters = {
  range: TimeRange;
  /** `YYYY-MM-DDTHH:mm` in UTC, only with `range=custom`. */
  from?: string;
  to?: string;
  q?: string;
  source?: string;
  destination?: string;
  ip?: string;
  port?: number;
  protocol?: string;
  direction?: string;
  event_type?: string;
  connection_type?: string;
  limit: number;
  cursor?: string;
};

type Params = Record<string, string | string[] | undefined>;

function first(params: Params, key: string): string | undefined {
  const value = params[key];
  const text = Array.isArray(value) ? value[0] : value;
  if (typeof text !== "string") return undefined;
  const trimmed = text.trim();
  if (!trimmed || /[\u0000-\u001f\u007f]/.test(trimmed)) return undefined;
  return trimmed;
}

function oneOf<T extends string>(value: string | undefined, allowed: readonly T[]): T | undefined {
  return value && (allowed as readonly string[]).includes(value) ? (value as T) : undefined;
}

const ID = /^[A-Za-z0-9._:/-]{1,64}$/;
const CURSOR = /^\d{1,12}:[A-Za-z0-9_/-]{1,160}$/;
const LOCAL_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/;

/** Parses the page's own query string; anything invalid is dropped. */
export function trafficFiltersFromParams(params: Params): TrafficFilters {
  const range =
    oneOf(
      first(params, "range"),
      TIME_RANGES.map((r) => r.value),
    ) ?? "24h";
  const limitValue = Number(first(params, "limit"));
  const limit = (PAGE_SIZES as readonly number[]).includes(limitValue) ? limitValue : 50;
  const filters: TrafficFilters = { range, limit };
  if (range === "custom") {
    const from = first(params, "from");
    const to = first(params, "to");
    if (from && LOCAL_TIME.test(from) && Number.isFinite(localToSeconds(from))) filters.from = from;
    if (to && LOCAL_TIME.test(to) && Number.isFinite(localToSeconds(to))) filters.to = to;
  }
  const q = first(params, "q");
  if (q && q.length <= 100) filters.q = q;
  for (const key of ["source", "destination"] as const) {
    const value = first(params, key);
    if (value && ID.test(value)) filters[key] = value;
  }
  const ip = first(params, "ip");
  if (ip && /^[0-9A-Fa-f.:]{2,45}$/.test(ip)) filters.ip = ip;
  const port = first(params, "port");
  if (port && /^\d{1,5}$/.test(port) && Number(port) <= 65_535) filters.port = Number(port);
  filters.protocol = oneOf(first(params, "protocol"), PROTOCOLS);
  filters.direction = oneOf(first(params, "direction"), DIRECTIONS);
  filters.event_type = oneOf(first(params, "event_type"), EVENT_TYPES);
  filters.connection_type = oneOf(first(params, "connection_type"), CONNECTION_TYPES);
  const cursor = first(params, "cursor");
  if (cursor && CURSOR.test(cursor)) filters.cursor = cursor;
  for (const key of Object.keys(filters) as (keyof TrafficFilters)[]) {
    if (filters[key] === undefined) delete filters[key];
  }
  return filters;
}

/** `YYYY-MM-DDTHH:mm` read as UTC. */
export function localToSeconds(value: string): number {
  return Math.floor(Date.parse(`${value}:00Z`) / 1000);
}

/** The coordinator's time window for these filters. */
export function timeWindow(filters: TrafficFilters, now: number): { from: number; to: number } {
  if (filters.range === "custom") {
    const to = filters.to ? localToSeconds(filters.to) : now;
    const from = filters.from ? localToSeconds(filters.from) : to - 86_400;
    return from <= to ? { from, to } : { from: to, to: from };
  }
  const span = TIME_RANGES.find((r) => r.value === filters.range)?.seconds ?? 86_400;
  return { from: now - span, to: now };
}

/** Query for `GET /traffic/flows` (or the export, without paging). */
export function coordinatorTrafficQuery(
  filters: TrafficFilters,
  now: number,
  options: { paging: boolean } = { paging: true },
): URLSearchParams {
  const query = new URLSearchParams();
  const window = timeWindow(filters, now);
  query.set("from", String(window.from));
  query.set("to", String(window.to));
  if (options.paging) {
    query.set("limit", String(filters.limit));
    if (filters.cursor) query.set("cursor", filters.cursor);
  }
  for (const key of [
    "q",
    "source",
    "destination",
    "ip",
    "port",
    "protocol",
    "direction",
    "event_type",
    "connection_type",
  ] as const) {
    const value = filters[key];
    if (value !== undefined && value !== "") query.set(key, String(value));
  }
  return query;
}

/** The page's own query string for these filters with some replaced. */
export function trafficSearch(
  filters: TrafficFilters,
  overrides: Partial<Record<keyof TrafficFilters, string | number | undefined>> = {},
): string {
  const merged: Record<string, string | number | undefined> = { ...filters, ...overrides };
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(merged)) {
    if (value === undefined || value === "") continue;
    if (key === "range" && value === "24h") continue;
    if (key === "limit" && value === 50) continue;
    query.set(key, String(value));
  }
  const text = query.toString();
  return text ? `?${text}` : "";
}

/** Number of narrowing filters in the Filter popover. */
export function popoverFilterCount(filters: TrafficFilters): number {
  return (["ip", "port", "protocol", "direction", "event_type", "connection_type"] as const).filter(
    (key) => filters[key] !== undefined,
  ).length;
}

// ---------------------------------------------------------------------------
// Sentences

export type Segment = { text: string; strong?: boolean };

function hostPort(endpoint: FlowEndpoint): string {
  const host = endpoint.ip.includes(":") ? `[${endpoint.ip}]` : endpoint.ip;
  return endpoint.port ? `${host}:${endpoint.port}` : endpoint.ip;
}

/** `device **name**`, `resource **name** (10.0.0.5:443)`, `**Unknown** (1.2.3.4:80)`. */
function endpointPhrase(endpoint: FlowEndpoint, withKind = true): Segment[] {
  switch (endpoint.kind) {
    case "device":
      return [
        ...(withKind ? [{ text: "device " }] : []),
        { text: endpoint.name || endpoint.ip, strong: true },
      ];
    case "resource":
      return [
        ...(withKind ? [{ text: "resource " }] : []),
        { text: endpoint.name || hostPort(endpoint), strong: true },
        { text: ` (${hostPort(endpoint)})` },
      ];
    case "route":
      return [
        ...(withKind ? [{ text: "route " }] : []),
        { text: endpoint.name || endpoint.route || "", strong: true },
        { text: ` (${hostPort(endpoint)})` },
      ];
    default:
      return [{ text: "Unknown", strong: true }, { text: ` (${hostPort(endpoint)})` }];
  }
}

function connectionWords(type: FlowEventView["connection_type"]): string {
  if (type === "p2p") return "a direct connection";
  if (type === "relay") return "a relayed connection";
  return "a connection";
}

function blockReason(rule: FlowRule): string {
  if (rule.basis === "default_deny") return "blocked by default deny";
  if (rule.basis === "deny_rule") return `blocked by ${rule.label}`;
  return rule.label || "blocked";
}

/** One event as a sentence, from its reporter's point of view. */
export function eventSentence(event: FlowEventView): Segment[] {
  const conn = connectionWords(event.connection_type);
  const forwarding =
    event.connection_type === "routed" && event.router !== null && event.router.id === event.reporter.id;
  let segments: Segment[];
  if (forwarding) {
    const verb =
      event.event_type === "start"
        ? "received a connection to"
        : event.event_type === "end"
          ? "stopped forwarding a connection to"
          : "blocked a connection to";
    segments = [
      { text: "Routing peer " },
      { text: event.reporter.name, strong: true },
      { text: ` ${verb} ` },
      ...endpointPhrase(event.destination),
      { text: " from " },
      ...endpointPhrase(event.source, false),
    ];
  } else if (event.direction === "outbound") {
    const verb =
      event.event_type === "start"
        ? `requested ${conn} to`
        : event.event_type === "end"
          ? `stopped ${conn} to`
          : `blocked ${conn} to`;
    segments = [
      { text: "Device " },
      { text: event.reporter.name, strong: true },
      { text: ` ${verb} ` },
      ...endpointPhrase(event.destination),
    ];
  } else {
    const verb =
      event.event_type === "start"
        ? `received ${conn} from`
        : event.event_type === "end"
          ? `stopped ${conn} from`
          : `blocked ${conn} from`;
    segments = [
      { text: "Device " },
      { text: event.reporter.name, strong: true },
      { text: ` ${verb} ` },
      ...endpointPhrase(event.source),
    ];
  }
  if (event.event_type === "drop") segments.push({ text: ` — ${blockReason(event.rule)}` });
  if (event.aggregated) segments.push({ text: " (rule counters, not single connections)" });
  return segments;
}

export function sentenceText(segments: Segment[]): string {
  return segments.map((segment) => segment.text).join("");
}

/** How the policy step of a flow's timeline reads. */
export function policyStep(group: FlowGroup): {
  lead: string;
  label: string;
  href: string | null;
  outcome: string;
} | null {
  const head = group.events[0];
  if (!head) return null;
  const rule = head.rule;
  const blocked = group.events.some((event) => event.event_type === "drop");
  switch (rule.basis) {
    case "rule":
    case "deny_rule":
      return {
        lead: "Policy",
        label: rule.label,
        href: rule.index === null ? "/acls" : `/acls#rule-${rule.index + 1}`,
        outcome: rule.basis === "deny_rule" || blocked ? "blocked the connection" : "allowed the connection",
      };
    case "default_same_tag":
      return { lead: "Policy", label: rule.label, href: "/acls", outcome: "allowed the connection" };
    case "default_deny":
      return {
        lead: "",
        label: "Default deny",
        href: "/acls",
        outcome: blocked
          ? "blocked the connection"
          : "applies: no rule allows this, so the destination is expected to refuse it",
      };
    case "resource":
      return {
        lead: "",
        label: rule.label,
        href: head.destination.id ? `/networks/${encodeURIComponent(head.destination.id)}` : "/networks",
        outcome: "granted the connection",
      };
    case "route":
      return { lead: "", label: rule.label, href: "/networks", outcome: "carried the connection" };
    default:
      return { lead: "Policy", label: rule.label || "not evaluated", href: null, outcome: "" };
  }
}

export type FlowStatus = "blocked" | "closed" | "open";

export function flowStatus(group: FlowGroup): FlowStatus {
  if (group.events.some((event) => event.event_type === "drop")) return "blocked";
  if (group.events.some((event) => event.event_type === "end")) return "closed";
  return "open";
}

/** Counters of a flow. End events carry running totals, so take the largest. */
export function flowTotals(events: FlowEventView[]): {
  rx_bytes: number;
  tx_bytes: number;
  rx_packets: number;
  tx_packets: number;
} {
  const totals = { rx_bytes: 0, tx_bytes: 0, rx_packets: 0, tx_packets: 0 };
  for (const event of events) {
    for (const key of Object.keys(totals) as (keyof typeof totals)[]) {
      totals[key] = Math.max(totals[key], event[key] ?? 0);
    }
  }
  return totals;
}

// ---------------------------------------------------------------------------
// Formatting

export function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = value;
  let unit = 0;
  while (size >= 1000 && unit < units.length - 1) {
    size /= 1000;
    unit += 1;
  }
  return `${unit === 0 ? size.toFixed(0) : size.toFixed(size < 10 ? 2 : 1)} ${units[unit]}`;
}

const DATE = new Intl.DateTimeFormat("en-AU", {
  timeZone: "UTC",
  day: "numeric",
  month: "short",
  year: "numeric",
});
const TIME = new Intl.DateTimeFormat("en-AU", {
  timeZone: "UTC",
  hour: "numeric",
  minute: "2-digit",
  second: "2-digit",
  hour12: true,
});

export function formatDate(seconds: number): string {
  return DATE.format(new Date(seconds * 1000));
}

export function formatTime(seconds: number): string {
  return `${TIME.format(new Date(seconds * 1000))} UTC`;
}

export function isoTime(seconds: number): string {
  return new Date(seconds * 1000).toISOString();
}

export function protocolLabel(event: FlowEventView): string {
  if (event.protocol === "icmpv6") return "ICMPv6";
  if (event.protocol === "other") return event.protocol_number ? `IP ${event.protocol_number}` : "Other";
  return event.protocol.toUpperCase();
}

/** Port chip text: the destination port, or the ICMP type name. */
export function portLabel(event: FlowEventView): string | null {
  if (event.protocol === "icmp" || event.protocol === "icmpv6") {
    return event.icmp_name ?? (event.icmp_type !== null ? `Type ${event.icmp_type}` : null);
  }
  return event.destination.port ? String(event.destination.port) : null;
}

export function endpointAddress(endpoint: FlowEndpoint): string {
  return hostPort(endpoint);
}
