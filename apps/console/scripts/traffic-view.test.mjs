import { describe, expect, test } from "bun:test";
import {
  coordinatorTrafficQuery,
  eventSentence,
  flowStatus,
  flowTotals,
  formatBytes,
  formatTime,
  policyStep,
  portLabel,
  sentenceText,
  timeWindow,
  trafficFiltersFromParams,
  trafficSearch,
} from "../src/lib/traffic-view.ts";

const ALICE = { id: "a1", name: "alice-mac", os: "macos" };
const SERVER = { id: "s1", name: "server", os: "linux" };
const ROUTER = { id: "r1", name: "router-1", os: "linux" };

function endpoint(kind, name, ip, port, extra = {}) {
  return { kind, id: kind === "unknown" ? null : `${name}-id`, name, ip, port, os: null, user_id: null, route: null, ...extra };
}

function event(extra = {}) {
  return {
    id: "e1",
    flow_id: "f1",
    event_type: "start",
    at: 1_782_000_000,
    window_start: 1_781_999_970,
    window_end: 1_782_000_000,
    reporter: ALICE,
    direction: "outbound",
    protocol: "tcp",
    protocol_number: null,
    icmp_type: null,
    icmp_code: null,
    icmp_name: null,
    source: endpoint("device", "alice-mac", "100.64.0.2", 50000),
    destination: endpoint("device", "server", "100.64.0.3", 22),
    router: null,
    rule: { basis: "rule", index: 0, label: "Rule 1: allow group:staff → role:owner", hint: null },
    connection_type: "p2p",
    rx_bytes: 0,
    tx_bytes: 0,
    rx_packets: 0,
    tx_packets: 0,
    aggregated: false,
    received_at: 1_782_000_010,
    ...extra,
  };
}

describe("sentences", () => {
  test("outbound direct and relayed", () => {
    expect(sentenceText(eventSentence(event()))).toBe(
      "Device alice-mac requested a direct connection to device server",
    );
    const segments = eventSentence(event({ connection_type: "relay", event_type: "end" }));
    expect(sentenceText(segments)).toBe("Device alice-mac stopped a relayed connection to device server");
    expect(segments.filter((s) => s.strong).map((s) => s.text)).toEqual(["alice-mac", "server"]);
  });

  test("inbound and drops name the deciding rule", () => {
    const inbound = event({ reporter: SERVER, direction: "inbound" });
    expect(sentenceText(eventSentence(inbound))).toBe(
      "Device server received a direct connection from device alice-mac",
    );
    const dropped = event({
      reporter: SERVER,
      direction: "inbound",
      event_type: "drop",
      rule: { basis: "default_deny", index: null, label: "Default deny", hint: "acl:default" },
    });
    expect(sentenceText(eventSentence(dropped))).toBe(
      "Device server blocked a direct connection from device alice-mac — blocked by default deny",
    );
    const denied = event({ ...dropped, rule: { basis: "deny_rule", index: 2, label: "Rule 3: deny x", hint: null } });
    expect(sentenceText(eventSentence(denied))).toEndWith("— blocked by Rule 3: deny x");
  });

  test("routing peer and resource", () => {
    const resource = endpoint("resource", "Billing DB", "10.20.5.7", 5432, { route: "10.20.5.0/24" });
    const forwarded = event({
      reporter: ROUTER,
      direction: "inbound",
      connection_type: "routed",
      router: ROUTER,
      destination: resource,
    });
    expect(sentenceText(eventSentence(forwarded))).toBe(
      "Routing peer router-1 received a connection to resource Billing DB (10.20.5.7:5432) from alice-mac",
    );
    const client = event({ connection_type: "routed", router: ROUTER, destination: resource });
    expect(sentenceText(eventSentence(client))).toBe(
      "Device alice-mac requested a connection to resource Billing DB (10.20.5.7:5432)",
    );
    const unknown = event({ destination: endpoint("unknown", "", "203.0.113.9", 443) });
    expect(sentenceText(eventSentence(unknown))).toBe(
      "Device alice-mac requested a direct connection to Unknown (203.0.113.9:443)",
    );
    const aggregated = event({ aggregated: true });
    expect(sentenceText(eventSentence(aggregated))).toEndWith("(rule counters, not single connections)");
  });

  test("policy step, status and totals", () => {
    const group = {
      key: "a1/f1",
      reporter_id: "a1",
      flow_id: "f1",
      first_at: 1,
      last_at: 2,
      events: [event(), event({ id: "e2", event_type: "end", rx_bytes: 9100, tx_bytes: 4200, rx_packets: 8 })],
    };
    expect(policyStep(group)).toEqual({
      lead: "Policy",
      label: "Rule 1: allow group:staff → role:owner",
      href: "/acls#rule-1",
      outcome: "allowed the connection",
    });
    expect(flowStatus(group)).toBe("closed");
    expect(flowTotals(group.events)).toEqual({ rx_bytes: 9100, tx_bytes: 4200, rx_packets: 8, tx_packets: 0 });
    const blocked = { ...group, events: [event({ event_type: "drop", rule: { basis: "default_deny", index: null, label: "Default deny", hint: null } })] };
    expect(flowStatus(blocked)).toBe("blocked");
    expect(policyStep(blocked)?.outcome).toBe("blocked the connection");
  });
});

describe("filters", () => {
  test("invalid params are dropped, valid ones kept", () => {
    const filters = trafficFiltersFromParams({
      q: "  alice ",
      range: "7d",
      protocol: "gre",
      port: "70000",
      direction: "inbound",
      event_type: "drop",
      connection_type: "routed",
      source: "a1",
      destination: "10.20.0.0/16",
      limit: "33",
      cursor: "1782000000:abc/f-1",
      ip: "x'; drop",
    });
    expect(filters).toEqual({
      range: "7d",
      limit: 50,
      q: "alice",
      source: "a1",
      destination: "10.20.0.0/16",
      direction: "inbound",
      event_type: "drop",
      connection_type: "routed",
      cursor: "1782000000:abc/f-1",
    });
    expect(trafficFiltersFromParams({ range: "bogus", limit: "200", port: "443" })).toEqual({
      range: "24h",
      limit: 200,
      port: 443,
    });
  });

  test("custom range only applies with range=custom and maps to UTC seconds", () => {
    expect(trafficFiltersFromParams({ from: "2026-06-21T00:00" })).toEqual({ range: "24h", limit: 50 });
    const custom = trafficFiltersFromParams({ range: "custom", from: "2026-06-21T00:00", to: "2026-06-21T01:00" });
    expect(timeWindow(custom, 0)).toEqual({ from: 1_782_000_000, to: 1_782_003_600 });
    expect(timeWindow({ range: "1h", limit: 50 }, 10_000)).toEqual({ from: 6_400, to: 10_000 });
  });

  test("coordinator query carries only known keys", () => {
    const filters = trafficFiltersFromParams({ range: "1h", q: "db", port: "5432", cursor: "5:x" });
    const query = coordinatorTrafficQuery(filters, 10_000);
    expect(Object.fromEntries(query)).toEqual({
      from: "6400",
      to: "10000",
      limit: "50",
      cursor: "5:x",
      q: "db",
      port: "5432",
    });
    const exportQuery = coordinatorTrafficQuery(filters, 10_000, { paging: false });
    expect(exportQuery.has("limit")).toBe(false);
    expect(exportQuery.has("cursor")).toBe(false);
    expect(trafficSearch(filters, { cursor: undefined })).toBe("?range=1h&q=db&port=5432");
  });
});

describe("formatting", () => {
  test("bytes, times and ports", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(500)).toBe("500 B");
    expect(formatBytes(5580)).toBe("5.58 KB");
    expect(formatTime(1_782_000_000)).toMatch(/^12:00:00\s?am UTC$/i);
    expect(portLabel(event())).toBe("22");
    expect(portLabel(event({ protocol: "icmp", icmp_type: 8, icmp_name: "Echo" }))).toBe("Echo");
  });
});
