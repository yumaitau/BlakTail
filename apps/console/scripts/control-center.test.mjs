import { test } from "node:test";
import assert from "node:assert/strict";
import {
  deviceGraph,
  groupGraph,
  networkDetailGraph,
  networksGraph,
  networksOf,
  servicesLabel,
} from "../src/lib/control-center.ts";

const node = (id, label, tags, state = "online", role = "member") => ({
  id,
  name: label,
  label,
  role,
  tags,
  state,
  last_seen_at: 1,
  transport: { state: "direct", reported_at: 1, stale: false },
  packet_filter: "enforced",
  advertised_routes: [],
  approved_routes: [],
});

const edge = (source, target, rules, enforcement = "device_enforced") => ({
  kind: "device",
  source_node_id: source,
  target_node_id: target,
  resource_id: null,
  destination: target,
  basis: rules.length ? "rule" : "default_same_tag",
  enforcement,
  path: "direct",
  explanation: "",
  edit: { surface: "policy", id: null },
  rules,
});

const selector = (over = {}) => ({ roles: [], tags: [], groups: [], hosts: [], ...over });

const topology = {
  org_id: "org",
  generated_at: 1,
  control_revision: 1,
  policy: { revision: 3, etag: "x", defaults: "deny" },
  nodes: [
    node("a", "laptop", ["ranger"]),
    node("b", "nas", ["office"]),
    node("c", "till", ["store"], "stale"),
    node("r", "router", ["office"]),
  ],
  resources: [
    {
      id: "res1",
      name: "Records",
      destination: "10.0.0.10/32",
      enabled: true,
      state: "distributing",
      selected_routing_peer: "r",
      routing_peers: [{ node_id: "r", name: "router", state: "primary" }],
      receiving: 1,
      kind: "cidr",
      ports: ["443"],
      protocols: ["tcp"],
      port_enforcement: "enforced",
      access: { roles: [], tags: ["ranger"], groups: [] },
    },
    {
      id: "res2",
      name: "Wiki",
      destination: "wiki.example.org.au",
      enabled: true,
      state: "dns_not_resolved",
      selected_routing_peer: "r",
      routing_peers: [{ node_id: "r", name: "router", state: "primary" }],
      receiving: 0,
      kind: "dns",
      ports: [],
      protocols: [],
      port_enforcement: "enforced",
      access: { roles: [], tags: ["store"], groups: [] },
    },
  ],
  routes: [],
  edges: [
    edge("a", "b", [0]),
    edge("a", "r", [0], "unknown"),
    {
      ...edge("a", "r", []),
      kind: "resource",
      resource_id: "res1",
      destination: "Records (10.0.0.10/32)",
      basis: "resource_access",
      enforcement: "route_not_filtered",
      edit: { surface: "network_resource", id: "res1" },
    },
  ],
  rules: [
    { index: 0, action: "allow", src: selector({ tags: ["ranger"] }), dst: selector({ tags: ["office"] }), protocols: ["tcp"], ports: ["443"], posture: [] },
    { index: 1, action: "deny", src: selector({ tags: ["store"] }), dst: selector({ tags: ["ranger"] }), protocols: [], ports: [], posture: [] },
  ],
  groups: [],
  truncated: false,
  notes: [],
};

test("service labels read like a firewall rule", () => {
  assert.equal(servicesLabel([], []), "All");
  assert.equal(servicesLabel(["tcp"], ["443"]), "TCP:443");
  assert.equal(servicesLabel(["tcp", "udp"], ["53"]), "TCP/UDP:53");
  assert.equal(servicesLabel(["icmp"], []), "ICMP");
});

test("device tab draws only rules the coordinator compiled for that device", () => {
  const graph = deviceGraph(topology, "a");
  const ids = graph.nodes.map((n) => n.id).sort();
  assert.ok(ids.includes("rule:0"));
  assert.ok(!ids.includes("rule:1"), "the store deny never applies to this device");
  const rule = graph.nodes.find((n) => n.id === "rule:0");
  assert.equal(rule.label, "Rule 1");
  assert.equal(rule.badge, "TCP:443");
  const toOffice = graph.edges.find((e) => e.source === "rule:0" && e.target === "sel:tag:office");
  // One target enforces ports, the other is unknown: enforced wins, both counted.
  assert.equal(toOffice.state, "allowed");
  assert.ok(graph.edges.some((e) => e.source === "device:a" && e.target === "access:res1"));
  // A device with no compiled paths has no edges at all.
  assert.equal(deviceGraph(topology, "c").edges.length, 0);
});

test("group tab marks written-but-unused rules and denies distinctly", () => {
  const store = groupGraph(topology, "tag:store");
  const deny = store.edges.find((e) => e.source === "rule:1" && e.target === "sel:tag:ranger");
  assert.equal(deny.state, "denied");
  const ranger = groupGraph(topology, "tag:ranger");
  assert.equal(ranger.edges.find((e) => e.source === "src:tag:ranger" && e.target === "rule:0").state, "allowed");
  const wiki = store.edges.find((e) => e.target === "access:res2");
  assert.equal(wiki.state, "inactive", "no store device receives the wiki today");
});

test("networks group resources by routing peers and drill into resources", () => {
  const networks = networksOf(topology);
  assert.equal(networks.length, 1);
  assert.equal(networks[0].name, "router");
  assert.equal(networks[0].resources.length, 2);
  const overview = networksGraph(topology);
  const label = overview.edges.find((e) => e.source === "sel:tag:ranger");
  assert.equal(label.label, "TCP:443");
  assert.equal(label.state, "allowed");
  const detail = networkDetailGraph(topology, networks[0].key);
  assert.ok(detail.nodes.some((n) => n.id === "res:res2" && n.sub === "wiki.example.org.au"));
  assert.equal(networkDetailGraph(topology, "missing").nodes.length, 0);
});
