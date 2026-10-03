// Control Center graph model. Pure functions over the coordinator topology
// read model (GET /v1/orgs/:org/topology): every edge drawn here is either a
// coordinator edge (device, route, resource) or a published rule whose
// selector it names, and an edge is only drawn "allowed" when the coordinator
// compiled at least one matching device path. Nothing is invented.

import type {
  Topology,
  TopologyEdge,
  TopologyNode,
  TopologyResource,
  TopologyRule,
  TopologySelector,
} from "./coord-topology";
import { roleLabel, type OrgRole } from "./roles";

export type EdgeState = "allowed" | "unenforced" | "denied" | "inactive";

export type Detail = { label: string; value: string };

export type GraphNode = {
  id: string;
  kind: "device" | "selector" | "rule" | "resource" | "network" | "route";
  label: string;
  sub?: string;
  /** Rule pills: protocol and port summary, e.g. `TCP:443` or `All`. */
  badge?: string;
  /** Status dot: online/allowed (ok), offline/unknown (idle), deny (bad). */
  status?: "ok" | "idle" | "bad";
  icon?: "device" | "tag" | "group" | "role" | "any" | "host" | "cidr" | "dns" | "network" | "route";
  /** Network cards list their resources inline. */
  items?: { label: string; sub: string; icon: "cidr" | "dns" }[];
  /** Network cards: online routing peers / total. */
  peers?: { online: number; total: number };
  /** Column for the deterministic left-to-right layout. */
  rank: number;
  title: string;
  details: Detail[];
  link?: { href: string; label: string };
  /** A network the Networks tab can drill into. */
  drill?: string;
};

export type GraphEdge = {
  id: string;
  source: string;
  target: string;
  state: EdgeState;
  label?: string;
  /** Plain-language reading for the list view and screen readers. */
  text: string;
};

export type Graph = { nodes: GraphNode[]; edges: GraphEdge[] };

export type SelectorKey = `${"tag" | "group" | "role"}:${string}`;

export type Network = {
  key: string;
  name: string;
  resources: TopologyResource[];
  routingPeers: { id: string; name: string; online: boolean }[];
};

const PROTOCOL_LABEL = { tcp: "TCP", udp: "UDP", icmp: "ICMP" } as const;

/** `TCP:443`, `TCP/UDP:53`, `ICMP` or `All`. */
export function servicesLabel(protocols: string[], ports: string[]): string {
  if (protocols.length === 0 && ports.length === 0) return "All";
  const proto = protocols.length
    ? protocols.map((p) => PROTOCOL_LABEL[p as keyof typeof PROTOCOL_LABEL] ?? p.toUpperCase()).join("/")
    : "TCP/UDP";
  if (ports.length === 0) return protocols.length === 3 ? "All" : proto;
  if (protocols.length === 1 && protocols[0] === "icmp") return "ICMP";
  return `${proto}:${ports.join(",")}`;
}

export function ruleLabel(rule: Pick<TopologyRule, "index">): string {
  return `Rule ${rule.index + 1}`;
}

function plural(count: number, one: string, many = `${one}s`) {
  return `${count} ${count === 1 ? one : many}`;
}

export function selectorLabel(key: SelectorKey): string {
  const [kind, value] = splitKey(key);
  if (kind === "role") return `${roleLabel(value as OrgRole)} role`;
  if (kind === "tag") return `tag:${value}`;
  return value;
}

function splitKey(key: string): [string, string] {
  const at = key.indexOf(":");
  return [key.slice(0, at), key.slice(at + 1)];
}

export function selectorKeys(selector: Pick<TopologySelector, "roles" | "tags" | "groups">): SelectorKey[] {
  return [
    ...selector.groups.map((value) => `group:${value}` as const),
    ...selector.tags.map((value) => `tag:${value}` as const),
    ...selector.roles.map((value) => `role:${value}` as const),
  ];
}

/** Devices (this organisation's, as the coordinator listed) a selector item names. */
export function devicesFor(topology: Topology, key: SelectorKey): TopologyNode[] {
  const [kind, value] = splitKey(key);
  if (kind === "group") {
    const ids = new Set(topology.groups.find((group) => group.name === value)?.devices ?? []);
    return topology.nodes.filter((node) => ids.has(node.id));
  }
  if (kind === "tag") return topology.nodes.filter((node) => node.tags.some((tag) => tag === value));
  return topology.nodes.filter((node) => node.role === value);
}

/** Every selector item the organisation uses: tags on devices, policy groups, roles in rules. */
export function allSelectors(topology: Topology): SelectorKey[] {
  const keys = new Set<SelectorKey>();
  for (const group of topology.groups) keys.add(`group:${group.name}`);
  for (const node of topology.nodes) for (const tag of node.tags) keys.add(`tag:${tag}`);
  for (const rule of topology.rules) {
    for (const key of [...selectorKeys(rule.src), ...selectorKeys(rule.dst)]) keys.add(key);
  }
  for (const resource of topology.resources) for (const key of selectorKeys(resource.access)) keys.add(key);
  const order = { group: 0, tag: 1, role: 2 } as Record<string, number>;
  return [...keys].sort((a, b) => {
    const [ka, va] = splitKey(a);
    const [kb, vb] = splitKey(b);
    return order[ka]! - order[kb]! || va.localeCompare(vb);
  });
}

function selectorIcon(key: SelectorKey): GraphNode["icon"] {
  return splitKey(key)[0] as "tag" | "group" | "role";
}

function deviceState(node: TopologyNode): string {
  return {
    online: "Online",
    stale: "Offline (stale heartbeat)",
    never: "Never seen",
    suspended: "Suspended",
    expired: "Credential expired",
  }[node.state];
}

function deviceNode(node: TopologyNode, id: string, rank: number): GraphNode {
  return {
    id,
    kind: "device",
    label: node.label,
    sub: node.tags.length ? node.tags.map((tag) => `tag:${tag}`).join(" ") : "untagged",
    status: node.state === "online" ? "ok" : node.state === "suspended" || node.state === "expired" ? "bad" : "idle",
    icon: "device",
    rank,
    title: `Device ${node.label}, ${deviceState(node).toLowerCase()}`,
    details: [
      { label: "State", value: deviceState(node) },
      { label: "Role", value: roleLabel(node.role) },
      { label: "Tags", value: node.tags.join(", ") || "None" },
      {
        label: "Transport",
        value:
          node.transport.state === "not_measured"
            ? "Not measured"
            : `${node.transport.state}${node.transport.stale ? " (stale report)" : ""}`,
      },
      { label: "Inbound filter", value: node.packet_filter.replace("_", " ") },
      { label: "Approved routes", value: node.approved_routes.join(", ") || "None" },
    ],
    link: { href: `/devices/${node.id}`, label: "Open device" },
  };
}

function selectorNode(topology: Topology, key: SelectorKey, id: string, rank: number, count?: number): GraphNode {
  const devices = devicesFor(topology, key);
  const shown = count ?? devices.length;
  const [kind, value] = splitKey(key);
  const group = kind === "group" ? topology.groups.find((g) => g.name === value) : undefined;
  return {
    id,
    kind: "selector",
    label: selectorLabel(key),
    sub: plural(shown, "device"),
    icon: selectorIcon(key),
    rank,
    title: `${selectorLabel(key)}: ${plural(shown, "device")}`,
    details: [
      { label: "Kind", value: kind === "group" ? "Policy group" : kind === "tag" ? "Device tag" : "Owner role" },
      ...(group ? [{ label: "Members", value: plural(group.members, "person", "people") }] : []),
      { label: "Devices", value: devices.map((device) => device.label).join(", ") || "None today" },
    ],
    link: { href: kind === "tag" ? "/devices" : "/acls", label: kind === "tag" ? "Devices" : "Open policies" },
  };
}

function ruleNode(rule: TopologyRule, id: string, rank: number, status: GraphNode["status"]): GraphNode {
  const describe = (selector: TopologySelector) =>
    [...selectorKeys(selector).map(selectorLabel), ...selector.hosts.map((host) => `host ${host}`)].join(", ") ||
    "Anyone";
  return {
    id,
    kind: "rule",
    label: ruleLabel(rule),
    badge: servicesLabel(rule.protocols, rule.ports),
    status: rule.action === "deny" ? "bad" : status,
    rank,
    title: `${ruleLabel(rule)}: ${rule.action} ${servicesLabel(rule.protocols, rule.ports)}`,
    details: [
      { label: "Action", value: rule.action === "allow" ? "Allow" : "Deny" },
      { label: "From", value: describe(rule.src) },
      { label: "To", value: describe(rule.dst) },
      { label: "Services", value: servicesLabel(rule.protocols, rule.ports) },
      { label: "Posture", value: rule.posture.join(", ") || "None" },
    ],
    link: { href: "/acls", label: "Edit in Policies" },
  };
}

function resourceDestination(resource: TopologyResource) {
  return resource.destination || "No destination";
}

function resourceNode(resource: TopologyResource, id: string, rank: number): GraphNode {
  return {
    id,
    kind: "resource",
    label: resource.name,
    sub: resourceDestination(resource),
    icon: resource.kind === "dns" ? "dns" : "cidr",
    status: resource.state === "distributing" ? "ok" : "idle",
    rank,
    title: `Resource ${resource.name} (${resourceDestination(resource)}), ${resource.state.replaceAll("_", " ")}`,
    details: [
      { label: "Destination", value: resourceDestination(resource) },
      { label: "State", value: resource.state.replaceAll("_", " ") },
      { label: "Services", value: servicesLabel(resource.protocols, resource.ports) },
      { label: "Port filtering", value: resource.port_enforcement.replace("_", " ") },
      { label: "Receiving devices", value: String(resource.receiving) },
      {
        label: "Routing peers",
        value:
          resource.routing_peers
            .map((peer) => `${peer.name ?? peer.node_id} (${peer.state.replaceAll("_", " ")})`)
            .join(", ") || "None",
      },
    ],
    link: { href: `/networks/${resource.id}`, label: "Open resource" },
  };
}

/**
 * BlakTail resources have no network container, so the graph groups them by
 * the routing peers that carry them: resources sharing the same routing-peer
 * set form one network. The name is those routing peers.
 */
export function networksOf(topology: Topology): Network[] {
  const nodes = new Map(topology.nodes.map((node) => [node.id, node]));
  const groups = new Map<string, Network>();
  for (const resource of topology.resources) {
    const peers = [...resource.routing_peers].sort((a, b) => a.node_id.localeCompare(b.node_id));
    const key = peers.length ? peers.map((peer) => peer.node_id).join("+") : "none";
    const existing = groups.get(key);
    if (existing) {
      existing.resources.push(resource);
      continue;
    }
    const routingPeers = peers
      .map((peer) => {
        const node = nodes.get(peer.node_id);
        return {
          id: peer.node_id,
          name: node?.label ?? peer.name ?? peer.node_id.slice(0, 8),
          online: node?.state === "online",
        };
      })
      .sort((a, b) => a.name.localeCompare(b.name));
    groups.set(key, {
      key,
      name: routingPeers.length ? routingPeers.map((peer) => peer.name).join(" + ") : "No routing peer",
      resources: [resource],
      routingPeers,
    });
  }
  return [...groups.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function networkNode(network: Network, id: string, rank: number): GraphNode {
  const online = network.routingPeers.filter((peer) => peer.online).length;
  return {
    id,
    kind: "network",
    label: network.name,
    sub: plural(network.resources.length, "resource"),
    icon: "network",
    items: network.resources.map((resource) => ({
      label: resource.name,
      sub: resourceDestination(resource),
      icon: resource.kind === "dns" ? "dns" : "cidr",
    })),
    peers: { online, total: network.routingPeers.length },
    status: online > 0 ? "ok" : "idle",
    rank,
    title: `Network routed by ${network.name}: ${plural(network.resources.length, "resource")}, ${online} of ${network.routingPeers.length} routing peers online`,
    details: [
      { label: "Resources", value: network.resources.map((r) => `${r.name} (${resourceDestination(r)})`).join(", ") },
      {
        label: "Routing peers",
        value:
          network.routingPeers.map((peer) => `${peer.name} (${peer.online ? "online" : "offline"})`).join(", ") ||
          "None",
      },
    ],
    link:
      network.resources.length === 1
        ? { href: `/networks/${network.resources[0]!.id}`, label: "Open resource" }
        : { href: "/networks", label: "Open networks" },
    drill: network.key,
  };
}

function edgeStateFor(edge: Pick<TopologyEdge, "enforcement">): EdgeState {
  return edge.enforcement === "device_enforced" ? "allowed" : "unenforced";
}

function strongest(states: EdgeState[]): EdgeState {
  if (states.includes("allowed")) return "allowed";
  if (states.includes("unenforced")) return "unenforced";
  if (states.includes("denied")) return "denied";
  return "inactive";
}

const STATE_TEXT: Record<EdgeState, string> = {
  allowed: "allowed and enforced on the destination",
  unenforced: "allowed; ports not proven enforced on the destination",
  denied: "denied",
  inactive: "written in policy; no device currently uses it",
};

class Builder {
  nodes = new Map<string, GraphNode>();
  edges = new Map<string, GraphEdge & { states: EdgeState[] }>();
  node(node: GraphNode) {
    if (!this.nodes.has(node.id)) this.nodes.set(node.id, node);
    return node.id;
  }
  edge(source: string, target: string, state: EdgeState, label?: string) {
    const id = `${source}->${target}`;
    const existing = this.edges.get(id);
    if (existing) {
      existing.states.push(state);
      return;
    }
    this.edges.set(id, { id, source, target, state, label, text: "", states: [state] });
  }
  graph(): Graph {
    const nodes = [...this.nodes.values()];
    const names = new Map(nodes.map((node) => [node.id, node.label]));
    const edges = [...this.edges.values()].map(({ states, ...edge }) => {
      const state = strongest(states);
      return {
        ...edge,
        state,
        text: `${names.get(edge.source)} to ${names.get(edge.target)}${edge.label ? ` (${edge.label})` : ""}: ${STATE_TEXT[state]}.`,
      };
    });
    return { nodes, edges };
  }
}

/** Devices tab: one device → the rules that admit its paths → what they reach. */
export function deviceGraph(topology: Topology, deviceId: string): Graph {
  const b = new Builder();
  const nodes = new Map(topology.nodes.map((node) => [node.id, node]));
  const source = nodes.get(deviceId);
  if (!source) return b.graph();
  const root = b.node(deviceNode(source, `device:${source.id}`, 0));
  const rules = new Map(topology.rules.map((rule) => [rule.index, rule]));
  const groupsByDevice = new Map<string, string[]>();
  for (const group of topology.groups) {
    for (const id of group.devices) groupsByDevice.set(id, [...(groupsByDevice.get(id) ?? []), group.name]);
  }
  const outgoing = topology.edges.filter((edge) => edge.source_node_id === source.id);

  // Per rule and destination selector item, the reachable targets.
  const reach = new Map<string, Set<string>>();
  const add = (key: string, target: string) => reach.set(key, (reach.get(key) ?? new Set()).add(target));

  for (const edge of outgoing.filter((e) => e.kind === "device" && e.target_node_id)) {
    const target = nodes.get(edge.target_node_id!);
    if (!target) continue;
    const state = edgeStateFor(edge);
    if (edge.rules.length === 0) {
      // Admitted only by the legacy same-tag default.
      const pill = b.node({
        id: "default",
        kind: "rule",
        label: "Default: same tag",
        badge: "All",
        status: "ok",
        rank: 1,
        title: "Default policy: devices sharing a tag (or both untagged) reach each other",
        details: [
          { label: "Basis", value: "Legacy same-tag default; no rule matched" },
          { label: "Services", value: "All" },
        ],
        link: { href: "/acls", label: "Edit in Policies" },
      });
      b.edge(root, pill, state);
      const shared = source.tags.filter((tag) => target.tags.includes(tag));
      const keys: SelectorKey[] = shared.length ? shared.map((tag) => `tag:${tag}` as const) : [];
      if (keys.length === 0) {
        add(`default|untagged`, target.id);
      }
      for (const key of keys) add(`default|${key}`, target.id);
      continue;
    }
    for (const index of edge.rules) {
      const rule = rules.get(index);
      if (!rule) continue;
      const pill = b.node(ruleNode(rule, `rule:${index}`, 1, "ok"));
      b.edge(root, pill, rule.action === "deny" ? "denied" : state);
      const keys = selectorKeys(rule.dst).filter((key) => {
        const [kind, value] = splitKey(key);
        if (kind === "tag") return target.tags.some((tag) => tag === value);
        if (kind === "group") return (groupsByDevice.get(target.id) ?? []).includes(value);
        return target.role === value;
      });
      if (keys.length === 0) add(`rule:${index}|any`, target.id);
      for (const key of keys) add(`rule:${index}|${key}`, target.id);
    }
  }
  for (const [composite, targets] of reach) {
    const [pill, key] = composite.split("|") as [string, string];
    const rule = pill.startsWith("rule:") ? rules.get(Number(pill.slice(5))) : undefined;
    const state = rule?.action === "deny" ? "denied" : undefined;
    const edgeState = (targetId: string): EdgeState => {
      if (state) return state;
      const edge = outgoing.find((e) => e.kind === "device" && e.target_node_id === targetId);
      return edge ? edgeStateFor(edge) : "inactive";
    };
    const targetStates = [...targets].map(edgeState);
    let dest: string;
    if (key === "any" || key === "untagged") {
      if (targets.size <= 4) {
        for (const id of targets) {
          const target = nodes.get(id)!;
          const node = b.node(deviceNode(target, `target:${id}`, 2));
          b.edge(pill, node, edgeState(id));
        }
        continue;
      }
      dest = b.node({
        id: `any:${key}`,
        kind: "selector",
        label: key === "any" ? "Any device" : "Untagged devices",
        sub: plural(targets.size, "device"),
        icon: "any",
        rank: 2,
        title: `${key === "any" ? "Any device" : "Untagged devices"}: ${plural(targets.size, "device")}`,
        details: [{ label: "Devices", value: [...targets].map((id) => nodes.get(id)?.label ?? id).join(", ") }],
      });
    } else {
      dest = b.node(selectorNode(topology, key as SelectorKey, `sel:${key}`, 2));
    }
    b.edge(pill, dest, strongest(targetStates));
  }

  // Approved subnet and exit routes, carried by a router.
  for (const edge of outgoing.filter((e) => e.kind === "route" || e.kind === "exit")) {
    const router = edge.target_node_id ? nodes.get(edge.target_node_id) : undefined;
    const pill = b.node({
      id: `route:${edge.target_node_id}`,
      kind: "rule",
      label: `Routes via ${router?.label ?? "router"}`,
      badge: "All",
      status: router?.state === "online" ? "ok" : "idle",
      rank: 1,
      title: `Approved routes carried by ${router?.label ?? "a router"}; subnet traffic is not port-filtered`,
      details: [
        { label: "Router", value: router?.label ?? "Unknown" },
        { label: "Filtering", value: "Subnet routes are not port-filtered" },
      ],
      link: router ? { href: `/devices/${router.id}`, label: "Open router" } : undefined,
    });
    b.edge(root, pill, "unenforced");
    const dest = b.node({
      id: `cidr:${edge.destination}`,
      kind: "route",
      label: edge.kind === "exit" ? "Exit node" : edge.destination,
      sub: edge.kind === "exit" ? edge.destination : "Subnet route",
      icon: "route",
      rank: 2,
      title: edge.explanation,
      details: [{ label: "Explanation", value: edge.explanation }],
      link: { href: "/networks#routes", label: "Open routes" },
    });
    b.edge(pill, dest, "unenforced");
  }

  // Network resources this device receives.
  const networks = networksOf(topology);
  const resources = new Map(topology.resources.map((resource) => [resource.id, resource]));
  for (const edge of outgoing.filter((e) => e.kind === "resource" && e.resource_id)) {
    const resource = resources.get(edge.resource_id!);
    if (!resource) continue;
    const network = networks.find((n) => n.resources.some((r) => r.id === resource.id));
    const pill = b.node({
      id: `access:${resource.id}`,
      kind: "rule",
      label: `${resource.name} access`,
      badge: servicesLabel(resource.protocols, resource.ports),
      status: "ok",
      rank: 1,
      title: `Resource access for ${resource.name}: ${servicesLabel(resource.protocols, resource.ports)}`,
      details: [
        { label: "Who receives it", value: selectorKeys(resource.access).map(selectorLabel).join(", ") || "Nobody" },
        { label: "Services", value: servicesLabel(resource.protocols, resource.ports) },
        { label: "Port filtering", value: resource.port_enforcement.replace("_", " ") },
      ],
      link: { href: `/networks/${resource.id}`, label: "Edit resource" },
    });
    const state: EdgeState = resource.port_enforcement === "enforced" ? "allowed" : "unenforced";
    b.edge(root, pill, state);
    const dest = network ? b.node(networkNode(network, `net:${network.key}`, 2)) : b.node(resourceNode(resource, `res:${resource.id}`, 2));
    b.edge(pill, dest, state, undefined);
  }
  return b.graph();
}

/** Whether the coordinator compiled any device path from `from` devices to `to` devices via `rule`. */
function ruleInUse(topology: Topology, rule: TopologyRule, from: Set<string>, to: Set<string> | null): EdgeState[] {
  return topology.edges
    .filter(
      (edge) =>
        edge.kind === "device" &&
        edge.rules.includes(rule.index) &&
        from.has(edge.source_node_id) &&
        (to === null || (edge.target_node_id !== null && to.has(edge.target_node_id))),
    )
    .map((edge) => (rule.action === "deny" ? "denied" : edgeStateFor(edge)));
}

/** Groups tab: a selector item → rules naming it as source → their destinations. */
export function groupGraph(topology: Topology, key: SelectorKey): Graph {
  const b = new Builder();
  const devices = devicesFor(topology, key);
  const from = new Set(devices.map((device) => device.id));
  const root = b.node(selectorNode(topology, key, `src:${key}`, 0));
  for (const rule of topology.rules) {
    const sources = selectorKeys(rule.src);
    if (sources.length > 0 && !sources.includes(key)) continue;
    const used = ruleInUse(topology, rule, from, null);
    const pillState = used.length ? strongest(used) : rule.action === "deny" ? "denied" : "inactive";
    const pill = b.node(ruleNode(rule, `rule:${rule.index}`, 1, used.length ? "ok" : "idle"));
    b.edge(root, pill, pillState);
    const destinations = selectorKeys(rule.dst);
    if (destinations.length === 0 && rule.dst.hosts.length === 0) {
      const dest = b.node({
        id: "any",
        kind: "selector",
        label: "Any device",
        sub: plural(topology.nodes.length, "device"),
        icon: "any",
        rank: 2,
        title: `Any device: ${plural(topology.nodes.length, "device")}`,
        details: [{ label: "Devices", value: topology.nodes.map((n) => n.label).join(", ") || "None" }],
      });
      b.edge(pill, dest, pillState);
    }
    for (const dstKey of destinations) {
      const to = new Set(devicesFor(topology, dstKey).map((device) => device.id));
      const states = ruleInUse(topology, rule, from, to);
      const dest = b.node(selectorNode(topology, dstKey, `sel:${dstKey}`, 2));
      b.edge(pill, dest, states.length ? strongest(states) : rule.action === "deny" ? "denied" : "inactive");
    }
    for (const host of rule.dst.hosts) {
      const dest = b.node({
        id: `host:${host}`,
        kind: "route",
        label: host,
        sub: "Policy host",
        icon: "host",
        rank: 2,
        title: `Named policy host ${host}, reached through a subnet route`,
        details: [{ label: "Reached through", value: "An approved subnet route (not port-filtered at the router)" }],
        link: { href: "/acls", label: "Open policies" },
      });
      b.edge(pill, dest, rule.action === "deny" ? "denied" : "unenforced");
    }
  }
  const networks = networksOf(topology);
  for (const resource of topology.resources) {
    if (!selectorKeys(resource.access).includes(key)) continue;
    const network = networks.find((n) => n.resources.some((r) => r.id === resource.id))!;
    const receiving = topology.edges.some(
      (edge) => edge.kind === "resource" && edge.resource_id === resource.id && from.has(edge.source_node_id),
    );
    const state: EdgeState = !receiving ? "inactive" : resource.port_enforcement === "enforced" ? "allowed" : "unenforced";
    const pill = b.node({
      id: `access:${resource.id}`,
      kind: "rule",
      label: `${resource.name} access`,
      badge: servicesLabel(resource.protocols, resource.ports),
      status: receiving ? "ok" : "idle",
      rank: 1,
      title: `Resource access for ${resource.name}`,
      details: [
        { label: "Who receives it", value: selectorKeys(resource.access).map(selectorLabel).join(", ") },
        { label: "Services", value: servicesLabel(resource.protocols, resource.ports) },
      ],
      link: { href: `/networks/${resource.id}`, label: "Edit resource" },
    });
    b.edge(root, pill, state);
    b.edge(pill, b.node(networkNode(network, `net:${network.key}`, 2)), state);
  }
  return b.graph();
}

function resourceState(topology: Topology, resource: TopologyResource, key: SelectorKey): EdgeState {
  const from = new Set(devicesFor(topology, key).map((device) => device.id));
  const receiving = topology.edges.some(
    (edge) => edge.kind === "resource" && edge.resource_id === resource.id && from.has(edge.source_node_id),
  );
  if (!receiving) return "inactive";
  return resource.port_enforcement === "enforced" ? "allowed" : "unenforced";
}

/** Networks tab overview: who can reach each network, labelled with services. */
export function networksGraph(topology: Topology): Graph {
  const b = new Builder();
  for (const network of networksOf(topology)) {
    const target = b.node(networkNode(network, `net:${network.key}`, 1));
    for (const resource of network.resources) {
      for (const key of selectorKeys(resource.access)) {
        const source = b.node(selectorNode(topology, key, `sel:${key}`, 0));
        b.edge(source, target, resourceState(topology, resource, key), servicesLabel(resource.protocols, resource.ports));
      }
    }
  }
  return b.graph();
}

/** Networks tab drill-in: who → resource access → resource. */
export function networkDetailGraph(topology: Topology, networkKey: string): Graph {
  const b = new Builder();
  const network = networksOf(topology).find((n) => n.key === networkKey);
  if (!network) return b.graph();
  for (const resource of network.resources) {
    const dest = b.node(resourceNode(resource, `res:${resource.id}`, 2));
    const pill = b.node({
      id: `access:${resource.id}`,
      kind: "rule",
      label: `${resource.name} access`,
      badge: servicesLabel(resource.protocols, resource.ports),
      status: resource.receiving > 0 ? "ok" : "idle",
      rank: 1,
      title: `Resource access for ${resource.name}`,
      details: [
        { label: "Who receives it", value: selectorKeys(resource.access).map(selectorLabel).join(", ") || "Nobody" },
        { label: "Services", value: servicesLabel(resource.protocols, resource.ports) },
        { label: "Port filtering", value: resource.port_enforcement.replace("_", " ") },
      ],
      link: { href: `/networks/${resource.id}`, label: "Edit resource" },
    });
    const states: EdgeState[] = [];
    for (const key of selectorKeys(resource.access)) {
      const state = resourceState(topology, resource, key);
      states.push(state);
      b.edge(b.node(selectorNode(topology, key, `sel:${key}`, 0)), pill, state);
    }
    b.edge(pill, dest, states.length ? strongest(states) : "inactive");
  }
  return b.graph();
}
