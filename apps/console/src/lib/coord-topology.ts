import "server-only";

import { coordFetch, readError, type DeviceTag } from "./coord";
import type { OrgRole } from "./roles";
import type { ConsoleContext } from "./session";

export type TopologyNode = {
  id: string;
  name: string;
  label: string;
  role: OrgRole;
  tags: DeviceTag[];
  state: "online" | "stale" | "never" | "suspended" | "expired";
  last_seen_at: number | null;
  transport: {
    state: "direct" | "relay" | "mixed" | "not_measured";
    reported_at: number | null;
    stale: boolean;
  };
  packet_filter: "enforced" | "unknown" | "not_enforced";
  advertised_routes: string[];
  approved_routes: string[];
};

export type TopologyEdge = {
  kind: "device" | "resource" | "route" | "exit";
  source_node_id: string;
  target_node_id: string | null;
  resource_id: string | null;
  destination: string;
  basis: string;
  enforcement: "device_enforced" | "not_enforced" | "unknown" | "route_not_filtered" | "peer_map";
  path: "direct" | "relay" | "mixed" | "unknown" | "peer_offline";
  explanation: string;
  edit: { surface: "policy" | "network_resource" | "device"; id: string | null };
};

export type TopologyResource = {
  id: string;
  name: string;
  destination: string;
  enabled: boolean;
  state: string;
  selected_routing_peer: string | null;
  routing_peers: { node_id: string; name: string | null; state: string }[];
  receiving: number;
};

export type Topology = {
  org_id: string;
  generated_at: number;
  control_revision: number;
  policy: { revision: number; etag: string; defaults: string };
  nodes: TopologyNode[];
  resources: TopologyResource[];
  routes: { node_id: string; cidr: string; kind: "subnet" | "exit" }[];
  edges: TopologyEdge[];
  truncated: boolean;
  notes: string[];
};

export async function getTopology(ctx: ConsoleContext): Promise<Topology> {
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}/topology`, {
    ctx,
    method: "GET",
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json() as Promise<Topology>;
}

/** Owner-scoped console page where the thing behind an edge is changed. */
export function editHref(edge: Pick<TopologyEdge, "edit">): string {
  switch (edge.edit.surface) {
    case "network_resource":
      return edge.edit.id ? `/networks/${edge.edit.id}` : "/networks";
    case "device":
      return edge.edit.id ? `/devices/${edge.edit.id}` : "/devices";
    default:
      return "/acls";
  }
}
