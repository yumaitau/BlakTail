import "server-only";

import type { ConsoleContext } from "./session";
import { coordFetch, type DeviceTag } from "./coord";
import type { OrgRole } from "./roles";

export type ResourceProtocol = "tcp" | "udp" | "icmp";

export type ResourceAccess = {
  roles: OrgRole[];
  tags: DeviceTag[];
  groups: string[];
};

export type RoutingPeer = { node_id: string; metric: number };

/** Whether a routing peer filters what it forwards (`forward-filter`). */
export type ForwardingState = "enforced" | "not_enforced";

export type RoutingPeerState =
  | "primary"
  | "standby"
  | "offline"
  | "not_advertising"
  | "not_connector"
  | "expired"
  | "missing";

export type ResourceState =
  | "distributing"
  | "stale"
  | "no_routing_peer"
  | "dns_not_resolved"
  | "dns_blocked"
  | "disabled";

export type ConnectorLease = {
  route: string;
  ttl: number;
  resolved_at: number;
  expires_at: number;
};

export type ConnectorReport = {
  node_id: string;
  state: "resolved" | "empty" | "blocked" | "error";
  reason: string;
  reported_at: number;
};

export type NetworkResource = {
  id: string;
  name: string;
  description: string;
  kind: "cidr" | "dns";
  cidr: string | null;
  dns_target: string | null;
  family: "ipv4" | "ipv6" | null;
  dns_resolution: "resolved" | "blocked" | "not_resolved" | null;
  ports: string[];
  protocols: ResourceProtocol[];
  port_enforcement: ForwardingState;
  routing_peers: RoutingPeer[];
  access: ResourceAccess;
  enabled: boolean;
  allow_nested_overlap: boolean;
  public_route_confirmed_by: string | null;
  masquerade: "always";
  revision: number;
  etag: string;
  created_at: number;
  updated_at: number;
  connector?: {
    selected: string | null;
    answers: ConnectorLease[];
    reports: ConnectorReport[];
    blocked_reason: string | null;
  };
  status: {
    state: ResourceState;
    selected_routing_peer: string | null;
    forwarding: ForwardingState | "no_routing_peer";
    forwarding_detail: string;
    routing_peers: {
      node_id: string;
      name: string | null;
      metric: number;
      state: RoutingPeerState;
      online: boolean;
      last_seen_at: number | null;
      covering_route: string | null;
      forwarding: ForwardingState;
    }[];
    clients: {
      node_id: string;
      name: string;
      receives: boolean;
      reason: string;
    }[];
  };
};

export type DeviceRoutes = {
  node_id: string;
  name: string;
  display_name: string | null;
  online: boolean;
  last_seen_at: number | null;
  credential_expired: boolean;
  advertised_routes: string[];
  approved_routes: string[];
  unapproved_routes: string[];
  forwarding: ForwardingState;
  forwarding_detail: string;
};

export type NetworksOverview = {
  resources: NetworkResource[];
  device_routes: DeviceRoutes[];
};

export type NetworkResourceInput = {
  name: string;
  description: string;
  cidr?: string;
  dns_target?: string;
  ports: string[];
  protocols: ResourceProtocol[];
  routing_peers: RoutingPeer[];
  access: ResourceAccess;
  enabled: boolean;
  allow_nested_overlap: boolean;
  confirm_public_route: boolean;
  etag?: string;
  dry_run?: boolean;
};

async function networksFetch(
  ctx: ConsoleContext,
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  return coordFetch(`/v1/orgs/${ctx.coordOrgId}/networks${path}`, {
    ...init,
    ctx,
  });
}

async function readError(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { error?: string };
    if (body.error) return body.error;
  } catch {
    /* ignore */
  }
  return `Coordinator returned ${res.status}`;
}

async function expectJson<T>(res: Response): Promise<T> {
  if (!res.ok) throw new Error(await readError(res));
  return res.json() as Promise<T>;
}

export async function listNetworks(ctx: ConsoleContext): Promise<NetworksOverview> {
  return expectJson(await networksFetch(ctx, "", { method: "GET" }));
}

export async function getNetworkResource(
  ctx: ConsoleContext,
  id: string,
): Promise<NetworkResource | null> {
  const res = await networksFetch(ctx, `/${encodeURIComponent(id)}`, { method: "GET" });
  if (res.status === 404) return null;
  return expectJson(res);
}

export async function createNetworkResource(
  ctx: ConsoleContext,
  input: NetworkResourceInput,
): Promise<NetworkResource> {
  return expectJson(
    await networksFetch(ctx, "", { method: "POST", body: JSON.stringify(input) }),
  );
}

export async function updateNetworkResource(
  ctx: ConsoleContext,
  id: string,
  input: NetworkResourceInput,
): Promise<NetworkResource> {
  return expectJson(
    await networksFetch(ctx, `/${encodeURIComponent(id)}`, {
      method: "PUT",
      body: JSON.stringify(input),
    }),
  );
}

export async function deleteNetworkResource(
  ctx: ConsoleContext,
  id: string,
  etag: string,
): Promise<void> {
  const res = await networksFetch(ctx, `/${encodeURIComponent(id)}`, {
    method: "DELETE",
    headers: { "if-match": `"${etag}"` },
  });
  if (!res.ok) throw new Error(await readError(res));
}

/** Converts a stored resource back into a full-replacement PUT body. */
export function resourceInput(resource: NetworkResource): NetworkResourceInput {
  return {
    name: resource.name,
    description: resource.description,
    ...(resource.cidr ? { cidr: resource.cidr } : {}),
    ...(resource.dns_target ? { dns_target: resource.dns_target } : {}),
    ports: resource.ports,
    protocols: resource.protocols,
    routing_peers: resource.routing_peers,
    access: resource.access,
    enabled: resource.enabled,
    allow_nested_overlap: resource.allow_nested_overlap,
    confirm_public_route: false,
    etag: resource.etag,
  };
}
