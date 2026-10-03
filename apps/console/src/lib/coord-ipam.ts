import "server-only";

import { coordFetch } from "./coord";
import type { ConsoleContext } from "./session";

export type IpamPool = {
  family: "ipv4" | "ipv6";
  cidr: string;
  supernet: string;
  usable: number;
  used: number;
  reserved: number;
  in_grace: number;
  available: number;
  note: string;
};

export type AddressState = "active" | "retiring" | "revoked" | "tombstoned" | "released";

export type IpamAddress = {
  address: string;
  ipv6: string;
  state: AddressState;
  node_id: string | null;
  node_name: string | null;
  released_at: number | null;
  reusable_at: number | null;
  reservation_id: string | null;
};

export type ReservationState =
  | "held"
  | "waiting"
  | "assigned"
  | "pending_reenrolment"
  | "conflict";

export type IpamReservation = {
  id: string;
  address: string;
  ipv6: string;
  bound_name: string | null;
  bound_key_fingerprint: string | null;
  reason: string;
  created_by: string;
  created_at: number;
  revision: number;
  etag: string;
  state: ReservationState;
  detail: string;
};

export type IpamConflict = { address: string; kind: string; detail: string };

export type IpamView = {
  pools: IpamPool[];
  addresses: IpamAddress[];
  reservations: IpamReservation[];
  conflicts: IpamConflict[];
  reuse_grace_seconds: number;
  next_free: string | null;
  /** Smallest and largest IPv4 pool prefix lengths, e.g. [20, 24]. */
  pool_prefix_range: [number, number];
  renumber: RenumberSummary;
};

export type RenumberMove = {
  node_id: string;
  name: string;
  old_addresses: string[];
  new_addresses: string[];
};

export type RenumberPlanState = "staged" | "completed" | "rolled_back";

export type RenumberPlan = {
  id: string;
  kind: "pool" | "devices";
  state: RenumberPlanState;
  previous_pool: string;
  target_pool: string;
  moves: RenumberMove[];
  window_seconds: number;
  window_ends_at: number;
  reason: string;
  created_by: string;
  created_at: number;
  finished_by: string | null;
  finished_at: number | null;
  revision: number;
  etag: string;
};

export type RenumberSummary = {
  staged: RenumberPlan | null;
  history: RenumberPlan[];
  default_window_seconds: number;
  min_window_seconds: number;
};

export type RenumberBlocker = { kind: string; detail: string };

export type RenumberPreview = {
  kind: "pool" | "devices";
  current_pool: string;
  target_pool: string;
  window_seconds: number;
  moves: RenumberMove[];
  unchanged_devices: number;
  peer_maps: number;
  forward_allow_lists: number;
  magic_dns_names: string[];
  blockers: RenumberBlocker[];
};

/** Either a pool change or a list of devices, never both. */
export type RenumberInput = {
  pool?: string;
  devices?: { node_id: string; address?: string }[];
  window_seconds?: number;
  reason?: string;
};

export type ReservationInput = {
  address: string;
  bound_name?: string;
  bound_wg_public_key?: string;
  reason: string;
};

async function ipamFetch(
  ctx: ConsoleContext,
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  return coordFetch(`/v1/orgs/${ctx.coordOrgId}/ipam${path}`, {
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

export async function getIpam(ctx: ConsoleContext): Promise<IpamView> {
  const res = await ipamFetch(ctx, "", { method: "GET" });
  if (!res.ok) throw new Error(await readError(res));
  return res.json() as Promise<IpamView>;
}

/** Replaying an identical reservation is a no-op on the coordinator. */
export async function reserveAddress(
  ctx: ConsoleContext,
  input: ReservationInput,
): Promise<IpamReservation> {
  const res = await ipamFetch(ctx, "/reservations", {
    method: "POST",
    body: JSON.stringify(input),
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json() as Promise<IpamReservation>;
}

/** Idempotent: releasing an already-released reservation succeeds. */
export async function releaseReservation(
  ctx: ConsoleContext,
  id: string,
  etag: string,
): Promise<void> {
  const res = await ipamFetch(ctx, `/reservations/${encodeURIComponent(id)}`, {
    method: "DELETE",
    headers: { "if-match": `"${etag}"` },
  });
  if (res.status === 412) {
    throw new Error("Someone else changed this reservation. Reload to see the latest version.");
  }
  if (!res.ok) throw new Error(await readError(res));
}

export async function previewRenumber(
  ctx: ConsoleContext,
  input: RenumberInput,
): Promise<RenumberPreview> {
  const res = await ipamFetch(ctx, "/renumber/preview", {
    method: "POST",
    body: JSON.stringify(input),
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json() as Promise<RenumberPreview>;
}

export async function startRenumber(
  ctx: ConsoleContext,
  input: RenumberInput,
): Promise<RenumberPlan> {
  const res = await ipamFetch(ctx, "/renumber", {
    method: "POST",
    body: JSON.stringify(input),
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json() as Promise<RenumberPlan>;
}

/** Completes or rolls back the staged plan; the etag guards against a stale page. */
export async function finishRenumber(
  ctx: ConsoleContext,
  planId: string,
  etag: string,
  how: "complete" | "rollback",
): Promise<RenumberPlan> {
  const res = await ipamFetch(ctx, `/renumber/${encodeURIComponent(planId)}/${how}`, {
    method: "POST",
    headers: { "if-match": `"${etag}"` },
  });
  if (res.status === 412) {
    throw new Error("This renumber plan changed since the page loaded. Reload to see its state.");
  }
  if (!res.ok) throw new Error(await readError(res));
  return res.json() as Promise<RenumberPlan>;
}
