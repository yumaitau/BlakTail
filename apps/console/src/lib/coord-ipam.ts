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

export type AddressState = "active" | "revoked" | "tombstoned" | "released";

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
