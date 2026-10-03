import "server-only";

import {
  coordFetch,
  type AuditEvent,
  type CoordNode,
  type DeviceTag,
} from "./coord";
import { can } from "./roles";
import type { ConsoleContext } from "./session";

export type HeartbeatState = "online" | "stale" | "never";
export type TransportState = "direct" | "relay" | "mixed" | "not_measured";
export type LifecycleState = "active" | "suspended" | "revoked" | "deleted";

export type PeerDetail = {
  node: CoordNode & { suspended?: boolean };
  server_time: number;
  public_key_fingerprint: string;
  heartbeat: {
    state: HeartbeatState;
    last_seen_at: number | null;
    age_seconds: number | null;
    online_window_seconds: number;
  };
  transport: {
    state: TransportState;
    reported_at: number | null;
    source: string;
    relay_endpoint: string | null;
    relay_endpoint_updated_at: number | null;
  };
  version: {
    agent_version: string | null;
    minimum_version: string;
    status: "supported" | "below_minimum" | "unknown";
    upgrade_guide: string;
  };
  lifecycle: {
    state: LifecycleState;
    suspended_at: number | null;
    revoked_at: number | null;
    deleted_at: number | null;
  };
  audit: AuditEvent[];
};

export type JoinKeyState = "active" | "expired" | "revoked" | "used_up";

/** Inventory row. The coordinator never returns the secret or its hash. */
export type JoinKeySummary = {
  id: string;
  name: string;
  description: string;
  created_by: string;
  created_by_role: string;
  created_at: number;
  expires_at: number;
  single_use: boolean;
  max_uses: number | null;
  use_count: number;
  remaining_uses: number | null;
  last_used_at: number | null;
  revoked_at: number | null;
  tags: DeviceTag[];
  state: JoinKeyState;
};

export type MintedJoinKey = {
  id: string;
  key: string;
  expires_at: number;
  single_use: boolean;
  name: string;
  max_uses: number | null;
};

export class CoordRequestError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

/** Coordinator URL shown in install instructions; never carries a secret. */
export function agentCoordinatorUrl(): string | null {
  return process.env.COORD_BASE_URL?.replace(/\/$/, "") ?? null;
}

async function coordRequest<T>(
  ctx: ConsoleContext,
  path: string,
  init: { method: string; body?: unknown },
): Promise<T> {
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}${path}`, {
    method: init.method,
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
    ctx,
  });
  if (!res.ok) {
    let message = `Coordinator returned ${res.status}`;
    try {
      const body = (await res.json()) as { error?: string };
      if (body.error) message = body.error;
    } catch {
      /* keep status message */
    }
    throw new CoordRequestError(message, res.status);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export function getPeerDetail(
  ctx: ConsoleContext,
  nodeId: string,
): Promise<PeerDetail> {
  return coordRequest(ctx, `/nodes/${encodeURIComponent(nodeId)}`, {
    method: "GET",
  });
}

export async function setPeerSuspended(
  ctx: ConsoleContext,
  nodeId: string,
  suspend: boolean,
  reason: string,
): Promise<void> {
  if (!can(ctx.role, "manage_peers")) {
    throw new Error("Only owners and admins can suspend or resume devices.");
  }
  await coordRequest<void>(
    ctx,
    `/nodes/${encodeURIComponent(nodeId)}/${suspend ? "suspend" : "resume"}`,
    { method: "POST", body: suspend ? { reason } : {} },
  );
}

export function listJoinKeys(ctx: ConsoleContext): Promise<JoinKeySummary[]> {
  if (!can(ctx.role, "manage_join_keys")) {
    throw new Error("Members cannot list join keys.");
  }
  return coordRequest(ctx, "/join-keys", { method: "GET" });
}

export function mintEnrolmentKey(
  ctx: ConsoleContext,
  input: {
    name: string;
    description: string;
    expiresInSeconds: number;
    singleUse: boolean;
    maxUses: number | null;
    tags: DeviceTag[];
  },
): Promise<MintedJoinKey> {
  if (!can(ctx.role, "manage_join_keys")) {
    throw new Error("Members cannot mint join keys.");
  }
  return coordRequest(ctx, "/join-keys", {
    method: "POST",
    body: {
      name: input.name,
      description: input.description,
      expires_in_seconds: input.expiresInSeconds,
      single_use: input.singleUse,
      max_uses: input.singleUse ? null : input.maxUses,
      tags: input.tags,
    },
  });
}

export async function revokeJoinKey(
  ctx: ConsoleContext,
  keyId: string,
): Promise<void> {
  if (!can(ctx.role, "manage_join_keys")) {
    throw new Error("Members cannot revoke join keys.");
  }
  await coordRequest<void>(ctx, `/join-keys/${encodeURIComponent(keyId)}`, {
    method: "DELETE",
  });
}
