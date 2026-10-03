import "server-only";

import { coordFetch, readError, type DeviceTag } from "./coord";
import { permissionReason } from "./roles";
import type { ConsoleContext } from "./session";

export type PqMode = "off" | "prefer" | "require";

/** What the agent on one side of a pair says it actually negotiated. */
export type PqState =
  | "classical"
  | "negotiating"
  | "established"
  | "degraded"
  | "required_not_established";

export type PqRule = { tags: [DeviceTag, DeviceTag]; mode: PqMode };

export type PqPolicy = {
  mode: PqMode;
  block_unestablished: boolean;
  rules: PqRule[];
  revision: number;
  updated_by: string;
  updated_at: number;
};

export type PqPeerProtection = {
  node_id: string;
  peer_id: string;
  peer_name: string;
  state: PqState;
  mode: PqMode;
  algorithm: string;
  epoch: number;
  last_rotation_at: number | null;
  rotated_seconds_ago: number | null;
  blocked: boolean;
  reason: string;
  reported_at: number;
  stale: boolean;
};

/** Policy, capability per device and per-peer reports. Never key material. */
export type PqOverview = {
  org_id: string;
  server_time: number;
  policy: PqPolicy;
  devices: { id: string; name: string; capable: boolean }[];
  peers: PqPeerProtection[];
};

export async function getPqOverview(ctx: ConsoleContext, nodeId?: string): Promise<PqOverview> {
  const query = nodeId ? `?node_id=${encodeURIComponent(nodeId)}` : "";
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}/post-quantum${query}`, {
    ctx,
    method: "GET",
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json() as Promise<PqOverview>;
}

export async function putPqPolicy(
  ctx: ConsoleContext,
  input: {
    mode: PqMode;
    block_unestablished: boolean;
    rules: PqRule[];
    expected_revision: number;
  },
): Promise<PqPolicy> {
  const denied = permissionReason(ctx.role, "manage_security");
  if (denied) throw new Error(denied);
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}/post-quantum`, {
    ctx,
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(input),
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json() as Promise<PqPolicy>;
}

function ago(seconds: number): string {
  if (seconds < 90) return `${seconds}s ago`;
  if (seconds < 7200) return `${Math.round(seconds / 60)} min ago`;
  return `${Math.round(seconds / 3600)} h ago`;
}

const REASONS: Record<string, string> = {
  policy_off: "Policy does not ask for post-quantum protection on this pair.",
  peer_not_capable: "The peer's agent does not advertise pq-psk (older or opted-out agent).",
  local_not_capable: "This device's agent does not advertise pq-psk.",
  not_yet_established: "No hybrid key has been agreed yet.",
  rotation_failed: "Rotation has failed past the key lifetime.",
  block_not_supported_here:
    "This platform cannot block the pair; the Linux side blocks it if it runs a current agent.",
};

/**
 * The per-peer protection label. Wording is deliberately literal: it names
 * the algorithms and never says "quantum-safe".
 */
export function protectionLabel(row: PqPeerProtection): {
  label: string;
  detail: string;
  tone: "online" | "warn" | "offline" | "";
} {
  const reason = REASONS[row.reason] ?? "";
  switch (row.state) {
    case "established":
      return {
        label: `Hybrid PQ (ML-KEM-768 + X25519)${
          row.rotated_seconds_ago !== null ? `, rotated ${ago(row.rotated_seconds_ago)}` : ""
        }`,
        detail: `Epoch ${row.epoch}. Authentication is still classical WireGuard.`,
        tone: "online",
      };
    case "degraded":
      return {
        label: "Hybrid PQ key expired (rotation failing)",
        detail: `${reason} The last agreed key stays in use; traffic is not blocked because policy is prefer.`,
        tone: "warn",
      };
    case "required_not_established":
      return {
        label: "Required but not established",
        detail: `${reason}${row.blocked ? " Traffic for this pair is blocked except the key exchange." : " Traffic is not blocked by this device."}`,
        tone: "offline",
      };
    case "negotiating":
      return {
        label: "Classical (hybrid PQ negotiating)",
        detail: reason,
        tone: "",
      };
    default:
      return { label: "Classical", detail: reason, tone: "" };
  }
}
