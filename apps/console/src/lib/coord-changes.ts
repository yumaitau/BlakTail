import "server-only";

import { coordFetch, readError } from "./coord";
import type { TopologyEdge } from "./coord-topology";
import type { ConsoleContext } from "./session";

export type ChangeSurface = "policy" | "dns" | "resources";

export type DraftPayload = {
  policy?: Record<string, unknown>;
  dns?: Record<string, unknown>;
  resources?: Record<string, unknown>[];
};

export type ChangeDraft = {
  id: string;
  title: string;
  status: "open" | "published" | "discarded" | "expired";
  version: number;
  surfaces: ChangeSurface[];
  created_by: string;
  created_by_name: string;
  updated_by: string;
  created_at: number;
  updated_at: number;
  expires_at: number;
  closed_at: number | null;
  closed_by: string | null;
  base: {
    policy_etag?: string;
    policy_revision?: number;
    dns_etag?: string;
    dns_revision?: number;
    resources_etag?: string;
  };
  /** Absent unless this role may manage every surface the draft touches. */
  payload?: DraftPayload;
  result?: Record<string, unknown>;
  can_edit: boolean;
};

export type RiskFlag = { code: string; severity: "high" | "warning"; message: string };

export type PairResult = {
  source_node_id: string;
  destination_node_id: string;
  protocol?: "tcp" | "udp" | "icmp" | null;
  port?: number | null;
  before: { decision: "allow" | "deny"; basis: string; enforcement: string };
  after: { decision: "allow" | "deny"; basis: string; enforcement: string } | null;
  changed: boolean;
};

export type ResourceChange = {
  op: "create" | "update" | "delete";
  id: string;
  name: string;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
};

export type DraftPreview = {
  draft_id: string;
  version: number;
  generated_at: number;
  valid: boolean;
  errors: string[];
  stale_surfaces: ChangeSurface[];
  policy?: { before: unknown; after: unknown };
  dns?: { before: unknown; after: unknown };
  resources: ResourceChange[];
  reachability: { added: TopologyEdge[]; removed: TopologyEdge[]; truncated: boolean };
  pairs: PairResult[];
  risks: RiskFlag[];
  dns_warnings: string[];
  notes: string[];
};

export type PreviewPair = {
  source_node_id: string;
  destination_node_id: string;
  protocol?: "tcp" | "udp" | "icmp";
  port?: number;
};

function path(ctx: ConsoleContext, suffix = ""): string {
  return `/v1/orgs/${ctx.coordOrgId}/changes${suffix}`;
}

async function send<T>(
  ctx: ConsoleContext,
  suffix: string,
  method: string,
  body?: unknown,
): Promise<T> {
  const res = await coordFetch(path(ctx, suffix), {
    ctx,
    method,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json() as Promise<T>;
}

export async function listDrafts(ctx: ConsoleContext): Promise<ChangeDraft[]> {
  return (await send<{ drafts: ChangeDraft[] }>(ctx, "", "GET")).drafts;
}

export async function getDraft(ctx: ConsoleContext, id: string): Promise<ChangeDraft | null> {
  const res = await coordFetch(path(ctx, `/${encodeURIComponent(id)}`), { ctx, method: "GET" });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(await readError(res));
  return res.json() as Promise<ChangeDraft>;
}

export function createDraft(
  ctx: ConsoleContext,
  title: string,
  surfaces: ChangeSurface[],
): Promise<ChangeDraft> {
  return send(ctx, "", "POST", { title, surfaces });
}

export function updateDraft(
  ctx: ConsoleContext,
  id: string,
  version: number,
  title: string,
  payload: DraftPayload,
): Promise<ChangeDraft> {
  return send(ctx, `/${encodeURIComponent(id)}`, "PUT", { version, title, payload });
}

export function previewDraft(
  ctx: ConsoleContext,
  id: string,
  pairs: PreviewPair[],
): Promise<DraftPreview> {
  return send(ctx, `/${encodeURIComponent(id)}/preview`, "POST", { pairs });
}

export function rebaseDraft(ctx: ConsoleContext, id: string, version: number): Promise<ChangeDraft> {
  return send(ctx, `/${encodeURIComponent(id)}/rebase`, "POST", { version });
}

export function discardDraft(ctx: ConsoleContext, id: string, version: number): Promise<ChangeDraft> {
  return send(ctx, `/${encodeURIComponent(id)}/discard`, "POST", { version });
}

export function publishDraft(
  ctx: ConsoleContext,
  id: string,
  version: number,
  confirmRisks: string[],
): Promise<ChangeDraft> {
  return send(ctx, `/${encodeURIComponent(id)}/publish`, "POST", {
    version,
    confirm_risks: confirmRisks,
  });
}
