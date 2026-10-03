import "server-only";

import { coordFetch, readError } from "./coord";
import { can } from "./roles";
import type { ConsoleContext } from "./session";

export type Residency = "onshore" | "offshore";
export type LoggingMode = "off" | "metadata" | "full";

export type AgentSettings = {
  allow_offshore: boolean;
  updated_at: number | null;
  updated_by: string | null;
};

export type AgentProvider = {
  id: string;
  name: string;
  kind: "openai_compatible";
  base_url: string;
  data_location: string;
  residency: Residency;
  has_credential: boolean;
  models: string[];
  enabled: boolean;
  blocked_by_policy: boolean;
  revision: number;
  created_at: number;
  updated_at: number;
};

export type AgentPolicy = {
  bound_node_id: string | null;
  allowed_provider_ids: string[];
  allowed_models: string[];
  daily_request_quota: number;
  daily_token_quota: number;
  max_request_bytes: number;
  logging_mode: LoggingMode;
  log_retention_days: number;
  redact_patterns: string[];
};

export type AgentKey = {
  id: string;
  name: string;
  key_prefix: string;
  policy: AgentPolicy;
  revision: number;
  created_by: string;
  created_at: number;
  updated_at: number;
  last_used_at: number | null;
  revoked_at: number | null;
  today: { requests: number; tokens: number; denied: number };
};

export type AgentGateway = {
  id: string;
  name: string;
  last_seen_at: number | null;
  /** Reports the agent-gateway capability. */
  capable: boolean;
  /** Designated by an owner or admin; only capable and designated devices act as gateways. */
  designated: boolean;
};

export type AgentOverview = {
  settings: AgentSettings;
  providers: AgentProvider[];
  keys: AgentKey[];
  gateways: AgentGateway[];
  icip_warning: string;
  day: string;
};

export type AgentUsageDay = {
  day: string;
  key_id: string;
  key_name: string | null;
  model: string;
  requests: number;
  errors: number;
  prompt_tokens: number;
  completion_tokens: number;
};

export type AgentRequest = {
  id: string;
  key_id: string;
  model: string;
  provider_id: string;
  caller_node_id: string | null;
  status: "pending" | "ok" | "error" | "abandoned";
  http_status: number | null;
  request_bytes: number;
  prompt_tokens: number;
  completion_tokens: number;
  usage_estimated: boolean;
  latency_ms: number | null;
  started_at: number;
  has_content: boolean;
  content_expires_at: number | null;
};

export type AgentUsage = { days: AgentUsageDay[]; recent: AgentRequest[] };

export type ProviderInput = {
  name: string;
  base_url: string;
  data_location: string;
  residency: Residency;
  credential?: string;
  models: string[];
};

export type ProviderUpdate = {
  revision: number;
  enabled?: boolean;
  credential?: string;
  clear_credential?: boolean;
};

function agentsPath(ctx: ConsoleContext, suffix = ""): string {
  return `/v1/orgs/${ctx.coordOrgId}/agents${suffix}`;
}

function requireManage(ctx: ConsoleContext) {
  if (!can(ctx.role, "manage_agent_gateway")) {
    throw new Error("Your role cannot change the agent network.");
  }
}

async function send<T>(res: Response, conflict: string): Promise<T> {
  if (res.status === 412) throw new Error(conflict);
  if (!res.ok) throw new Error(await readError(res));
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export async function getAgentOverview(ctx: ConsoleContext): Promise<AgentOverview> {
  const res = await coordFetch(agentsPath(ctx), { method: "GET", ctx });
  return send<AgentOverview>(res, "");
}

export async function getAgentUsage(ctx: ConsoleContext, days = 14): Promise<AgentUsage> {
  const res = await coordFetch(agentsPath(ctx, `/usage?days=${days}`), { method: "GET", ctx });
  return send<AgentUsage>(res, "");
}

export async function setAllowOffshore(
  ctx: ConsoleContext,
  allowOffshore: boolean,
): Promise<AgentSettings> {
  requireManage(ctx);
  const res = await coordFetch(agentsPath(ctx, "/settings"), {
    method: "PUT",
    ctx,
    body: JSON.stringify({ allow_offshore: allowOffshore }),
  });
  return send<AgentSettings>(res, "");
}

export async function setGatewayDesignation(
  ctx: ConsoleContext,
  nodeId: string,
  designated: boolean,
): Promise<void> {
  requireManage(ctx);
  const res = await coordFetch(agentsPath(ctx, `/gateways/${encodeURIComponent(nodeId)}`), {
    method: "PUT",
    ctx,
    body: JSON.stringify({ designated }),
  });
  await send<void>(res, "");
}

export async function createProvider(
  ctx: ConsoleContext,
  input: ProviderInput,
): Promise<AgentProvider> {
  requireManage(ctx);
  const res = await coordFetch(agentsPath(ctx, "/providers"), {
    method: "POST",
    ctx,
    body: JSON.stringify(input),
  });
  return send<AgentProvider>(res, "");
}

export async function updateProvider(
  ctx: ConsoleContext,
  providerId: string,
  update: ProviderUpdate,
): Promise<AgentProvider> {
  requireManage(ctx);
  const res = await coordFetch(agentsPath(ctx, `/providers/${encodeURIComponent(providerId)}`), {
    method: "PATCH",
    ctx,
    body: JSON.stringify(update),
  });
  return send<AgentProvider>(res, "Someone else changed this provider; reload to see the latest.");
}

export async function deleteProvider(ctx: ConsoleContext, providerId: string): Promise<void> {
  requireManage(ctx);
  const res = await coordFetch(agentsPath(ctx, `/providers/${encodeURIComponent(providerId)}`), {
    method: "DELETE",
    ctx,
  });
  await send<void>(res, "");
}

export async function createAgentKey(
  ctx: ConsoleContext,
  name: string,
  policy: AgentPolicy,
  acknowledgeIcip: boolean,
): Promise<{ key: AgentKey; secret: string }> {
  requireManage(ctx);
  const res = await coordFetch(agentsPath(ctx, "/keys"), {
    method: "POST",
    ctx,
    body: JSON.stringify({ name, policy, acknowledge_icip: acknowledgeIcip }),
  });
  return send<{ key: AgentKey; secret: string }>(res, "");
}

export async function updateAgentKey(
  ctx: ConsoleContext,
  keyId: string,
  revision: number,
  policy: AgentPolicy,
  acknowledgeIcip: boolean,
): Promise<AgentKey> {
  requireManage(ctx);
  const res = await coordFetch(agentsPath(ctx, `/keys/${encodeURIComponent(keyId)}`), {
    method: "PUT",
    ctx,
    body: JSON.stringify({ revision, policy, acknowledge_icip: acknowledgeIcip }),
  });
  return send<AgentKey>(res, "Someone else changed this key; reload to see the latest policy.");
}

export async function revokeAgentKey(ctx: ConsoleContext, keyId: string): Promise<void> {
  requireManage(ctx);
  const res = await coordFetch(agentsPath(ctx, `/keys/${encodeURIComponent(keyId)}`), {
    method: "DELETE",
    ctx,
  });
  await send<void>(res, "");
}

export async function getRequestContent(
  ctx: ConsoleContext,
  requestId: string,
): Promise<{ request: string; response: string; expires_at: number }> {
  if (ctx.role !== "owner") throw new Error("Only owners can read stored prompts.");
  const res = await coordFetch(
    agentsPath(ctx, `/requests/${encodeURIComponent(requestId)}/content`),
    { method: "GET", ctx },
  );
  return send(res, "");
}
