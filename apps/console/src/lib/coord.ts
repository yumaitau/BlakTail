import "server-only";

import { requireWriteAssurance } from "./auth-policy";
import { CoordError } from "./errors";
import { coordError, errorText, rememberResponseRole } from "./server-errors";
import { signCoordAssertion } from "./coord-assertion";
import { can, permissionReason, roleLabel } from "./roles";
import {
  organisationContext,
  type ConsoleContext,
  type PersonSessionContext,
} from "./session";

export type DeviceTag = "office" | "ranger" | "store";

export type CoordNode = {
  id: string;
  name: string;
  display_name: string | null;
  wg_public_key: string;
  endpoint: string | null;
  allowed_ips: string[];
  advertised_routes: string[];
  approved_routes: string[];
  dns_name: string;
  user_id: string;
  user_role: string;
  tags: DeviceTag[];
  created_at: number;
  credential_expires_at: number;
  expired: boolean;
  expires_soon: boolean;
  revoked: boolean;
  suspended?: boolean;
  deleted?: boolean;
  online?: boolean;
  last_seen_at?: number | null;
  os?: string | null;
  os_version?: string | null;
  agent_version?: string | null;
  hostname?: string | null;
  capabilities?: string[];
  ephemeral?: boolean;
  shares?: DeviceShare[];
  dns_applied_revision?: number;
};

export type DeviceShare = {
  label: string;
  path: string;
  port: number;
  read_only: boolean;
  enabled: boolean;
};

export type ApiClient = {
  id: string;
  name: string;
  token_prefix: string;
  scopes: string[];
  created_at: number;
  last_used_at: number | null;
  expires_at: number | null;
  revoked: boolean;
  suspended?: boolean;
  rotated_at?: number | null;
};

export type ApiClientCreated = ApiClient & {
  token: string;
};

export type WebhookDestination = {
  id: string;
  name: string;
  url: string;
  secret_prefix: string;
  enabled: boolean;
  created_at: number;
  /** Catalogued event types, or ["*"] for every event. */
  event_types?: string[];
  secret?: string | null;
  /** "webhook" (default), or an email/Slack/Teams channel (coord-notifications). */
  kind?: "webhook" | "email" | "slack" | "teams";
  recipients?: string[];
  quiet_hours?: { timezone: string; start: string; end: string } | null;
  digest_minutes?: number;
  residency_acknowledged_at?: number | null;
};

export type WebhookDelivery = {
  id: string;
  destination_id: string;
  event_id: string;
  event_type: string;
  created_at: number;
  attempts: number;
  last_error: string | null;
  delivered_at: number | null;
  dead_lettered_at: number | null;
};

export type NetworkNode = CoordNode & {
  organisation_id: string;
  organisation_name: string;
  network_account_id: string;
  network_account_name: string;
  effective_role: ConsoleContext["role"];
};

export type NetworkNodeInventory = {
  nodes: NetworkNode[];
  errors: string[];
};

export type JoinKeyResult = {
  id: string;
  key: string;
  expires_at: number;
  single_use: boolean;
};

export type DeviceAuthorizationPreview = {
  name: string;
  public_key_fingerprint: string;
  expires_at: number;
  approved: boolean;
};

export type CoordHealth = {
  status: string;
};

export type AuditEvent = {
  id: string;
  actor_user_id: string;
  actor_name: string;
  actor_email: string;
  actor_role: string;
  action: string;
  target_type: string;
  target_id: string | null;
  details: unknown;
  created_at: number;
};

function coordBaseUrl(): string {
  const url = process.env.COORD_BASE_URL;
  if (!url) {
    throw new Error("COORD_BASE_URL is required (HTTPS coordinator URL).");
  }
  return url.replace(/\/$/, "");
}

/** Default per-request timeout. Streams (exports) pass their own `signal`. */
const COORD_TIMEOUT_MS = 30_000;

export async function coordFetch(
  path: string,
  init: RequestInit & { ctx?: ConsoleContext } = {},
): Promise<Response> {
  const { ctx, headers: initHeaders, ...rest } = init;
  const headers = new Headers(initHeaders);
  if (ctx) {
    const method = (rest.method ?? "GET").toUpperCase();
    if (method !== "GET" && method !== "HEAD") {
      // The organisation's MFA rule gates every coordinator write.
      await requireWriteAssurance(ctx);
    }
    headers.set("Authorization", `Bearer ${signCoordAssertion(ctx)}`);
  }
  if (!headers.has("content-type") && rest.body) {
    headers.set("content-type", "application/json");
  }
  const url = `${coordBaseUrl()}${path}`;
  let res: Response;
  try {
    res = await fetch(url, {
      ...rest,
      signal: rest.signal ?? AbortSignal.timeout(COORD_TIMEOUT_MS),
      headers,
      cache: "no-store",
    });
  } catch (cause) {
    // Network failure or timeout: log the cause, surface a mapped message.
    const timeout =
      cause instanceof Error && (cause.name === "TimeoutError" || cause.name === "AbortError");
    const error = new CoordError({ transport: timeout ? "timeout" : "network" });
    console.error(
      JSON.stringify({
        level: "error",
        scope: `coordinator ${path.split("?")[0]}`,
        ref: error.ref,
        kind: error.user.kind,
        cause: cause instanceof Error ? `${cause.name}: ${cause.message}` : String(cause),
      }),
    );
    error.logged = true;
    throw error;
  }
  if (ctx && !res.ok) rememberResponseRole(res, roleLabel(ctx.role));
  return res;
}

/**
 * Raw coordinator error text, for server logs only. Never show it to people:
 * throw `await coordError(res)` instead.
 */
export async function readError(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { error?: string; code?: string; request_id?: string };
    if (body.error) {
      return `${body.error} (${body.code ?? res.status}${body.request_id ? `, ${body.request_id}` : ""})`;
    }
  } catch {
    /* ignore */
  }
  return `Coordinator returned ${res.status}`;
}

export { coordError };

export async function getCoordHealth(): Promise<CoordHealth> {
  const res = await coordFetch("/health", { method: "GET" });
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json() as Promise<CoordHealth>;
}

export async function listNodes(ctx: ConsoleContext): Promise<CoordNode[]> {
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}/nodes`, {
    method: "GET",
    ctx,
  });
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json() as Promise<CoordNode[]>;
}

export async function listAllNodes(
  person: PersonSessionContext,
): Promise<NetworkNodeInventory> {
  const inventories = await Promise.all(
    person.organisations.map(async (organisation) => {
      const ctx = organisationContext(person, organisation.organisationId);
      try {
        const nodes = await listNodes(ctx);
        return {
          nodes: nodes.map((node) => {
            const identityIndex = organisation.identityUserIds.indexOf(
              node.user_id,
            );
            const accountIndex = identityIndex < 0 ? 0 : identityIndex;
            return {
              ...node,
              organisation_id: ctx.organisationId,
              organisation_name: ctx.organisationName,
              network_account_id:
                organisation.networkAccountIds[accountIndex] ??
                ctx.networkAccountId,
              network_account_name:
                organisation.networkAccountNames[accountIndex] ??
                ctx.networkAccountName,
              effective_role: ctx.role,
            };
          }),
          error: null,
        };
      } catch (error) {
        return {
          nodes: [],
          error: `${organisation.organisationName}: ${
            errorText(error, "Could not load devices.", "inventory")
          }`,
        };
      }
    }),
  );
  return {
    nodes: inventories
      .flatMap((inventory) => inventory.nodes)
      .sort(
        (left, right) =>
          left.organisation_name.localeCompare(right.organisation_name) ||
          (left.display_name || left.name).localeCompare(
            right.display_name || right.name,
          ),
      ),
    errors: inventories.flatMap((inventory) =>
      inventory.error ? [inventory.error] : [],
    ),
  };
}

export async function listAuditEvents(
  ctx: ConsoleContext,
): Promise<AuditEvent[]> {
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}/audit?limit=100`, {
    method: "GET",
    ctx,
  });
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json() as Promise<AuditEvent[]>;
}

export async function revokeNode(
  ctx: ConsoleContext,
  nodeId: string,
): Promise<void> {
  const denied = permissionReason(ctx.role, "manage_peers");
  if (denied) {
    throw new Error(denied);
  }
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}/nodes/${nodeId}`, {
    method: "DELETE",
    ctx,
  });
  if (!res.ok) {
    throw await coordError(res);
  }
}

export async function tombstoneNode(
  ctx: ConsoleContext,
  nodeId: string,
): Promise<void> {
  const denied = permissionReason(ctx.role, "manage_peers");
  if (denied) {
    throw new Error(denied);
  }
  const res = await coordFetch(
    `/v1/orgs/${ctx.coordOrgId}/nodes/${nodeId}/tombstone`,
    {
      method: "POST",
      ctx,
    },
  );
  if (!res.ok) {
    throw await coordError(res);
  }
}

export async function listApiClients(
  ctx: ConsoleContext,
): Promise<ApiClient[]> {
  const denied = permissionReason(ctx.role, "manage_api_clients");
  if (denied) {
    throw new Error(denied);
  }
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}/api-clients`, {
    method: "GET",
    ctx,
  });
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json() as Promise<ApiClient[]>;
}

export async function createApiClient(
  ctx: ConsoleContext,
  input: { name: string; scopes: string[] },
): Promise<ApiClientCreated> {
  const denied = permissionReason(ctx.role, "manage_api_clients");
  if (denied) {
    throw new Error(denied);
  }
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}/api-clients`, {
    method: "POST",
    ctx,
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json() as Promise<ApiClientCreated>;
}

export async function listWebhooks(
  ctx: ConsoleContext,
): Promise<WebhookDestination[]> {
  const denied = permissionReason(ctx.role, "manage_integrations");
  if (denied) {
    throw new Error(denied);
  }
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}/webhooks`, {
    method: "GET",
    ctx,
  });
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json() as Promise<WebhookDestination[]>;
}

export async function createWebhook(
  ctx: ConsoleContext,
  input: { name: string; url: string },
): Promise<WebhookDestination> {
  const denied = permissionReason(ctx.role, "manage_integrations");
  if (denied) {
    throw new Error(denied);
  }
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}/webhooks`, {
    method: "POST",
    ctx,
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json() as Promise<WebhookDestination>;
}

export async function disableWebhook(
  ctx: ConsoleContext,
  destinationId: string,
): Promise<void> {
  const denied = permissionReason(ctx.role, "manage_integrations");
  if (denied) {
    throw new Error(denied);
  }
  const res = await coordFetch(
    `/v1/orgs/${ctx.coordOrgId}/webhooks/${destinationId}`,
    {
      method: "DELETE",
      ctx,
    },
  );
  if (!res.ok) {
    throw await coordError(res);
  }
}

export async function listWebhookDeliveries(
  ctx: ConsoleContext,
  destinationId: string,
): Promise<WebhookDelivery[]> {
  const denied = permissionReason(ctx.role, "manage_integrations");
  if (denied) {
    throw new Error(denied);
  }
  const res = await coordFetch(
    `/v1/orgs/${ctx.coordOrgId}/webhooks/${destinationId}/deliveries`,
    {
      method: "GET",
      ctx,
    },
  );
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json() as Promise<WebhookDelivery[]>;
}

export async function emitMembershipUpdated(
  ctx: ConsoleContext,
  payload: { membership_id: string; role: string; status: string; previous_role?: string },
): Promise<void> {
  if (!can(ctx.role, "manage_security")) {
    return;
  }
  const events = ["membership.updated"];
  if (payload.previous_role && payload.previous_role !== payload.role) {
    events.push("membership.role_changed");
  }
  try {
    for (const eventType of events) {
      const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}/webhooks/events`, {
        method: "POST",
        ctx,
        body: JSON.stringify({
          event_type: eventType,
          payload,
        }),
      });
      if (!res.ok) {
        console.warn(`membership webhook enqueue failed: ${await readError(res)}`);
      }
    }
  } catch (error) {
    console.warn(
      `membership webhook enqueue failed: ${
        error instanceof Error ? error.message : "unknown error"
      }`,
    );
  }
}

export async function replayWebhookDelivery(
  ctx: ConsoleContext,
  deliveryId: string,
): Promise<void> {
  const denied = permissionReason(ctx.role, "manage_integrations");
  if (denied) {
    throw new Error(denied);
  }
  const res = await coordFetch(
    `/v1/orgs/${ctx.coordOrgId}/webhooks/deliveries/${deliveryId}/replay`,
    {
      method: "POST",
      ctx,
    },
  );
  if (!res.ok) {
    throw await coordError(res);
  }
}

export async function revokeApiClient(
  ctx: ConsoleContext,
  clientId: string,
): Promise<void> {
  const denied = permissionReason(ctx.role, "manage_api_clients");
  if (denied) {
    throw new Error(denied);
  }
  const res = await coordFetch(
    `/v1/orgs/${ctx.coordOrgId}/api-clients/${clientId}`,
    {
      method: "DELETE",
      ctx,
    },
  );
  if (!res.ok) {
    throw await coordError(res);
  }
}

export async function updateNodeFriendlyName(
  ctx: ConsoleContext,
  nodeId: string,
  friendlyName: string,
): Promise<void> {
  const denied = permissionReason(ctx.role, "manage_peers");
  if (denied) {
    throw new Error(denied);
  }
  const res = await coordFetch(
    `/v1/orgs/${ctx.coordOrgId}/nodes/${nodeId}/friendly-name`,
    {
      method: "PUT",
      ctx,
      body: JSON.stringify({ friendly_name: friendlyName }),
    },
  );
  if (!res.ok) {
    throw await coordError(res);
  }
}

export async function approveNodeRoutes(
  ctx: ConsoleContext,
  nodeId: string,
  approvedRoutes: string[],
): Promise<void> {
  const denied = permissionReason(ctx.role, "manage_networks");
  if (denied) {
    throw new Error(denied);
  }
  const res = await coordFetch(
    `/v1/orgs/${ctx.coordOrgId}/nodes/${nodeId}/routes`,
    {
      method: "PUT",
      ctx,
      body: JSON.stringify({ approved_routes: approvedRoutes }),
    },
  );
  if (!res.ok) {
    throw await coordError(res);
  }
}

export async function mintJoinKey(
  ctx: ConsoleContext,
  input: {
    expiresInSeconds?: number;
    singleUse?: boolean;
    tags?: DeviceTag[];
  },
): Promise<JoinKeyResult> {
  const denied = permissionReason(ctx.role, "manage_join_keys");
  if (denied) {
    throw new Error(denied);
  }
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}/join-keys`, {
    method: "POST",
    ctx,
    body: JSON.stringify({
      expires_in_seconds: input.expiresInSeconds ?? 3600,
      single_use: input.singleUse ?? true,
      tags: input.tags ?? [],
    }),
  });
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json() as Promise<JoinKeyResult>;
}

export async function getDeviceAuthorization(
  ctx: ConsoleContext,
  code: string,
): Promise<DeviceAuthorizationPreview> {
  const res = await coordFetch(
    `/v1/orgs/${ctx.coordOrgId}/device-authorizations/${encodeURIComponent(code)}`,
    {
      method: "GET",
      ctx,
    },
  );
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json() as Promise<DeviceAuthorizationPreview>;
}

export async function approveDeviceAuthorization(
  ctx: ConsoleContext,
  code: string,
  tags: DeviceTag[],
): Promise<{ status: string; expires_at: number }> {
  const res = await coordFetch(
    `/v1/orgs/${ctx.coordOrgId}/device-authorizations/${encodeURIComponent(code)}`,
    {
      method: "POST",
      ctx,
      body: JSON.stringify({ tags }),
    },
  );
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json() as Promise<{ status: string; expires_at: number }>;
}

export async function getAcl(ctx: ConsoleContext): Promise<unknown> {
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}/acl`, {
    method: "GET",
    ctx,
  });
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json();
}

export type OrgDnsSettings = {
  managed: boolean;
  global_resolvers: string[];
  split: { suffix: string; resolvers: string[] }[];
  search_domains: string[];
  records: { name: string; type: "A" | "AAAA"; value: string }[];
  nameserver_groups?: NameserverGroup[];
  zones?: DnsZone[];
};

export type NameserverGroup = {
  name: string;
  resolvers: string[];
  match_domains: string[];
  enabled: boolean;
  all_devices: boolean;
  tags: DeviceTag[];
};

export type ZoneRecordType = "A" | "AAAA" | "CNAME" | "TXT";

export type ZoneRecord = {
  name: string;
  type: ZoneRecordType;
  value: string;
  ttl?: number;
};

export type DnsZone = {
  name: string;
  enabled: boolean;
  records: ZoneRecord[];
};

export type OrgDnsResponse = {
  revision: number;
  etag: string;
  has_previous: boolean;
  magic_dns_suffix: string;
  dns: OrgDnsSettings;
  record_preview?: { name: string; split_suffix: string | null }[];
  applied?: number;
  enrolled?: number;
  warnings?: string[];
};

export async function getDns(ctx: ConsoleContext): Promise<OrgDnsResponse> {
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}/dns`, {
    method: "GET",
    ctx,
  });
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json() as Promise<OrgDnsResponse>;
}

export type WireGuardOnlyPeer = {
  id: string;
  name: string;
  kind: string;
  wg_public_key: string;
  endpoint: string;
  allowed_ips: string[];
  tags: DeviceTag[];
  created_at: number;
  expires_at: number | null;
  revoked_at: number | null;
  revision: number;
  previous_wg_public_key?: string | null;
  overlap_until?: number | null;
};

export type NetworkWgOnlyPeer = WireGuardOnlyPeer & {
  organisation_id: string;
  organisation_name: string;
};

export async function listWgOnlyPeers(
  ctx: ConsoleContext,
): Promise<WireGuardOnlyPeer[]> {
  const res = await coordFetch(
    `/v1/orgs/${ctx.coordOrgId}/wireguard-only-peers`,
    { method: "GET", ctx },
  );
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json() as Promise<WireGuardOnlyPeer[]>;
}

export async function listAllWgOnlyPeers(
  person: PersonSessionContext,
): Promise<{ peers: NetworkWgOnlyPeer[]; errors: string[] }> {
  const inventories = await Promise.all(
    person.organisations.map(async (organisation) => {
      const ctx = organisationContext(person, organisation.organisationId);
      try {
        const peers = await listWgOnlyPeers(ctx);
        return {
          peers: peers.map((peer) => ({
            ...peer,
            organisation_id: ctx.organisationId,
            organisation_name: ctx.organisationName,
          })),
          error: null,
        };
      } catch (error) {
        return {
          peers: [],
          error: `${organisation.organisationName}: ${
            errorText(error, "Could not load unmanaged peers.", "inventory")
          }`,
        };
      }
    }),
  );
  return {
    peers: inventories
      .flatMap((inventory) => inventory.peers)
      .sort(
        (left, right) =>
          left.organisation_name.localeCompare(right.organisation_name) ||
          left.name.localeCompare(right.name),
      ),
    errors: inventories.flatMap((inventory) =>
      inventory.error ? [inventory.error] : [],
    ),
  };
}

export async function createWgOnlyPeer(
  ctx: ConsoleContext,
  input: {
    name: string;
    wg_public_key: string;
    endpoint: string;
    allowed_ips: string[];
    tags: DeviceTag[];
  },
): Promise<WireGuardOnlyPeer> {
  const denied = permissionReason(ctx.role, "manage_peers");
  if (denied) {
    throw new Error(denied);
  }
  const res = await coordFetch(
    `/v1/orgs/${ctx.coordOrgId}/wireguard-only-peers`,
    {
      method: "POST",
      ctx,
      body: JSON.stringify({
        kind: "wireguard_only",
        ...input,
      }),
    },
  );
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json() as Promise<WireGuardOnlyPeer>;
}

export async function rotateWgOnlyPeer(
  ctx: ConsoleContext,
  peerId: string,
  input: { wg_public_key: string; overlap_seconds?: number },
): Promise<WireGuardOnlyPeer> {
  const denied = permissionReason(ctx.role, "manage_peers");
  if (denied) {
    throw new Error(denied);
  }
  const res = await coordFetch(
    `/v1/orgs/${ctx.coordOrgId}/wireguard-only-peers/${peerId}/rotate`,
    {
      method: "POST",
      ctx,
      body: JSON.stringify(input),
    },
  );
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json() as Promise<WireGuardOnlyPeer>;
}

export async function revokeWgOnlyPeer(
  ctx: ConsoleContext,
  peerId: string,
): Promise<void> {
  const denied = permissionReason(ctx.role, "manage_peers");
  if (denied) {
    throw new Error(denied);
  }
  const res = await coordFetch(
    `/v1/orgs/${ctx.coordOrgId}/wireguard-only-peers/${peerId}`,
    { method: "DELETE", ctx },
  );
  if (!res.ok) {
    throw await coordError(res);
  }
}

export async function putAcl(
  ctx: ConsoleContext,
  acl: unknown,
  etag?: string,
): Promise<void> {
  const denied = permissionReason(ctx.role, "manage_policy");
  if (denied) {
    throw new Error(denied);
  }
  const headers = new Headers();
  if (etag) {
    headers.set("If-Match", etag);
  }
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}/acl`, {
    method: "PUT",
    ctx,
    headers,
    body: JSON.stringify(acl),
  });
  if (!res.ok) {
    throw await coordError(res);
  }
}

export { roleLabel };
