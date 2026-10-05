import "server-only";

import { coordFetch, coordError } from "./coord";
import { can } from "./roles";
import type { ConsoleContext } from "./session";

export type TlsMode = "operator_files" | "acme_http01";
export type AuthMode = "none" | "oidc";

export type RouteStatus =
  | "active"
  | "organisation_disabled"
  | "emergency_disabled"
  | "disabled"
  | "target_unavailable"
  | "target_unsupported"
  | "target_is_ingress"
  | "blocked_by_policy"
  | "ingress_offline"
  | "ingress_not_capable"
  | "ingress_not_designated"
  | "no_ingress_node";

export type RouteLimits = {
  rate_limit_per_minute: number;
  max_body_bytes: number;
  max_connections: number;
  log_retention_days: number;
};

export type IngressRouteState = {
  node_id: string;
  node_name: string;
  state: RouteStatus;
  certificate_not_after: number | null;
  certificate_source: string | null;
  last_error: string | null;
};

export type PublicRoute = {
  id: string;
  fqdn: string;
  target_service_id: string | null;
  target_node_id: string;
  target_node_name: string | null;
  target_port: number;
  tls_mode: TlsMode;
  auth_mode: AuthMode;
  allowed_email_domains: string[];
  allowed_source_cidrs: string[];
  limits: RouteLimits;
  enabled: boolean;
  emergency_disabled_at: number | null;
  emergency_disabled_by: string | null;
  emergency_reason: string | null;
  revision: number;
  status: RouteStatus;
  ingress: IngressRouteState[];
  created_at: number;
  updated_at: number;
};

export type IngressNode = {
  id: string;
  name: string;
  online: boolean;
  last_config_at: number | null;
  capable: boolean;
  /** Designated by an owner; only capable and designated devices receive routes. */
  designated: boolean;
};

export type IngressWorkspace = {
  settings: { enabled: boolean; abuse_contact: string; updated_at: number | null };
  ingress_nodes: IngressNode[];
  routes: PublicRoute[];
  stale_after_secs: number;
};

export type RouteInput = {
  fqdn: string;
  confirm_fqdn: string;
  target_service_id?: string;
  target_node_id?: string;
  target_port?: number;
  tls_mode: TlsMode;
  auth_mode: AuthMode;
  allowed_email_domains: string[];
  allowed_source_cidrs: string[];
} & RouteLimits;

export type RouteUpdate = {
  revision: number;
  confirm_fqdn?: string;
  enabled?: boolean;
};

function ingressPath(ctx: ConsoleContext, suffix = ""): string {
  return `/v1/orgs/${ctx.coordOrgId}/public-ingress${suffix}`;
}

function requireOwner(ctx: ConsoleContext) {
  if (!can(ctx.role, "manage_public_ingress")) {
    throw new Error("Only owners can publish services to the Internet.");
  }
}

async function json<T>(res: Response): Promise<T> {
  if (res.status === 412) {
    throw new Error("Someone else changed this route; reload to see the latest revision.");
  }
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json() as Promise<T>;
}

export async function getIngressWorkspace(ctx: ConsoleContext): Promise<IngressWorkspace> {
  return json(await coordFetch(ingressPath(ctx), { method: "GET", ctx }));
}

export async function setIngressEnabled(
  ctx: ConsoleContext,
  input: { enabled: boolean; abuse_contact: string; confirm?: string },
): Promise<IngressWorkspace> {
  requireOwner(ctx);
  return json(
    await coordFetch(ingressPath(ctx, "/settings"), {
      method: "PUT",
      ctx,
      body: JSON.stringify(input),
    }),
  );
}

export async function setIngressDesignation(
  ctx: ConsoleContext,
  nodeId: string,
  designated: boolean,
): Promise<IngressWorkspace> {
  requireOwner(ctx);
  return json(
    await coordFetch(ingressPath(ctx, `/nodes/${encodeURIComponent(nodeId)}`), {
      method: "PUT",
      ctx,
      body: JSON.stringify({ designated }),
    }),
  );
}

export async function createRoute(ctx: ConsoleContext, input: RouteInput): Promise<PublicRoute> {
  requireOwner(ctx);
  return json(
    await coordFetch(ingressPath(ctx, "/routes"), {
      method: "POST",
      ctx,
      body: JSON.stringify(input),
    }),
  );
}

export async function updateRoute(
  ctx: ConsoleContext,
  routeId: string,
  update: RouteUpdate,
): Promise<PublicRoute> {
  requireOwner(ctx);
  return json(
    await coordFetch(ingressPath(ctx, `/routes/${encodeURIComponent(routeId)}`), {
      method: "PATCH",
      ctx,
      body: JSON.stringify(update),
    }),
  );
}

export async function deleteRoute(ctx: ConsoleContext, routeId: string): Promise<void> {
  requireOwner(ctx);
  const res = await coordFetch(ingressPath(ctx, `/routes/${encodeURIComponent(routeId)}`), {
    method: "DELETE",
    ctx,
  });
  if (!res.ok) {
    throw await coordError(res);
  }
}

/** Any role that manages services may pull the kill switch. */
export async function emergencyDisableRoute(
  ctx: ConsoleContext,
  routeId: string,
  reason: string,
): Promise<PublicRoute> {
  if (!can(ctx.role, "manage_services") && !can(ctx.role, "manage_public_ingress")) {
    throw new Error("Your role cannot disable public routes.");
  }
  return json(
    await coordFetch(
      ingressPath(ctx, `/routes/${encodeURIComponent(routeId)}/emergency-disable`),
      { method: "POST", ctx, body: JSON.stringify({ reason }) },
    ),
  );
}
