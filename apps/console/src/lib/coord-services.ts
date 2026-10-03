import "server-only";

import { coordFetch, readError, type DeviceTag } from "./coord";
import { can } from "./roles";
import type { ConsoleContext } from "./session";

export type ServiceProtocol = "http" | "https";

export type ServiceStatus =
  | "disabled"
  | "target_unavailable"
  | "awaiting_certificate"
  | "certificate_issued"
  | "target_unhealthy"
  | "serving";

export type ServiceCertificate = {
  serial: string;
  fingerprint_sha256: string;
  not_before: number;
  not_after: number;
  issued_at: number;
};

export type PrivateService = {
  id: string;
  name: string;
  fqdn: string;
  description: string;
  target_node_id: string;
  target_node_name: string | null;
  target_node_available: boolean;
  port: number;
  protocol: ServiceProtocol;
  access_tags: DeviceTag[];
  enabled: boolean;
  revision: number;
  status: ServiceStatus;
  status_detail: string;
  reachable: false;
  certificate: ServiceCertificate | null;
  created_at: number;
  updated_at: number;
};

export type ServiceCa = {
  cert_pem: string;
  fingerprint_sha256: string;
  not_after: number;
};

export type ServiceWorkspace = {
  namespace: string;
  ca: ServiceCa | null;
  services: PrivateService[];
};

export type ServiceInput = {
  name: string;
  target_node_id: string;
  port: number;
  protocol: ServiceProtocol;
  access_tags: DeviceTag[];
  description: string;
};

export type ServicePreview = {
  fqdn: string | null;
  valid: boolean;
  problems: string[];
  warnings: string[];
};

export type ServiceUpdate = {
  revision: number;
  enabled?: boolean;
  port?: number;
  protocol?: ServiceProtocol;
  access_tags?: DeviceTag[];
  target_node_id?: string;
  description?: string;
};

function servicesPath(ctx: ConsoleContext, suffix = ""): string {
  return `/v1/orgs/${ctx.coordOrgId}/services${suffix}`;
}

function requireManage(ctx: ConsoleContext) {
  if (!can(ctx.role, "manage_services")) {
    throw new Error("Your role cannot change private services.");
  }
}

export async function listServices(
  ctx: ConsoleContext,
): Promise<ServiceWorkspace> {
  const res = await coordFetch(servicesPath(ctx), { method: "GET", ctx });
  if (!res.ok) {
    throw new Error(await readError(res));
  }
  return res.json() as Promise<ServiceWorkspace>;
}

export async function previewService(
  ctx: ConsoleContext,
  input: ServiceInput,
): Promise<ServicePreview> {
  const res = await coordFetch(servicesPath(ctx, "/preview"), {
    method: "POST",
    ctx,
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    throw new Error(await readError(res));
  }
  return res.json() as Promise<ServicePreview>;
}

export async function createService(
  ctx: ConsoleContext,
  input: ServiceInput,
): Promise<PrivateService> {
  requireManage(ctx);
  const res = await coordFetch(servicesPath(ctx), {
    method: "POST",
    ctx,
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    throw new Error(await readError(res));
  }
  return res.json() as Promise<PrivateService>;
}

export async function updateService(
  ctx: ConsoleContext,
  serviceId: string,
  update: ServiceUpdate,
): Promise<PrivateService> {
  requireManage(ctx);
  const res = await coordFetch(
    servicesPath(ctx, `/${encodeURIComponent(serviceId)}`),
    { method: "PATCH", ctx, body: JSON.stringify(update) },
  );
  if (res.status === 412) {
    throw new Error(
      "Someone else changed this service; reload to see the latest revision.",
    );
  }
  if (!res.ok) {
    throw new Error(await readError(res));
  }
  return res.json() as Promise<PrivateService>;
}

export async function deleteService(
  ctx: ConsoleContext,
  serviceId: string,
): Promise<void> {
  requireManage(ctx);
  const res = await coordFetch(
    servicesPath(ctx, `/${encodeURIComponent(serviceId)}`),
    { method: "DELETE", ctx },
  );
  if (!res.ok) {
    throw new Error(await readError(res));
  }
}
