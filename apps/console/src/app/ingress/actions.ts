"use server";

import { actionFailure, type ActionFailure } from "@/lib/server-errors";
import { revalidatePath } from "next/cache";
import type { ActionResult } from "@/app/actions";
import {
  createRoute,
  deleteRoute,
  emergencyDisableRoute,
  setIngressDesignation,
  setIngressEnabled,
  updateRoute,
  type AuthMode,
  type RouteInput,
  type TlsMode,
} from "@/lib/coord-ingress";
import { can } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

const OWNER_ONLY = "Only owners can publish services to the Internet.";

const ROUTE_FIELDS = {
  fqdn: ["fqdn", "hostname"],
  confirmFqdn: ["confirm"],
  allowedDomains: ["email domain"],
  allowedSources: ["cidr", "source"],
  abuseContact: ["abuse", "contact"],
  port: ["port"],
};

function failure(error: unknown, fallback: string): ActionFailure {
  return actionFailure(error, fallback, "ingress", { fields: ROUTE_FIELDS });
}

function int(formData: FormData, name: string, fallback: number): number {
  const value = Number(formData.get(name) ?? fallback);
  return Number.isInteger(value) ? value : fallback;
}

function readRoute(formData: FormData): RouteInput {
  const target = String(formData.get("target") ?? "");
  const tls = String(formData.get("tlsMode") ?? "operator_files");
  const auth = String(formData.get("authMode") ?? "none");
  const input: RouteInput = {
    fqdn: String(formData.get("fqdn") ?? "").trim(),
    confirm_fqdn: String(formData.get("confirmFqdn") ?? "").trim(),
    tls_mode: (tls === "acme_http01" ? "acme_http01" : "operator_files") as TlsMode,
    auth_mode: (auth === "oidc" ? "oidc" : "none") as AuthMode,
    allowed_email_domains: String(formData.get("allowedDomains") ?? "")
      .split(/[\s,]+/)
      .map((domain) => domain.trim())
      .filter(Boolean),
    allowed_source_cidrs: String(formData.get("allowedSources") ?? "")
      .split(/[\s,]+/)
      .map((cidr) => cidr.trim())
      .filter(Boolean),
    rate_limit_per_minute: int(formData, "rate", 600),
    max_body_bytes: int(formData, "maxBodyMiB", 10) * 1024 * 1024,
    max_connections: int(formData, "maxConnections", 256),
    log_retention_days: int(formData, "retention", 30),
  };
  if (target.startsWith("service:")) {
    input.target_service_id = target.slice("service:".length);
  } else if (target.startsWith("node:")) {
    input.target_node_id = target.slice("node:".length);
    input.target_port = int(formData, "port", 0);
  }
  return input;
}

export async function setIngressEnabledAction(formData: FormData): Promise<ActionResult> {
  try {
    const ctx = await requireConsoleContext();
    if (!can(ctx.role, "manage_public_ingress")) {
      return { ok: false, error: OWNER_ONLY };
    }
    await setIngressEnabled(ctx, {
      enabled: formData.get("enabled") === "true",
      abuse_contact: String(formData.get("abuseContact") ?? "").trim(),
      confirm: String(formData.get("confirm") ?? "").trim() || undefined,
    });
    revalidatePath("/ingress");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not change public ingress.");
  }
}

export async function setIngressDesignationAction(
  nodeId: string,
  designated: boolean,
): Promise<ActionResult> {
  try {
    const ctx = await requireConsoleContext();
    if (!can(ctx.role, "manage_public_ingress")) {
      return { ok: false, error: OWNER_ONLY };
    }
    await setIngressDesignation(ctx, nodeId, designated);
    revalidatePath("/ingress");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not change the ingress designation.");
  }
}

export async function createRouteAction(formData: FormData): Promise<ActionResult> {
  try {
    const ctx = await requireConsoleContext();
    if (!can(ctx.role, "manage_public_ingress")) {
      return { ok: false, error: OWNER_ONLY };
    }
    const input = readRoute(formData);
    if (!input.fqdn) {
      return { ok: false, error: "Enter the public hostname.", fieldErrors: { fqdn: "Enter the public hostname." } };
    }
    if (input.confirm_fqdn.toLowerCase().replace(/\.$/u, "") !== input.fqdn.toLowerCase().replace(/\.$/u, "")) {
      const error = "Type the same hostname again to confirm.";
      return { ok: false, error, fieldErrors: { confirmFqdn: error } };
    }
    await createRoute(ctx, input);
    revalidatePath("/ingress");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not publish this route.");
  }
}

export async function setRouteEnabledAction(
  routeId: string,
  revision: number,
  enabled: boolean,
  confirmFqdn: string,
): Promise<ActionResult> {
  try {
    const ctx = await requireConsoleContext();
    if (!can(ctx.role, "manage_public_ingress")) {
      return { ok: false, error: OWNER_ONLY };
    }
    await updateRoute(ctx, routeId, {
      revision,
      enabled,
      confirm_fqdn: enabled ? confirmFqdn : undefined,
    });
    revalidatePath("/ingress");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not change this route.");
  }
}

export async function deleteRouteAction(routeId: string): Promise<ActionResult> {
  try {
    const ctx = await requireConsoleContext();
    if (!can(ctx.role, "manage_public_ingress")) {
      return { ok: false, error: OWNER_ONLY };
    }
    await deleteRoute(ctx, routeId);
    revalidatePath("/ingress");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not delete this route.");
  }
}

export async function emergencyDisableAction(
  routeId: string,
  reason: string,
): Promise<ActionResult> {
  try {
    const ctx = await requireConsoleContext();
    if (!can(ctx.role, "manage_services") && !can(ctx.role, "manage_public_ingress")) {
      return { ok: false, error: "Your role cannot disable public routes." };
    }
    await emergencyDisableRoute(ctx, routeId, reason.trim().slice(0, 200));
    revalidatePath("/ingress");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not disable this route.");
  }
}
