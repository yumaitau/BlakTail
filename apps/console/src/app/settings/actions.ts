"use server";

import { revalidatePath } from "next/cache";
import {
  addDomain,
  removeDomain,
  requireSecurityAssurance,
  saveSignInPolicy,
  verifyDomain,
} from "@/lib/auth-policy";
import { parseStepUpMinutes } from "@/lib/auth-policy-core";
import { setWebhookSubscriptions } from "@/lib/coord-events";
import { rotateApiClient, setApiClientSuspended } from "@/lib/coord-identity";
import { permissionReason } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

type Result<T = void> = { ok: true; data: T } | { ok: false; error: string };

function failure(error: unknown, fallback: string): { ok: false; error: string } {
  return { ok: false, error: error instanceof Error ? error.message : fallback };
}

export async function rotateApiClientAction(
  formData: FormData,
): Promise<Result<{ token: string; prefix: string }>> {
  try {
    const ctx = await requireConsoleContext();
    const denied = permissionReason(ctx.role, "manage_api_clients");
    if (denied) return { ok: false, error: denied };
    await requireSecurityAssurance(ctx);
    const clientId = String(formData.get("clientId") ?? "");
    if (!clientId) return { ok: false, error: "Choose a credential to rotate." };
    const rotated = await rotateApiClient(ctx, clientId);
    revalidatePath("/settings");
    return { ok: true, data: { token: rotated.token, prefix: rotated.token_prefix } };
  } catch (error) {
    return failure(error, "Could not rotate the automation credential.");
  }
}

export async function setApiClientSuspendedAction(formData: FormData): Promise<Result> {
  try {
    const ctx = await requireConsoleContext();
    const denied = permissionReason(ctx.role, "manage_api_clients");
    if (denied) return { ok: false, error: denied };
    await requireSecurityAssurance(ctx);
    const clientId = String(formData.get("clientId") ?? "");
    if (!clientId) return { ok: false, error: "Choose a credential." };
    await setApiClientSuspended(ctx, clientId, formData.get("suspended") === "true");
    revalidatePath("/settings");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not change the automation credential.");
  }
}

export async function saveSignInPolicyAction(formData: FormData): Promise<Result> {
  try {
    const ctx = await requireConsoleContext();
    await saveSignInPolicy(ctx, {
      stepUpMaxAgeMinutes: parseStepUpMinutes(formData.get("stepUpMaxAgeMinutes")),
      requireMfaForPrivileged: formData.get("requireMfaForPrivileged") === "true",
    });
    revalidatePath("/settings");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not save the sign-in policy.");
  }
}

export async function addDomainAction(formData: FormData): Promise<Result> {
  try {
    const ctx = await requireConsoleContext();
    await addDomain(ctx, String(formData.get("domain") ?? ""));
    revalidatePath("/settings");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not add the domain.");
  }
}

export async function verifyDomainAction(
  formData: FormData,
): Promise<Result<{ verified: boolean }>> {
  try {
    const ctx = await requireConsoleContext();
    const result = await verifyDomain(ctx, String(formData.get("domainId") ?? ""));
    revalidatePath("/settings");
    return { ok: true, data: result };
  } catch (error) {
    return failure(error, "Could not check the domain.");
  }
}

export async function removeDomainAction(formData: FormData): Promise<Result> {
  try {
    const ctx = await requireConsoleContext();
    await removeDomain(ctx, String(formData.get("domainId") ?? ""));
    revalidatePath("/settings");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not remove the domain.");
  }
}

export async function setWebhookSubscriptionsAction(formData: FormData): Promise<Result> {
  try {
    const ctx = await requireConsoleContext();
    const denied = permissionReason(ctx.role, "manage_integrations");
    if (denied) return { ok: false, error: denied };
    const destinationId = String(formData.get("destinationId") ?? "");
    if (!destinationId) return { ok: false, error: "Choose a destination." };
    const eventTypes =
      formData.get("all") === "on" ? ["*"] : formData.getAll("event_types").map(String);
    if (eventTypes.length === 0) {
      return { ok: false, error: "Choose at least one event, or all events." };
    }
    await setWebhookSubscriptions(ctx, destinationId, eventTypes);
    revalidatePath("/settings");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not save the event subscriptions.");
  }
}
