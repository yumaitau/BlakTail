"use server";

import { revalidatePath } from "next/cache";
import type { ActionResult } from "@/app/actions";
import {
  createAgentKey,
  createProvider,
  deleteProvider,
  getRequestContent,
  revokeAgentKey,
  setAllowOffshore,
  setGatewayDesignation,
  updateAgentKey,
  updateProvider,
  type AgentPolicy,
  type LoggingMode,
} from "@/lib/coord-agents";
import { can } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

function message(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

function lines(value: FormDataEntryValue | null): string[] {
  return String(value ?? "")
    .split(/\r?\n|,/u)
    .map((line) => line.trim())
    .filter(Boolean);
}

function int(value: FormDataEntryValue | null, fallback: number): number {
  const parsed = Number(value);
  return Number.isInteger(parsed) ? parsed : fallback;
}

function readPolicy(formData: FormData): AgentPolicy {
  const mode = String(formData.get("loggingMode") ?? "off");
  const loggingMode: LoggingMode = mode === "metadata" || mode === "full" ? mode : "off";
  const bound = String(formData.get("boundNodeId") ?? "").trim();
  return {
    bound_node_id: bound || null,
    allowed_provider_ids: formData.getAll("providerIds").map(String),
    allowed_models: lines(formData.get("allowedModels")),
    daily_request_quota: int(formData.get("dailyRequestQuota"), 1000),
    daily_token_quota: int(formData.get("dailyTokenQuota"), 1_000_000),
    max_request_bytes: int(formData.get("maxRequestKib"), 256) * 1024,
    logging_mode: loggingMode,
    log_retention_days: loggingMode === "full" ? int(formData.get("retentionDays"), 7) : 0,
    // Patterns are regular expressions, so only newlines separate them.
    redact_patterns: String(formData.get("redactPatterns") ?? "")
      .split(/\r?\n/u)
      .map((line) => line.trim())
      .filter(Boolean),
  };
}

async function manage(): Promise<Awaited<ReturnType<typeof requireConsoleContext>>> {
  const ctx = await requireConsoleContext();
  if (!can(ctx.role, "manage_agent_gateway")) {
    throw new Error("Only owners and admins can change the agent network.");
  }
  return ctx;
}

export async function setOffshoreAction(allow: boolean): Promise<ActionResult> {
  try {
    const ctx = await manage();
    if (ctx.role !== "owner") {
      return { ok: false, error: "Only an owner can decide whether data may go offshore." };
    }
    await setAllowOffshore(ctx, allow);
    revalidatePath("/agents");
    return { ok: true, data: undefined };
  } catch (error) {
    return { ok: false, error: message(error, "Could not change the offshore policy.") };
  }
}

export async function setGatewayDesignationAction(
  nodeId: string,
  designated: boolean,
): Promise<ActionResult> {
  try {
    const ctx = await manage();
    await setGatewayDesignation(ctx, nodeId, designated);
    revalidatePath("/agents");
    return { ok: true, data: undefined };
  } catch (error) {
    return { ok: false, error: message(error, "Could not change the gateway designation.") };
  }
}

export async function createProviderAction(formData: FormData): Promise<ActionResult> {
  try {
    const ctx = await manage();
    const credential = String(formData.get("credential") ?? "").trim();
    await createProvider(ctx, {
      name: String(formData.get("name") ?? "").trim(),
      base_url: String(formData.get("baseUrl") ?? "").trim(),
      data_location: String(formData.get("dataLocation") ?? "").trim(),
      residency: formData.get("residency") === "offshore" ? "offshore" : "onshore",
      credential: credential || undefined,
      models: lines(formData.get("models")),
    });
    revalidatePath("/agents");
    return { ok: true, data: undefined };
  } catch (error) {
    return { ok: false, error: message(error, "Could not add this provider.") };
  }
}

export async function setProviderEnabledAction(
  providerId: string,
  revision: number,
  enabled: boolean,
): Promise<ActionResult> {
  try {
    const ctx = await manage();
    await updateProvider(ctx, providerId, { revision, enabled });
    revalidatePath("/agents");
    return { ok: true, data: undefined };
  } catch (error) {
    return { ok: false, error: message(error, "Could not update this provider.") };
  }
}

export async function rotateProviderCredentialAction(
  providerId: string,
  revision: number,
  formData: FormData,
): Promise<ActionResult> {
  try {
    const ctx = await manage();
    const credential = String(formData.get("credential") ?? "").trim();
    if (!credential) return { ok: false, error: "Enter the new credential." };
    await updateProvider(ctx, providerId, { revision, credential });
    revalidatePath("/agents");
    return { ok: true, data: undefined };
  } catch (error) {
    return { ok: false, error: message(error, "Could not replace the credential.") };
  }
}

export async function deleteProviderAction(providerId: string): Promise<ActionResult> {
  try {
    const ctx = await manage();
    await deleteProvider(ctx, providerId);
    revalidatePath("/agents");
    return { ok: true, data: undefined };
  } catch (error) {
    return { ok: false, error: message(error, "Could not delete this provider.") };
  }
}

export async function createKeyAction(formData: FormData): Promise<ActionResult<{ secret: string }>> {
  try {
    const ctx = await manage();
    const created = await createAgentKey(
      ctx,
      String(formData.get("name") ?? "").trim(),
      readPolicy(formData),
      formData.get("acknowledgeIcip") === "on",
    );
    revalidatePath("/agents");
    return { ok: true, data: { secret: created.secret } };
  } catch (error) {
    return { ok: false, error: message(error, "Could not create this agent key.") };
  }
}

export async function updateKeyAction(
  keyId: string,
  revision: number,
  formData: FormData,
): Promise<ActionResult> {
  try {
    const ctx = await manage();
    await updateAgentKey(
      ctx,
      keyId,
      revision,
      readPolicy(formData),
      formData.get("acknowledgeIcip") === "on",
    );
    revalidatePath("/agents");
    return { ok: true, data: undefined };
  } catch (error) {
    return { ok: false, error: message(error, "Could not update this key's policy.") };
  }
}

export async function revokeKeyAction(keyId: string): Promise<ActionResult> {
  try {
    const ctx = await manage();
    await revokeAgentKey(ctx, keyId);
    revalidatePath("/agents");
    return { ok: true, data: undefined };
  } catch (error) {
    return { ok: false, error: message(error, "Could not revoke this key.") };
  }
}

export async function readContentAction(
  requestId: string,
): Promise<ActionResult<{ request: string; response: string }>> {
  try {
    const ctx = await requireConsoleContext();
    const content = await getRequestContent(ctx, requestId);
    return { ok: true, data: { request: content.request, response: content.response } };
  } catch (error) {
    return { ok: false, error: message(error, "Could not read this stored prompt.") };
  }
}
