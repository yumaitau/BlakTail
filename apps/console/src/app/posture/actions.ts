"use server";

import { actionFailure } from "@/lib/server-errors";
import { revalidatePath } from "next/cache";
import {
  createPostureCheck,
  deletePostureCheck,
  updatePostureCheck,
  type PostureDefinition,
} from "@/lib/coord-policy";
import {
  approveDeviceHardware,
  createPostureIntegration,
  deletePostureIntegration,
  syncPostureIntegration,
  updatePostureIntegration,
  type ProviderConfig,
  type ProviderKind,
  type SyncReport,
} from "@/lib/coord-posture-integrations";
import { can } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

export type PostureActionResult = { ok: true } | { ok: false; error: string };

const OS_FAMILIES = ["linux", "macos", "ios", "android", "windows"];
const VERSION = /^v?\d+(\.\d+){0,3}$/u;

function hoursToSeconds(value: FormDataEntryValue | null, label: string): number | undefined {
  const text = String(value ?? "").trim();
  if (!text) return undefined;
  const hours = Number(text);
  if (!Number.isFinite(hours) || hours <= 0) {
    throw new Error(`${label} must be a positive number of hours.`);
  }
  return Math.round(hours * 3600);
}

function definitionFrom(formData: FormData): PostureDefinition {
  const definition: PostureDefinition = {};
  const description = String(formData.get("description") ?? "").trim();
  if (description) definition.description = description;
  const agent = String(formData.get("min_agent_version") ?? "").trim();
  if (agent) {
    if (!VERSION.test(agent)) throw new Error("Minimum agent version must look like 0.2.0.");
    definition.min_agent_version = agent;
  }
  const families = formData
    .getAll("os_families")
    .map(String)
    .filter((family) => OS_FAMILIES.includes(family));
  if (families.length) definition.os_families = families;
  const minimums = String(formData.get("min_os_versions") ?? "").trim();
  if (minimums) {
    const entries: Record<string, string> = {};
    for (const pair of minimums.split(",")) {
      const [family, version] = pair.split("=").map((part) => part.trim().toLowerCase());
      if (!family || !version || !OS_FAMILIES.includes(family) || !VERSION.test(version)) {
        throw new Error("Minimum OS versions look like macos=14.0, linux=22.04.");
      }
      entries[family] = version;
    }
    definition.min_os_versions = entries;
  }
  const credential = hoursToSeconds(formData.get("max_credential_age_hours"), "Credential age");
  if (credential !== undefined) definition.max_credential_age_secs = credential;
  const report = hoursToSeconds(formData.get("max_report_age_hours"), "Report freshness");
  if (report !== undefined) definition.max_report_age_secs = report;
  if (formData.get("require_approved_peer") === "on") definition.require_approved_peer = true;
  definition.on_missing_data = formData.get("on_missing_data") === "pass" ? "pass" : "fail";
  const integration = String(formData.get("integration_id") ?? "").trim();
  if (integration) {
    const minutes = Number(String(formData.get("integration_max_age_minutes") ?? "60").trim() || "60");
    if (!Number.isFinite(minutes) || minutes < 1) {
      throw new Error("Provider data freshness must be at least 1 minute.");
    }
    definition.integration = {
      integration_id: integration,
      max_age_secs: Math.round(minutes * 60),
      on_outage: formData.get("integration_on_outage") === "pass" ? "pass" : "fail",
    };
    const seen = hoursToSeconds(formData.get("integration_last_seen_hours"), "Provider last seen");
    if (seen !== undefined) definition.integration.max_last_seen_secs = seen;
  }
  return definition;
}

async function managerContext() {
  const ctx = await requireConsoleContext();
  if (!can(ctx.role, "manage_policy")) {
    throw new Error("Only owners and admins can change posture checks.");
  }
  return ctx;
}

function failure(error: unknown, fallback: string): PostureActionResult {
  return actionFailure(error, fallback);
}

export async function createPostureCheckAction(formData: FormData): Promise<PostureActionResult> {
  try {
    const ctx = await managerContext();
    const name = String(formData.get("name") ?? "").trim();
    if (!/^[a-z][a-z0-9-]{0,31}$/u.test(name)) {
      return { ok: false, error: "Name must be 1-32 lowercase letters, digits or hyphens." };
    }
    await createPostureCheck(ctx, name, definitionFrom(formData));
    revalidatePath("/posture");
    return { ok: true };
  } catch (error) {
    return failure(error, "Could not create the posture check.");
  }
}

export async function updatePostureCheckAction(formData: FormData): Promise<PostureActionResult> {
  try {
    const ctx = await managerContext();
    const id = String(formData.get("id") ?? "");
    const version = Number(formData.get("version"));
    if (!id || !Number.isInteger(version)) {
      return { ok: false, error: "Reload the page and try again." };
    }
    await updatePostureCheck(ctx, id, version, definitionFrom(formData));
    revalidatePath("/posture");
    return { ok: true };
  } catch (error) {
    return failure(error, "Could not update the posture check.");
  }
}

export async function deletePostureCheckAction(id: string): Promise<PostureActionResult> {
  try {
    const ctx = await managerContext();
    await deletePostureCheck(ctx, id);
    revalidatePath("/posture");
    return { ok: true };
  } catch (error) {
    return failure(error, "Could not delete the posture check.");
  }
}

const PROVIDER_KINDS: ProviderKind[] = ["intune", "crowdstrike", "sentinelone", "fleetdm", "huntress"];
const CONFIG_FIELDS = ["tenant_id", "client_id", "region", "console_url", "server_url", "api_key"] as const;

export type IntegrationActionResult =
  | { ok: true; report?: SyncReport }
  | { ok: false; error: string };

/** Provider credentials are owner-only, mirroring the coordinator. */
async function securityContext() {
  const ctx = await requireConsoleContext();
  if (!can(ctx.role, "manage_security")) {
    throw new Error("Only organisation owners can manage device-health integrations.");
  }
  return ctx;
}

function integrationFailure(error: unknown, fallback: string): IntegrationActionResult {
  return actionFailure(error, fallback);
}

export async function createIntegrationAction(formData: FormData): Promise<IntegrationActionResult> {
  try {
    const ctx = await securityContext();
    const kind = String(formData.get("kind") ?? "") as ProviderKind;
    if (!PROVIDER_KINDS.includes(kind)) return { ok: false, error: "Choose a provider." };
    if (formData.get("privacy_acknowledged") !== "on") {
      return { ok: false, error: "Read and acknowledge the data notice before connecting." };
    }
    const config: ProviderConfig = {};
    for (const field of CONFIG_FIELDS) {
      const value = String(formData.get(field) ?? "").trim();
      if (value) config[field] = value;
    }
    if (formData.get("match_hostname") === "on") config.match_hostname = true;
    const minutes = Number(String(formData.get("interval_minutes") ?? "15").trim() || "15");
    if (!Number.isFinite(minutes) || minutes < 5 || minutes > 1440) {
      return { ok: false, error: "Sync interval must be 5-1440 minutes." };
    }
    const { id } = await createPostureIntegration(ctx, {
      kind,
      name: String(formData.get("name") ?? "").trim(),
      config,
      secret: String(formData.get("secret") ?? ""),
      interval_secs: Math.round(minutes * 60),
      privacy_acknowledged: true,
    });
    const report = await syncPostureIntegration(ctx, id);
    revalidatePath("/posture");
    return { ok: true, report };
  } catch (error) {
    return integrationFailure(error, "Could not connect the provider.");
  }
}

export async function syncIntegrationAction(id: string): Promise<IntegrationActionResult> {
  try {
    const ctx = await securityContext();
    const report = await syncPostureIntegration(ctx, id);
    revalidatePath("/posture");
    return { ok: true, report };
  } catch (error) {
    return integrationFailure(error, "Could not test the connection.");
  }
}

export async function setIntegrationEnabledAction(
  id: string,
  enabled: boolean,
): Promise<IntegrationActionResult> {
  try {
    const ctx = await securityContext();
    await updatePostureIntegration(ctx, id, { enabled });
    revalidatePath("/posture");
    return { ok: true };
  } catch (error) {
    return integrationFailure(error, "Could not update the integration.");
  }
}

export async function rotateIntegrationSecretAction(formData: FormData): Promise<IntegrationActionResult> {
  try {
    const ctx = await securityContext();
    const id = String(formData.get("id") ?? "");
    const secret = String(formData.get("secret") ?? "");
    if (!id || !secret) return { ok: false, error: "Enter the new secret." };
    await updatePostureIntegration(ctx, id, { secret });
    const report = await syncPostureIntegration(ctx, id);
    revalidatePath("/posture");
    return { ok: true, report };
  } catch (error) {
    return integrationFailure(error, "Could not replace the secret.");
  }
}

export async function deleteIntegrationAction(id: string): Promise<IntegrationActionResult> {
  try {
    const ctx = await securityContext();
    await deletePostureIntegration(ctx, id);
    revalidatePath("/posture");
    return { ok: true };
  } catch (error) {
    return integrationFailure(error, "Could not remove the integration.");
  }
}

export async function approveHardwareAction(nodeId: string): Promise<IntegrationActionResult> {
  try {
    const ctx = await securityContext();
    await approveDeviceHardware(ctx, nodeId);
    revalidatePath("/posture");
    return { ok: true };
  } catch (error) {
    return integrationFailure(error, "Could not approve the hardware change.");
  }
}
