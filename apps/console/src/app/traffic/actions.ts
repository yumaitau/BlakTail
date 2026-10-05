"use server";

import { actionFailure, type ActionFailure } from "@/lib/server-errors";
import { revalidatePath } from "next/cache";
import { requireSecurityAssurance } from "@/lib/auth-policy";
import { deleteTrafficRecords, putTrafficSettings } from "@/lib/coord-events";
import { permissionReason } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

export type TrafficActionResult = { ok: true; message: string } | ActionFailure;

async function ownerContext() {
  const ctx = await requireConsoleContext();
  const denied = permissionReason(ctx.role, "manage_security");
  if (denied) throw new Error(denied);
  await requireSecurityAssurance(ctx);
  return ctx;
}

function failure(error: unknown, fallback: string): TrafficActionResult {
  return actionFailure(error, fallback);
}

export async function saveTrafficSettingsAction(formData: FormData): Promise<TrafficActionResult> {
  try {
    const ctx = await ownerContext();
    const percent = Number(formData.get("sampling_percent"));
    const retention = Number(formData.get("retention_days"));
    if (!Number.isFinite(percent) || percent < 1 || percent > 100) {
      return { ok: false, error: "Sampling must be between 1 and 100 per cent." };
    }
    if (!Number.isInteger(retention) || retention < 1 || retention > 30) {
      return { ok: false, error: "Retention must be 1 to 30 whole days." };
    }
    const enabled = formData.get("enabled") === "on";
    await putTrafficSettings(ctx, {
      enabled,
      sampling_rate: percent / 100,
      retention_days: retention,
    });
    revalidatePath("/traffic");
    return {
      ok: true,
      message: enabled
        ? "Traffic diagnostics are on. Devices start reporting per-flow events within about a minute."
        : "Traffic diagnostics are off. New uploads are refused from now on.",
    };
  } catch (error) {
    return failure(error, "Could not save traffic settings.");
  }
}

export async function deleteTrafficRecordsAction(): Promise<TrafficActionResult> {
  try {
    const ctx = await ownerContext();
    const { deleted, deleted_events: events = 0 } = await deleteTrafficRecords(ctx);
    revalidatePath("/traffic");
    return {
      ok: true,
      message: `Deleted ${deleted} aggregate records and ${events} traffic events.`,
    };
  } catch (error) {
    return failure(error, "Could not delete traffic records.");
  }
}
