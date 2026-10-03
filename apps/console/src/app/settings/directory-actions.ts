"use server";

import { revalidatePath } from "next/cache";
import {
  addGroupMapping,
  applyDirectoryDrift,
  previewDirectoryDrift,
  removeGroupMapping,
  saveDirectorySettings,
  type DriftPreview,
} from "@/lib/directory-mapping";
import type { DriftChange } from "@/lib/directory-mapping-core";
import { requireConsoleContext } from "@/lib/session";

type Result<T = void> = { ok: true; data: T } | { ok: false; error: string };

function failure(error: unknown, fallback: string): { ok: false; error: string } {
  return { ok: false, error: error instanceof Error ? error.message : fallback };
}

export async function saveDirectorySettingsAction(formData: FormData): Promise<Result> {
  try {
    const ctx = await requireConsoleContext();
    await saveDirectorySettings(ctx, {
      allowOwnerMapping: formData.get("allowOwnerMapping") === "on",
      deprovisionGraceDays: formData.get("deprovisionGraceDays"),
    });
    revalidatePath("/settings");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not save directory settings.");
  }
}

export async function addGroupMappingAction(formData: FormData): Promise<Result> {
  try {
    const ctx = await requireConsoleContext();
    await addGroupMapping(ctx, {
      source: formData.get("source"),
      groupName: formData.get("groupName"),
      role: formData.get("role"),
    });
    revalidatePath("/settings");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not add the group mapping.");
  }
}

export async function removeGroupMappingAction(formData: FormData): Promise<Result> {
  try {
    const ctx = await requireConsoleContext();
    await removeGroupMapping(ctx, String(formData.get("mappingId") ?? ""));
    revalidatePath("/settings");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not remove the group mapping.");
  }
}

export async function previewDirectoryDriftAction(): Promise<Result<DriftPreview>> {
  try {
    const ctx = await requireConsoleContext();
    return { ok: true, data: await previewDirectoryDrift(ctx) };
  } catch (error) {
    return failure(error, "Could not preview directory changes.");
  }
}

export async function applyDirectoryDriftAction(
  formData: FormData,
): Promise<Result<{ applied: DriftChange[]; blocked: DriftChange[] }>> {
  try {
    const ctx = await requireConsoleContext();
    const result = await applyDirectoryDrift(ctx, String(formData.get("signature") ?? ""));
    revalidatePath("/settings");
    return { ok: true, data: result };
  } catch (error) {
    return failure(error, "Could not apply directory changes.");
  }
}
