"use server";

import { actionFailure, type ActionFailure } from "@/lib/server-errors";
import { revalidatePath } from "next/cache";
import type { ActionResult } from "@/app/actions";
import type { DeviceTag } from "@/lib/coord";
import { mintEnrolmentKey, revokeJoinKey } from "@/lib/coord-peers";
import { can } from "@/lib/roles";
import { requireOrganisationContext } from "@/lib/session";

function isDeviceTag(value: string): value is DeviceTag {
  return value === "office" || value === "ranger" || value === "store";
}

async function joinKeyContext(formData: FormData) {
  const organisationId = String(formData.get("organisationId") ?? "").trim();
  if (!organisationId) {
    throw new Error("Choose the network for this key.");
  }
  const ctx = await requireOrganisationContext(organisationId);
  if (!can(ctx.role, "manage_join_keys")) {
    throw new Error("Only owners and admins can manage join keys.");
  }
  return ctx;
}

function invalid(field: string, error: string): ActionFailure {
  return { ok: false, error, fieldErrors: { [field]: error } };
}

export async function mintEnrolmentKeyAction(
  formData: FormData,
): Promise<ActionResult<{ key: string; expiresAt: number; name: string }>> {
  try {
    const ctx = await joinKeyContext(formData);
    const name = String(formData.get("name") ?? "").trim();
    const description = String(formData.get("description") ?? "").trim();
    if (!name) return invalid("name", "Give the key a name.");
    if ([...name].length > 64) {
      return invalid("name", "Names must be 64 characters or fewer.");
    }
    if ([...description].length > 200) {
      return invalid("description", "Descriptions must be 200 characters or fewer.");
    }
    const expiresInSeconds = Number(formData.get("expiresInSeconds") ?? 3600);
    if (!Number.isInteger(expiresInSeconds) || expiresInSeconds < 60 || expiresInSeconds > 2_592_000) {
      return { ok: false, error: "Choose an expiry between one minute and 30 days." };
    }
    const singleUse = formData.get("usage") !== "reusable";
    const rawMaxUses = String(formData.get("maxUses") ?? "").trim();
    const maxUses = rawMaxUses ? Number(rawMaxUses) : null;
    if (!singleUse && maxUses !== null && (!Number.isInteger(maxUses) || maxUses < 1 || maxUses > 10_000)) {
      return invalid("maxUses", "Maximum uses must be a whole number from 1 to 10000, or blank.");
    }
    const tags = formData.getAll("tags").map(String).filter(isDeviceTag);
    const minted = await mintEnrolmentKey(ctx, {
      name,
      description,
      expiresInSeconds,
      singleUse,
      maxUses,
      tags,
    });
    revalidatePath("/join-keys");
    return {
      ok: true,
      data: { key: minted.key, expiresAt: minted.expires_at, name: minted.name },
    };
  } catch (error) {
    return actionFailure(error, "Could not mint join key.");
  }
}

export async function revokeJoinKeyAction(
  formData: FormData,
): Promise<ActionResult> {
  try {
    const ctx = await joinKeyContext(formData);
    const keyId = String(formData.get("keyId") ?? "").trim();
    if (!keyId) return { ok: false, error: "Choose a key to revoke." };
    await revokeJoinKey(ctx, keyId);
    revalidatePath("/join-keys");
    return { ok: true, data: undefined };
  } catch (error) {
    return actionFailure(error, "Could not revoke join key.");
  }
}
