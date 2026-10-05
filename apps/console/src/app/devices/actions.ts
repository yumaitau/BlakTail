"use server";

import { actionFailure } from "@/lib/server-errors";
import { revalidatePath } from "next/cache";
import type { ActionResult } from "@/app/actions";
import { setPeerSuspended } from "@/lib/coord-peers";
import { can } from "@/lib/roles";
import { requireOrganisationContext } from "@/lib/session";

export async function setDeviceSuspendedAction(
  formData: FormData,
): Promise<ActionResult> {
  try {
    const organisationId = String(formData.get("organisationId") ?? "").trim();
    const nodeId = String(formData.get("nodeId") ?? "").trim();
    if (!organisationId || !nodeId) {
      return { ok: false, error: "Choose a device and its network account." };
    }
    const ctx = await requireOrganisationContext(organisationId);
    if (!can(ctx.role, "manage_peers")) {
      return {
        ok: false,
        error: "Only owners and admins can suspend or resume devices.",
      };
    }
    const suspend = formData.get("suspend") === "true";
    const reason = String(formData.get("reason") ?? "").trim();
    if ([...reason].length > 200) {
      return { ok: false, error: "Keep the reason to 200 characters or fewer." };
    }
    await setPeerSuspended(ctx, nodeId, suspend, reason);
    revalidatePath("/devices");
    revalidatePath(`/devices/${nodeId}`);
    return { ok: true, data: undefined };
  } catch (error) {
    return actionFailure(error, "Could not change suspension.");
  }
}
