"use server";

import { actionFailure } from "@/lib/server-errors";
import { revalidatePath } from "next/cache";
import { db } from "@/lib/db/client";
import { scimToken } from "@/lib/db/schema";
import { newScimToken } from "@/lib/scim-core";
import { requireSecurityAssurance } from "@/lib/auth-policy";
import { permissionReason } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

export async function mintScimTokenAction(): Promise<
  { ok: true; token: string } | { ok: false; error: string }
> {
  try {
    const ctx = await requireConsoleContext();
    const denied = permissionReason(ctx.role, "manage_security");
    if (denied) {
      return { ok: false, error: denied };
    }
    await requireSecurityAssurance(ctx);
    const minted = newScimToken();
    await db().insert(scimToken).values({
      id: crypto.randomUUID(),
      organisationId: ctx.organisationId,
      tokenHash: minted.hash,
      label: "Identity provider",
    });
    revalidatePath("/settings");
    return { ok: true, token: minted.token };
  } catch (error) {
    return actionFailure(error, "Could not mint a SCIM token.");
  }
}
