"use server";

import { revalidatePath } from "next/cache";
import { db } from "@/lib/db/client";
import { scimToken } from "@/lib/db/schema";
import { newScimToken } from "@/lib/scim-core";
import { requireConsoleContext } from "@/lib/session";

export async function mintScimTokenAction(): Promise<
  { ok: true; token: string } | { ok: false; error: string }
> {
  try {
    const ctx = await requireConsoleContext();
    if (ctx.role !== "owner") {
      return { ok: false, error: "Only an owner can mint a SCIM token." };
    }
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
    return {
      ok: false,
      error: error instanceof Error ? error.message : "Could not mint a SCIM token.",
    };
  }
}
