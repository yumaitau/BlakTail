"use server";

import { revalidatePath } from "next/cache";
import {
  beginIdentityLink,
  completeIdentityLink,
  IdentityLinkError,
  recoverIdentity,
  resolveIdentityRoleConflict,
  suspendIdentity,
  unlinkIdentity,
} from "@/lib/identity-links";
import { isOrgRole, type OrgRole } from "@/lib/roles";
import { requirePersonSessionContext } from "@/lib/session";

type IdentityActionResult<T = void> =
  | { ok: true; data: T }
  | { ok: false; error: string };

function refreshIdentityViews() {
  revalidatePath("/devices");
  revalidatePath("/settings");
  revalidatePath("/audit");
}

function message(error: unknown, fallback: string) {
  return error instanceof IdentityLinkError ? error.message : fallback;
}

export async function beginIdentityLinkAction(): Promise<
  IdentityActionResult<{ token: string; expiresAt: string }>
> {
  const ctx = await requirePersonSessionContext();
  try {
    const challenge = await beginIdentityLink(ctx);
    revalidatePath("/audit");
    return {
      ok: true,
      data: {
        token: challenge.token,
        expiresAt: challenge.expiresAt.toISOString(),
      },
    };
  } catch (error) {
    return {
      ok: false,
      error: message(error, "Could not start identity linking."),
    };
  }
}

export async function completeIdentityLinkAction(
  formData: FormData,
): Promise<
  IdentityActionResult<{ linked: boolean; ownerResolutionRequired: boolean }>
> {
  const ctx = await requirePersonSessionContext();
  try {
    const result = await completeIdentityLink(ctx, {
      token: String(formData.get("challenge") ?? ""),
      currentPassword: String(formData.get("currentPassword") ?? ""),
      email: String(formData.get("email") ?? ""),
      password: String(formData.get("password") ?? ""),
    });
    refreshIdentityViews();
    return { ok: true, data: result };
  } catch (error) {
    revalidatePath("/audit");
    return {
      ok: false,
      error: message(
        error,
        "Linking could not be completed. Fresh reauthentication or account recovery is required.",
      ),
    };
  }
}

export async function unlinkIdentityAction(
  formData: FormData,
): Promise<IdentityActionResult> {
  const ctx = await requirePersonSessionContext();
  try {
    await unlinkIdentity(
      ctx,
      String(formData.get("identityUserId") ?? ""),
      String(formData.get("currentPassword") ?? ""),
    );
    refreshIdentityViews();
    return { ok: true, data: undefined };
  } catch (error) {
    revalidatePath("/audit");
    return {
      ok: false,
      error: message(error, "Could not unlink that sign-in identity."),
    };
  }
}

export async function suspendIdentityAction(
  formData: FormData,
): Promise<IdentityActionResult> {
  const ctx = await requirePersonSessionContext();
  try {
    await suspendIdentity(
      ctx,
      String(formData.get("identityUserId") ?? ""),
      String(formData.get("currentPassword") ?? ""),
    );
    refreshIdentityViews();
    return { ok: true, data: undefined };
  } catch (error) {
    revalidatePath("/audit");
    return {
      ok: false,
      error: message(error, "Could not revoke that sign-in identity."),
    };
  }
}

export async function recoverIdentityAction(
  formData: FormData,
): Promise<IdentityActionResult> {
  const ctx = await requirePersonSessionContext();
  try {
    await recoverIdentity(
      ctx,
      String(formData.get("identityUserId") ?? ""),
      String(formData.get("currentPassword") ?? ""),
    );
    refreshIdentityViews();
    return { ok: true, data: undefined };
  } catch (error) {
    revalidatePath("/audit");
    return {
      ok: false,
      error: message(error, "Could not recover that sign-in identity."),
    };
  }
}

function role(value: FormDataEntryValue | null): OrgRole | null {
  return isOrgRole(value) ? value : null;
}

export async function resolveIdentityRoleConflictAction(
  formData: FormData,
): Promise<IdentityActionResult<{ linked: boolean }>> {
  const ctx = await requirePersonSessionContext();
  try {
    const resolvedRole = role(formData.get("resolvedRole"));
    if (!resolvedRole) {
      return { ok: false, error: "Choose one of the existing roles." };
    }
    const result = await resolveIdentityRoleConflict(
      ctx,
      String(formData.get("conflictId") ?? ""),
      resolvedRole,
    );
    refreshIdentityViews();
    return { ok: true, data: result };
  } catch (error) {
    revalidatePath("/audit");
    return {
      ok: false,
      error: message(error, "Could not resolve that role conflict."),
    };
  }
}
