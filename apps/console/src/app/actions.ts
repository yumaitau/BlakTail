"use server";

import { revalidatePath } from "next/cache";
import { revokeSessionsForMembership } from "@/lib/coord-remote";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import {
  approveDeviceAuthorization,
  approveNodeRoutes,
  getAcl,
  putAcl,
  createApiClient,
  createWebhook,
  createWgOnlyPeer,
  rotateWgOnlyPeer,
  disableWebhook,
  emitMembershipUpdated,
  listWebhookDeliveries,
  replayWebhookDelivery,
  revokeApiClient,
  revokeWgOnlyPeer,
  revokeNode,
  tombstoneNode,
  updateNodeFriendlyName,
  type DeviceTag,
  type WebhookDelivery,
} from "@/lib/coord";
import { AssuranceError, requireSecurityAssurance } from "@/lib/auth-policy";
import { can, isOrgRole, permissionReason } from "@/lib/roles";
import {
  ORGANISATION_COOKIE,
  requireConsoleContext,
  requireOrganisationContext,
  requirePersonSessionContext,
} from "@/lib/session";
import {
  createInvitation,
  InvitationError,
  isInvitationRole,
  revokeInvitation,
  type InvitationRole,
} from "@/lib/invitations";
import { OidcError, changeMembership, upsertIdentityProvider } from "@/lib/oidc";

export type ActionResult<T = void> =
  | { ok: true; data: T }
  | { ok: false; error: string };

function isDeviceTag(value: string): value is DeviceTag {
  return value === "office" || value === "ranger" || value === "store";
}

function owningOrganisation(formData: FormData): string {
  const organisationId = String(formData.get("organisationId") ?? "").trim();
  if (!organisationId) {
    throw new Error("The device's network account is required.");
  }
  return organisationId;
}

export async function approveDeviceAuthorizationAction(
  formData: FormData,
): Promise<ActionResult<{ expiresAt: number }>> {
  try {
    const ctx = await requireConsoleContext();
    const code = String(formData.get("code") ?? "").trim();
    if (!code) {
      return { ok: false, error: "Device code is required." };
    }
    const tags = can(ctx.role, "manage_peers")
      ? formData.getAll("tags").map(String).filter(isDeviceTag)
      : [];
    const result = await approveDeviceAuthorization(ctx, code, tags);
    revalidatePath("/enroll");
    return { ok: true, data: { expiresAt: result.expires_at } };
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof Error
          ? error.message
          : "Could not approve device enrollment.",
    };
  }
}

export async function revokeDeviceAction(
  formData: FormData,
): Promise<ActionResult> {
  try {
    const ctx = await requireOrganisationContext(
      owningOrganisation(formData),
    );
    const denied = permissionReason(ctx.role, "manage_peers");
    if (denied) {
      return { ok: false, error: denied };
    }
    const nodeId = String(formData.get("nodeId") ?? "");
    if (!nodeId) {
      return { ok: false, error: "Choose a device to revoke." };
    }
    await revokeNode(ctx, nodeId);
    revalidatePath("/devices");
    return { ok: true, data: undefined };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : "Could not revoke device.",
    };
  }
}

export async function tombstoneDeviceAction(
  formData: FormData,
): Promise<ActionResult> {
  try {
    const ctx = await requireOrganisationContext(
      owningOrganisation(formData),
    );
    const denied = permissionReason(ctx.role, "manage_peers");
    if (denied) {
      return { ok: false, error: denied };
    }
    const nodeId = String(formData.get("nodeId") ?? "");
    if (!nodeId) {
      return { ok: false, error: "Choose a device to delete." };
    }
    await tombstoneNode(ctx, nodeId);
    revalidatePath("/devices");
    return { ok: true, data: undefined };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : "Could not delete device.",
    };
  }
}

export async function createApiClientAction(
  formData: FormData,
): Promise<ActionResult<{ token: string; prefix: string }>> {
  try {
    const ctx = await requireConsoleContext();
    const denied = permissionReason(ctx.role, "manage_api_clients");
    if (denied) {
      return { ok: false, error: denied };
    }
    await requireSecurityAssurance(ctx);
    const name = String(formData.get("name") ?? "").trim();
    const scopes = formData
      .getAll("scopes")
      .map((value) => String(value))
      .filter(Boolean);
    if (!name) {
      return { ok: false, error: "Name the automation client." };
    }
    const created = await createApiClient(ctx, {
      name,
      scopes: scopes.length > 0 ? scopes : ["status:read", "devices:read"],
    });
    revalidatePath("/settings");
    return { ok: true, data: { token: created.token, prefix: created.token_prefix } };
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof Error
          ? error.message
          : "Could not create automation credential.",
    };
  }
}

export async function revokeApiClientAction(
  formData: FormData,
): Promise<ActionResult> {
  try {
    const ctx = await requireConsoleContext();
    const denied = permissionReason(ctx.role, "manage_api_clients");
    if (denied) {
      return { ok: false, error: denied };
    }
    await requireSecurityAssurance(ctx);
    const clientId = String(formData.get("clientId") ?? "");
    if (!clientId) {
      return { ok: false, error: "Choose a credential to revoke." };
    }
    await revokeApiClient(ctx, clientId);
    revalidatePath("/settings");
    return { ok: true, data: undefined };
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof Error
          ? error.message
          : "Could not revoke automation credential.",
    };
  }
}

export async function createWebhookAction(
  formData: FormData,
): Promise<ActionResult<{ secret: string; prefix: string }>> {
  try {
    const ctx = await requireConsoleContext();
    const denied = permissionReason(ctx.role, "manage_integrations");
    if (denied) {
      return { ok: false, error: denied };
    }
    const name = String(formData.get("name") ?? "").trim();
    const url = String(formData.get("url") ?? "").trim();
    if (!name) {
      return { ok: false, error: "Name the webhook destination." };
    }
    if (!url) {
      return { ok: false, error: "Enter an HTTPS destination URL." };
    }
    const created = await createWebhook(ctx, { name, url });
    revalidatePath("/settings");
    return {
      ok: true,
      data: {
        secret: created.secret ?? "",
        prefix: created.secret_prefix,
      },
    };
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof Error
          ? error.message
          : "Could not create webhook destination.",
    };
  }
}

export async function disableWebhookAction(
  formData: FormData,
): Promise<ActionResult> {
  try {
    const ctx = await requireConsoleContext();
    const denied = permissionReason(ctx.role, "manage_integrations");
    if (denied) {
      return { ok: false, error: denied };
    }
    const destinationId = String(formData.get("destinationId") ?? "");
    if (!destinationId) {
      return { ok: false, error: "Choose a webhook destination to disable." };
    }
    await disableWebhook(ctx, destinationId);
    revalidatePath("/settings");
    return { ok: true, data: undefined };
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof Error
          ? error.message
          : "Could not disable webhook destination.",
    };
  }
}

export async function listWebhookDeliveriesAction(
  destinationId: string,
): Promise<ActionResult<{ deliveries: WebhookDelivery[] }>> {
  try {
    const ctx = await requireConsoleContext();
    const denied = permissionReason(ctx.role, "manage_integrations");
    if (denied) {
      return { ok: false, error: denied };
    }
    if (!destinationId) {
      return { ok: false, error: "Choose a webhook destination." };
    }
    const deliveries = await listWebhookDeliveries(ctx, destinationId);
    return { ok: true, data: { deliveries } };
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof Error
          ? error.message
          : "Could not list webhook deliveries.",
    };
  }
}

export async function replayWebhookDeliveryAction(
  formData: FormData,
): Promise<ActionResult> {
  try {
    const ctx = await requireConsoleContext();
    const denied = permissionReason(ctx.role, "manage_integrations");
    if (denied) {
      return { ok: false, error: denied };
    }
    const deliveryId = String(formData.get("deliveryId") ?? "");
    if (!deliveryId) {
      return { ok: false, error: "Choose a delivery to replay." };
    }
    await replayWebhookDelivery(ctx, deliveryId);
    revalidatePath("/settings");
    return { ok: true, data: undefined };
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof Error
          ? error.message
          : "Could not replay webhook delivery.",
    };
  }
}

export async function createWgOnlyPeerAction(
  formData: FormData,
): Promise<ActionResult> {
  try {
    const ctx = await requireOrganisationContext(
      owningOrganisation(formData),
    );
    const denied = permissionReason(ctx.role, "manage_peers");
    if (denied) {
      return { ok: false, error: denied };
    }
    const name = String(formData.get("name") ?? "").trim();
    const wgPublicKey = String(formData.get("wgPublicKey") ?? "").trim();
    const endpoint = String(formData.get("endpoint") ?? "").trim();
    const allowedIps = String(formData.get("allowedIps") ?? "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
    const tags = formData.getAll("tags").map(String).filter(isDeviceTag);
    if (!name || !wgPublicKey || !endpoint || allowedIps.length === 0) {
      return {
        ok: false,
        error: "Name, public key, endpoint, and AllowedIPs are required.",
      };
    }
    await createWgOnlyPeer(ctx, {
      name,
      wg_public_key: wgPublicKey,
      endpoint,
      allowed_ips: allowedIps,
      tags,
    });
    revalidatePath("/devices");
    return { ok: true, data: undefined };
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof Error
          ? error.message
          : "Could not add unmanaged WireGuard peer.",
    };
  }
}

export async function rotateWgOnlyPeerAction(
  formData: FormData,
): Promise<ActionResult> {
  try {
    const ctx = await requireOrganisationContext(
      owningOrganisation(formData),
    );
    const denied = permissionReason(ctx.role, "manage_peers");
    if (denied) {
      return { ok: false, error: denied };
    }
    const peerId = String(formData.get("peerId") ?? "").trim();
    const wgPublicKey = String(formData.get("wgPublicKey") ?? "").trim();
    const overlapSeconds = Number(formData.get("overlapSeconds") ?? "300");
    if (!peerId || !wgPublicKey) {
      return { ok: false, error: "Peer and new public key are required." };
    }
    await rotateWgOnlyPeer(ctx, peerId, {
      wg_public_key: wgPublicKey,
      overlap_seconds: overlapSeconds,
    });
    revalidatePath("/devices");
    return { ok: true, data: undefined };
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof Error
          ? error.message
          : "Could not rotate unmanaged WireGuard peer.",
    };
  }
}

export async function revokeWgOnlyPeerAction(
  formData: FormData,
): Promise<ActionResult> {
  try {
    const ctx = await requireOrganisationContext(
      owningOrganisation(formData),
    );
    const denied = permissionReason(ctx.role, "manage_peers");
    if (denied) {
      return { ok: false, error: denied };
    }
    const peerId = String(formData.get("peerId") ?? "").trim();
    if (!peerId) {
      return { ok: false, error: "Choose an unmanaged peer to revoke." };
    }
    await revokeWgOnlyPeer(ctx, peerId);
    revalidatePath("/devices");
    return { ok: true, data: undefined };
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof Error
          ? error.message
          : "Could not revoke unmanaged WireGuard peer.",
    };
  }
}

export async function updateDeviceFriendlyNameAction(
  formData: FormData,
): Promise<ActionResult<{ friendlyName: string | null }>> {
  try {
    const ctx = await requireOrganisationContext(
      owningOrganisation(formData),
    );
    const denied = permissionReason(ctx.role, "manage_peers");
    if (denied) {
      return { ok: false, error: denied };
    }
    const nodeId = String(formData.get("nodeId") ?? "");
    if (!nodeId) {
      return { ok: false, error: "Choose a device to rename." };
    }
    const friendlyName = String(formData.get("friendlyName") ?? "").trim();
    if ([...friendlyName].length > 64) {
      return {
        ok: false,
        error: "Friendly names must be 64 characters or fewer.",
      };
    }
    await updateNodeFriendlyName(ctx, nodeId, friendlyName);
    revalidatePath("/devices");
    return {
      ok: true,
      data: { friendlyName: friendlyName || null },
    };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : "Could not rename device.",
    };
  }
}

export async function approveNodeRoutesAction(
  formData: FormData,
): Promise<ActionResult> {
  try {
    const ctx = await requireOrganisationContext(
      owningOrganisation(formData),
    );
    const denied = permissionReason(ctx.role, "manage_networks");
    if (denied) {
      return { ok: false, error: denied };
    }
    const nodeId = String(formData.get("nodeId") ?? "");
    if (!nodeId) {
      return { ok: false, error: "Choose a device." };
    }
    const approvedRoutes = formData
      .getAll("approvedRoutes")
      .map(String)
      .filter(Boolean);
    await approveNodeRoutes(ctx, nodeId, approvedRoutes);
    revalidatePath("/devices");
    return { ok: true, data: undefined };
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof Error ? error.message : "Could not approve routes.",
    };
  }
}

export async function saveAclAction(formData: FormData): Promise<ActionResult> {
  try {
    const ctx = await requireConsoleContext();
    const denied = permissionReason(ctx.role, "manage_policy");
    if (denied) {
      return { ok: false, error: denied };
    }
    const etag = String(formData.get("etag") ?? "");
    if (formData.get("rollback") === "true") {
      await putAcl(ctx, { rollback: true }, etag);
      revalidatePath("/acls");
      return { ok: true, data: undefined };
    }
    const raw = String(formData.get("aclJson") ?? "");
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return { ok: false, error: "ACL must be valid JSON." };
    }
    await putAcl(ctx, parsed, etag);
    revalidatePath("/acls");
    return { ok: true, data: undefined };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : "Could not save ACL.",
    };
  }
}

export async function loadAclAction(): Promise<ActionResult<unknown>> {
  try {
    const ctx = await requireConsoleContext();
    return { ok: true, data: await getAcl(ctx) };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : "Could not load ACL.",
    };
  }
}

export async function createInvitationAction(
  formData: FormData,
): Promise<ActionResult<{ id: string; url: string }>> {
  try {
    const ctx = await requireConsoleContext();
    const email = String(formData.get("email") ?? "");
    const requestedRole = String(formData.get("role") ?? "member");
    if (!isInvitationRole(requestedRole)) {
      return { ok: false, error: "Choose one of the listed invitation roles." };
    }
    if (can(ctx.role, "manage_security")) {
      await requireSecurityAssurance(ctx);
    }
    const result = await createInvitation(
      ctx,
      email,
      requestedRole as InvitationRole,
    );
    revalidatePath("/settings");
    revalidatePath("/audit");
    return {
      ok: true,
      data: { id: result.invitation.id, url: result.url },
    };
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof InvitationError || error instanceof AssuranceError
          ? error.message
          : "Could not create invitation.",
    };
  }
}

export async function revokeInvitationAction(
  formData: FormData,
): Promise<ActionResult> {
  try {
    const ctx = await requireConsoleContext();
    const invitationId = String(formData.get("invitationId") ?? "");
    if (!invitationId) {
      return { ok: false, error: "Choose an invitation to revoke." };
    }
    await requireSecurityAssurance(ctx);
    await revokeInvitation(ctx, invitationId);
    revalidatePath("/settings");
    revalidatePath("/audit");
    return { ok: true, data: undefined };
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof InvitationError || error instanceof AssuranceError
          ? error.message
          : "Could not revoke invitation.",
    };
  }
}

const consolePaths = new Set([
  "/control-center",
  "/devices",
  "/join-keys",
  "/acls",
  "/audit",
  "/status",
  "/settings",
]);

export async function upsertOidcProviderAction(
  formData: FormData,
): Promise<ActionResult> {
  try {
    const ctx = await requireConsoleContext();
    const denied = permissionReason(ctx.role, "manage_security");
    if (denied) {
      return { ok: false, error: denied };
    }
    await requireSecurityAssurance(ctx);
    const allowDomains = String(formData.get("allowDomains") ?? "")
      .split(",")
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean);
    const allowGroups = String(formData.get("allowGroups") ?? "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
    await upsertIdentityProvider({
      organisationId: ctx.organisationId,
      issuer: String(formData.get("issuer") ?? ""),
      clientId: String(formData.get("clientId") ?? ""),
      clientSecret: String(formData.get("clientSecret") ?? ""),
      enabled: formData.get("enabled") === "true",
      allowDomains,
      allowGroups,
      jitMembership: formData.get("jitMembership") === "true",
      actorUserId: ctx.userId,
      actorEmail: ctx.email,
    });
    revalidatePath("/settings");
    return { ok: true, data: undefined };
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof OidcError
          ? error.message
          : error instanceof Error
            ? error.message
            : "Could not save the identity provider.",
    };
  }
}

export async function changeMembershipAction(
  formData: FormData,
): Promise<ActionResult> {
  try {
    const ctx = await requireConsoleContext();
    const membershipId = String(formData.get("membershipId") ?? "");
    const status = String(formData.get("status") ?? "") as
      | "active"
      | "suspended"
      | "removed"
      | "";
    const requestedRole = String(formData.get("role") ?? "");
    const role = isOrgRole(requestedRole) ? requestedRole : undefined;
    if (!membershipId) {
      return { ok: false, error: "Choose a membership." };
    }
    if (requestedRole && !role) {
      return { ok: false, error: "Choose one of the listed roles." };
    }
    const denied = permissionReason(ctx.role, "manage_security");
    if (denied) {
      return { ok: false, error: denied };
    }
    await requireSecurityAssurance(ctx);
    const next = await changeMembership({
      organisationId: ctx.organisationId,
      membershipId,
      status: status || undefined,
      role,
      actorUserId: ctx.userId,
      actorEmail: ctx.email,
      actorRole: ctx.role,
    });
    await emitMembershipUpdated(ctx, {
      membership_id: membershipId,
      role: next.role,
      status: next.status,
      previous_role: next.previousRole,
    });
    await revokeSessionsForMembership(ctx, membershipId, next);
    revalidatePath("/settings");
    return { ok: true, data: undefined };
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof OidcError
          ? error.message
          : error instanceof Error
            ? error.message
            : "Could not update membership.",
    };
  }
}

export async function selectOrganisationAction(formData: FormData) {
  const person = await requirePersonSessionContext();
  const organisationId = String(formData.get("organisationId") ?? "");
  if (
    !person.organisations.some(
      (organisation) => organisation.organisationId === organisationId,
    )
  ) {
    throw new Error("That network account is no longer accessible.");
  }
  const jar = await cookies();
  jar.set(ORGANISATION_COOKIE, organisationId, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 60 * 60 * 24 * 365,
  });
  const requestedPath = String(formData.get("returnPath") ?? "/devices");
  redirect(consolePaths.has(requestedPath) ? requestedPath : "/devices");
}
