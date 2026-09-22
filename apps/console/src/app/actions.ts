"use server";

import { revalidatePath } from "next/cache";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import {
  approveDeviceAuthorization,
  approveNodeRoutes,
  getAcl,
  mintJoinKey,
  putAcl,
  putDns,
  type OrgDnsSettings,
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
import {
  canMutateTailnet,
  ORGANISATION_COOKIE,
  requireConsoleContext,
  requireOrganisationContext,
  requirePersonSessionContext,
} from "@/lib/session";
import {
  createInvitation,
  InvitationError,
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

export async function mintJoinKeyAction(
  formData: FormData,
): Promise<ActionResult<{ key: string; expiresAt: number }>> {
  try {
    const ctx = await requireConsoleContext();
    if (!canMutateTailnet(ctx.role)) {
      return { ok: false, error: "Only owners and admins can mint join keys." };
    }
    const expiresInSeconds = Number(formData.get("expiresInSeconds") ?? 3600);
    const singleUse = formData.get("singleUse") !== "false";
    const tags = formData.getAll("tags").map(String).filter(isDeviceTag);
    const result = await mintJoinKey(ctx, {
      expiresInSeconds,
      singleUse,
      tags,
    });
    revalidatePath("/join-keys");
    return {
      ok: true,
      data: { key: result.key, expiresAt: result.expires_at },
    };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : "Could not mint join key.",
    };
  }
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
    const tags = canMutateTailnet(ctx.role)
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
    if (!canMutateTailnet(ctx.role)) {
      return { ok: false, error: "Only owners and admins can revoke devices." };
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
    if (!canMutateTailnet(ctx.role)) {
      return { ok: false, error: "Only owners and admins can delete devices." };
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
    if (ctx.role !== "owner") {
      return { ok: false, error: "Only owners can create automation credentials." };
    }
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
    if (ctx.role !== "owner") {
      return { ok: false, error: "Only owners can revoke automation credentials." };
    }
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
    if (!canMutateTailnet(ctx.role)) {
      return {
        ok: false,
        error: "Only owners and admins can create webhook destinations.",
      };
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
    if (!canMutateTailnet(ctx.role)) {
      return {
        ok: false,
        error: "Only owners and admins can disable webhook destinations.",
      };
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
    if (!canMutateTailnet(ctx.role)) {
      return {
        ok: false,
        error: "Only owners and admins can list webhook deliveries.",
      };
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
    if (!canMutateTailnet(ctx.role)) {
      return {
        ok: false,
        error: "Only owners and admins can replay webhook deliveries.",
      };
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
    if (!canMutateTailnet(ctx.role)) {
      return {
        ok: false,
        error: "Only owners and admins can add unmanaged WireGuard peers.",
      };
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
    if (!canMutateTailnet(ctx.role)) {
      return {
        ok: false,
        error: "Only owners and admins can rotate unmanaged WireGuard peers.",
      };
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
    if (!canMutateTailnet(ctx.role)) {
      return {
        ok: false,
        error: "Only owners and admins can revoke unmanaged WireGuard peers.",
      };
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
    if (!canMutateTailnet(ctx.role)) {
      return { ok: false, error: "Only owners and admins can rename devices." };
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
    if (!canMutateTailnet(ctx.role)) {
      return {
        ok: false,
        error: "Only owners and admins can approve subnet or exit-node routes.",
      };
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
    if (!canMutateTailnet(ctx.role)) {
      return { ok: false, error: "Only owners and admins can edit access policy." };
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

export async function saveDnsAction(formData: FormData): Promise<ActionResult> {
  try {
    const ctx = await requireConsoleContext();
    if (!canMutateTailnet(ctx.role)) {
      return { ok: false, error: "Only owners and admins can publish DNS settings." };
    }
    const etag = String(formData.get("etag") ?? "");
    const rollback = formData.get("rollback") === "true";
    if (rollback) {
      await putDns(ctx, { rollback: true }, etag);
      revalidatePath("/settings");
      return { ok: true, data: undefined };
    }
    const raw = String(formData.get("dnsJson") ?? "");
    let parsed: OrgDnsSettings;
    try {
      parsed = JSON.parse(raw) as OrgDnsSettings;
    } catch {
      return { ok: false, error: "DNS settings must be valid JSON." };
    }
    await putDns(ctx, { dns: parsed }, etag);
    revalidatePath("/settings");
    return { ok: true, data: undefined };
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof Error ? error.message : "Could not publish DNS settings.",
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
    if (requestedRole !== "admin" && requestedRole !== "member") {
      return { ok: false, error: "Invitation role must be admin or member." };
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
        error instanceof InvitationError
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
    await revokeInvitation(ctx, invitationId);
    revalidatePath("/settings");
    revalidatePath("/audit");
    return { ok: true, data: undefined };
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof InvitationError
          ? error.message
          : "Could not revoke invitation.",
    };
  }
}

const consolePaths = new Set([
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
    if (ctx.role !== "owner") {
      return { ok: false, error: "Only owners can configure the identity provider." };
    }
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
    const role = String(formData.get("role") ?? "") as "admin" | "member" | "";
    if (!membershipId) {
      return { ok: false, error: "Choose a membership." };
    }
    const next = await changeMembership({
      organisationId: ctx.organisationId,
      membershipId,
      status: status || undefined,
      role: role || undefined,
      actorUserId: ctx.userId,
      actorEmail: ctx.email,
      actorRole: ctx.role,
    });
    await emitMembershipUpdated(ctx, {
      membership_id: membershipId,
      role: next.role,
      status: next.status,
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
