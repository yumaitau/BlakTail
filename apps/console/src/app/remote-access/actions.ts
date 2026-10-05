"use server";

import { actionFailure } from "@/lib/server-errors";
import { revalidatePath } from "next/cache";
import { requireSecurityAssurance } from "@/lib/auth-policy";
import {
  acknowledgeHostKey,
  issueRemoteSession,
  revokeRemoteSession,
  saveRemoteSettings,
  type RemoteSessionKind,
} from "@/lib/coord-remote";
import { requireConsoleContext, requireOrganisationContext } from "@/lib/session";

export type RemoteActionResult<T = undefined> =
  | { ok: true; message: string; data: T }
  | { ok: false; error: string };

function failure(error: unknown, fallback: string): { ok: false; error: string } {
  return actionFailure(error, fallback);
}

const UUID = /^[0-9a-f-]{36}$/i;

export type StartedSession = {
  sessionId: string;
  ticket: string;
  gatewayUrl: string;
  ticketExpiresAt: number;
  maxEndAt: number;
  idleTimeoutSeconds: number;
  targetName: string;
  osUser: string;
};

/**
 * Asks the coordinator for a single-use ticket. The ticket goes only to
 * this browser tab, which hands it to the gateway within 60 seconds.
 */
export async function startRemoteSessionAction(
  formData: FormData,
): Promise<RemoteActionResult<StartedSession>> {
  try {
    const organisationId = String(formData.get("organisationId") ?? "");
    const ctx = await requireOrganisationContext(organisationId);
    const nodeId = String(formData.get("nodeId") ?? "");
    const kind = String(formData.get("kind") ?? "ssh") as RemoteSessionKind;
    const osUser = String(formData.get("osUser") ?? "").trim();
    const reason = String(formData.get("reason") ?? "").trim();
    const duration = Number(formData.get("durationMinutes") ?? 30);
    if (!UUID.test(nodeId)) return { ok: false, error: "Choose a device." };
    if (kind !== "ssh" && kind !== "rdp") return { ok: false, error: "Choose SSH or RDP." };
    if (!osUser) return { ok: false, error: "Enter the account to log in as." };
    if (reason.length < 4) {
      return { ok: false, error: "Say why you need access (at least 4 characters)." };
    }
    if (!Number.isInteger(duration) || duration < 1 || duration > 30) {
      return { ok: false, error: "Session length must be 1 to 30 minutes." };
    }
    const issued = await issueRemoteSession(ctx, {
      kind,
      target_node_id: nodeId,
      os_user: osUser,
      reason,
      duration_minutes: duration,
    });
    return {
      ok: true,
      message: "Session ticket issued.",
      data: {
        sessionId: issued.session_id,
        ticket: issued.ticket,
        gatewayUrl: issued.gateway_url,
        ticketExpiresAt: issued.ticket_expires_at,
        maxEndAt: issued.max_end_at,
        idleTimeoutSeconds: issued.idle_timeout_seconds,
        targetName: issued.target_name,
        osUser: issued.os_user,
      },
    };
  } catch (error) {
    return failure(error, "Could not start the session.");
  }
}

export async function endRemoteSessionAction(
  formData: FormData,
): Promise<RemoteActionResult> {
  try {
    const organisationId = String(formData.get("organisationId") ?? "");
    const ctx = organisationId
      ? await requireOrganisationContext(organisationId)
      : await requireConsoleContext();
    const sessionId = String(formData.get("sessionId") ?? "");
    if (!UUID.test(sessionId)) return { ok: false, error: "Choose a session." };
    await revokeRemoteSession(ctx, sessionId);
    revalidatePath("/remote-access");
    return { ok: true, message: "Session revoked. The gateway ends it within seconds.", data: undefined };
  } catch (error) {
    return failure(error, "Could not revoke the session.");
  }
}

export async function saveRemoteSettingsAction(
  formData: FormData,
): Promise<RemoteActionResult> {
  try {
    const ctx = await requireConsoleContext();
    await requireSecurityAssurance(ctx);
    const gatewayNodeId = String(formData.get("gatewayNodeId") ?? "");
    const gatewayUrl = String(formData.get("gatewayUrl") ?? "").trim();
    if (gatewayNodeId && !UUID.test(gatewayNodeId)) {
      return { ok: false, error: "Choose the gateway device." };
    }
    await saveRemoteSettings(ctx, {
      gateway_node_id: gatewayNodeId || null,
      gateway_url: gatewayUrl,
    });
    revalidatePath("/remote-access");
    return {
      ok: true,
      message: gatewayNodeId
        ? "Gateway saved. Devices that opted in trust the organisation SSH CA from it after their next sync."
        : "Gateway removed. No new sessions can start.",
      data: undefined,
    };
  } catch (error) {
    return failure(error, "Could not save remote access settings.");
  }
}

export async function acknowledgeHostKeyAction(
  formData: FormData,
): Promise<RemoteActionResult> {
  try {
    const ctx = await requireConsoleContext();
    const nodeId = String(formData.get("nodeId") ?? "");
    const fingerprint = String(formData.get("fingerprint") ?? "");
    if (!UUID.test(nodeId) || !fingerprint.startsWith("SHA256:")) {
      return { ok: false, error: "Choose a pending host key." };
    }
    await acknowledgeHostKey(ctx, nodeId, fingerprint);
    revalidatePath("/remote-access");
    return { ok: true, message: "New host key accepted.", data: undefined };
  } catch (error) {
    return failure(error, "Could not accept the host key.");
  }
}
