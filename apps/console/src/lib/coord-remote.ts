import "server-only";

import { AssuranceError, getSignInPolicy } from "./auth-policy";
import { stepUpRefusal } from "./auth-policy-core";
import { coordFetch, readError } from "./coord";
import { writeConsoleAudit } from "./console-audit";
import { rawSqlClient } from "./db/client";
import { can, permissionReason, type Permission } from "./roles";
import type { ConsoleContext } from "./session";

/** ADR 0006: a terminal needs a sign-in within the last 5 minutes. */
export const REMOTE_STEP_UP_MINUTES = 5;

export type RemoteSettings = {
  configured: boolean;
  gateway_node_id: string | null;
  gateway_name: string | null;
  gateway_state: "not_configured" | "online" | "offline" | "suspended" | "credential_expired" | "removed";
  gateway_url: string;
  ca_public_key: string;
  updated_at: number | null;
  updated_by: string;
  ticket_ttl_seconds: number;
  max_session_seconds: number;
  idle_timeout_seconds: number;
};

export type HostKey = {
  node_id: string;
  fingerprint: string;
  reported_at: number;
  pending_fingerprint: string | null;
  pending_reported_at: number | null;
  acknowledged_at: number | null;
};

export type RemoteSessionKind = "ssh" | "rdp";

export type RemoteSession = {
  id: string;
  kind: RemoteSessionKind;
  status: "issued" | "active" | "ended" | "expired" | "revoked";
  user_id: string;
  user_name: string;
  target_node_id: string;
  gateway_node_id: string;
  os_user: string;
  reason: string;
  created_at: number;
  redeemed_at: number | null;
  ended_at: number | null;
  end_reason: string | null;
  max_end_at: number;
  revoked_at: number | null;
  bytes_to_target: number;
  bytes_from_target: number;
};

export type IssuedSession = {
  session_id: string;
  kind: RemoteSessionKind;
  ticket: string;
  gateway_url: string;
  ticket_expires_at: number;
  max_end_at: number;
  idle_timeout_seconds: number;
  target_name: string;
  os_user: string;
};

export type JobTarget = { tags?: string[]; node_ids?: string[] };

export type JobTemplate = {
  id: string;
  name: string;
  argv: string[];
  timeout_secs: number;
  output_cap_bytes: number;
  target: JobTarget;
  created_at: number;
  created_by: string;
};

export type JobRun = {
  id: string;
  template_id: string;
  template_name: string;
  node_id: string;
  argv: string[];
  timeout_secs: number;
  output_cap_bytes: number;
  reason: string;
  status:
    | "pending_approval"
    | "approved"
    | "running"
    | "succeeded"
    | "failed"
    | "timed_out"
    | "output_capped"
    | "cancelled"
    | "rejected"
    | "expired"
    | "error";
  requested_by: string;
  requested_at: number;
  decided_by: string | null;
  decided_at: number | null;
  claimed_at: number | null;
  cancel_requested_at: number | null;
  finished_at: number | null;
  exit_code: number | null;
  output: string | null;
  output_truncated: boolean;
};

function requirePermission(ctx: ConsoleContext, permission: Permission) {
  const denied = permissionReason(ctx.role, permission);
  if (denied) throw new Error(denied);
}

async function call<T>(
  ctx: ConsoleContext,
  path: string,
  init: { method: string; body?: unknown } = { method: "GET" },
): Promise<T> {
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}${path}`, {
    method: init.method,
    ctx,
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
  if (!res.ok) throw new Error(await readError(res));
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

/**
 * Opening a terminal is more sensitive than any configuration change: the
 * organisation's MFA rule applies (via coordFetch) and the sign-in must be
 * recent, whatever the organisation's general step-up setting.
 */
export async function requireRemoteAssurance(ctx: ConsoleContext): Promise<void> {
  const policy = await getSignInPolicy(ctx.organisationId);
  const minutes = Math.min(policy.stepUpMaxAgeMinutes ?? REMOTE_STEP_UP_MINUTES, REMOTE_STEP_UP_MINUTES);
  const refusal = stepUpRefusal({ ...policy, stepUpMaxAgeMinutes: minutes }, ctx.sessionCreatedAt);
  if (!refusal) return;
  await writeConsoleAudit({
    organisationId: ctx.organisationId,
    actorUserId: ctx.userId,
    actorEmail: ctx.email,
    actorRole: ctx.role,
    source: "console",
    action: "auth.step_up_required",
    result: "denied",
    targetType: "remote_session",
    targetId: ctx.sessionId,
    details: { max_age_minutes: minutes },
  });
  throw new AssuranceError(
    `Remote sessions need a sign-in within the last ${minutes} minutes. Sign out and sign in again, then start the session.`,
    "step_up_required",
  );
}

export async function getRemoteSettings(ctx: ConsoleContext): Promise<RemoteSettings> {
  requirePermission(ctx, "view_network");
  return call(ctx, "/remote-access/settings");
}

export async function saveRemoteSettings(
  ctx: ConsoleContext,
  input: { gateway_node_id: string | null; gateway_url: string },
): Promise<RemoteSettings> {
  requirePermission(ctx, "manage_security");
  return call(ctx, "/remote-access/settings", { method: "PUT", body: input });
}

export async function listHostKeys(ctx: ConsoleContext): Promise<HostKey[]> {
  requirePermission(ctx, "view_network");
  return call(ctx, "/remote-access/host-keys");
}

export async function acknowledgeHostKey(
  ctx: ConsoleContext,
  nodeId: string,
  fingerprint: string,
): Promise<void> {
  requirePermission(ctx, "manage_peers");
  await call(ctx, `/remote-access/host-keys/${encodeURIComponent(nodeId)}/acknowledge`, {
    method: "POST",
    body: { fingerprint },
  });
}

export async function listRemoteSessions(ctx: ConsoleContext): Promise<RemoteSession[]> {
  requirePermission(ctx, "use_remote_sessions");
  return call(ctx, "/remote-access/sessions");
}

export async function issueRemoteSession(
  ctx: ConsoleContext,
  input: {
    kind: RemoteSessionKind;
    target_node_id: string;
    os_user: string;
    reason: string;
    duration_minutes: number;
  },
): Promise<IssuedSession> {
  requirePermission(ctx, "use_remote_sessions");
  await requireRemoteAssurance(ctx);
  return call(ctx, "/remote-access/sessions", { method: "POST", body: input });
}

export async function revokeRemoteSession(ctx: ConsoleContext, sessionId: string): Promise<void> {
  requirePermission(ctx, "use_remote_sessions");
  await call(ctx, `/remote-access/sessions/${encodeURIComponent(sessionId)}/revoke`, {
    method: "POST",
    body: {},
  });
}

/**
 * Ends a person's open sessions when their membership is suspended,
 * removed or loses the remote-session permission. Best effort: sessions
 * are also capped at 30 minutes.
 */
export async function revokeSessionsForMembership(
  ctx: ConsoleContext,
  membershipId: string,
  next: { role: string; status: string },
): Promise<void> {
  if (next.status === "active" && can(next.role as ConsoleContext["role"], "use_remote_sessions")) {
    return;
  }
  try {
    const sql = rawSqlClient();
    const [row] = (await sql`
      SELECT user_id FROM membership
      WHERE id = ${membershipId} AND organisation_id = ${ctx.organisationId}
    `) as { user_id: string }[];
    if (!row) return;
    await call(ctx, `/remote-access/users/${encodeURIComponent(row.user_id)}/revoke`, {
      method: "POST",
      body: {},
    });
  } catch (error) {
    console.warn(
      `remote session revoke failed: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }
}

export async function listJobTemplates(ctx: ConsoleContext): Promise<JobTemplate[]> {
  requirePermission(ctx, "use_remote_sessions");
  return call(ctx, "/remote-jobs/templates");
}

export async function createJobTemplate(
  ctx: ConsoleContext,
  input: {
    name: string;
    argv: string[];
    timeout_secs: number;
    output_cap_bytes: number;
    target: JobTarget;
  },
): Promise<JobTemplate> {
  requirePermission(ctx, "manage_remote_jobs");
  return call(ctx, "/remote-jobs/templates", { method: "POST", body: input });
}

export async function disableJobTemplate(ctx: ConsoleContext, templateId: string): Promise<void> {
  requirePermission(ctx, "manage_remote_jobs");
  await call(ctx, `/remote-jobs/templates/${encodeURIComponent(templateId)}`, {
    method: "DELETE",
  });
}

export async function listJobRuns(ctx: ConsoleContext): Promise<JobRun[]> {
  requirePermission(ctx, "use_remote_sessions");
  return call(ctx, "/remote-jobs/runs");
}

export async function requestJobRun(
  ctx: ConsoleContext,
  input: { template_id: string; node_id: string; reason: string },
): Promise<JobRun> {
  requirePermission(ctx, "use_remote_sessions");
  return call(ctx, "/remote-jobs/runs", { method: "POST", body: input });
}

export async function decideJobRun(
  ctx: ConsoleContext,
  runId: string,
  decision: "approve" | "reject" | "cancel",
): Promise<JobRun> {
  requirePermission(ctx, decision === "cancel" ? "use_remote_sessions" : "manage_remote_jobs");
  if (decision === "approve") await requireRemoteAssurance(ctx);
  return call(ctx, `/remote-jobs/runs/${encodeURIComponent(runId)}/${decision}`, {
    method: "POST",
    body: {},
  });
}
