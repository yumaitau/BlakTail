import "server-only";

import { randomBytes, randomUUID } from "node:crypto";
import { resolveTxt } from "node:dns/promises";
import {
  AssuranceError,
  DEFAULT_SIGN_IN_POLICY,
  domainTxtName,
  domainTxtValue,
  jitDomainRefusal,
  mfaRefusal,
  normaliseDomain,
  stepUpRefusal,
  txtRecordsProve,
  type SignInPolicy,
} from "./auth-policy-core";
import { writeConsoleAudit } from "./console-audit";
import { rawSqlClient } from "./db/client";
import { can, permissionReason } from "./roles";
import type { ConsoleContext } from "./session";

export { AssuranceError } from "./auth-policy-core";

export async function getSignInPolicy(organisationId: string): Promise<SignInPolicy> {
  const sql = rawSqlClient();
  const [row] = await sql`
    SELECT step_up_max_age_minutes, require_mfa_for_privileged
    FROM organisation_sign_in_policy WHERE organisation_id = ${organisationId}
  `;
  if (!row) return DEFAULT_SIGN_IN_POLICY;
  return {
    stepUpMaxAgeMinutes: row.step_up_max_age_minutes ?? null,
    requireMfaForPrivileged: row.require_mfa_for_privileged === true,
  };
}

export async function identityAssurance(
  userId: string,
): Promise<{ hasPassword: boolean; twoFactorEnabled: boolean }> {
  const sql = rawSqlClient();
  const [row] = await sql`
    SELECT
      coalesce(u.two_factor_enabled, false) AS two_factor_enabled,
      EXISTS (
        SELECT 1 FROM account a
        WHERE a.user_id = u.id AND a.provider_id = 'credential'
          AND a.password IS NOT NULL
      ) AS has_password
    FROM "user" u WHERE u.id = ${userId}
  `;
  return {
    hasPassword: row?.has_password === true,
    twoFactorEnabled: row?.two_factor_enabled === true,
  };
}

/** MFA policy for any coordinator write made by a privileged role. */
export async function requireWriteAssurance(ctx: ConsoleContext): Promise<void> {
  const policy = await getSignInPolicy(ctx.organisationId);
  if (!policy.requireMfaForPrivileged) return;
  const refusal = mfaRefusal(policy, ctx.role, await identityAssurance(ctx.userId));
  if (refusal) throw new AssuranceError(refusal, "mfa_required");
}

/**
 * Security-sensitive changes: the organisation's MFA rule plus a recent
 * sign-in. Evaluated against the organisation being changed, never against
 * another organisation the same person can reach.
 */
export async function requireSecurityAssurance(ctx: ConsoleContext): Promise<void> {
  const policy = await getSignInPolicy(ctx.organisationId);
  const mfa = mfaRefusal(policy, ctx.role, await identityAssurance(ctx.userId));
  if (mfa) throw new AssuranceError(mfa, "mfa_required");
  const stepUp = stepUpRefusal(policy, ctx.sessionCreatedAt);
  if (stepUp) {
    await writeConsoleAudit({
      organisationId: ctx.organisationId,
      actorUserId: ctx.userId,
      actorEmail: ctx.email,
      actorRole: ctx.role,
      source: "console",
      action: "auth.step_up_required",
      result: "denied",
      targetType: "session",
      targetId: ctx.sessionId,
      details: { max_age_minutes: policy.stepUpMaxAgeMinutes },
    });
    throw new AssuranceError(stepUp, "step_up_required");
  }
}

function requireSecurityPermission(ctx: ConsoleContext) {
  const reason = permissionReason(ctx.role, "manage_security");
  if (reason) throw new Error(reason);
}

export async function saveSignInPolicy(
  ctx: ConsoleContext,
  next: SignInPolicy,
): Promise<void> {
  requireSecurityPermission(ctx);
  await requireSecurityAssurance(ctx);
  if (next.requireMfaForPrivileged) {
    // Do not let an owner lock themselves out of security changes.
    const refusal = mfaRefusal(next, ctx.role, await identityAssurance(ctx.userId));
    if (refusal) {
      throw new Error(
        "Turn on two-step verification for your own sign-in before requiring it for owners and admins.",
      );
    }
  }
  const sql = rawSqlClient();
  await sql`
    INSERT INTO organisation_sign_in_policy (
      organisation_id, step_up_max_age_minutes, require_mfa_for_privileged,
      updated_by_user_id, updated_at
    ) VALUES (
      ${ctx.organisationId}, ${next.stepUpMaxAgeMinutes},
      ${next.requireMfaForPrivileged}, ${ctx.userId}, now()
    )
    ON CONFLICT (organisation_id) DO UPDATE SET
      step_up_max_age_minutes = excluded.step_up_max_age_minutes,
      require_mfa_for_privileged = excluded.require_mfa_for_privileged,
      updated_by_user_id = excluded.updated_by_user_id,
      updated_at = now()
  `;
  await writeConsoleAudit({
    organisationId: ctx.organisationId,
    actorUserId: ctx.userId,
    actorEmail: ctx.email,
    actorRole: ctx.role,
    source: "console",
    action: "sign_in_policy.updated",
    result: "ok",
    targetType: "organisation",
    targetId: ctx.organisationId,
    details: {
      step_up_max_age_minutes: next.stepUpMaxAgeMinutes,
      require_mfa_for_privileged: next.requireMfaForPrivileged,
    },
  });
}

export type OrganisationDomain = {
  id: string;
  domain: string;
  txtName: string;
  txtValue: string;
  createdAt: string;
  lastCheckedAt: string | null;
  verifiedAt: string | null;
};

export async function listDomains(organisationId: string): Promise<OrganisationDomain[]> {
  const sql = rawSqlClient();
  const rows = await sql`
    SELECT id, domain, verification_token, created_at, last_checked_at, verified_at
    FROM organisation_domain WHERE organisation_id = ${organisationId}
    ORDER BY domain
  `;
  return rows.map(
    (row: {
      id: string;
      domain: string;
      verification_token: string;
      created_at: Date;
      last_checked_at: Date | null;
      verified_at: Date | null;
    }) => ({
      id: row.id,
      domain: row.domain,
      txtName: domainTxtName(row.domain),
      txtValue: domainTxtValue(row.verification_token),
      createdAt: new Date(row.created_at).toISOString(),
      lastCheckedAt: row.last_checked_at ? new Date(row.last_checked_at).toISOString() : null,
      verifiedAt: row.verified_at ? new Date(row.verified_at).toISOString() : null,
    }),
  );
}

async function domainVerifiedElsewhere(
  organisationId: string,
  domain: string,
): Promise<boolean> {
  const sql = rawSqlClient();
  const [row] = await sql`
    SELECT 1 FROM organisation_domain
    WHERE domain = ${domain} AND organisation_id <> ${organisationId}
      AND verified_at IS NOT NULL
    LIMIT 1
  `;
  return Boolean(row);
}

async function auditDomain(
  ctx: ConsoleContext,
  action: string,
  result: string,
  id: string,
  domain: string,
) {
  await writeConsoleAudit({
    organisationId: ctx.organisationId,
    actorUserId: ctx.userId,
    actorEmail: ctx.email,
    actorRole: ctx.role,
    source: "console",
    action,
    result,
    targetType: "organisation_domain",
    targetId: id,
    details: { domain },
  });
}

export async function addDomain(ctx: ConsoleContext, input: string): Promise<void> {
  requireSecurityPermission(ctx);
  await requireSecurityAssurance(ctx);
  const domain = normaliseDomain(input);
  if (await domainVerifiedElsewhere(ctx.organisationId, domain)) {
    throw new Error("That domain is already verified by another organisation.");
  }
  const id = randomUUID();
  const sql = rawSqlClient();
  const inserted = await sql`
    INSERT INTO organisation_domain (
      id, organisation_id, domain, verification_token, created_by_user_id
    ) VALUES (
      ${id}, ${ctx.organisationId}, ${domain},
      ${randomBytes(24).toString("base64url")}, ${ctx.userId}
    )
    ON CONFLICT (organisation_id, domain) DO NOTHING
    RETURNING id
  `;
  if (inserted.length === 0) {
    throw new Error("That domain is already listed for this organisation.");
  }
  await auditDomain(ctx, "sign_in_domain.added", "ok", id, domain);
}

type TxtResolver = (name: string) => Promise<string[][]>;

async function lookupTxt(name: string, resolver: TxtResolver): Promise<string[][]> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      resolver(name),
      new Promise<string[][]>((_, reject) => {
        timer = setTimeout(() => reject(new Error("DNS lookup timed out.")), 5000);
      }),
    ]);
  } catch {
    return [];
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export async function verifyDomain(
  ctx: ConsoleContext,
  domainId: string,
  resolver: TxtResolver = resolveTxt,
): Promise<{ verified: boolean }> {
  requireSecurityPermission(ctx);
  await requireSecurityAssurance(ctx);
  const sql = rawSqlClient();
  const [row] = await sql`
    SELECT id, domain, verification_token, verified_at FROM organisation_domain
    WHERE id = ${domainId} AND organisation_id = ${ctx.organisationId}
  `;
  if (!row) throw new Error("That domain was not found.");
  if (row.verified_at) return { verified: true };
  if (await domainVerifiedElsewhere(ctx.organisationId, row.domain)) {
    await auditDomain(ctx, "sign_in_domain.verify", "conflict", row.id, row.domain);
    throw new Error("That domain is already verified by another organisation.");
  }
  const proven = txtRecordsProve(
    await lookupTxt(domainTxtName(row.domain), resolver),
    row.verification_token,
  );
  try {
    await sql`
      UPDATE organisation_domain
      SET last_checked_at = now(),
        verified_at = CASE WHEN ${proven} THEN now() ELSE NULL END
      WHERE id = ${row.id} AND organisation_id = ${ctx.organisationId}
    `;
  } catch {
    // The partial unique index lost a race with another organisation.
    await auditDomain(ctx, "sign_in_domain.verify", "conflict", row.id, row.domain);
    throw new Error("That domain is already verified by another organisation.");
  }
  await auditDomain(
    ctx,
    "sign_in_domain.verify",
    proven ? "ok" : "not_found",
    row.id,
    row.domain,
  );
  return { verified: proven };
}

export async function removeDomain(ctx: ConsoleContext, domainId: string): Promise<void> {
  requireSecurityPermission(ctx);
  await requireSecurityAssurance(ctx);
  const sql = rawSqlClient();
  const [row] = await sql`
    DELETE FROM organisation_domain
    WHERE id = ${domainId} AND organisation_id = ${ctx.organisationId}
    RETURNING id, domain
  `;
  if (!row) throw new Error("That domain was not found.");
  await auditDomain(ctx, "sign_in_domain.removed", "ok", row.id, row.domain);
}

/** Used inside the OIDC callback transaction before creating a JIT member. */
export async function jitDomainCheck(
  transaction: (strings: TemplateStringsArray, ...values: unknown[]) => PromiseLike<unknown>,
  organisationId: string,
  email: string | undefined,
): Promise<string | null> {
  const rows = (await transaction`
    SELECT organisation_id, domain FROM organisation_domain
    WHERE verified_at IS NOT NULL
      AND (organisation_id = ${organisationId} OR domain = ${email?.split("@")[1]?.toLowerCase() ?? ""})
  `) as { organisation_id: string; domain: string }[];
  return jitDomainRefusal(
    email,
    rows.filter((row) => row.organisation_id === organisationId).map((row) => row.domain),
    rows.filter((row) => row.organisation_id !== organisationId).map((row) => row.domain),
  );
}

export function canManageSecurity(ctx: ConsoleContext): boolean {
  return can(ctx.role, "manage_security");
}
