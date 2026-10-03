import "server-only";

import type { SQL, TransactionSQL } from "bun";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { verifyPassword } from "better-auth/crypto";
import { rawSqlClient } from "./db/client";
import { consumeRateLimit } from "./request-security";
import type { OrgRole } from "./roles";
import type { PersonSessionContext } from "./session";

const LINK_TTL_MS = 10 * 60 * 1000;
const GENERIC_LINK_ERROR =
  "Linking could not be completed. Fresh reauthentication or account recovery is required.";

export class IdentityLinkError extends Error {
  constructor(
    message: string,
    readonly code: string,
  ) {
    super(message);
  }
}

export type LoginIdentitySummary = {
  userId: string;
  email: string;
  name: string;
  status: "active" | "suspended";
  current: boolean;
  methods: string[];
};

export type NetworkAccountSummary = {
  id: string;
  name: string;
  organisationId: string;
  organisationName: string;
  role: OrgRole;
  identityUserId: string;
};

export type PendingRoleConflict = {
  id: string;
  organisationId: string;
  organisationName: string;
  requesterRole: OrgRole;
  targetRole: OrgRole;
  expiresAt: Date;
};

type SharedOrganisationRow = {
  organisation_id: string;
  target_role: OrgRole;
  requester_roles: OrgRole[];
};

type IdentitySettingsRow = {
  user_id: string;
  email: string;
  name: string;
  status: "active" | "suspended";
  methods: string[];
};

type NetworkAccountSettingsRow = {
  id: string;
  name: string;
  organisation_id: string;
  organisation_name: string;
  role: OrgRole;
  login_identity_user_id: string;
};

type ConflictSettingsRow = {
  id: string;
  organisation_id: string;
  organisation_name: string;
  requester_role: OrgRole;
  target_role: OrgRole;
  expires_at: Date | string;
};

function challengeHash(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function normaliseEmail(value: string): string {
  return value.trim().toLowerCase();
}

async function appendAudit(
  sql: SQL | TransactionSQL,
  event: {
    organisationId?: string;
    actorUserId?: string;
    actorEmail?: string;
    actorRole?: string;
    action: string;
    result: "success" | "denied";
    targetType: string;
    targetId?: string;
    details?: unknown;
  },
) {
  await sql`
    INSERT INTO console_audit_event (
      id, organisation_id, actor_user_id, actor_email, actor_role,
      source, action, result, target_type, target_id, details
    ) VALUES (
      ${randomUUID()}, ${event.organisationId ?? null},
      ${event.actorUserId ?? null}, ${event.actorEmail ?? ""},
      ${event.actorRole ?? "person"}, 'console', ${event.action},
      ${event.result}, ${event.targetType}, ${event.targetId ?? null},
      CAST(${JSON.stringify(event.details ?? {})} AS jsonb)
    )
  `;
}

async function credentialMatches(
  sql: SQL | TransactionSQL,
  userId: string,
  password: string,
): Promise<boolean> {
  if (!password || password.length > 256) return false;
  const [method] = await sql`
    SELECT password
    FROM account
    WHERE user_id = ${userId}
      AND provider_id = 'credential'
      AND password IS NOT NULL
    ORDER BY created_at
    LIMIT 1
  `;
  if (!method?.password) return false;
  try {
    return await verifyPassword({ hash: method.password, password });
  } catch {
    return false;
  }
}

async function lockPeople(
  transaction: TransactionSQL,
  ...personIds: string[]
) {
  for (const personId of [...new Set(personIds)].sort()) {
    await transaction`
      SELECT pg_advisory_xact_lock(hashtextextended(${personId}, 0))
    `;
  }
}

async function rejectChallenge(
  transaction: TransactionSQL,
  challenge: { id: string; requester_user_id: string },
  reason: string,
) {
  await transaction`
    UPDATE identity_link_challenge
    SET status = 'rejected', failure_code = ${reason}, completed_at = now()
    WHERE id = ${challenge.id}
  `;
  await appendAudit(transaction, {
    actorUserId: challenge.requester_user_id,
    action: "identity_link.rejected",
    result: "denied",
    targetType: "identity_link_challenge",
    targetId: challenge.id,
    details: { reason },
  });
}

async function completeMerge(
  transaction: TransactionSQL,
  challenge: {
    id: string;
    requester_person_id: string;
    requester_user_id: string;
    target_user_id: string;
  },
) {
  const [targetIdentity] = await transaction`
    SELECT person_id, status
    FROM person_login_identity
    WHERE user_id = ${challenge.target_user_id}
    FOR UPDATE
  `;
  const [requesterIdentity] = await transaction`
    SELECT person_id, status
    FROM person_login_identity
    WHERE user_id = ${challenge.requester_user_id}
    FOR UPDATE
  `;
  if (
    !targetIdentity ||
    !requesterIdentity ||
    targetIdentity.status !== "active" ||
    requesterIdentity.status !== "active" ||
    requesterIdentity.person_id !== challenge.requester_person_id ||
    targetIdentity.person_id === challenge.requester_person_id
  ) {
    await rejectChallenge(transaction, challenge, "link_graph_changed");
    return new IdentityLinkError(GENERIC_LINK_ERROR, "link_graph_changed");
  }

  await lockPeople(
    transaction,
    challenge.requester_person_id,
    targetIdentity.person_id,
  );
  const [targetGraph] = await transaction`
    SELECT count(*)::int AS identity_count
    FROM person_login_identity
    WHERE person_id = ${targetIdentity.person_id}
  `;
  if (targetGraph.identity_count !== 1) {
    await rejectChallenge(transaction, challenge, "identity_linked_elsewhere");
    return new IdentityLinkError(GENERIC_LINK_ERROR, "recovery_required");
  }

  await transaction`
    UPDATE person_login_identity
    SET person_id = ${challenge.requester_person_id}, linked_at = now()
    WHERE user_id = ${challenge.target_user_id}
      AND person_id = ${targetIdentity.person_id}
      AND status = 'active'
  `;

  const conflicts = await transaction`
    SELECT organisation_id, resolved_role
    FROM identity_link_conflict
    WHERE challenge_id = ${challenge.id}
    ORDER BY organisation_id
  `;
  for (const conflict of conflicts) {
    if (!conflict.resolved_role) {
      throw new IdentityLinkError(
        "An organisation owner must resolve the role conflict.",
        "owner_resolution_required",
      );
    }
    const [signature] = await transaction`
      SELECT string_agg(m.id || ':' || m.role, '|' ORDER BY m.id)
        AS membership_signature
      FROM person_login_identity pli
      JOIN membership m ON m.user_id = pli.user_id
      JOIN network_account na ON na.membership_id = m.id
        AND na.login_identity_user_id = pli.user_id
        AND na.organisation_id = m.organisation_id
        AND na.status = 'active'
      WHERE pli.person_id = ${challenge.requester_person_id}
        AND pli.status = 'active'
        AND m.organisation_id = ${conflict.organisation_id}
    `;
    await transaction`
      INSERT INTO membership_role_resolution (
        id, person_id, organisation_id, effective_role,
        membership_signature, resolved_by_user_id
      )
      SELECT ${randomUUID()}, ${challenge.requester_person_id},
        c.organisation_id, c.resolved_role, ${signature.membership_signature},
        c.resolved_by_user_id
      FROM identity_link_conflict c
      WHERE c.challenge_id = ${challenge.id}
        AND c.organisation_id = ${conflict.organisation_id}
      ON CONFLICT (person_id, organisation_id)
      DO UPDATE SET effective_role = EXCLUDED.effective_role,
        membership_signature = EXCLUDED.membership_signature,
        resolved_by_user_id = EXCLUDED.resolved_by_user_id,
        created_at = now()
    `;
  }

  await transaction`
    DELETE FROM person
    WHERE id = ${targetIdentity.person_id}
      AND NOT EXISTS (
        SELECT 1 FROM person_login_identity
        WHERE person_id = ${targetIdentity.person_id}
      )
  `;
  await transaction`
    UPDATE identity_link_challenge
    SET status = 'succeeded', completed_at = now(), failure_code = NULL
    WHERE id = ${challenge.id}
  `;
  await appendAudit(transaction, {
    actorUserId: challenge.requester_user_id,
    action: "identity_link.succeeded",
    result: "success",
    targetType: "login_identity",
    targetId: challenge.target_user_id,
    details: { authentication: "fresh", memberships: "preserved" },
  });
  return null;
}

export async function beginIdentityLink(
  ctx: PersonSessionContext,
): Promise<{ token: string; expiresAt: Date }> {
  await consumeRateLimit(`identity-link:begin:${ctx.personId}`, 600, 10);
  const token = `btl_${randomBytes(32).toString("base64url")}`;
  const expiresAt = new Date(Date.now() + LINK_TTL_MS);
  const challengeId = randomUUID();
  const sql = rawSqlClient();
  const outcome = await sql.begin(
    "isolation level read committed",
    async (transaction) => {
      await lockPeople(transaction, ctx.personId);
      const expired = await transaction`
        UPDATE identity_link_challenge
        SET status = 'expired', failure_code = 'expired', completed_at = now()
        WHERE requester_person_id = ${ctx.personId}
          AND status IN ('pending', 'awaiting_owner')
          AND expires_at <= now()
        RETURNING id
      `;
      for (const challenge of expired) {
        await appendAudit(transaction, {
          actorUserId: ctx.userId,
          actorEmail: ctx.email,
          action: "identity_link.rejected",
          result: "denied",
          targetType: "identity_link_challenge",
          targetId: challenge.id,
          details: { reason: "expired" },
        });
      }
      const [openChallenge] = await transaction`
        SELECT id FROM identity_link_challenge
        WHERE requester_person_id = ${ctx.personId}
          AND status IN ('pending', 'awaiting_owner')
          AND expires_at > now()
        LIMIT 1
        FOR UPDATE
      `;
      if (openChallenge) {
        await appendAudit(transaction, {
          actorUserId: ctx.userId,
          actorEmail: ctx.email,
          action: "identity_link.request_rejected",
          result: "denied",
          targetType: "identity_link_challenge",
          targetId: openChallenge.id,
          details: { reason: "concurrent_link_in_progress" },
        });
        return new IdentityLinkError(
          "A link or owner-resolution request is already in progress.",
          "concurrent_link",
        );
      }
      await transaction`
        INSERT INTO identity_link_challenge (
          id, token_hash, requester_person_id, requester_user_id,
          requester_session_id, expires_at
        ) VALUES (
          ${challengeId}, ${challengeHash(token)}, ${ctx.personId},
          ${ctx.userId}, ${ctx.sessionId}, ${expiresAt.toISOString()}
        )
      `;
      await appendAudit(transaction, {
        actorUserId: ctx.userId,
        actorEmail: ctx.email,
        action: "identity_link.requested",
        result: "success",
        targetType: "identity_link_challenge",
        targetId: challengeId,
        details: { expires_at: expiresAt.toISOString() },
      });
      return null;
    },
  );
  if (outcome instanceof IdentityLinkError) {
    throw outcome;
  }
  return { token, expiresAt };
}

export async function completeIdentityLink(
  ctx: PersonSessionContext,
  input: {
    token: string;
    currentPassword: string;
    email: string;
    password: string;
  },
): Promise<{ linked: boolean; ownerResolutionRequired: boolean }> {
  await consumeRateLimit(
    `identity-link:complete:${ctx.personId}:${ctx.userId}`,
    600,
    10,
  );
  const token = input.token.trim();
  if (!token.startsWith("btl_") || token.length > 128) {
    throw new IdentityLinkError(GENERIC_LINK_ERROR, "invalid_challenge");
  }
  const email = normaliseEmail(input.email);
  const sql = rawSqlClient();
  const outcome = await sql.begin("isolation level serializable", async (transaction) => {
    const [challenge] = await transaction`
      SELECT id, requester_person_id, requester_user_id,
        requester_session_id, status, expires_at, target_user_id
      FROM identity_link_challenge
      WHERE token_hash = ${challengeHash(token)}
      FOR UPDATE
    `;
    if (!challenge) {
      throw new IdentityLinkError(GENERIC_LINK_ERROR, "invalid_challenge");
    }
    if (challenge.status !== "pending") {
      await appendAudit(transaction, {
        actorUserId: ctx.userId,
        action: "identity_link.rejected",
        result: "denied",
        targetType: "identity_link_challenge",
        targetId: challenge.id,
        details: { reason: "replay" },
      });
      return new IdentityLinkError(GENERIC_LINK_ERROR, "replay");
    }
    if (
      challenge.requester_person_id !== ctx.personId ||
      challenge.requester_user_id !== ctx.userId ||
      challenge.requester_session_id !== ctx.sessionId
    ) {
      await rejectChallenge(transaction, challenge, "session_mismatch");
      return new IdentityLinkError(GENERIC_LINK_ERROR, "reauthentication_required");
    }
    if (new Date(challenge.expires_at).getTime() <= Date.now()) {
      await transaction`
        UPDATE identity_link_challenge
        SET status = 'expired', failure_code = 'expired', completed_at = now()
        WHERE id = ${challenge.id}
      `;
      await appendAudit(transaction, {
        actorUserId: ctx.userId,
        action: "identity_link.rejected",
        result: "denied",
        targetType: "identity_link_challenge",
        targetId: challenge.id,
        details: { reason: "expired" },
      });
      return new IdentityLinkError(GENERIC_LINK_ERROR, "expired");
    }

    const [target] = await transaction`
      SELECT u.id, pli.person_id, pli.status
      FROM "user" u
      JOIN person_login_identity pli ON pli.user_id = u.id
      WHERE lower(u.email) = ${email}
      LIMIT 1
      FOR UPDATE OF pli
    `;
    const currentReauthenticated = await credentialMatches(
      transaction,
      ctx.userId,
      input.currentPassword,
    );
    const targetReauthenticated = await credentialMatches(
      transaction,
      target?.id ?? ctx.userId,
      input.password,
    );
    if (
      !target ||
      target.status !== "active" ||
      !currentReauthenticated ||
      !targetReauthenticated
    ) {
      await rejectChallenge(transaction, challenge, "reauthentication_failed");
      return new IdentityLinkError(GENERIC_LINK_ERROR, "reauthentication_required");
    }
    // A password alone must not pull a TOTP-protected identity (and its
    // organisation roles) into another person's session.
    const [targetFactor] = await transaction`
      SELECT coalesce(two_factor_enabled, false) AS enabled
      FROM "user" WHERE id = ${target.id}
    `;
    if (targetFactor?.enabled === true) {
      await rejectChallenge(transaction, challenge, "two_factor_required");
      return new IdentityLinkError(
        "That sign-in uses two-step verification, so it cannot be linked with its password alone. Turn two-step verification off for it first, or keep it separate.",
        "reauthentication_required",
      );
    }

    await lockPeople(transaction, ctx.personId, target.person_id);
    const [targetGraph] = await transaction`
      SELECT count(*)::int AS identity_count
      FROM person_login_identity
      WHERE person_id = ${target.person_id}
    `;
    if (target.person_id === ctx.personId) {
      await rejectChallenge(transaction, challenge, "already_linked");
      return new IdentityLinkError(GENERIC_LINK_ERROR, "already_linked");
    }
    if (targetGraph.identity_count !== 1) {
      await rejectChallenge(transaction, challenge, "identity_linked_elsewhere");
      return new IdentityLinkError(GENERIC_LINK_ERROR, "recovery_required");
    }

    await transaction`
      UPDATE identity_link_challenge
      SET target_user_id = ${target.id}, authenticated_at = now()
      WHERE id = ${challenge.id}
    `;
    const sharedOrganisations = (await transaction`
      SELECT tm.organisation_id, tm.role AS target_role,
        array_agg(DISTINCT rm.role) AS requester_roles
      FROM person_login_identity rpli
      JOIN membership rm ON rm.user_id = rpli.user_id
      JOIN membership tm ON tm.organisation_id = rm.organisation_id
      WHERE rpli.person_id = ${ctx.personId}
        AND rpli.status = 'active'
        AND tm.user_id = ${target.id}
      GROUP BY tm.organisation_id, tm.role
      ORDER BY tm.organisation_id
    `) as unknown as SharedOrganisationRow[];
    const conflicts = sharedOrganisations.flatMap((shared) => {
      if (
        !shared.requester_roles.some(
          (role: OrgRole) => role !== shared.target_role,
        )
      ) {
        return [];
      }
      const organisation = ctx.organisations.find(
        (candidate) => candidate.organisationId === shared.organisation_id,
      );
      return organisation
        ? [
            {
              organisation_id: shared.organisation_id,
              requester_role: organisation.role,
              target_role: shared.target_role as OrgRole,
            },
          ]
        : [];
    });
    if (conflicts.length > 0) {
      for (const conflict of conflicts) {
        await transaction`
          INSERT INTO identity_link_conflict (
            id, challenge_id, organisation_id, requester_role, target_role
          ) VALUES (
            ${randomUUID()}, ${challenge.id}, ${conflict.organisation_id},
            ${conflict.requester_role}, ${conflict.target_role}
          )
        `;
        await appendAudit(transaction, {
          organisationId: conflict.organisation_id,
          actorUserId: ctx.userId,
          actorEmail: ctx.email,
          action: "identity_link.role_conflict",
          result: "denied",
          targetType: "identity_link_challenge",
          targetId: challenge.id,
          details: {
            requester_role: conflict.requester_role,
            target_role: conflict.target_role,
            resolution: "owner_required",
          },
        });
      }
      await transaction`
        UPDATE identity_link_challenge
        SET status = 'awaiting_owner', failure_code = 'role_conflict'
        WHERE id = ${challenge.id}
      `;
      return { linked: false, ownerResolutionRequired: true };
    }

    const mergeError = await completeMerge(transaction, {
      ...challenge,
      target_user_id: target.id,
    });
    if (mergeError) return mergeError;
    return { linked: true, ownerResolutionRequired: false };
  });
  if (outcome instanceof IdentityLinkError) {
    throw outcome;
  }
  return outcome;
}

export async function listIdentitySettings(ctx: PersonSessionContext): Promise<{
  identities: LoginIdentitySummary[];
  networkAccounts: NetworkAccountSummary[];
  conflicts: PendingRoleConflict[];
}> {
  const sql = rawSqlClient();
  const identities = (await sql`
    SELECT pli.user_id, u.email, u.name, pli.status,
      array_remove(array_agg(DISTINCT a.provider_id), NULL) AS methods
    FROM person_login_identity pli
    JOIN "user" u ON u.id = pli.user_id
    LEFT JOIN account a ON a.user_id = u.id
    WHERE pli.person_id = ${ctx.personId}
    GROUP BY pli.user_id, u.email, u.name, pli.status, pli.linked_at
    ORDER BY pli.linked_at, pli.user_id
  `) as unknown as IdentitySettingsRow[];
  const networkAccounts = (await sql`
    SELECT na.id, na.name, na.organisation_id, o.name AS organisation_name,
      m.role, na.login_identity_user_id
    FROM person_login_identity pli
    JOIN network_account na ON na.login_identity_user_id = pli.user_id
      AND na.status = 'active'
    JOIN membership m ON m.id = na.membership_id
    JOIN organisation o ON o.id = na.organisation_id
    WHERE pli.person_id = ${ctx.personId}
      AND pli.status = 'active'
    ORDER BY o.name, na.name, na.id
  `) as unknown as NetworkAccountSettingsRow[];
  const conflicts = (await sql`
    SELECT c.id, c.organisation_id, o.name AS organisation_name,
      c.requester_role, c.target_role, ch.expires_at
    FROM identity_link_conflict c
    JOIN identity_link_challenge ch ON ch.id = c.challenge_id
    JOIN organisation o ON o.id = c.organisation_id
    WHERE ch.status = 'awaiting_owner'
      AND ch.expires_at > now()
      AND c.resolved_at IS NULL
      AND EXISTS (
        SELECT 1
        FROM membership owner_membership
        JOIN person_login_identity owner_identity
          ON owner_identity.user_id = owner_membership.user_id
        WHERE owner_membership.organisation_id = c.organisation_id
          AND owner_membership.role = 'owner'
          AND owner_identity.person_id = ${ctx.personId}
          AND owner_identity.status = 'active'
      )
    ORDER BY ch.created_at, c.organisation_id
  `) as unknown as ConflictSettingsRow[];
  return {
    identities: identities.map((identity) => ({
      userId: identity.user_id,
      email: identity.email,
      name: identity.name,
      status: identity.status,
      current: identity.user_id === ctx.userId,
      methods: identity.methods,
    })),
    networkAccounts: networkAccounts.map((networkAccount) => ({
      id: networkAccount.id,
      name: networkAccount.name,
      organisationId: networkAccount.organisation_id,
      organisationName: networkAccount.organisation_name,
      role: networkAccount.role,
      identityUserId: networkAccount.login_identity_user_id,
    })),
    conflicts: conflicts.map((conflict) => ({
      id: conflict.id,
      organisationId: conflict.organisation_id,
      organisationName: conflict.organisation_name,
      requesterRole: conflict.requester_role,
      targetRole: conflict.target_role,
      expiresAt: new Date(conflict.expires_at),
    })),
  };
}

/** The organisation a role conflict belongs to, for its security checks. */
export async function roleConflictOrganisationId(
  conflictId: string,
): Promise<string | null> {
  const sql = rawSqlClient();
  const [row] = await sql`
    SELECT organisation_id FROM identity_link_conflict WHERE id = ${conflictId}
  `;
  return row?.organisation_id ?? null;
}

export async function resolveIdentityRoleConflict(
  ctx: PersonSessionContext,
  conflictId: string,
  resolvedRole: OrgRole,
): Promise<{ linked: boolean }> {
  await consumeRateLimit(`identity-link:resolve:${ctx.personId}`, 600, 10);
  const sql = rawSqlClient();
  const outcome = await sql.begin("isolation level serializable", async (transaction) => {
    const [conflict] = await transaction`
      SELECT c.*, ch.requester_person_id, ch.requester_user_id,
        ch.target_user_id, ch.status AS challenge_status, ch.expires_at
      FROM identity_link_conflict c
      JOIN identity_link_challenge ch ON ch.id = c.challenge_id
      WHERE c.id = ${conflictId}
      FOR UPDATE OF c, ch
    `;
    if (
      !conflict ||
      conflict.challenge_status !== "awaiting_owner" ||
      conflict.resolved_at ||
      (resolvedRole !== conflict.requester_role &&
        resolvedRole !== conflict.target_role)
    ) {
      throw new IdentityLinkError(
        "This role-conflict decision is invalid or expired.",
        "invalid_conflict",
      );
    }
    if (new Date(conflict.expires_at).getTime() <= Date.now()) {
      await transaction`
        UPDATE identity_link_challenge
        SET status = 'expired', failure_code = 'expired', completed_at = now()
        WHERE id = ${conflict.challenge_id}
      `;
      await appendAudit(transaction, {
        organisationId: conflict.organisation_id,
        actorUserId: ctx.userId,
        actorEmail: ctx.email,
        action: "identity_link.role_conflict_resolution",
        result: "denied",
        targetType: "identity_link_conflict",
        targetId: conflict.id,
        details: { reason: "expired" },
      });
      return new IdentityLinkError(
        "This role-conflict decision is invalid or expired.",
        "invalid_conflict",
      );
    }
    const owner = ctx.organisations.find(
      (organisation) =>
        organisation.organisationId === conflict.organisation_id &&
        organisation.role === "owner",
    );
    if (!owner) {
      await appendAudit(transaction, {
        organisationId: conflict.organisation_id,
        actorUserId: ctx.userId,
        actorEmail: ctx.email,
        action: "identity_link.role_conflict_resolution",
        result: "denied",
        targetType: "identity_link_conflict",
        targetId: conflict.id,
        details: { reason: "owner_required" },
      });
      return new IdentityLinkError(
        "An organisation owner must resolve this role conflict.",
        "owner_required",
      );
    }
    await transaction`
      UPDATE identity_link_conflict
      SET resolved_role = ${resolvedRole}, resolved_by_user_id = ${ctx.userId},
        resolved_at = now()
      WHERE id = ${conflict.id} AND resolved_at IS NULL
    `;
    await appendAudit(transaction, {
      organisationId: conflict.organisation_id,
      actorUserId: ctx.userId,
      actorEmail: ctx.email,
      actorRole: "owner",
      action: "identity_link.role_conflict_resolved",
      result: "success",
      targetType: "identity_link_conflict",
      targetId: conflict.id,
      details: { effective_role: resolvedRole },
    });
    const [remaining] = await transaction`
      SELECT count(*)::int AS unresolved
      FROM identity_link_conflict
      WHERE challenge_id = ${conflict.challenge_id}
        AND resolved_at IS NULL
    `;
    if (remaining.unresolved > 0) return { linked: false };
    const mergeError = await completeMerge(transaction, {
      id: conflict.challenge_id,
      requester_person_id: conflict.requester_person_id,
      requester_user_id: conflict.requester_user_id,
      target_user_id: conflict.target_user_id,
    });
    if (mergeError) return mergeError;
    return { linked: true };
  });
  if (outcome instanceof IdentityLinkError) {
    throw outcome;
  }
  return outcome;
}

async function verifyCurrentIdentity(
  ctx: PersonSessionContext,
  password: string,
): Promise<void> {
  const sql = rawSqlClient();
  if (!(await credentialMatches(sql, ctx.userId, password))) {
    throw new IdentityLinkError(
      "Fresh reauthentication of your current sign-in is required.",
      "reauthentication_required",
    );
  }
}

export async function unlinkIdentity(
  ctx: PersonSessionContext,
  targetUserId: string,
  currentPassword: string,
): Promise<void> {
  await consumeRateLimit(`identity-link:manage:${ctx.personId}`, 600, 10);
  await verifyCurrentIdentity(ctx, currentPassword);
  if (targetUserId === ctx.userId) {
    throw new IdentityLinkError(
      "Sign in with another linked identity before unlinking this one.",
      "current_identity",
    );
  }
  const sql = rawSqlClient();
  const outcome = await sql.begin("isolation level serializable", async (transaction) => {
    await lockPeople(transaction, ctx.personId);
    const [target] = await transaction`
      SELECT pli.user_id, pli.status, u.name
      FROM person_login_identity pli
      JOIN "user" u ON u.id = pli.user_id
      WHERE pli.person_id = ${ctx.personId}
        AND pli.user_id = ${targetUserId}
      FOR UPDATE OF pli
    `;
    const [graph] = await transaction`
      SELECT count(*) FILTER (WHERE status = 'active')::int AS active_count
      FROM person_login_identity
      WHERE person_id = ${ctx.personId}
    `;
    if (!target || target.status !== "active" || graph.active_count <= 1) {
      await appendAudit(transaction, {
        actorUserId: ctx.userId,
        actorEmail: ctx.email,
        action: "identity_link.unlink",
        result: "denied",
        targetType: "login_identity",
        targetId: targetUserId,
        details: { reason: "last_or_unavailable_sign_in" },
      });
      return new IdentityLinkError(
        "Unlinking would remove the last usable sign-in method.",
        "last_sign_in",
      );
    }
    const [usable] = await transaction`
      SELECT count(*)::int AS method_count
      FROM account
      WHERE user_id = ${targetUserId}
        AND (password IS NOT NULL OR provider_id <> 'credential')
    `;
    if (usable.method_count < 1) {
      await appendAudit(transaction, {
        actorUserId: ctx.userId,
        actorEmail: ctx.email,
        action: "identity_link.unlink",
        result: "denied",
        targetType: "login_identity",
        targetId: targetUserId,
        details: { reason: "no_usable_sign_in_method" },
      });
      return new IdentityLinkError(
        "Unlinking would orphan a network account that has no usable sign-in method.",
        "orphaned_account",
      );
    }
    const newPersonId = randomUUID();
    await transaction`
      INSERT INTO person (id, display_name)
      VALUES (${newPersonId}, ${target.name})
    `;
    await transaction`
      UPDATE person_login_identity
      SET person_id = ${newPersonId}, linked_at = now()
      WHERE user_id = ${targetUserId} AND person_id = ${ctx.personId}
    `;
    await transaction`
      DELETE FROM membership_role_resolution
      WHERE person_id = ${ctx.personId}
        AND organisation_id IN (
          SELECT organisation_id FROM membership WHERE user_id = ${targetUserId}
        )
    `;
    await appendAudit(transaction, {
      actorUserId: ctx.userId,
      actorEmail: ctx.email,
      action: "identity_link.unlinked",
      result: "success",
      targetType: "login_identity",
      targetId: targetUserId,
      details: { memberships: "preserved", sessions: "live_graph_recheck" },
    });
    return null;
  });
  if (outcome instanceof IdentityLinkError) {
    throw outcome;
  }
}

export async function suspendIdentity(
  ctx: PersonSessionContext,
  targetUserId: string,
  currentPassword: string,
): Promise<void> {
  await consumeRateLimit(`identity-link:manage:${ctx.personId}`, 600, 10);
  await verifyCurrentIdentity(ctx, currentPassword);
  if (targetUserId === ctx.userId) {
    throw new IdentityLinkError(
      "The identity in the current session cannot revoke itself.",
      "current_identity",
    );
  }
  const sql = rawSqlClient();
  const outcome = await sql.begin("isolation level serializable", async (transaction) => {
    await lockPeople(transaction, ctx.personId);
    const [target] = await transaction`
      SELECT status FROM person_login_identity
      WHERE person_id = ${ctx.personId} AND user_id = ${targetUserId}
      FOR UPDATE
    `;
    const [graph] = await transaction`
      SELECT count(*) FILTER (WHERE status = 'active')::int AS active_count
      FROM person_login_identity WHERE person_id = ${ctx.personId}
    `;
    const orphanedOwners = await transaction`
      SELECT m.organisation_id
      FROM membership m
      WHERE m.user_id = ${targetUserId} AND m.role = 'owner'
        AND NOT EXISTS (
          SELECT 1
          FROM person_login_identity pli
          JOIN membership other_owner ON other_owner.user_id = pli.user_id
          WHERE pli.status = 'active'
            AND pli.user_id <> ${targetUserId}
            AND other_owner.organisation_id = m.organisation_id
            AND other_owner.role = 'owner'
            AND EXISTS (
              SELECT 1 FROM account sign_in_method
              WHERE sign_in_method.user_id = pli.user_id
                AND (sign_in_method.password IS NOT NULL
                  OR sign_in_method.provider_id <> 'credential')
            )
        )
    `;
    if (
      !target ||
      target.status !== "active" ||
      graph.active_count <= 1 ||
      orphanedOwners.length > 0
    ) {
      await appendAudit(transaction, {
        actorUserId: ctx.userId,
        actorEmail: ctx.email,
        action: "identity_link.revocation",
        result: "denied",
        targetType: "login_identity",
        targetId: targetUserId,
        details: {
          reason:
            orphanedOwners.length > 0
              ? "sole_owner_would_be_orphaned"
              : "last_or_unavailable_sign_in",
        },
      });
      return new IdentityLinkError(
        orphanedOwners.length > 0
          ? "Revocation would orphan a sole-owner organisation."
          : "Revocation would remove the last usable sign-in method.",
        "revocation_denied",
      );
    }
    await transaction`
      UPDATE person_login_identity
      SET status = 'suspended', suspended_at = now()
      WHERE person_id = ${ctx.personId} AND user_id = ${targetUserId}
    `;
    await appendAudit(transaction, {
      actorUserId: ctx.userId,
      actorEmail: ctx.email,
      action: "identity_link.revoked",
      result: "success",
      targetType: "login_identity",
      targetId: targetUserId,
      details: { memberships: "preserved", sessions: "invalidated_by_graph" },
    });
    return null;
  });
  if (outcome instanceof IdentityLinkError) {
    throw outcome;
  }
}

export async function recoverIdentity(
  ctx: PersonSessionContext,
  targetUserId: string,
  currentPassword: string,
): Promise<void> {
  await consumeRateLimit(`identity-link:manage:${ctx.personId}`, 600, 10);
  await verifyCurrentIdentity(ctx, currentPassword);
  const sql = rawSqlClient();
  await sql.begin("isolation level serializable", async (transaction) => {
    await lockPeople(transaction, ctx.personId);
    const changed = await transaction`
      UPDATE person_login_identity
      SET status = 'active', suspended_at = NULL, linked_at = now()
      WHERE person_id = ${ctx.personId}
        AND user_id = ${targetUserId}
        AND status = 'suspended'
      RETURNING user_id
    `;
    if (changed.length !== 1) {
      throw new IdentityLinkError(
        "That identity is not available for recovery.",
        "recovery_unavailable",
      );
    }
    await appendAudit(transaction, {
      actorUserId: ctx.userId,
      actorEmail: ctx.email,
      action: "identity_link.recovered",
      result: "success",
      targetType: "login_identity",
      targetId: targetUserId,
      details: { memberships: "preserved" },
    });
  });
}
