import "server-only";

import type { SQL, TransactionSQL } from "bun";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { hashPassword } from "better-auth/crypto";
import { can, isOrgRole, type OrgRole } from "./roles";
import type { ConsoleContext } from "./session";
import { rawSqlClient } from "./db/client";
import { consumeRateLimit } from "./request-security";

export type InvitationRole = Exclude<OrgRole, "owner">;

export function isInvitationRole(value: unknown): value is InvitationRole {
  return isOrgRole(value) && value !== "owner";
}

export class InvitationError extends Error {
  constructor(
    message: string,
    readonly status = 400,
  ) {
    super(message);
  }
}

export type PendingInvitation = {
  id: string;
  email: string;
  role: InvitationRole;
  expiresAt: Date;
  createdAt: Date;
};

type PendingInvitationRow = {
  id: string;
  email: string;
  role: InvitationRole;
  expires_at: Date | string;
  created_at: Date | string;
};

function tokenHash(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function normaliseEmail(value: string): string {
  const email = value.trim().toLowerCase();
  if (
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ) {
    throw new InvitationError("Enter a valid invitation email.");
  }
  return email;
}

function validName(value: string): string {
  const name = value.trim();
  if (!name || [...name].length > 128 || /[\u0000-\u001f\u007f]/u.test(name)) {
    throw new InvitationError("Name must contain 1-128 printable characters.");
  }
  return name;
}

async function appendAudit(
  sql: SQL | TransactionSQL,
  event: {
    organisationId: string;
    actorUserId?: string;
    actorEmail: string;
    actorRole: string;
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
      ${randomUUID()}, ${event.organisationId}, ${event.actorUserId ?? null},
      ${event.actorEmail}, ${event.actorRole}, 'console', ${event.action},
      ${event.result}, ${event.targetType}, ${event.targetId ?? null},
      CAST(${JSON.stringify(event.details ?? {})} AS jsonb)
    )
  `;
}

export async function createInvitation(
  ctx: ConsoleContext,
  emailValue: string,
  role: InvitationRole,
): Promise<{ invitation: PendingInvitation; url: string }> {
  const sql = rawSqlClient();
  const email = normaliseEmail(emailValue);
  if (!isInvitationRole(role)) {
    throw new InvitationError("Choose one of the listed invitation roles.");
  }
  if (!can(ctx.role, "manage_security")) {
    await appendAudit(sql, {
      organisationId: ctx.organisationId,
      actorUserId: ctx.userId,
      actorEmail: ctx.email,
      actorRole: ctx.role,
      action: "invitation.create",
      result: "denied",
      targetType: "invitation",
      details: { requested_role: role },
    });
    throw new InvitationError("Only organisation owners can invite users.", 403);
  }
  await consumeRateLimit(
    `invitation:create:${ctx.organisationId}:${ctx.userId}`,
    3600,
    20,
  );
  const token = `bti_${randomBytes(32).toString("base64url")}`;
  const id = randomUUID();
  const expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000);
  await sql.begin("isolation level serializable", async (transaction) => {
    await transaction`SELECT pg_advisory_xact_lock(hashtextextended(${email}, 0))`;
    const [existingUser] = await transaction`
      SELECT u.id, m.id AS membership_id
      FROM "user" u
      LEFT JOIN membership m ON m.user_id = u.id
        AND m.organisation_id = ${ctx.organisationId}
      WHERE lower(u.email) = ${email}
      LIMIT 1
    `;
    if (existingUser?.membership_id) {
      throw new InvitationError(
        "That account already belongs to this workspace.",
      );
    }
    await transaction`
      UPDATE invitation SET status = 'revoked', revoked_at = now()
      WHERE organisation_id = ${ctx.organisationId}
        AND email = ${email} AND status = 'pending' AND expires_at <= now()
    `;
    const [pending] = await transaction`
      SELECT id FROM invitation
      WHERE organisation_id = ${ctx.organisationId}
        AND email = ${email} AND status = 'pending'
      LIMIT 1
    `;
    if (pending) throw new InvitationError("A pending invitation already exists.");
    await transaction`
      INSERT INTO invitation (
        id, organisation_id, email, role, token_hash,
        inviter_user_id, expires_at
      ) VALUES (
        ${id}, ${ctx.organisationId}, ${email}, ${role}, ${tokenHash(token)},
        ${ctx.userId}, ${expiresAt.toISOString()}
      )
    `;
    await appendAudit(transaction, {
      organisationId: ctx.organisationId,
      actorUserId: ctx.userId,
      actorEmail: ctx.email,
      actorRole: ctx.role,
      action: "invitation.created",
      result: "success",
      targetType: "invitation",
      targetId: id,
      details: { invited_email: email, role, expires_at: expiresAt.toISOString() },
    });
  });
  const baseUrl = process.env.BETTER_AUTH_URL;
  if (!baseUrl) throw new Error("BETTER_AUTH_URL is required.");
  const url = new URL("/invite", baseUrl);
  url.searchParams.set("token", token);
  return {
    invitation: { id, email, role, expiresAt, createdAt: new Date() },
    url: url.toString(),
  };
}

export async function listPendingInvitations(
  ctx: ConsoleContext,
): Promise<PendingInvitation[]> {
  if (!can(ctx.role, "manage_security")) return [];
  const sql = rawSqlClient();
  const rows = await sql<PendingInvitationRow[]>`
    SELECT id, email, role, expires_at, created_at
    FROM invitation
    WHERE organisation_id = ${ctx.organisationId}
      AND status = 'pending' AND expires_at > now()
    ORDER BY created_at DESC, id DESC
  `;
  return rows.map((row) => ({
    id: row.id,
    email: row.email,
    role: row.role,
    expiresAt: new Date(row.expires_at),
    createdAt: new Date(row.created_at),
  }));
}

export async function revokeInvitation(
  ctx: ConsoleContext,
  invitationId: string,
): Promise<void> {
  const sql = rawSqlClient();
  if (!can(ctx.role, "manage_security")) {
    await appendAudit(sql, {
      organisationId: ctx.organisationId,
      actorUserId: ctx.userId,
      actorEmail: ctx.email,
      actorRole: ctx.role,
      action: "invitation.revoke",
      result: "denied",
      targetType: "invitation",
      targetId: invitationId,
    });
    throw new InvitationError("Only organisation owners can revoke invitations.", 403);
  }
  await sql.begin("isolation level serializable", async (transaction) => {
    const changed = await transaction`
      UPDATE invitation SET status = 'revoked', revoked_at = now()
      WHERE id = ${invitationId}
        AND organisation_id = ${ctx.organisationId}
        AND status = 'pending'
      RETURNING id
    `;
    if (changed.length !== 1) {
      throw new InvitationError("Pending invitation not found.");
    }
    await appendAudit(transaction, {
      organisationId: ctx.organisationId,
      actorUserId: ctx.userId,
      actorEmail: ctx.email,
      actorRole: ctx.role,
      action: "invitation.revoked",
      result: "success",
      targetType: "invitation",
      targetId: invitationId,
    });
  });
}

export async function acceptInvitation(input: {
  token: string;
  email?: string;
  name?: string;
  password?: string;
  authenticatedUser?: { id: string; email: string };
}): Promise<{
  email: string;
  organisationId: string;
  accountCreated: boolean;
}> {
  const token = input.token.trim();
  if (!token.startsWith("bti_") || token.length < 40 || token.length > 128) {
    throw new InvitationError("Invitation is invalid or expired.");
  }
  const authenticatedUser = input.authenticatedUser;
  const email = normaliseEmail(authenticatedUser?.email ?? input.email ?? "");
  let name: string | undefined;
  let passwordHash: string | undefined;
  if (!authenticatedUser) {
    name = validName(input.name ?? "");
    const password = input.password ?? "";
    if (password.length < 10 || password.length > 128) {
      throw new InvitationError("Password must contain 10-128 characters.");
    }
    passwordHash = await hashPassword(password);
  }
  const sql = rawSqlClient();
  const outcome = await sql.begin(
    "isolation level serializable",
    async (transaction) => {
      const [invitation] = await transaction`
        SELECT id, organisation_id, email, role, status, expires_at
        FROM invitation WHERE token_hash = ${tokenHash(token)} FOR UPDATE
      `;
      if (
        !invitation ||
        invitation.status !== "pending" ||
        new Date(invitation.expires_at).getTime() <= Date.now()
      ) {
        return {
          ok: false as const,
          message: "Invitation is invalid or expired.",
          status: 400,
        };
      }
      if (invitation.email.toLowerCase() !== email) {
        await appendAudit(transaction, {
          organisationId: invitation.organisation_id,
          actorUserId: authenticatedUser?.id,
          actorEmail: email,
          actorRole: "invitee",
          action: "invitation.accept",
          result: "denied",
          targetType: "invitation",
          targetId: invitation.id,
          details: { reason: "recipient_mismatch" },
        });
        return {
          ok: false as const,
          message: authenticatedUser
            ? "Sign in with the account named in this invitation."
            : "Invitation is invalid or expired.",
          status: authenticatedUser ? 403 : 400,
        };
      }
      await transaction`SELECT pg_advisory_xact_lock(hashtextextended(${email}, 0))`;
      const [existingUser] = await transaction`
        SELECT id, email FROM "user" WHERE lower(email) = ${email} LIMIT 1
      `;
      let userId: string;
      let accountCreated = false;
      if (authenticatedUser) {
        if (!existingUser || existingUser.id !== authenticatedUser.id) {
          await appendAudit(transaction, {
            organisationId: invitation.organisation_id,
            actorUserId: authenticatedUser.id,
            actorEmail: email,
            actorRole: "invitee",
            action: "invitation.accept",
            result: "denied",
            targetType: "invitation",
            targetId: invitation.id,
            details: { reason: "authenticated_identity_mismatch" },
          });
          return {
            ok: false as const,
            message: "Sign in with the account named in this invitation.",
            status: 403,
          };
        }
        userId = existingUser.id;
      } else {
        if (existingUser) {
          await appendAudit(transaction, {
            organisationId: invitation.organisation_id,
            actorUserId: existingUser.id,
            actorEmail: email,
            actorRole: "invitee",
            action: "invitation.accept",
            result: "denied",
            targetType: "invitation",
            targetId: invitation.id,
            details: { reason: "existing_account_requires_sign_in" },
          });
          return {
            ok: false as const,
            message: "This email already has an account. Sign in, then open the invitation again.",
            status: 409,
          };
        }
        userId = randomUUID();
        accountCreated = true;
        await transaction`
          INSERT INTO "user" (id, name, email, email_verified)
          VALUES (${userId}, ${name!}, ${email}, true)
        `;
        await transaction`
          INSERT INTO account (
            id, issuer, account_id, provider_id, user_id, password
          ) VALUES (
            ${randomUUID()}, 'local:credential', ${userId},
            'credential', ${userId}, ${passwordHash!}
          )
        `;
        await transaction`
          INSERT INTO person (id, display_name)
          VALUES (${userId}, ${name!})
        `;
        await transaction`
          INSERT INTO person_login_identity (id, person_id, user_id)
          VALUES (${randomUUID()}, ${userId}, ${userId})
        `;
      }
      const [existingMembership] = await transaction`
        SELECT id FROM membership
        WHERE organisation_id = ${invitation.organisation_id}
          AND user_id = ${userId}
        LIMIT 1
      `;
      if (existingMembership) {
        await transaction`
          UPDATE invitation SET status = 'revoked', revoked_at = now()
          WHERE id = ${invitation.id} AND status = 'pending'
        `;
        await appendAudit(transaction, {
          organisationId: invitation.organisation_id,
          actorUserId: userId,
          actorEmail: email,
          actorRole: invitation.role,
          action: "invitation.accept",
          result: "denied",
          targetType: "invitation",
          targetId: invitation.id,
          details: { reason: "membership_already_exists" },
        });
        return {
          ok: false as const,
          message: "This account already has access to the workspace.",
          status: 409,
        };
      }
      const membershipId = randomUUID();
      const networkAccountId = randomUUID();
      await transaction`
        INSERT INTO membership (id, organisation_id, user_id, role)
        VALUES (${membershipId}, ${invitation.organisation_id},
          ${userId}, ${invitation.role})
      `;
      await transaction`
        INSERT INTO network_account (
          id, membership_id, login_identity_user_id,
          organisation_id, name
        )
        SELECT ${networkAccountId}, ${membershipId}, ${userId}, o.id, o.name
        FROM organisation o
        WHERE o.id = ${invitation.organisation_id}
      `;
      await transaction`
        UPDATE invitation SET status = 'accepted', accepted_at = now()
        WHERE id = ${invitation.id} AND status = 'pending'
      `;
      await appendAudit(transaction, {
        organisationId: invitation.organisation_id,
        actorUserId: userId,
        actorEmail: email,
        actorRole: invitation.role,
        action: "invitation.accepted",
        result: "success",
        targetType: "invitation",
        targetId: invitation.id,
      });
      await appendAudit(transaction, {
        organisationId: invitation.organisation_id,
        actorUserId: userId,
        actorEmail: email,
        actorRole: invitation.role,
        action: "role.assigned",
        result: "success",
        targetType: "membership",
        targetId: userId,
        details: { role: invitation.role },
      });
      return {
        ok: true as const,
        email,
        organisationId: invitation.organisation_id,
        accountCreated,
      };
    },
  );
  if (!outcome.ok) {
    throw new InvitationError(outcome.message, outcome.status);
  }
  return {
    email: outcome.email,
    organisationId: outcome.organisationId,
    accountCreated: outcome.accountCreated,
  };
}
