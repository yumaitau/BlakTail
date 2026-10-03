import { writeConsoleAudit } from "./console-audit";
import { rawSqlClient } from "./db/client";
import { scimActivation } from "./directory-mapping-core";
import { getDirectorySettings, sweepDeprovisioned } from "./directory-mapping";
import type { OrgRole } from "./roles";
import { bearerToken, scimList, scimUser, tokenMatches } from "./scim-core";
import type { ScimUserInput } from "./scim-core";

export class ScimError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

export async function organisationForToken(header: string | null): Promise<string> {
  const presented = bearerToken(header);
  if (!presented?.startsWith("bts_")) {
    throw new ScimError("A SCIM bearer token is required.", 401);
  }
  const rows = await rawSqlClient()`
    SELECT organisation_id, token_hash
    FROM scim_token
    WHERE revoked_at IS NULL
  `;
  for (const row of rows) {
    if (tokenMatches(presented, String(row.token_hash))) {
      const organisationId = String(row.organisation_id);
      // Lazy sweep: grace periods that ended become tombstones.
      await sweepDeprovisioned(organisationId);
      return organisationId;
    }
  }
  throw new ScimError("SCIM token was rejected.", 401);
}

type UserRow = {
  id: string;
  email: string;
  name: string;
  external_id: string | null;
  status: string;
  role: string;
};

async function loadUsers(organisationId: string, email: string | null): Promise<UserRow[]> {
  const sql = rawSqlClient();
  const rows = email
    ? await sql`
        SELECT u.id, u.email, u.name, m.status, m.role,
          (
            SELECT account_id FROM account
            WHERE user_id = u.id AND issuer = ${`scim:${organisationId}`}
            LIMIT 1
          ) AS external_id
        FROM membership m
        JOIN "user" u ON u.id = m.user_id
        WHERE m.organisation_id = ${organisationId}
          AND lower(u.email) = ${email}
        ORDER BY lower(u.email)
      `
    : await sql`
        SELECT u.id, u.email, u.name, m.status, m.role,
          (
            SELECT account_id FROM account
            WHERE user_id = u.id AND issuer = ${`scim:${organisationId}`}
            LIMIT 1
          ) AS external_id
        FROM membership m
        JOIN "user" u ON u.id = m.user_id
        WHERE m.organisation_id = ${organisationId}
        ORDER BY lower(u.email)
      `;
  return (rows as Array<Record<string, unknown>>).map((row) => ({
    id: String(row.id),
    email: String(row.email),
    name: String(row.name),
    external_id: row.external_id ? String(row.external_id) : null,
    status: String(row.status),
    role: String(row.role),
  }));
}

function resource(row: UserRow) {
  return scimUser({
    id: row.id,
    userName: row.email,
    displayName: row.name,
    externalId: row.external_id ?? row.email,
    active: row.status === "active",
  });
}

export async function listScimUsers(organisationId: string, email: string | null) {
  const rows = await loadUsers(organisationId, email);
  return scimList(rows.map(resource));
}

export async function getScimUser(organisationId: string, userId: string) {
  const rows = await loadUsers(organisationId, null);
  const row = rows.find((candidate) => candidate.id === userId);
  if (!row) throw new ScimError("User was not found.", 404);
  return resource(row);
}

export async function provisionScimUser(organisationId: string, input: ScimUserInput) {
  const sql = rawSqlClient();
  const userId = await sql.begin(async (transaction) => {
    const [existing] = await transaction`
      SELECT id FROM "user" WHERE lower(email) = ${input.userName} LIMIT 1
    `;
    const id = existing ? String(existing.id) : crypto.randomUUID();
    if (!existing) {
      await transaction`
        INSERT INTO "user" (id, name, email, email_verified)
        VALUES (${id}, ${input.displayName}, ${input.userName}, true)
      `;
      await transaction`
        INSERT INTO person (id, display_name) VALUES (${id}, ${input.displayName})
      `;
      await transaction`
        INSERT INTO person_login_identity (id, person_id, user_id)
        VALUES (${crypto.randomUUID()}, ${id}, ${id})
      `;
    }
    const [membership] = await transaction`
      SELECT id, role FROM membership
      WHERE organisation_id = ${organisationId} AND user_id = ${id}
      LIMIT 1
    `;
    if (!membership) {
      const membershipId = crypto.randomUUID();
      await transaction`
        INSERT INTO membership (id, organisation_id, user_id, role, status)
        VALUES (
          ${membershipId}, ${organisationId}, ${id}, 'member',
          ${input.active ? "active" : "suspended"}
        )
      `;
      await transaction`
        INSERT INTO network_account (
          id, membership_id, login_identity_user_id, organisation_id, name
        )
        SELECT ${crypto.randomUUID()}, ${membershipId}, ${id}, o.id, o.name
        FROM organisation o WHERE o.id = ${organisationId}
      `;
    } else if (membership.role !== "owner") {
      await applyActivation(transaction as unknown as Sql, organisationId, String(membership.id), input.active);
    }
    await transaction`
      INSERT INTO account (id, issuer, account_id, provider_id, user_id)
      VALUES (
        ${crypto.randomUUID()}, ${`scim:${organisationId}`}, ${input.externalId},
        'scim', ${id}
      )
      ON CONFLICT (issuer, account_id) DO NOTHING
    `;
    return id;
  });
  return getScimUser(organisationId, userId);
}

type Sql = ReturnType<typeof rawSqlClient>;

/**
 * Deactivation suspends at once and starts the organisation's deprovision
 * grace period; the membership becomes a tombstone when it ends.
 */
async function applyActivation(
  sql: Sql,
  organisationId: string,
  membershipId: string,
  active: boolean,
): Promise<string> {
  const [row] = await sql`
    SELECT role, status, deprovision_at, tombstoned_at FROM membership
    WHERE id = ${membershipId} AND organisation_id = ${organisationId}
  `;
  if (!row) throw new ScimError("User was not found.", 404);
  const settings = await getDirectorySettings(organisationId, sql);
  const next = scimActivation(
    {
      role: row.role as OrgRole,
      status: String(row.status),
      deprovisionAt: row.deprovision_at ? new Date(String(row.deprovision_at)) : null,
      tombstonedAt: row.tombstoned_at ? new Date(String(row.tombstoned_at)) : null,
    },
    active,
    settings,
    new Date(),
  );
  await sql`
    UPDATE membership
    SET status = ${next.status}, role = ${next.role},
      role_source = COALESCE(${next.roleSource ?? null}, role_source),
      deprovision_at = CAST(${next.deprovisionAt?.toISOString() ?? null} AS timestamptz),
      tombstoned_at = CAST(${next.tombstonedAt?.toISOString() ?? null} AS timestamptz)
    WHERE id = ${membershipId} AND organisation_id = ${organisationId}
  `;
  return next.status;
}

export async function setScimActive(
  organisationId: string,
  userId: string,
  active: boolean,
) {
  const [membership] = await rawSqlClient()`
    SELECT id, role FROM membership
    WHERE organisation_id = ${organisationId} AND user_id = ${userId}
    LIMIT 1
  `;
  if (!membership) throw new ScimError("User was not found.", 404);
  if (membership.role === "owner" && !active) {
    throw new ScimError("The organisation owner cannot be deactivated by SCIM.", 409);
  }
  if (membership.role !== "owner") {
    const status = await applyActivation(rawSqlClient(), organisationId, String(membership.id), active);
    await writeConsoleAudit({
      organisationId,
      actorUserId: "system",
      actorEmail: "",
      actorRole: "system",
      source: "scim",
      action: active ? "scim.user_activated" : "scim.user_deprovisioned",
      result: "ok",
      targetType: "membership",
      targetId: String(membership.id),
      details: { status },
    });
    await rawSqlClient()`
      UPDATE person_login_identity
      SET status = ${active ? "active" : "suspended"},
          suspended_at = CASE WHEN ${active} THEN NULL ELSE now() END
      WHERE user_id = ${userId}
    `;
  }
  return getScimUser(organisationId, userId);
}
