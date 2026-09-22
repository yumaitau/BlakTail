import { rawSqlClient } from "./db/client";
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
      return String(row.organisation_id);
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
    let id = existing ? String(existing.id) : crypto.randomUUID();
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
      await transaction`
        UPDATE membership
        SET status = ${input.active ? "active" : "suspended"}
        WHERE id = ${membership.id}
      `;
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

export async function setScimActive(
  organisationId: string,
  userId: string,
  active: boolean,
) {
  const [membership] = await rawSqlClient()`
    SELECT role FROM membership
    WHERE organisation_id = ${organisationId} AND user_id = ${userId}
    LIMIT 1
  `;
  if (!membership) throw new ScimError("User was not found.", 404);
  if (membership.role === "owner" && !active) {
    throw new ScimError("The organisation owner cannot be deactivated by SCIM.", 409);
  }
  if (membership.role !== "owner") {
    await rawSqlClient()`
      UPDATE membership
      SET status = ${active ? "active" : "suspended"}
      WHERE organisation_id = ${organisationId} AND user_id = ${userId}
    `;
    await rawSqlClient()`
      UPDATE person_login_identity
      SET status = ${active ? "active" : "suspended"},
          suspended_at = ${active ? null : new Date()}
      WHERE user_id = ${userId}
    `;
  }
  return getScimUser(organisationId, userId);
}
