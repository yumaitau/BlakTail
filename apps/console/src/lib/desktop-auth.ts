import "server-only";

import { randomUUID } from "node:crypto";
import type { Session } from "@/lib/auth";
import { rawSqlClient } from "@/lib/db/client";
import {
  codeExpiresAt,
  credentialExpiresAt,
  credentialUsable,
  DESKTOP_CODE_PREFIX,
  DESKTOP_CREDENTIAL_PREFIX,
  desktopBearer,
  hashDesktopSecret,
  newDesktopSecret,
  verifyS256,
  type AuthoriseRequest,
} from "@/lib/desktop-auth-core";
import {
  consoleContextFromSession,
  resolveSessionContext,
  type ConsoleContext,
  type PersonSessionContext,
} from "@/lib/session";

type CredentialRow = {
  credential_id: string;
  credential_expires_at: Date;
  revoked_at: Date | null;
  session_id: string;
  session_expires_at: Date;
  session_created_at: Date;
  session_updated_at: Date;
  session_auth_method: string | null;
  user_id: string;
  email: string;
  name: string;
  email_verified: boolean;
  image: string | null;
  two_factor_enabled: boolean;
  user_created_at: Date;
  user_updated_at: Date;
};

/**
 * Resolves a desktop credential (`btd_…`) from an Authorization Bearer header.
 * Browser session tokens are not accepted. The credential is live only while
 * it is unrevoked, unexpired, and the browser session that approved it still
 * exists; the returned session then goes through the same live identity,
 * suspension and role checks as a browser request.
 */
export async function sessionFromBearer(request: Request): Promise<Session | null> {
  const token = desktopBearer(request.headers.get("authorization"));
  if (!token) return null;
  const sql = rawSqlClient();
  const [row] = (await sql`
    SELECT d.id AS credential_id, d.expires_at AS credential_expires_at, d.revoked_at,
      s.id AS session_id, s.expires_at AS session_expires_at,
      s.created_at AS session_created_at, s.updated_at AS session_updated_at,
      s.auth_method AS session_auth_method,
      u.id AS user_id, u.email, u.name, u.email_verified, u.image,
      u.two_factor_enabled, u.created_at AS user_created_at, u.updated_at AS user_updated_at
    FROM desktop_credential d
    JOIN session s ON s.id = d.session_id AND s.user_id = d.user_id
    JOIN "user" u ON u.id = d.user_id
    WHERE d.token_hash = ${hashDesktopSecret(token)}
    LIMIT 1
  `) as unknown as CredentialRow[];
  if (!row) return null;
  const credentialExpires = new Date(row.credential_expires_at);
  const sessionExpires = new Date(row.session_expires_at);
  if (
    !credentialUsable(
      {
        revokedAt: row.revoked_at ? new Date(row.revoked_at) : null,
        expiresAt: credentialExpires,
        sessionExpiresAt: sessionExpires,
      },
      new Date(),
    )
  ) {
    return null;
  }
  await sql`
    UPDATE desktop_credential SET last_used_at = now()
    WHERE id = ${row.credential_id}
      AND (last_used_at IS NULL OR last_used_at < now() - interval '5 minutes')
  `;
  const expiresAt =
    credentialExpires.getTime() < sessionExpires.getTime() ? credentialExpires : sessionExpires;
  // Shaped like a Better Auth session so the shared context resolvers apply.
  // The session id is the approving browser session (step-up and identity-link
  // checks key on it); the token is never exposed here.
  return {
    session: {
      id: row.session_id,
      token: "",
      userId: row.user_id,
      expiresAt,
      createdAt: new Date(row.session_created_at),
      updatedAt: new Date(row.session_updated_at),
      ipAddress: null,
      userAgent: null,
      // The approving browser session's sign-in method, so privileged MFA
      // rules judge the desktop credential exactly as they judge that session.
      authMethod: row.session_auth_method,
    },
    user: {
      id: row.user_id,
      email: row.email,
      name: row.name,
      emailVerified: row.email_verified,
      image: row.image,
      twoFactorEnabled: row.two_factor_enabled,
      createdAt: new Date(row.user_created_at),
      updatedAt: new Date(row.user_updated_at),
    },
  } as unknown as Session;
}

/** Stores a hashed, 60-second, single-use code bound to the user, session and challenge. */
export async function issueDesktopCode(
  session: Session,
  request: AuthoriseRequest,
): Promise<string> {
  const { secret, hash } = newDesktopSecret(DESKTOP_CODE_PREFIX);
  const sql = rawSqlClient();
  await sql`DELETE FROM desktop_auth_code WHERE expires_at < now() - interval '1 hour'`;
  await sql`
    INSERT INTO desktop_auth_code
      (id, code_hash, user_id, session_id, code_challenge, redirect_uri, expires_at)
    VALUES (
      ${randomUUID()}, ${hash}, ${session.user.id}, ${session.session.id},
      ${request.codeChallenge}, ${request.redirectUri},
      ${codeExpiresAt(new Date()).toISOString()}
    )
  `;
  return secret;
}

export class DesktopTokenError extends Error {}

/**
 * Redeems a code once. The code is consumed before the verifier is checked,
 * so a wrong verifier burns it.
 */
export async function exchangeDesktopCode(
  code: unknown,
  verifier: unknown,
  redirectUri: string,
): Promise<{ token: string; expiresAt: Date }> {
  if (typeof code !== "string" || !code.startsWith(DESKTOP_CODE_PREFIX) || code.length > 100) {
    throw new DesktopTokenError("The sign-in code is invalid or has expired.");
  }
  const sql = rawSqlClient();
  const [row] = await sql`
    UPDATE desktop_auth_code SET used_at = now()
    WHERE code_hash = ${hashDesktopSecret(code)}
      AND used_at IS NULL
      AND expires_at > now()
    RETURNING user_id, session_id, code_challenge, redirect_uri
  `;
  if (
    !row ||
    String(row.redirect_uri) !== redirectUri ||
    !verifyS256(verifier, String(row.code_challenge))
  ) {
    throw new DesktopTokenError("The sign-in code is invalid or has expired.");
  }
  const [live] = await sql`
    SELECT 1 FROM session
    WHERE id = ${row.session_id} AND user_id = ${row.user_id} AND expires_at > now()
  `;
  if (!live) {
    throw new DesktopTokenError("The browser session that approved this sign-in has ended.");
  }
  const { secret, hash } = newDesktopSecret(DESKTOP_CREDENTIAL_PREFIX);
  const expiresAt = credentialExpiresAt(new Date());
  await sql`
    INSERT INTO desktop_credential (id, token_hash, user_id, session_id, expires_at)
    VALUES (
      ${randomUUID()}, ${hash}, ${row.user_id}, ${row.session_id}, ${expiresAt.toISOString()}
    )
  `;
  return { token: secret, expiresAt };
}

/** Revokes the presented desktop credential (app sign-out). */
export async function revokeDesktopCredential(request: Request): Promise<boolean> {
  const token = desktopBearer(request.headers.get("authorization"));
  if (!token) return false;
  const rows = await rawSqlClient()`
    UPDATE desktop_credential SET revoked_at = now()
    WHERE token_hash = ${hashDesktopSecret(token)} AND revoked_at IS NULL
    RETURNING id
  `;
  return rows.length > 0;
}

export async function requirePersonContextFromSession(
  session: Session,
): Promise<PersonSessionContext> {
  return resolveSessionContext(session);
}

export async function requireConsoleContextFromSession(
  session: Session,
  organisationId?: string,
): Promise<ConsoleContext> {
  return consoleContextFromSession(
    session,
    organisationId,
    organisationId !== undefined,
  );
}
