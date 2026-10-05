import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { and, eq } from "drizzle-orm";
import { auth } from "./auth";
import { getSignInPolicy, jitDomainCheck } from "./auth-policy";
import { linkFreshnessRefusal } from "./auth-policy-core";
import { writeConsoleAudit } from "./console-audit";
import { db, rawSqlClient } from "./db/client";
import { identityProvider, oidcLoginState } from "./db/schema";
import {
  OidcTokenError,
  emailDomainAllowed,
  findJwk,
  groupsAllowed,
  groupsFromClaims,
  mergeGroups,
  requireVerifiedEmail,
  signBetterAuthCookie,
  subjectAllowed,
  syntheticOidcEmail,
  verifySignedJwt,
  type JsonWebKey,
} from "./oidc-jwt";

import {
  isOrgRole,
  ownerChangeRefusal,
  permissionReason,
  type OrgRole,
} from "./roles";

export class OidcError extends Error {}

function base64url(buffer: Buffer): string {
  return buffer
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function secretKey(): Buffer {
  const secret = process.env.BETTER_AUTH_SECRET;
  if (!secret || Buffer.byteLength(secret) < 32) {
    throw new OidcError("BETTER_AUTH_SECRET must be at least 32 bytes.");
  }
  return createHash("sha256").update(secret).digest();
}

function sealSecret(plain: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", secretKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  return `enc:${iv.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}.${encrypted.toString("base64url")}`;
}

function openSecret(value: string): string {
  if (!value.startsWith("enc:")) {
    return value;
  }
  const [ivPart, tagPart, dataPart] = value.slice(4).split(".");
  if (!ivPart || !tagPart || !dataPart) {
    throw new OidcError("Stored identity-provider secret is corrupt.");
  }
  const decipher = createDecipheriv(
    "aes-256-gcm",
    secretKey(),
    Buffer.from(ivPart, "base64url"),
  );
  decipher.setAuthTag(Buffer.from(tagPart, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(dataPart, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}

function callbackUrl(): string {
  const base = process.env.BETTER_AUTH_URL ?? "http://localhost:3000";
  return `${base.replace(/\/$/, "")}/api/oidc/callback`;
}

export async function listIdentityProviders(organisationId: string) {
  const rows = await db()
    .select({
      id: identityProvider.id,
      issuer: identityProvider.issuer,
      clientId: identityProvider.clientId,
      enabled: identityProvider.enabled,
      jitMembership: identityProvider.jitMembership,
      defaultRole: identityProvider.defaultRole,
      allowDomainsJson: identityProvider.allowDomainsJson,
      allowGroupsJson: identityProvider.allowGroupsJson,
    })
    .from(identityProvider)
    .where(eq(identityProvider.organisationId, organisationId));
  return rows.map((row) => ({
    ...row,
    callbackUrl: callbackUrl(),
  }));
}

export async function upsertIdentityProvider(input: {
  organisationId: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  enabled: boolean;
  allowDomains: string[];
  allowGroups: string[];
  jitMembership: boolean;
  actorUserId: string;
  actorEmail: string;
}): Promise<void> {
  const issuer = new URL(input.issuer).origin;
  if (!issuer.startsWith("https://")) {
    throw new OidcError("Issuer must be an HTTPS origin.");
  }
  if (!input.clientId.trim() || input.clientSecret.trim().length < 16) {
    throw new OidcError("Client id and a 16+ character secret are required.");
  }
  const existing = await db()
    .select({ id: identityProvider.id })
    .from(identityProvider)
    .where(eq(identityProvider.organisationId, input.organisationId));
  const id = existing[0]?.id ?? crypto.randomUUID();
  await db()
    .insert(identityProvider)
    .values({
      id,
      organisationId: input.organisationId,
      issuer,
      clientId: input.clientId.trim(),
      clientSecret: sealSecret(input.clientSecret.trim()),
      enabled: input.enabled,
      allowDomainsJson: input.allowDomains,
      allowGroupsJson: input.allowGroups,
      jitMembership: input.jitMembership,
      defaultRole: "member",
    })
    .onConflictDoUpdate({
      target: [identityProvider.organisationId, identityProvider.issuer],
      set: {
        clientId: input.clientId.trim(),
        clientSecret: sealSecret(input.clientSecret.trim()),
        enabled: input.enabled,
        allowDomainsJson: input.allowDomains,
        allowGroupsJson: input.allowGroups,
        jitMembership: input.jitMembership,
        updatedAt: new Date(),
      },
    });
  await writeConsoleAudit({
    organisationId: input.organisationId,
    actorUserId: input.actorUserId,
    actorEmail: input.actorEmail,
    actorRole: "owner",
    source: "console",
    action: "oidc.provider_upserted",
    result: "ok",
    targetType: "identity_provider",
    targetId: id,
    details: { issuer, enabled: input.enabled },
  });
}

/**
 * Removes the organisation's identity provider. Linked single sign-on logins
 * and pending sign-in attempts go with it (cascade); people keep their
 * memberships and can be re-linked after a new provider is saved.
 */
export async function deleteIdentityProvider(input: {
  organisationId: string;
  providerId: string;
  actorUserId: string;
  actorEmail: string;
}): Promise<void> {
  const removed = await db()
    .delete(identityProvider)
    .where(
      and(
        eq(identityProvider.id, input.providerId),
        eq(identityProvider.organisationId, input.organisationId),
      ),
    )
    .returning({ issuer: identityProvider.issuer });
  if (removed.length === 0) {
    throw new OidcError("That identity provider was already removed.");
  }
  await writeConsoleAudit({
    organisationId: input.organisationId,
    actorUserId: input.actorUserId,
    actorEmail: input.actorEmail,
    actorRole: "owner",
    source: "console",
    action: "oidc.provider_deleted",
    result: "ok",
    targetType: "identity_provider",
    targetId: input.providerId,
    details: { issuer: removed[0]?.issuer },
  });
}

export async function startOidcLogin(organisationId: string, redirectTo: string) {
  const [provider] = await db()
    .select()
    .from(identityProvider)
    .where(eq(identityProvider.organisationId, organisationId));
  if (!provider?.enabled) {
    throw new OidcError("No enabled identity provider for this organisation.");
  }
  const metadata = await fetchOidcMetadata(provider.issuer);
  const verifier = base64url(randomBytes(32));
  const challenge = base64url(createHash("sha256").update(verifier).digest());
  const nonce = base64url(randomBytes(24));
  const state = crypto.randomUUID();
  await db().insert(oidcLoginState).values({
    id: state,
    organisationId,
    providerId: provider.id,
    codeVerifier: verifier,
    nonce,
    redirectTo: redirectTo.startsWith("/") ? redirectTo : "/control-center",
    expiresAt: new Date(Date.now() + 10 * 60 * 1000),
  });
  const url = new URL(metadata.authorization_endpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", provider.clientId);
  url.searchParams.set("redirect_uri", callbackUrl());
  url.searchParams.set("scope", "openid email profile groups");
  url.searchParams.set("state", state);
  url.searchParams.set("nonce", nonce);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

type OidcMetadata = {
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  issuer: string;
  userinfo_endpoint?: string;
};

async function fetchOidcMetadata(issuer: string): Promise<OidcMetadata> {
  const response = await fetch(
    `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`,
    { redirect: "error" },
  );
  if (!response.ok) {
    throw new OidcError("Could not load OpenID provider metadata.");
  }
  const metadata = (await response.json()) as OidcMetadata;
  if (
    metadata.issuer !== issuer ||
    !metadata.authorization_endpoint?.startsWith("https://") ||
    !metadata.token_endpoint?.startsWith("https://") ||
    !metadata.jwks_uri?.startsWith("https://")
  ) {
    throw new OidcError("Provider metadata issuer or endpoints are not trusted.");
  }
  return metadata;
}

async function fetchJwks(jwksUri: string): Promise<JsonWebKey[]> {
  const response = await fetch(jwksUri, { redirect: "error" });
  if (!response.ok) {
    throw new OidcError("Could not load provider signing keys.");
  }
  const body = (await response.json()) as { keys?: JsonWebKey[] };
  if (!Array.isArray(body.keys) || body.keys.length === 0) {
    throw new OidcError("Provider JWKS is empty.");
  }
  return body.keys;
}

export type CompletedOidcLogin = {
  userId: string;
  organisationId: string;
  redirectTo: string;
};

export async function completeOidcLogin(input: {
  state: string;
  code: string;
  linkingUserId?: string;
  linkingSessionCreatedAt?: Date;
}): Promise<CompletedOidcLogin> {
  const [login] = await db()
    .select()
    .from(oidcLoginState)
    .where(eq(oidcLoginState.id, input.state));
  if (!login || login.expiresAt.getTime() <= Date.now()) {
    throw new OidcError("Sign-in request expired. Start again.");
  }
  await db().delete(oidcLoginState).where(eq(oidcLoginState.id, input.state));
  const [provider] = await db()
    .select()
    .from(identityProvider)
    .where(eq(identityProvider.id, login.providerId));
  if (!provider?.enabled) {
    throw new OidcError("The identity provider is disabled.");
  }
  const metadata = await fetchOidcMetadata(provider.issuer);
  const tokenResponse = await fetch(metadata.token_endpoint, {
    method: "POST",
    redirect: "error",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: input.code,
      redirect_uri: callbackUrl(),
      client_id: provider.clientId,
      client_secret: openSecret(provider.clientSecret),
      code_verifier: login.codeVerifier,
    }),
  });
  if (!tokenResponse.ok) {
    throw new OidcError("The identity provider rejected the authorization code.");
  }
  const tokens = (await tokenResponse.json()) as {
    id_token?: string;
    access_token?: string;
  };
  if (!tokens.id_token) {
    throw new OidcError("The identity provider did not return an ID token.");
  }
  const parsed = (await import("./oidc-jwt")).parseJwt(tokens.id_token);
  const keys = await fetchJwks(metadata.jwks_uri);
  const key = findJwk(keys, parsed.header.kid, parsed.header.alg ?? "RS256");
  let claims;
  try {
    claims = verifySignedJwt(tokens.id_token, key, {
      issuer: provider.issuer,
      audience: provider.clientId,
      nonce: login.nonce,
    });
  } catch (error) {
    throw new OidcError(
      error instanceof OidcTokenError ? error.message : "ID token was rejected.",
    );
  }
  if (
    provider.allowGroupsJson.length > 0 &&
    groupsFromClaims(claims).length === 0 &&
    tokens.access_token &&
    metadata.userinfo_endpoint?.startsWith("https://")
  ) {
    const info = await fetch(metadata.userinfo_endpoint, {
      redirect: "error",
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    if (info.ok) {
      claims = mergeGroups(claims, await info.json());
    }
  }
  requireVerifiedEmail(claims, provider.allowDomainsJson);
  if (!emailDomainAllowed(claims.email, provider.allowDomainsJson)) {
    throw new OidcError("That email domain is not allowed for this organisation.");
  }
  if (!subjectAllowed(claims.sub, provider.allowSubjectsJson)) {
    throw new OidcError("That identity is not on the organisation allow-list.");
  }
  if (!groupsAllowed(claims, provider.allowGroupsJson)) {
    throw new OidcError(
      "That identity is not in an allowed organisation group.",
    );
  }
  const linkRefusal = input.linkingUserId
    ? linkFreshnessRefusal(
        await getSignInPolicy(login.organisationId),
        input.linkingSessionCreatedAt ?? new Date(0),
      )
    : null;
  const sql = rawSqlClient();
  const outcome = await sql.begin("isolation level serializable", async (transaction) => {
    const [bound] = await transaction`
      SELECT user_id FROM external_identity
      WHERE issuer = ${provider.issuer} AND subject = ${claims.sub}
      LIMIT 1
    `;
    let userId: string;
    if (bound) {
      if (input.linkingUserId && input.linkingUserId !== bound.user_id) {
        throw new OidcError(
          "This identity is already linked to a different account.",
        );
      }
      userId = bound.user_id;
    } else if (input.linkingUserId) {
      if (linkRefusal) throw new OidcError(linkRefusal);
      userId = input.linkingUserId;
      await transaction`
        INSERT INTO external_identity (
          id, organisation_id, provider_id, issuer, subject, user_id,
          email_snapshot, last_authenticated_at
        ) VALUES (
          ${crypto.randomUUID()}, ${login.organisationId}, ${provider.id},
          ${provider.issuer}, ${claims.sub}, ${userId},
          ${claims.email ?? null}, now()
        )
      `;
    } else {
      const email = claims.email?.trim().toLowerCase() || syntheticOidcEmail(provider.issuer, claims.sub);
      const [existingEmail] = await transaction`
        SELECT id FROM "user" WHERE lower(email) = ${email} LIMIT 1
      `;
      if (existingEmail) {
        throw new OidcError(
          "This email already has an account. Sign in with that account, then link this identity from Settings.",
        );
      }
      if (!provider.jitMembership) {
        throw new OidcError(
          "Just-in-time membership is disabled. Ask an owner to invite you.",
        );
      }
      const domainRefusal = await jitDomainCheck(
        transaction,
        login.organisationId,
        claims.email,
        claims.email_verified,
      );
      if (domainRefusal) {
        throw new OidcError(domainRefusal);
      }
      userId = crypto.randomUUID();
      const name = (claims.name || claims.email || "OIDC user").slice(0, 128);
      await transaction`
        INSERT INTO "user" (id, name, email, email_verified)
        VALUES (${userId}, ${name}, ${email}, ${claims.email_verified === true})
      `;
      await transaction`
        INSERT INTO account (
          id, issuer, account_id, provider_id, user_id
        ) VALUES (
          ${crypto.randomUUID()}, ${provider.issuer}, ${claims.sub},
          'oidc', ${userId}
        )
      `;
      await transaction`
        INSERT INTO person (id, display_name) VALUES (${userId}, ${name})
      `;
      await transaction`
        INSERT INTO person_login_identity (id, person_id, user_id)
        VALUES (${crypto.randomUUID()}, ${userId}, ${userId})
      `;
      const membershipId = crypto.randomUUID();
      await transaction`
        INSERT INTO membership (id, organisation_id, user_id, role, status)
        VALUES (
          ${membershipId}, ${login.organisationId}, ${userId},
          ${provider.defaultRole}, 'active'
        )
      `;
      await transaction`
        INSERT INTO network_account (
          id, membership_id, login_identity_user_id, organisation_id, name
        )
        SELECT ${crypto.randomUUID()}, ${membershipId}, ${userId}, o.id, o.name
        FROM organisation o WHERE o.id = ${login.organisationId}
      `;
      await transaction`
        INSERT INTO external_identity (
          id, organisation_id, provider_id, issuer, subject, user_id,
          email_snapshot, last_authenticated_at
        ) VALUES (
          ${crypto.randomUUID()}, ${login.organisationId}, ${provider.id},
          ${provider.issuer}, ${claims.sub}, ${userId},
          ${claims.email ?? null}, now()
        )
      `;
    }
    if (bound) {
      await transaction`
        UPDATE external_identity
        SET last_authenticated_at = now(), email_snapshot = ${claims.email ?? null}
        WHERE issuer = ${provider.issuer} AND subject = ${claims.sub}
      `;
    }
    const [member] = await transaction`
      SELECT id, status FROM membership
      WHERE organisation_id = ${login.organisationId} AND user_id = ${userId}
      LIMIT 1
    `;
    if (!member || member.status !== "active") {
      throw new OidcError(
        "This identity has no active membership in the organisation.",
      );
    }
    // Kept for directory group mapping previews; roles change only when an
    // owner applies a previewed mapping.
    await transaction`
      UPDATE membership
      SET idp_groups_json = CAST(${JSON.stringify(groupsFromClaims(claims).slice(0, 200))} AS jsonb),
        idp_groups_seen_at = now()
      WHERE id = ${member.id}
    `;
    return { userId };
  });
  await writeConsoleAudit({
    organisationId: login.organisationId,
    actorUserId: outcome.userId,
    actorEmail: claims.email ?? "",
    actorRole: "member",
    source: "oidc",
    action: "oidc.login",
    result: "ok",
    targetType: "external_identity",
    targetId: claims.sub,
    details: { issuer: provider.issuer, jit: !input.linkingUserId },
  });
  return {
    userId: outcome.userId,
    organisationId: login.organisationId,
    redirectTo: login.redirectTo,
  };
}

export async function establishConsoleSession(userId: string): Promise<{
  name: string;
  value: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: "lax";
  path: string;
  maxAge: number;
}> {
  const ctx = await auth.$context;
  const session = (await ctx.internalAdapter.createSession(userId)) as {
    token?: string;
  } | null;
  if (!session?.token) {
    throw new OidcError("Could not create a console session.");
  }
  const secret = process.env.BETTER_AUTH_SECRET;
  if (!secret) {
    throw new OidcError("BETTER_AUTH_SECRET is required.");
  }
  return {
    name: ctx.authCookies.sessionToken.name as string,
    value: signBetterAuthCookie(session.token, secret),
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 7,
  };
}

export async function listMemberships(organisationId: string): Promise<
  {
    id: string;
    userId: string;
    role: OrgRole;
    status: "invited" | "active" | "suspended" | "removed";
    email: string;
    name: string;
    hasPassword: boolean;
  }[]
> {
  const sql = rawSqlClient();
  const rows = await sql`
    SELECT m.id, m.user_id, m.role, m.status, u.email, u.name,
      EXISTS (
        SELECT 1 FROM account a
        WHERE a.user_id = m.user_id AND a.provider_id = 'credential'
          AND a.password IS NOT NULL
      ) AS has_password
    FROM membership m
    JOIN "user" u ON u.id = m.user_id
    WHERE m.organisation_id = ${organisationId}
    ORDER BY u.name, m.id
  `;
  return rows.map(
    (row: {
      id: string;
      user_id: string;
      role: OrgRole;
      status: "invited" | "active" | "suspended" | "removed";
      email: string;
      name: string;
      has_password: boolean;
    }) => ({
      id: row.id,
      userId: row.user_id,
      role: row.role,
      status: row.status,
      email: row.email,
      name: row.name,
      hasPassword: row.has_password === true,
    }),
  );
}

export async function changeMembership(input: {
  organisationId: string;
  membershipId: string;
  role?: OrgRole;
  status?: "active" | "suspended" | "removed";
  actorUserId: string;
  actorEmail: string;
  actorRole: OrgRole;
}): Promise<{ role: OrgRole; status: string; previousRole: OrgRole }> {
  const reason = permissionReason(input.actorRole, "manage_security");
  if (reason) {
    throw new OidcError(reason);
  }
  if (input.role !== undefined && !isOrgRole(input.role)) {
    throw new OidcError("Choose one of the listed roles.");
  }
  const audit = (result: string, details: Record<string, unknown>) =>
    writeConsoleAudit({
      organisationId: input.organisationId,
      actorUserId: input.actorUserId,
      actorEmail: input.actorEmail,
      actorRole: input.actorRole,
      source: "console",
      action: "membership.updated",
      result,
      targetType: "membership",
      targetId: input.membershipId,
      details,
    });
  const sql = rawSqlClient();
  // Serializable so two owners demoting each other cannot both pass the
  // last-owner check.
  const outcome = await sql.begin("isolation level serializable", async (transaction) => {
    const seats = (await transaction`
      SELECT m.id, m.role, m.status,
        EXISTS (
          SELECT 1 FROM account a
          WHERE a.user_id = m.user_id AND a.provider_id = 'credential'
            AND a.password IS NOT NULL
        ) AS has_password
      FROM membership m
      WHERE m.organisation_id = ${input.organisationId}
    `) as { id: string; role: OrgRole; status: string; has_password: boolean }[];
    const target = seats.find((seat) => seat.id === input.membershipId);
    if (!target) {
      return { error: "Membership was not found." } as const;
    }
    const next = {
      role: input.role ?? target.role,
      status: input.status ?? target.status,
    };
    const previous = { role: target.role, status: target.status };
    const refusal = ownerChangeRefusal(
      seats.map((seat) => ({
        membershipId: seat.id,
        role: seat.role,
        status: seat.status,
        hasPassword: seat.has_password === true,
      })),
      { membershipId: input.membershipId, role: input.role, status: input.status },
    );
    if (refusal) {
      return { error: refusal, previous, next } as const;
    }
    await transaction`
      UPDATE membership SET role = ${next.role}, status = ${next.status},
        role_source = CASE WHEN role = ${next.role} THEN role_source ELSE 'manual' END,
        deprovision_at = CASE WHEN ${next.status} = 'active' THEN NULL ELSE deprovision_at END,
        tombstoned_at = CASE WHEN ${next.status} = 'active' THEN NULL ELSE tombstoned_at END
      WHERE id = ${input.membershipId} AND organisation_id = ${input.organisationId}
    `;
    return { previous, next } as const;
  });
  if ("error" in outcome) {
    if ("next" in outcome) {
      await audit("denied", {
        previous: outcome.previous,
        requested: outcome.next,
        reason: outcome.error,
      });
    }
    throw new OidcError(outcome.error);
  }
  await audit("ok", {
    ...outcome.next,
    previous_role: outcome.previous.role,
    previous_status: outcome.previous.status,
  });
  return { ...outcome.next, previousRole: outcome.previous.role };
}
