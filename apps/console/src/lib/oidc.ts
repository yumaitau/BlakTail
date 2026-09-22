import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { eq } from "drizzle-orm";
import { auth } from "./auth";
import { writeConsoleAudit } from "./console-audit";
import { db, rawSqlClient } from "./db/client";
import {
  identityProvider,
  membership,
  oidcLoginState,
  user,
} from "./db/schema";
import {
  OidcTokenError,
  emailDomainAllowed,
  findJwk,
  groupsAllowed,
  requireVerifiedEmail,
  signBetterAuthCookie,
  subjectAllowed,
  syntheticOidcEmail,
  verifySignedJwt,
  type JsonWebKey,
} from "./oidc-jwt";

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
    redirectTo: redirectTo.startsWith("/") ? redirectTo : "/devices",
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
  const tokens = (await tokenResponse.json()) as { id_token?: string };
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

export async function listMemberships(organisationId: string) {
  return db()
    .select({
      id: membership.id,
      userId: membership.userId,
      role: membership.role,
      status: membership.status,
      email: user.email,
      name: user.name,
    })
    .from(membership)
    .innerJoin(user, eq(membership.userId, user.id))
    .where(eq(membership.organisationId, organisationId));
}

export async function changeMembership(input: {
  organisationId: string;
  membershipId: string;
  role?: "admin" | "member";
  status?: "active" | "suspended" | "removed";
  actorUserId: string;
  actorEmail: string;
  actorRole: "owner" | "admin" | "member";
}): Promise<{ role: "owner" | "admin" | "member"; status: string }> {
  if (input.actorRole !== "owner") {
    throw new OidcError("Only owners can change membership.");
  }
  const [target] = await db()
    .select()
    .from(membership)
    .where(eq(membership.id, input.membershipId));
  if (!target || target.organisationId !== input.organisationId) {
    throw new OidcError("Membership was not found.");
  }
  if (target.role === "owner" && input.status && input.status !== "active") {
    const owners = await db()
      .select({ id: membership.id, role: membership.role, status: membership.status })
      .from(membership)
      .where(eq(membership.organisationId, input.organisationId));
    const activeOwners = owners.filter(
      (row) => row.role === "owner" && row.status === "active",
    ).length;
    if (activeOwners <= 1) {
      throw new OidcError("The last owner cannot be removed or suspended.");
    }
  }
  await db()
    .update(membership)
    .set({
      role: input.role ?? target.role,
      status: input.status ?? target.status,
    })
    .where(eq(membership.id, input.membershipId));
  const next = {
    role: input.role ?? target.role,
    status: input.status ?? target.status,
  };
  await writeConsoleAudit({
    organisationId: input.organisationId,
    actorUserId: input.actorUserId,
    actorEmail: input.actorEmail,
    actorRole: input.actorRole,
    source: "console",
    action: "membership.updated",
    result: "ok",
    targetType: "membership",
    targetId: input.membershipId,
    details: next,
  });
  return next;
}
