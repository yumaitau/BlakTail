#!/usr/bin/env bun

import { SQL } from "bun";
import {
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { chmod, readFile, stat, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { hashPassword } from "better-auth/crypto";

const STATE_ID = "primary";
const DEFAULT_TOKEN_TTL_SECONDS = 15 * 60;
const BOOTSTRAP_CLAIM_WINDOW_MILLISECONDS = 60 * 1000;
const BOOTSTRAP_CLAIM_MAXIMUM = 10;
const ASSERTION_TTL_SECONDS = 60;

function requiredEnvironment(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

export function hashSecret(value) {
  return createHash("sha256").update(value).digest("hex");
}

function secretMatches(value, expectedHash) {
  const actual = Buffer.from(hashSecret(value), "hex");
  const expected = Buffer.from(expectedHash, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function parseFlags(values) {
  const flags = new Map();
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    const value = values[index + 1];
    if (!name?.startsWith("--") || value === undefined || value.startsWith("--")) {
      throw new Error("flags must use --name value");
    }
    if (flags.has(name)) throw new Error(`duplicate flag: ${name}`);
    flags.set(name, value);
  }
  return flags;
}

function requiredFlag(flags, name) {
  const value = flags.get(name)?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function assertOnlyFlags(flags, allowed) {
  for (const name of flags.keys()) {
    if (!allowed.includes(name)) throw new Error(`unknown flag: ${name}`);
  }
}

async function readProtectedSecret(path, label) {
  const metadata = await stat(path);
  if (!metadata.isFile()) throw new Error(`${label} must reference a regular file`);
  if ((metadata.mode & 0o077) !== 0) {
    throw new Error(`${label} must not be readable or writable by group/other`);
  }
  const value = (await readFile(path, "utf8")).trim();
  if (!value) throw new Error(`${label} is empty`);
  return value;
}

function normaliseEmail(value) {
  const email = value.trim().toLowerCase();
  if (
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ) {
    throw new Error("--email must be a valid email address");
  }
  return email;
}

function boundedText(value, flag, maximum) {
  const text = value.trim();
  if (!text || [...text].length > maximum || /[\u0000-\u001f\u007f]/u.test(text)) {
    throw new Error(`${flag} must contain 1-${maximum} printable characters`);
  }
  return text;
}

function database() {
  return new SQL(requiredEnvironment("DATABASE_URL"), {
    max: 1,
    prepare: false,
  });
}

export function signServiceAssertion({
  organisationId,
  action,
  actorEmail = "",
  now = Math.floor(Date.now() / 1000),
  jti = randomUUID(),
  secret = requiredEnvironment("BLAKTAIL_AUTH_HMAC_SECRET"),
}) {
  if (Buffer.byteLength(secret) < 32) {
    throw new Error("BLAKTAIL_AUTH_HMAC_SECRET must be at least 32 bytes");
  }
  const payload = Buffer.from(
    JSON.stringify({
      sub: "operator-cli",
      org_id: organisationId,
      role: "service",
      name: "BlakTail operator",
      email: actorEmail,
      iss: "blaktail-console",
      aud: "blaktail-coord",
      iat: now,
      exp: now + ASSERTION_TTL_SECONDS,
      jti,
      action,
    }),
  ).toString("base64url");
  const signature = createHmac("sha256", secret)
    .update(payload)
    .digest("base64url");
  return `${payload}.${signature}`;
}

async function appendAudit(sql, event) {
  await sql`
    INSERT INTO console_audit_event (
      id, organisation_id, actor_user_id, actor_email, actor_role,
      source, action, result, target_type, target_id, details
    ) VALUES (
      ${randomUUID()}, ${event.organisationId ?? null},
      ${event.actorUserId ?? null}, ${event.actorEmail ?? ""},
      ${event.actorRole}, ${event.source}, ${event.action}, ${event.result},
      ${event.targetType}, ${event.targetId ?? null},
      CAST(${JSON.stringify(event.details ?? {})} AS jsonb)
    )
  `;
}

async function consumeBootstrapRateLimit(sql) {
  const currentTime = Date.now();
  const [row] = await sql`
    INSERT INTO rate_limit (id, key, count, last_request)
    VALUES (${randomUUID()}, 'bootstrap:claim', 1, ${currentTime})
    ON CONFLICT (key) DO UPDATE SET
      count = CASE
        WHEN ${currentTime} - rate_limit.last_request >= ${BOOTSTRAP_CLAIM_WINDOW_MILLISECONDS}
          THEN 1
        ELSE rate_limit.count + 1
      END,
      last_request = CASE
        WHEN ${currentTime} - rate_limit.last_request >= ${BOOTSTRAP_CLAIM_WINDOW_MILLISECONDS}
          THEN ${currentTime}
        ELSE rate_limit.last_request
      END
    RETURNING count
  `;
  if (row.count > BOOTSTRAP_CLAIM_MAXIMUM) {
    throw new Error("too many bootstrap claim attempts; try again later");
  }
}

export async function initialiseBootstrap(sql, options = {}) {
  const ttlSeconds = options.ttlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS;
  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 3600) {
    throw new Error("bootstrap token TTL must be between 60 and 3600 seconds");
  }
  const token = options.token ?? `btb_${randomBytes(32).toString("base64url")}`;
  const tokenHash = hashSecret(token);
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
  const outcome = await sql.begin("isolation level serializable", async (transaction) => {
    const [state] = await transaction`
      SELECT status, token_expires_at
      FROM bootstrap_state WHERE id = ${STATE_ID} FOR UPDATE
    `;
    if (!state) throw new Error("bootstrap migration has not run");
    if (state.status === "locked") throw new Error("bootstrap is already locked");
    if (state.status === "provisioning") {
      throw new Error("bootstrap claim is provisioning; run bootstrap status");
    }
    if (
      state.status === "claimable" &&
      state.token_expires_at &&
      new Date(state.token_expires_at).getTime() > Date.now()
    ) {
      throw new Error("an unexpired bootstrap credential already exists");
    }
    const [{ count: ownerCount }] = await transaction`
      SELECT count(*)::int AS count FROM membership WHERE role = 'owner'
    `;
    if (ownerCount !== 0) {
      await transaction`
        UPDATE bootstrap_state SET status = 'locked', token_hash = NULL,
          token_expires_at = NULL, provisioning_user_id = NULL,
          provisioning_organisation_id = NULL, provisioning_coord_org_id = NULL,
          provisioning_email = NULL, provisioning_owner_name = NULL,
          provisioning_organisation_name = NULL, locked_at = now(), updated_at = now()
        WHERE id = ${STATE_ID}
      `;
      return "existing_owner";
    }
    await transaction`
      UPDATE bootstrap_state SET status = 'claimable',
        token_hash = ${tokenHash}, token_expires_at = ${expiresAt.toISOString()},
        provisioning_user_id = NULL, provisioning_organisation_id = NULL,
        provisioning_coord_org_id = NULL, provisioning_email = NULL,
        provisioning_owner_name = NULL, provisioning_organisation_name = NULL,
        updated_at = now()
      WHERE id = ${STATE_ID}
    `;
    await appendAudit(transaction, {
      actorRole: "operator",
      source: "on_host_cli",
      action: "bootstrap.created",
      result: "success",
      targetType: "bootstrap",
      targetId: STATE_ID,
      details: { expires_at: expiresAt.toISOString() },
    });
    return "claimable";
  });
  if (outcome === "existing_owner") {
    throw new Error("existing owner detected; bootstrap locked");
  }
  return { token, expiresAt };
}

async function prepareClaim(sql, input) {
  return sql.begin("isolation level serializable", async (transaction) => {
    const [state] = await transaction`
      SELECT * FROM bootstrap_state WHERE id = ${STATE_ID} FOR UPDATE
    `;
    if (!state) throw new Error("bootstrap migration has not run");
    if (state.status === "locked") {
      throw new Error("bootstrap credential is consumed or invalid");
    }
    if (state.status === "uninitialised") {
      throw new Error("bootstrap has not been initialised on-host");
    }
    if (
      !state.token_hash ||
      !state.token_expires_at ||
      new Date(state.token_expires_at).getTime() <= Date.now() ||
      !secretMatches(input.token, state.token_hash)
    ) {
      throw new Error("bootstrap credential is consumed, expired, or invalid");
    }

    if (state.status === "provisioning") {
      if (
        !state.provisioning_user_id ||
        !state.provisioning_organisation_id ||
        !state.provisioning_coord_org_id ||
        state.provisioning_email !== input.email ||
        state.provisioning_owner_name !== input.ownerName ||
        state.provisioning_organisation_name !== input.organisationName
      ) {
        throw new Error("bootstrap provisioning data does not match; run bootstrap status");
      }
      return {
        userId: state.provisioning_user_id,
        organisationId: state.provisioning_organisation_id,
        coordOrgId: state.provisioning_coord_org_id,
      };
    }

    const userId = randomUUID();
    const organisationId = randomUUID();
    const coordOrgId = randomUUID();
    await transaction`
      UPDATE bootstrap_state SET status = 'provisioning',
        provisioning_user_id = ${userId},
        provisioning_organisation_id = ${organisationId},
        provisioning_coord_org_id = ${coordOrgId},
        provisioning_email = ${input.email},
        provisioning_owner_name = ${input.ownerName},
        provisioning_organisation_name = ${input.organisationName},
        updated_at = now()
      WHERE id = ${STATE_ID}
    `;
    await appendAudit(transaction, {
      actorUserId: userId,
      actorEmail: input.email,
      actorRole: "operator",
      source: "on_host_cli",
      action: "bootstrap.claim_started",
      result: "success",
      targetType: "bootstrap",
      targetId: STATE_ID,
      details: { organisation_id: organisationId, coord_org_id: coordOrgId },
    });
    return { userId, organisationId, coordOrgId };
  });
}

async function prepareCoordinator(input, prepared) {
  const baseUrl = requiredEnvironment("COORD_BASE_URL").replace(/\/$/u, "");
  if (!/^https:\/\//u.test(baseUrl) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/u.test(baseUrl)) {
    throw new Error("COORD_BASE_URL must use HTTPS outside localhost");
  }
  const assertion = signServiceAssertion({
    organisationId: prepared.coordOrgId,
    action: "bootstrap.prepare",
    actorEmail: input.email,
  });
  const response = await fetch(`${baseUrl}/v1/orgs`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${assertion}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      id: prepared.coordOrgId,
      name: input.organisationName,
      acl: { version: 1, defaults: "deny", rules: [] },
    }),
  });
  if (response.status !== 200 && response.status !== 202) {
    throw new Error(`coordinator bootstrap preparation failed with HTTP ${response.status}`);
  }
  const body = await response.json();
  if (body.id !== prepared.coordOrgId) {
    throw new Error("coordinator bootstrap returned a different organisation id");
  }
}

async function createOwnerCredential(sql, input, prepared, passwordHash) {
  await sql.begin("isolation level serializable", async (transaction) => {
    const [state] = await transaction`
      SELECT * FROM bootstrap_state WHERE id = ${STATE_ID} FOR UPDATE
    `;
    if (
      state?.status !== "provisioning" ||
      state.provisioning_user_id !== prepared.userId ||
      state.provisioning_organisation_id !== prepared.organisationId ||
      state.provisioning_coord_org_id !== prepared.coordOrgId ||
      !state.token_hash ||
      !state.token_expires_at ||
      new Date(state.token_expires_at).getTime() <= Date.now() ||
      !secretMatches(input.token, state.token_hash)
    ) {
      throw new Error("bootstrap credential is consumed or state changed");
    }
    const [{ count: existingCredentialCount }] = await transaction`
      SELECT count(*)::int AS count FROM account
      WHERE issuer = 'local:credential' AND account_id = ${prepared.userId}
        AND provider_id = 'credential' AND user_id = ${prepared.userId}
    `;
    if (existingCredentialCount === 1) {
      const [existingIdentity] = await transaction`
        SELECT u.email, u.name AS owner_name, o.name AS organisation_name,
          o.coord_org_id, m.role
        FROM "user" u
        JOIN membership m ON m.user_id = u.id
          AND m.organisation_id = ${prepared.organisationId}
        JOIN organisation o ON o.id = m.organisation_id
        WHERE u.id = ${prepared.userId}
      `;
      if (
        !existingIdentity ||
        existingIdentity.email !== input.email ||
        existingIdentity.owner_name !== input.ownerName ||
        existingIdentity.organisation_name !== input.organisationName ||
        existingIdentity.coord_org_id !== prepared.coordOrgId ||
        existingIdentity.role !== "owner"
      ) {
        throw new Error("bootstrap owner identity state is invalid");
      }
      return;
    }
    if (existingCredentialCount !== 0) {
      throw new Error("bootstrap owner credential state is invalid");
    }
    const membershipId = randomUUID();
    const networkAccountId = randomUUID();
    await transaction`
      INSERT INTO "user" (id, name, email, email_verified)
      VALUES (${prepared.userId}, ${input.ownerName}, ${input.email}, true)
    `;
    await transaction`
      INSERT INTO person (id, display_name)
      VALUES (${prepared.userId}, ${input.ownerName})
    `;
    await transaction`
      INSERT INTO person_login_identity (id, person_id, user_id)
      VALUES (${randomUUID()}, ${prepared.userId}, ${prepared.userId})
    `;
    await transaction`
      INSERT INTO organisation (id, name, coord_org_id)
      VALUES (${prepared.organisationId}, ${input.organisationName}, ${prepared.coordOrgId})
    `;
    await transaction`
      INSERT INTO membership (id, organisation_id, user_id, role)
      VALUES (${membershipId}, ${prepared.organisationId}, ${prepared.userId}, 'owner')
    `;
    await transaction`
      INSERT INTO network_account (
        id, membership_id, login_identity_user_id, organisation_id, name
      ) VALUES (
        ${networkAccountId}, ${membershipId}, ${prepared.userId},
        ${prepared.organisationId}, ${input.organisationName}
      )
    `;
    await transaction`
      INSERT INTO account (
        id, issuer, account_id, provider_id, user_id, password
      ) VALUES (
        ${randomUUID()}, 'local:credential', ${prepared.userId},
        'credential', ${prepared.userId}, ${passwordHash}
      )
    `;
  });
}

async function commitCoordinator(input, prepared) {
  const baseUrl = requiredEnvironment("COORD_BASE_URL").replace(/\/$/u, "");
  const assertion = signServiceAssertion({
    organisationId: prepared.coordOrgId,
    action: "bootstrap.commit",
    actorEmail: input.email,
  });
  const response = await fetch(
    `${baseUrl}/v1/orgs/${prepared.coordOrgId}/bootstrap-commit`,
    {
      method: "POST",
      headers: { authorization: `Bearer ${assertion}` },
    },
  );
  if (response.status !== 200 && response.status !== 201) {
    throw new Error(`coordinator bootstrap commit failed with HTTP ${response.status}`);
  }
  const body = await response.json();
  if (body.id !== prepared.coordOrgId) {
    throw new Error("coordinator bootstrap commit returned a different organisation id");
  }
}

async function finishClaim(sql, input, prepared) {
  await sql.begin("isolation level serializable", async (transaction) => {
    const [state] = await transaction`
      SELECT * FROM bootstrap_state WHERE id = ${STATE_ID} FOR UPDATE
    `;
    if (
      state?.status !== "provisioning" ||
      state.provisioning_user_id !== prepared.userId ||
      state.provisioning_organisation_id !== prepared.organisationId ||
      state.provisioning_coord_org_id !== prepared.coordOrgId ||
      !state.token_hash ||
      !secretMatches(input.token, state.token_hash)
    ) {
      throw new Error("bootstrap credential is consumed or state changed");
    }
    const [{ count: credentialCount }] = await transaction`
      SELECT count(*)::int AS count FROM account
      WHERE issuer = 'local:credential' AND account_id = ${prepared.userId}
    `;
    if (credentialCount !== 1) {
      throw new Error("bootstrap owner credential is not ready");
    }
    await transaction`
      UPDATE console_audit_event
      SET organisation_id = ${prepared.organisationId}
      WHERE organisation_id IS NULL AND target_id = ${STATE_ID}
        AND action IN ('bootstrap.created', 'bootstrap.claim_started')
    `;
    await transaction`
      UPDATE bootstrap_state SET status = 'locked', token_hash = NULL,
        token_expires_at = NULL, provisioning_user_id = NULL,
        provisioning_organisation_id = NULL, provisioning_coord_org_id = NULL,
        provisioning_email = NULL, provisioning_owner_name = NULL,
        provisioning_organisation_name = NULL, locked_at = now(), updated_at = now()
      WHERE id = ${STATE_ID}
    `;
    await appendAudit(transaction, {
      organisationId: prepared.organisationId,
      actorUserId: prepared.userId,
      actorEmail: input.email,
      actorRole: "owner",
      source: "on_host_cli",
      action: "bootstrap.completed",
      result: "success",
      targetType: "organisation",
      targetId: prepared.organisationId,
    });
  });
}

export async function claimBootstrap(sql, input) {
  const password = input.password;
  if (password.length < 10 || password.length > 128) {
    throw new Error("owner password must contain 10-128 characters");
  }
  await consumeBootstrapRateLimit(sql);
  const prepared = await prepareClaim(sql, input);
  const passwordHash = await hashPassword(password);
  await prepareCoordinator(input, prepared);
  await createOwnerCredential(sql, input, prepared, passwordHash);
  await commitCoordinator(input, prepared);
  await finishClaim(sql, input, prepared);
  return prepared;
}

export async function bootstrapStatus(sql) {
  const [state] = await sql`
    SELECT status, token_expires_at, locked_at,
      provisioning_user_id, provisioning_organisation_id,
      provisioning_coord_org_id
    FROM bootstrap_state WHERE id = ${STATE_ID}
  `;
  if (!state) throw new Error("bootstrap migration has not run");
  const orphaned = await sql`
    SELECT o.id, o.name, o.coord_org_id
    FROM organisation o
    WHERE NOT EXISTS (
      SELECT 1 FROM membership m
      WHERE m.organisation_id = o.id AND m.role = 'owner'
    ) ORDER BY o.created_at, o.id
  `;
  return {
    status: state.status,
    tokenExpiresAt: state.token_expires_at?.toISOString() ?? null,
    lockedAt: state.locked_at?.toISOString() ?? null,
    provisioning: state.provisioning_user_id
      ? {
          userId: state.provisioning_user_id,
          organisationId: state.provisioning_organisation_id,
          coordOrgId: state.provisioning_coord_org_id,
        }
      : null,
    orphanedOrganisations: orphaned,
  };
}

export async function recoverOwner(sql, input) {
  if (input.password.length < 10 || input.password.length > 128) {
    throw new Error("owner password must contain 10-128 characters");
  }
  const passwordHash = await hashPassword(input.password);
  return await sql.begin("isolation level serializable", async (transaction) => {
    const [state] = await transaction`
      SELECT status FROM bootstrap_state WHERE id = ${STATE_ID} FOR UPDATE
    `;
    if (state?.status !== "locked") throw new Error("bootstrap is not locked");
    const owners = await transaction`
      SELECT u.id, u.email, m.organisation_id
      FROM "user" u JOIN membership m ON m.user_id = u.id
      WHERE m.role = 'owner' ORDER BY u.id
    `;
    if (owners.length !== 1 || owners[0].email.toLowerCase() !== input.email) {
      throw new Error("owner recovery requires the exact sole owner email");
    }
    const owner = owners[0];
    await transaction`
      INSERT INTO account (id, issuer, account_id, provider_id, user_id, password)
      VALUES (${randomUUID()}, 'local:credential', ${owner.id}, 'credential', ${owner.id}, ${passwordHash})
      ON CONFLICT (issuer, account_id) DO UPDATE
      SET password = EXCLUDED.password, updated_at = now()
    `;
    // Whoever took the account may have bound their own identity-provider
    // login, enrolled their own TOTP, or signed in through a linked identity.
    // Recovery removes all three so the rotated password is the only way in.
    const linked = await transaction`
      SELECT other.user_id
      FROM person_login_identity mine
      JOIN person_login_identity other ON other.person_id = mine.person_id
      WHERE mine.user_id = ${owner.id}
    `;
    const linkedUserIds = [
      ...new Set([owner.id, ...linked.map((row) => row.user_id)]),
    ];
    let sessionsRevoked = 0;
    let pendingSsoLinks = 0;
    for (const userId of linkedUserIds) {
      const sessions = await transaction`
        DELETE FROM session WHERE user_id = ${userId} RETURNING id
      `;
      const pending = await transaction`
        DELETE FROM oidc_login_state WHERE link_user_id = ${userId} RETURNING id
      `;
      sessionsRevoked += sessions.length;
      pendingSsoLinks += pending.length;
    }
    const ssoBindings = await transaction`
      DELETE FROM external_identity WHERE user_id = ${owner.id}
      RETURNING id
    `;
    const ssoAccounts = await transaction`
      DELETE FROM account WHERE user_id = ${owner.id} AND provider_id = 'oidc'
      RETURNING id
    `;
    const twoFactor = await transaction`
      DELETE FROM two_factor WHERE user_id = ${owner.id} RETURNING id
    `;
    await transaction`
      UPDATE "user" SET two_factor_enabled = false, updated_at = now()
      WHERE id = ${owner.id}
    `;
    await appendAudit(transaction, {
      organisationId: owner.organisation_id,
      actorUserId: owner.id,
      actorEmail: owner.email,
      actorRole: "owner",
      source: "on_host_cli",
      action: "owner.recovered",
      result: "success",
      targetType: "user",
      targetId: owner.id,
      details: {
        sessions_revoked: true,
        sessions_revoked_count: sessionsRevoked,
        linked_identities_signed_out: linkedUserIds.length,
        sso_bindings_removed: ssoBindings.length,
        sso_accounts_removed: ssoAccounts.length,
        pending_sso_links_removed: pendingSsoLinks,
        two_factor_reset: true,
        two_factor_secrets_removed: twoFactor.length,
      },
    });
    return {
      sessionsRevoked,
      linkedIdentitiesSignedOut: linkedUserIds.length,
      ssoBindingsRemoved: ssoBindings.length,
      twoFactorSecretsRemoved: twoFactor.length,
    };
  });
}

async function runCommand(command, flags) {
  const sql = database();
  try {
    if (command === "init") {
      assertOnlyFlags(flags, ["--token-file", "--ttl-seconds"]);
      const ttlSeconds = flags.has("--ttl-seconds")
        ? Number(requiredFlag(flags, "--ttl-seconds"))
        : DEFAULT_TOKEN_TTL_SECONDS;
      const result = await initialiseBootstrap(sql, { ttlSeconds });
      const tokenFile = flags.get("--token-file");
      if (tokenFile) {
        await writeFile(tokenFile, `${result.token}\n`, { mode: 0o600, flag: "wx" });
        await chmod(tokenFile, 0o600);
        process.stdout.write(
          `${JSON.stringify({ status: "claimable", expiresAt: result.expiresAt.toISOString(), tokenFile })}\n`,
        );
      } else {
        process.stdout.write(
          `Bootstrap credential (shown once): ${result.token}\nExpires: ${result.expiresAt.toISOString()}\n`,
        );
      }
      return;
    }
    if (command === "claim") {
      assertOnlyFlags(flags, [
        "--token-file",
        "--password-file",
        "--email",
        "--name",
        "--organisation-name",
      ]);
      const input = {
        token: await readProtectedSecret(
          requiredFlag(flags, "--token-file"),
          "--token-file",
        ),
        password: await readProtectedSecret(
          requiredFlag(flags, "--password-file"),
          "--password-file",
        ),
        email: normaliseEmail(requiredFlag(flags, "--email")),
        ownerName: boundedText(requiredFlag(flags, "--name"), "--name", 128),
        organisationName: boundedText(
          requiredFlag(flags, "--organisation-name"),
          "--organisation-name",
          128,
        ),
      };
      const result = await claimBootstrap(sql, input);
      process.stdout.write(
        `${JSON.stringify({ status: "locked", organisationId: result.organisationId, coordOrgId: result.coordOrgId })}\n`,
      );
      return;
    }
    if (command === "status") {
      assertOnlyFlags(flags, []);
      process.stdout.write(`${JSON.stringify(await bootstrapStatus(sql), null, 2)}\n`);
      return;
    }
    if (command === "recover-owner") {
      assertOnlyFlags(flags, ["--email", "--password-file"]);
      const recovered = await recoverOwner(sql, {
        email: normaliseEmail(requiredFlag(flags, "--email")),
        password: await readProtectedSecret(
          requiredFlag(flags, "--password-file"),
          "--password-file",
        ),
      });
      process.stdout.write(
        `${JSON.stringify({ status: "owner_recovered", sessionsRevoked: true, ...recovered })}\n`,
      );
      return;
    }
    throw new Error("usage: bootstrap.mjs init|claim|status|recover-owner [flags]");
  } finally {
    await sql.close({ timeout: 5 });
  }
}

export async function main(argv = process.argv.slice(2)) {
  const [command, ...values] = argv;
  await runCommand(command, parseFlags(values));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`bootstrap failed: ${error instanceof Error ? error.message : "unknown error"}\n`);
    process.exitCode = 1;
  });
}
