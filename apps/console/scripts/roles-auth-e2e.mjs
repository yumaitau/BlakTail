#!/usr/bin/env bun
// HTTP proof for roles, last-owner protection, step-up and TOTP against a
// real Postgres and a production build of the console. Needs
// TEST_DATABASE_URL (it drops and recreates the public schema) and a prior
// `bun run build`.

import { SQL } from "bun";
import assert from "node:assert/strict";
import { createHmac, randomUUID } from "node:crypto";
import { hashPassword } from "better-auth/crypto";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { claimBootstrap, initialiseBootstrap } from "./bootstrap.mjs";

const databaseUrl = process.env.TEST_DATABASE_URL;
if (!databaseUrl) throw new Error("TEST_DATABASE_URL is required");
const hmacSecret = "test-roles-auth-hmac-secret-at-least-32-bytes";
const authSecret = "test-roles-better-auth-secret-at-least-32-bytes";
const owner = {
  email: "owner.roles@example.test",
  name: "Roles Owner",
  password: "owner-roles-test-password",
  organisation: "Roles Test Organisation",
};
const colleague = {
  email: "colleague.roles@example.test",
  name: "Roles Colleague",
  password: "colleague-roles-test-password",
};

const journal = JSON.parse(
  await readFile(new URL("../drizzle/meta/_journal.json", import.meta.url), "utf8"),
);

async function resetDatabase(sql) {
  await sql.unsafe("DROP SCHEMA public CASCADE; CREATE SCHEMA public");
  for (const { tag } of journal.entries) {
    const source = await readFile(new URL(`../drizzle/${tag}.sql`, import.meta.url), "utf8");
    for (const statement of source.split("--> statement-breakpoint")) {
      if (statement.trim()) await sql.unsafe(statement);
    }
  }
}

async function listen(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return server.address().port;
}

function cookies(response) {
  return (response.headers.getSetCookie?.() ?? [])
    .map((value) => value.split(";", 1)[0])
    .filter((value) => !value.endsWith("="))
    .join("; ");
}

async function request(baseUrl, path, { method = "POST", cookie, body } = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      origin: baseUrl,
      "content-type": "application/json",
      ...(cookie ? { cookie } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "manual",
  });
  let json = null;
  try {
    json = await response.json();
  } catch {
    // 204
  }
  return { response, body: json };
}

function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of input.replace(/=+$/u, "").toUpperCase()) {
    const value = alphabet.indexOf(char);
    if (value < 0) throw new Error("bad base32");
    bits += value.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

function totp(secret, at = Date.now()) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30_000)));
  const digest = createHmac("sha1", secret).update(counter).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const code = (digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(code).padStart(6, "0");
}

async function stopChild(child) {
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, 5000)),
  ]);
  if (child.exitCode === null) child.kill("SIGKILL");
}

const sql = new SQL(databaseUrl, { max: 5, prepare: false });
const coordinatorWrites = [];
const coordinator = createServer(async (req, res) => {
  let raw = "";
  for await (const chunk of req) raw += chunk;
  if (req.url === "/v1/orgs") {
    const body = JSON.parse(raw);
    res.writeHead(202, { "content-type": "application/json" });
    res.end(JSON.stringify({ id: body.id, name: body.name }));
    return;
  }
  const commit = req.url?.match(/^\/v1\/orgs\/([^/]+)\/bootstrap-commit$/u);
  if (commit) {
    res.writeHead(201, { "content-type": "application/json" });
    res.end(JSON.stringify({ id: commit[1], name: owner.organisation }));
    return;
  }
  if (req.method !== "GET") coordinatorWrites.push(req.url);
  if (req.url?.endsWith("/webhooks/events")) {
    res.writeHead(202);
    res.end();
    return;
  }
  res.writeHead(204);
  res.end();
});

let consoleProcess;
const log = { value: "" };
const proof = {};

try {
  await resetDatabase(sql);
  const coordinatorPort = await listen(coordinator);
  process.env.COORD_BASE_URL = `http://127.0.0.1:${coordinatorPort}`;
  process.env.BLAKTAIL_AUTH_HMAC_SECRET = hmacSecret;
  const token = "btb_roles-e2e-token-never-written-to-database";
  await initialiseBootstrap(sql, { token, ttlSeconds: 600 });
  await claimBootstrap(sql, {
    token,
    password: owner.password,
    email: owner.email,
    ownerName: owner.name,
    organisationName: owner.organisation,
  });
  const [organisation] = await sql`SELECT id FROM organisation WHERE name = ${owner.organisation}`;
  const [ownerMembership] = await sql`
    SELECT m.id FROM membership m JOIN "user" u ON u.id = m.user_id WHERE u.email = ${owner.email}
  `;

  const colleagueId = randomUUID();
  const colleagueMembership = randomUUID();
  await sql.begin(async (tx) => {
    await tx`INSERT INTO "user" (id, name, email, email_verified) VALUES (${colleagueId}, ${colleague.name}, ${colleague.email}, true)`;
    await tx`INSERT INTO person (id, display_name) VALUES (${colleagueId}, ${colleague.name})`;
    await tx`INSERT INTO person_login_identity (id, person_id, user_id) VALUES (${randomUUID()}, ${colleagueId}, ${colleagueId})`;
    await tx`INSERT INTO membership (id, organisation_id, user_id, role) VALUES (${colleagueMembership}, ${organisation.id}, ${colleagueId}, 'member')`;
    await tx`INSERT INTO network_account (id, membership_id, login_identity_user_id, organisation_id, name) VALUES (${randomUUID()}, ${colleagueMembership}, ${colleagueId}, ${organisation.id}, ${owner.organisation})`;
    await tx`INSERT INTO account (id, issuer, account_id, provider_id, user_id, password) VALUES (${randomUUID()}, 'local:credential', ${colleagueId}, 'credential', ${colleagueId}, ${await hashPassword(colleague.password)})`;
  });

  const probe = createServer();
  const port = await listen(probe);
  await new Promise((resolve) => probe.close(resolve));
  const baseUrl = `http://127.0.0.1:${port}`;
  const nextBinary = new URL("../node_modules/next/dist/bin/next", import.meta.url);
  consoleProcess = spawn(
    process.execPath,
    [nextBinary.pathname, "start", "-H", "127.0.0.1", "-p", String(port)],
    {
      cwd: new URL("..", import.meta.url),
      env: {
        ...process.env,
        NODE_ENV: "production",
        DATABASE_URL: databaseUrl,
        BETTER_AUTH_SECRET: authSecret,
        BETTER_AUTH_URL: baseUrl,
        BETTER_AUTH_TRUSTED_ORIGINS: baseUrl,
        COORD_BASE_URL: process.env.COORD_BASE_URL,
        BLAKTAIL_AUTH_HMAC_SECRET: hmacSecret,
        NEXT_TELEMETRY_DISABLED: "1",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  for (const stream of [consoleProcess.stdout, consoleProcess.stderr]) {
    stream.on("data", (chunk) => {
      log.value = (log.value + chunk.toString()).slice(-20_000);
    });
  }
  const deadline = Date.now() + 30_000;
  for (;;) {
    if (consoleProcess.exitCode !== null) throw new Error(log.value);
    try {
      if ((await fetch(`${baseUrl}/sign-in`)).status === 200) break;
    } catch {
      // Starting.
    }
    if (Date.now() > deadline) throw new Error(`console not ready: ${log.value}`);
    await new Promise((resolve) => setTimeout(resolve, 200));
  }

  const signIn = async (who) => {
    const result = await request(baseUrl, "/api/auth/sign-in/email", {
      body: { email: who.email, password: who.password },
    });
    assert.equal(result.response.status, 200, JSON.stringify(result.body));
    return { cookie: cookies(result.response), body: result.body };
  };
  const patchMembership = (cookie, body) =>
    request(baseUrl, "/api/memberships", { method: "PATCH", cookie, body });
  const audits = (action) =>
    sql`SELECT result, details FROM console_audit_event WHERE action = ${action} ORDER BY created_at`;

  // Roles and last-owner protection.
  let ownerSession = await signIn(owner);
  const lastOwner = await patchMembership(ownerSession.cookie, {
    membershipId: ownerMembership.id,
    role: "admin",
  });
  assert.equal(lastOwner.response.status, 400, JSON.stringify(lastOwner.body));
  assert.match(lastOwner.body.error, /last active owner/u);
  const unknownRole = await patchMembership(ownerSession.cookie, {
    membershipId: colleagueMembership,
    role: "superuser",
  });
  assert.equal(unknownRole.response.status, 400);
  const promoted = await patchMembership(ownerSession.cookie, {
    membershipId: colleagueMembership,
    role: "network_admin",
  });
  assert.equal(promoted.response.status, 200, JSON.stringify(promoted.body));
  const [stored] = await sql`SELECT role FROM membership WHERE id = ${colleagueMembership}`;
  assert.equal(stored.role, "network_admin");
  const membershipAudit = await audits("membership.updated");
  assert.ok(membershipAudit.some((row) => row.result === "denied"));
  assert.ok(
    membershipAudit.some(
      (row) =>
        row.result === "ok" &&
        row.details.role === "network_admin" &&
        row.details.previous_role === "member",
    ),
  );
  proof.lastOwner = "refused-and-audited";
  proof.roleChange = "audited";

  // A network admin cannot change people.
  const colleagueSession = await signIn(colleague);
  const escalate = await patchMembership(colleagueSession.cookie, {
    membershipId: colleagueMembership,
    role: "owner",
  });
  assert.equal(escalate.response.status, 403, JSON.stringify(escalate.body));
  const me = await fetch(`${baseUrl}/api/me`, { headers: { cookie: colleagueSession.cookie } });
  assert.equal(me.status, 200);
  proof.networkAdminPeopleChange = "denied";

  // Step-up: an old session is refused for security changes; a fresh one is not.
  await sql`
    INSERT INTO organisation_sign_in_policy (organisation_id, step_up_max_age_minutes)
    VALUES (${organisation.id}, 5)
  `;
  await sql`
    UPDATE session SET created_at = now() - interval '30 minutes'
    WHERE user_id = (SELECT id FROM "user" WHERE email = ${owner.email})
  `;
  const stale = await patchMembership(ownerSession.cookie, {
    membershipId: colleagueMembership,
    role: "auditor",
  });
  assert.equal(stale.response.status, 403, JSON.stringify(stale.body));
  assert.match(stale.body.error, /sign-in within the last 5 minutes/u);
  assert.equal((await audits("auth.step_up_required")).length, 1);
  ownerSession = await signIn(owner);
  const fresh = await patchMembership(ownerSession.cookie, {
    membershipId: colleagueMembership,
    role: "auditor",
  });
  assert.equal(fresh.response.status, 200, JSON.stringify(fresh.body));
  proof.stepUp = "enforced";

  // TOTP enrolment and the sign-in challenge.
  const enable = await request(baseUrl, "/api/auth/two-factor/enable", {
    cookie: ownerSession.cookie,
    body: { password: owner.password },
  });
  assert.equal(enable.response.status, 200, JSON.stringify(enable.body));
  ownerSession = { cookie: cookies(enable.response) || ownerSession.cookie };
  const secret = base32Decode(new URL(enable.body.totpURI).searchParams.get("secret"));
  const backupCodes = enable.body.backupCodes;
  assert.ok(backupCodes.length >= 10);
  const confirm = await request(baseUrl, "/api/auth/two-factor/verify-totp", {
    cookie: ownerSession.cookie,
    body: { code: totp(secret) },
  });
  assert.equal(confirm.response.status, 200, JSON.stringify(confirm.body));
  const [enrolled] = await sql`SELECT two_factor_enabled FROM "user" WHERE email = ${owner.email}`;
  assert.equal(enrolled.two_factor_enabled, true);
  const [stored2fa] = await sql`SELECT secret, backup_codes FROM two_factor`;
  assert.ok(!stored2fa.secret.includes(enable.body.totpURI.split("secret=")[1]?.split("&")[0]));
  assert.ok(!stored2fa.backup_codes.includes(backupCodes[0]));

  const challenged = await request(baseUrl, "/api/auth/sign-in/email", {
    body: { email: owner.email, password: owner.password },
  });
  assert.equal(challenged.response.status, 200);
  assert.equal(challenged.body.twoFactorRedirect, true);
  const pendingCookie = cookies(challenged.response);
  assert.doesNotMatch(pendingCookie, /session_token=/u);
  const wrong = await request(baseUrl, "/api/auth/two-factor/verify-totp", {
    cookie: pendingCookie,
    body: { code: totp(secret) === "000000" ? "111111" : "000000" },
  });
  assert.notEqual(wrong.response.status, 200);
  const verified = await request(baseUrl, "/api/auth/two-factor/verify-totp", {
    cookie: pendingCookie,
    body: { code: totp(secret) },
  });
  assert.equal(verified.response.status, 200, JSON.stringify(verified.body));
  ownerSession = { cookie: cookies(verified.response) };
  assert.match(ownerSession.cookie, /session_token=/u);
  assert.equal(
    (await fetch(`${baseUrl}/api/me`, { headers: { cookie: ownerSession.cookie } })).status,
    200,
  );

  // Recovery code path: break-glass owner without the authenticator.
  const again = await request(baseUrl, "/api/auth/sign-in/email", {
    body: { email: owner.email, password: owner.password },
  });
  const recovered = await request(baseUrl, "/api/auth/two-factor/verify-backup-code", {
    cookie: cookies(again.response),
    body: { code: backupCodes[0] },
  });
  assert.equal(recovered.response.status, 200, JSON.stringify(recovered.body));
  const reused = await request(baseUrl, "/api/auth/sign-in/email", {
    body: { email: owner.email, password: owner.password },
  });
  const replay = await request(baseUrl, "/api/auth/two-factor/verify-backup-code", {
    cookie: cookies(reused.response),
    body: { code: backupCodes[0] },
  });
  assert.notEqual(replay.response.status, 200);
  ownerSession = { cookie: cookies(recovered.response) };
  proof.totp = "challenge-enforced";
  proof.recoveryCode = "single-use";

  // MFA policy: a privileged password identity without TOTP cannot write.
  await sql`
    UPDATE organisation_sign_in_policy SET require_mfa_for_privileged = true,
      step_up_max_age_minutes = NULL
    WHERE organisation_id = ${organisation.id}
  `;
  const toAdmin = await patchMembership(ownerSession.cookie, {
    membershipId: colleagueMembership,
    role: "admin",
  });
  assert.equal(toAdmin.response.status, 200, JSON.stringify(toAdmin.body));
  const adminSession = await signIn(colleague);
  const writesBefore = coordinatorWrites.length;
  const blockedWrite = await request(baseUrl, "/api/devices", {
    method: "PATCH",
    cookie: adminSession.cookie,
    body: {
      organisationId: organisation.id,
      nodeId: randomUUID(),
      operation: "rename",
      friendlyName: "x",
    },
  });
  assert.equal(blockedWrite.response.status, 400, JSON.stringify(blockedWrite.body));
  assert.match(blockedWrite.body.error, /two-step verification/u);
  assert.equal(coordinatorWrites.length, writesBefore);
  const ownerWrite = await request(baseUrl, "/api/devices", {
    method: "PATCH",
    cookie: ownerSession.cookie,
    body: {
      organisationId: organisation.id,
      nodeId: randomUUID(),
      operation: "rename",
      friendlyName: "x",
    },
  });
  assert.equal(ownerWrite.response.status, 204, JSON.stringify(ownerWrite.body));
  // The admin can still sign in and reach the console to enrol.
  assert.equal(
    (await fetch(`${baseUrl}/api/me`, { headers: { cookie: adminSession.cookie } })).status,
    200,
  );
  proof.mfaPolicy = "privileged-writes-blocked-sign-in-kept";

  console.log(JSON.stringify(proof));
} catch (error) {
  console.error(log.value.slice(-4000));
  throw error;
} finally {
  await stopChild(consoleProcess);
  await new Promise((resolve) => coordinator.close(resolve));
  await sql.close({ timeout: 5 });
}
