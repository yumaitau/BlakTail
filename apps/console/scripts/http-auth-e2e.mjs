#!/usr/bin/env bun

import { SQL } from "bun";
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { hashPassword } from "better-auth/crypto";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import {
  claimBootstrap,
  initialiseBootstrap,
} from "./bootstrap.mjs";

const databaseUrl = process.env.TEST_DATABASE_URL;
if (!databaseUrl) throw new Error("TEST_DATABASE_URL is required");
const hmacSecret = "test-http-auth-hmac-secret-at-least-32-bytes";
const authSecret = "test-http-better-auth-secret-at-least-32-bytes";
const owner = {
  email: "owner.http@example.test",
  name: "HTTP Test Owner",
  password: "owner-http-test-password",
  organisation: "BlakPath HTTP Test",
};
const secondOwner = {
  id: "second-owner-http-e2e",
  email: "second-owner.http@example.test",
  name: "Second HTTP Test Owner",
  password: "second-owner-http-test-password",
  organisationId: "second-org-http-e2e",
  organisation: "Ranger Operations",
  coordOrgId: "22222222-2222-4222-8222-222222222222",
};
const linkedIdentity = {
  email: "blue.identity@example.test",
  name: "Blue Identity",
  password: "blue-identity-test-password",
  organisation: "Blue Network",
};
const migrationJournal = JSON.parse(
  await readFile(new URL("../drizzle/meta/_journal.json", import.meta.url), "utf8"),
);
const migrations = migrationJournal.entries.map(({ tag }) => `${tag}.sql`);

async function listen(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  return address.port;
}

async function close(server) {
  if (!server.listening) return;
  await new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
}

async function resetDatabase(sql) {
  await sql.unsafe("DROP SCHEMA public CASCADE; CREATE SCHEMA public");
  for (const migration of migrations) {
    const source = await readFile(
      new URL(`../drizzle/${migration}`, import.meta.url),
      "utf8",
    );
    for (const statement of source.split("--> statement-breakpoint")) {
      if (statement.trim()) await sql.unsafe(statement);
    }
  }
}

function cookies(response) {
  const values = response.headers.getSetCookie?.() ?? [];
  const source = values.length ? values : [response.headers.get("set-cookie") ?? ""];
  return source
    .filter(Boolean)
    .map((value) => value.split(";", 1)[0])
    .join("; ");
}

function cookieValue(cookieHeader, names) {
  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    const name = part.slice(0, separator).trim();
    if (names.includes(name)) return part.slice(separator + 1).trim();
  }
  return null;
}

async function jsonRequest(baseUrl, path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: options.method ?? "POST",
    headers: {
      origin: options.origin ?? baseUrl,
      "content-type": "application/json",
      ...(options.cookie ? { cookie: options.cookie } : {}),
      ...(options.bearer ? { authorization: `Bearer ${options.bearer}` } : {}),
      ...(options.organisationId
        ? { "x-blaktail-organisation": options.organisationId }
        : {}),
    },
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    redirect: "manual",
  });
  let body = null;
  try {
    body = await response.json();
  } catch {
    // Empty 204 responses are expected.
  }
  return { response, body };
}

async function waitForConsole(baseUrl, child, log) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`console exited early: ${log.value.slice(-2000)}`);
    }
    try {
      const response = await fetch(`${baseUrl}/sign-in`);
      if (response.status === 200) return;
    } catch {
      // Startup race.
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`console did not become ready: ${log.value.slice(-2000)}`);
}

async function stopChild(child) {
  if (child.exitCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, 5000)),
  ]);
  if (child.exitCode === null) child.kill("SIGKILL");
}

const sql = new SQL(databaseUrl, {
  max: 10,
  prepare: false,
});
const coordinatorNodes = new Map();
const coordinatorWgOnlyPeers = new Map();
const coordinatorMutations = [];
const coordinator = createServer(async (request, response) => {
  let raw = "";
  for await (const chunk of request) raw += chunk;
  if (request.url === "/v1/orgs") {
    const body = JSON.parse(raw);
    response.writeHead(202, { "content-type": "application/json" });
    response.end(JSON.stringify({ id: body.id, name: body.name }));
    return;
  }
  const commit = request.url?.match(
    /^\/v1\/orgs\/([^/]+)\/bootstrap-commit$/u,
  );
  if (commit) {
    response.writeHead(201, { "content-type": "application/json" });
    response.end(JSON.stringify({ id: commit[1], name: owner.organisation }));
    return;
  }
  const nodes = request.url?.match(/^\/v1\/orgs\/([^/]+)\/nodes$/u);
  if (nodes && request.method === "GET") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify(coordinatorNodes.get(nodes[1]) ?? []));
    return;
  }
  const wgOnlyList = request.url?.match(
    /^\/v1\/orgs\/([^/]+)\/wireguard-only-peers$/u,
  );
  if (wgOnlyList && request.method === "GET") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(
      JSON.stringify(coordinatorWgOnlyPeers.get(wgOnlyList[1]) ?? []),
    );
    return;
  }
  if (wgOnlyList && request.method === "POST") {
    const body = JSON.parse(raw);
    const peer = {
      id: `wg-only-${wgOnlyList[1]}-${Date.now()}`,
      name: body.name,
      kind: body.kind ?? "wireguard_only",
      wg_public_key: body.wg_public_key,
      endpoint: body.endpoint,
      allowed_ips: body.allowed_ips ?? [],
      tags: body.tags ?? [],
      created_at: Math.floor(Date.now() / 1000),
      expires_at: null,
      revoked_at: null,
      revision: 1,
    };
    const existing = coordinatorWgOnlyPeers.get(wgOnlyList[1]) ?? [];
    existing.push(peer);
    coordinatorWgOnlyPeers.set(wgOnlyList[1], existing);
    response.writeHead(201, { "content-type": "application/json" });
    response.end(JSON.stringify(peer));
    return;
  }
  const wgOnlyRotate = request.url?.match(
    /^\/v1\/orgs\/([^/]+)\/wireguard-only-peers\/([^/]+)\/rotate$/u,
  );
  if (wgOnlyRotate && request.method === "POST") {
    const body = JSON.parse(raw);
    const peers = coordinatorWgOnlyPeers.get(wgOnlyRotate[1]) ?? [];
    const peer = peers.find((candidate) => candidate.id === wgOnlyRotate[2]);
    if (!peer) {
      response.writeHead(404, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: "Unmanaged peer not found." }));
      return;
    }
    peer.previous_wg_public_key = peer.wg_public_key;
    peer.wg_public_key = body.wg_public_key;
    peer.overlap_until =
      Math.floor(Date.now() / 1000) + Number(body.overlap_seconds ?? 300);
    peer.revision += 1;
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify(peer));
    return;
  }
  const wgOnlyPeer = request.url?.match(
    /^\/v1\/orgs\/([^/]+)\/wireguard-only-peers\/([^/]+)$/u,
  );
  if (wgOnlyPeer && request.method === "DELETE") {
    const peers = coordinatorWgOnlyPeers.get(wgOnlyPeer[1]) ?? [];
    const peer = peers.find((candidate) => candidate.id === wgOnlyPeer[2]);
    if (!peer) {
      response.writeHead(404, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: "Unmanaged peer not found." }));
      return;
    }
    peer.revoked_at = Math.floor(Date.now() / 1000);
    response.writeHead(204);
    response.end();
    return;
  }
  const joinKeys = request.url?.match(
    /^\/v1\/orgs\/([^/]+)\/join-keys$/u,
  );
  if (joinKeys && request.method === "POST") {
    response.writeHead(201, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        id: `join-key-${joinKeys[1]}`,
        key: "btj_http-e2e-single-use",
        expires_at: Math.floor(Date.now() / 1000) + 600,
        single_use: true,
      }),
    );
    return;
  }
  const mutation = request.url?.match(
    /^\/v1\/orgs\/([^/]+)\/nodes\/([^/]+)(?:\/(friendly-name|routes))?$/u,
  );
  if (mutation) {
    const [, orgId, nodeId, suffix] = mutation;
    const orgNodes = coordinatorNodes.get(orgId) ?? [];
    const node = orgNodes.find((candidate) => candidate.id === nodeId);
    if (!node) {
      response.writeHead(404, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: "Node not found." }));
      return;
    }
    const body = raw ? JSON.parse(raw) : {};
    const operation =
      request.method === "DELETE"
        ? "revoke"
        : suffix === "friendly-name"
          ? "rename"
          : "approve-routes";
    if (operation === "revoke") node.revoked = true;
    if (operation === "rename") node.display_name = body.friendly_name || null;
    if (operation === "approve-routes") {
      node.approved_routes = body.approved_routes ?? [];
    }
    coordinatorMutations.push({ orgId, nodeId, operation });
    response.writeHead(204);
    response.end();
    return;
  }
  response.writeHead(404, { "content-type": "application/json" });
  response.end(JSON.stringify({ error: "Not found." }));
});
let consoleProcess;
const consoleLog = { value: "" };

try {
  await resetDatabase(sql);
  const coordinatorPort = await listen(coordinator);
  process.env.COORD_BASE_URL = `http://127.0.0.1:${coordinatorPort}`;
  process.env.BLAKTAIL_AUTH_HMAC_SECRET = hmacSecret;
  const bootstrapToken = "btb_http-e2e-token-never-written-to-database";
  await initialiseBootstrap(sql, { token: bootstrapToken, ttlSeconds: 600 });
  await claimBootstrap(sql, {
    token: bootstrapToken,
    password: owner.password,
    email: owner.email,
    ownerName: owner.name,
    organisationName: owner.organisation,
  });

  const linkedUserId = randomUUID();
  const linkedPersonId = randomUUID();
  const linkedOrganisationId = randomUUID();
  const linkedCoordinatorOrgId = randomUUID();
  const linkedMembershipId = randomUUID();
  const linkedPasswordHash = await hashPassword(linkedIdentity.password);
  await sql.begin("isolation level serializable", async (transaction) => {
    await transaction`
      INSERT INTO "user" (id, name, email, email_verified)
      VALUES (
        ${linkedUserId}, ${linkedIdentity.name}, ${linkedIdentity.email}, true
      )
    `;
    await transaction`
      INSERT INTO person (id, display_name)
      VALUES (${linkedPersonId}, ${linkedIdentity.name})
    `;
    await transaction`
      INSERT INTO person_login_identity (id, person_id, user_id)
      VALUES (${randomUUID()}, ${linkedPersonId}, ${linkedUserId})
    `;
    await transaction`
      INSERT INTO organisation (id, name, coord_org_id)
      VALUES (
        ${linkedOrganisationId}, ${linkedIdentity.organisation},
        ${linkedCoordinatorOrgId}
      )
    `;
    await transaction`
      INSERT INTO membership (id, organisation_id, user_id, role)
      VALUES (
        ${linkedMembershipId}, ${linkedOrganisationId}, ${linkedUserId}, 'owner'
      )
    `;
    await transaction`
      INSERT INTO network_account (
        id, membership_id, login_identity_user_id, organisation_id, name
      ) VALUES (
        ${randomUUID()}, ${linkedMembershipId}, ${linkedUserId},
        ${linkedOrganisationId}, ${linkedIdentity.organisation}
      )
    `;
    await transaction`
      INSERT INTO account (
        id, issuer, account_id, provider_id, user_id, password
      ) VALUES (
        ${randomUUID()}, 'local:credential', ${linkedUserId}, 'credential',
        ${linkedUserId}, ${linkedPasswordHash}
      )
    `;
  });

  const [ownerOrganisation] = await sql`
    SELECT id, coord_org_id FROM organisation WHERE name = ${owner.organisation}
  `;
  const ownerNodeId = randomUUID();
  const linkedNodeId = randomUUID();
  const credentialExpiry = Math.floor(Date.now() / 1000) + 86_400;
  const node = (id, name, route = null) => ({
    id,
    name,
    display_name: null,
    wg_public_key: `wg-${id}`,
    endpoint: null,
    allowed_ips: [],
    advertised_routes: route ? [route] : [],
    approved_routes: [],
    dns_name: `${name}.test`,
    user_id: "fixture-user",
    user_role: "owner",
    tags: [],
    created_at: Math.floor(Date.now() / 1000),
    credential_expires_at: credentialExpiry,
    expired: false,
    expires_soon: false,
    revoked: false,
  });
  coordinatorNodes.set(ownerOrganisation.coord_org_id, [
    node(ownerNodeId, "red-machine"),
  ]);
  coordinatorNodes.set(linkedCoordinatorOrgId, [
    node(linkedNodeId, "blue-machine", "10.24.0.0/24"),
  ]);

  const probe = createServer();
  const consolePort = await listen(probe);
  await close(probe);
  const baseUrl = `http://127.0.0.1:${consolePort}`;
  const nextBinary = new URL("../node_modules/next/dist/bin/next", import.meta.url);
  consoleProcess = spawn(process.execPath, [nextBinary.pathname, "start", "-H", "127.0.0.1", "-p", String(consolePort)], {
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
  });
  for (const stream of [consoleProcess.stdout, consoleProcess.stderr]) {
    stream.on("data", (chunk) => {
      consoleLog.value = (consoleLog.value + chunk.toString()).slice(-20_000);
    });
  }
  await waitForConsole(baseUrl, consoleProcess, consoleLog);

  const signup = await jsonRequest(baseUrl, "/api/auth/sign-up/email", {
    body: {
      email: "public.signup@example.test",
      name: "Public Signup",
      password: "public-signup-password",
    },
  });
  assert.equal(signup.response.status, 400);
  assert.match(JSON.stringify(signup.body), /EMAIL_PASSWORD_SIGN_UP_DISABLED|not enabled/u);

  const ownerSignIn = await jsonRequest(baseUrl, "/api/auth/sign-in/email", {
    body: { email: owner.email, password: owner.password },
  });
  assert.equal(ownerSignIn.response.status, 200, JSON.stringify(ownerSignIn.body));
  const ownerCookie = cookies(ownerSignIn.response);
  assert.match(ownerCookie, /better-auth\.session_token/u);

  const initialMe = await fetch(`${baseUrl}/api/me`, {
    headers: { cookie: ownerCookie },
  });
  const initialMeBody = await initialMe.json();
  assert.equal(initialMe.status, 200, JSON.stringify(initialMeBody));
  assert.equal(initialMeBody.organisations.length, 1);

  const linkCsrf = await jsonRequest(baseUrl, "/api/identity-links", {
    cookie: ownerCookie,
    origin: "https://attacker.example",
    body: { operation: "start" },
  });
  assert.equal(linkCsrf.response.status, 403);

  const sessionOnlyStart = await jsonRequest(baseUrl, "/api/identity-links", {
    cookie: ownerCookie,
    body: { operation: "start" },
  });
  assert.equal(sessionOnlyStart.response.status, 201);
  const sessionOnly = await jsonRequest(baseUrl, "/api/identity-links", {
    cookie: ownerCookie,
    body: {
      operation: "complete",
      challenge: sessionOnlyStart.body.challenge,
      currentPassword: "not-the-current-identity-password",
      email: linkedIdentity.email,
      password: linkedIdentity.password,
    },
  });
  assert.equal(sessionOnly.response.status, 400);

  const emailOnlyStart = await jsonRequest(baseUrl, "/api/identity-links", {
    cookie: ownerCookie,
    body: { operation: "start" },
  });
  assert.equal(emailOnlyStart.response.status, 201);
  const emailOnly = await jsonRequest(baseUrl, "/api/identity-links", {
    cookie: ownerCookie,
    body: {
      operation: "complete",
      challenge: emailOnlyStart.body.challenge,
      currentPassword: owner.password,
      email: linkedIdentity.email,
      password: "not-the-linked-identity-password",
    },
  });
  assert.equal(emailOnly.response.status, 400);

  const expiringLink = await jsonRequest(baseUrl, "/api/identity-links", {
    cookie: ownerCookie,
    body: { operation: "start" },
  });
  assert.equal(expiringLink.response.status, 201);
  const expiringChallengeHash = createHash("sha256")
    .update(expiringLink.body.challenge)
    .digest("hex");
  await sql`
    UPDATE identity_link_challenge
    SET expires_at = now() - interval '1 second'
    WHERE status = 'pending' AND token_hash = ${expiringChallengeHash}
  `;
  const expiredLink = await jsonRequest(baseUrl, "/api/identity-links", {
    cookie: ownerCookie,
    body: {
      operation: "complete",
      challenge: expiringLink.body.challenge,
      currentPassword: owner.password,
      email: linkedIdentity.email,
      password: linkedIdentity.password,
    },
  });
  assert.equal(expiredLink.response.status, 400);

  const staleSessionLink = await jsonRequest(baseUrl, "/api/identity-links", {
    cookie: ownerCookie,
    body: { operation: "start" },
  });
  assert.equal(staleSessionLink.response.status, 201);
  const refreshedOwnerSignIn = await jsonRequest(
    baseUrl,
    "/api/auth/sign-in/email",
    { body: { email: owner.email, password: owner.password } },
  );
  assert.equal(refreshedOwnerSignIn.response.status, 200);
  const staleSessionAttempt = await jsonRequest(
    baseUrl,
    "/api/identity-links",
    {
      cookie: cookies(refreshedOwnerSignIn.response),
      body: {
        operation: "complete",
        challenge: staleSessionLink.body.challenge,
        currentPassword: owner.password,
        email: linkedIdentity.email,
        password: linkedIdentity.password,
      },
    },
  );
  assert.equal(staleSessionAttempt.response.status, 400);

  const linkStart = await jsonRequest(baseUrl, "/api/identity-links", {
    cookie: ownerCookie,
    body: { operation: "start" },
  });
  assert.equal(linkStart.response.status, 201);
  const linkChallenge = linkStart.body.challenge;
  const linked = await jsonRequest(baseUrl, "/api/identity-links", {
    cookie: ownerCookie,
    body: {
      operation: "complete",
      challenge: linkChallenge,
      currentPassword: owner.password,
      email: linkedIdentity.email,
      password: linkedIdentity.password,
    },
  });
  assert.equal(linked.response.status, 200, JSON.stringify(linked.body));

  const linkedMe = await fetch(`${baseUrl}/api/me`, {
    headers: { cookie: ownerCookie },
  });
  assert.equal(linkedMe.status, 200);
  const linkedMeBody = await linkedMe.json();
  assert.deepEqual(
    linkedMeBody.organisations.map((organisation) => organisation.name).sort(),
    [linkedIdentity.organisation, owner.organisation].sort(),
  );
  const tokenMatch = ownerCookie.match(
    /(?:^|; )(?:__Secure-)?better-auth\.session_token=([^;]+)/u,
  );
  assert.ok(tokenMatch);
  const linkedDesktopMe = await fetch(`${baseUrl}/api/desktop/me`, {
    headers: { authorization: `Bearer ${decodeURIComponent(tokenMatch[1])}` },
  });
  assert.equal(linkedDesktopMe.status, 200);
  assert.equal((await linkedDesktopMe.json()).organisations.length, 2);

  const allDevices = await fetch(`${baseUrl}/api/devices`, {
    headers: { cookie: ownerCookie },
  });
  assert.equal(allDevices.status, 200);
  const allDeviceInventory = await allDevices.json();
  assert.deepEqual(allDeviceInventory.errors, []);
  const allDeviceRows = allDeviceInventory.devices;
  assert.deepEqual(
    allDeviceRows.map((device) => device.name).sort(),
    ["blue-machine", "red-machine"],
  );
  assert.deepEqual(
    allDeviceRows.map((device) => device.network_account_name).sort(),
    [linkedIdentity.organisation, owner.organisation].sort(),
  );

  const devicesPage = await fetch(`${baseUrl}/devices`, {
    headers: { cookie: ownerCookie },
  });
  const devicesHTML = await devicesPage.text();
  assert.equal(devicesPage.status, 200);
  assert.match(devicesHTML, /red-machine/u);
  assert.match(devicesHTML, /blue-machine/u);
  assert.match(devicesHTML, /Blue Network/u);
  assert.match(devicesHTML, /Unmanaged WireGuard peers/u);
  assert.match(devicesHTML, /wireguard_only/u);

  const emptyUnmanaged = await fetch(`${baseUrl}/api/wg-only-peers`, {
    headers: { cookie: ownerCookie },
  });
  assert.equal(emptyUnmanaged.status, 200);
  assert.deepEqual((await emptyUnmanaged.json()).peers, []);
  const createdUnmanaged = await jsonRequest(baseUrl, "/api/wg-only-peers", {
    cookie: ownerCookie,
    body: {
      organisationId: ownerOrganisation.id,
      name: "site-printer",
      wgPublicKey: "siteRouterPublicKeyExample+/=",
      endpoint: "203.0.113.10:51820",
      allowedIps: ["10.8.0.10/32"],
      tags: ["office"],
    },
  });
  assert.equal(
    createdUnmanaged.response.status,
    200,
    JSON.stringify(createdUnmanaged.body),
  );
  assert.equal(createdUnmanaged.body.kind, "wireguard_only");
  assert.equal(createdUnmanaged.body.name, "site-printer");
  const listedUnmanaged = await fetch(`${baseUrl}/api/wg-only-peers`, {
    headers: { cookie: ownerCookie },
  });
  const listedUnmanagedBody = await listedUnmanaged.json();
  assert.equal(listedUnmanaged.status, 200);
  assert.deepEqual(listedUnmanagedBody.errors, []);
  assert.equal(listedUnmanagedBody.peers.length, 1);
  assert.equal(listedUnmanagedBody.peers[0].kind, "wireguard_only");
  const unmanagedPage = await fetch(`${baseUrl}/devices`, {
    headers: { cookie: ownerCookie },
  });
  const unmanagedHTML = await unmanagedPage.text();
  assert.equal(unmanagedPage.status, 200);
  assert.match(unmanagedHTML, /site-printer/u);
  assert.match(unmanagedHTML, /Unmanaged/u);
  assert.match(unmanagedHTML, /Rotate/u);
  const rotatedUnmanaged = await jsonRequest(baseUrl, "/api/wg-only-peers", {
    cookie: ownerCookie,
    method: "PATCH",
    body: {
      organisationId: ownerOrganisation.id,
      peerId: createdUnmanaged.body.id,
      wgPublicKey: "rotatedRouterPublicKeyExample+/=",
      overlapSeconds: 300,
    },
  });
  assert.equal(
    rotatedUnmanaged.response.status,
    200,
    JSON.stringify(rotatedUnmanaged.body),
  );
  assert.equal(
    rotatedUnmanaged.body.wg_public_key,
    "rotatedRouterPublicKeyExample+/=",
  );
  assert.equal(
    rotatedUnmanaged.body.previous_wg_public_key,
    "siteRouterPublicKeyExample+/=",
  );

  const blueSettings = await fetch(`${baseUrl}/settings`, {
    headers: {
      cookie: `${ownerCookie}; blaktail.active_organisation=${linkedOrganisationId}`,
    },
  });
  assert.equal(blueSettings.status, 200);
  assert.match(await blueSettings.text(), /Blue Network/u);
  assert.equal(
    (blueSettings.headers.get("set-cookie") ?? "").includes(
      "better-auth.session_token",
    ),
    false,
  );
  const redSettings = await fetch(`${baseUrl}/settings`, {
    headers: {
      cookie: `${ownerCookie}; blaktail.active_organisation=${ownerOrganisation.id}`,
    },
  });
  assert.equal(redSettings.status, 200);
  assert.match(await redSettings.text(), /BlakPath HTTP Test/u);

  const renamed = await jsonRequest(baseUrl, "/api/devices", {
    method: "PATCH",
    cookie: ownerCookie,
    body: {
      operation: "rename",
      organisationId: ownerOrganisation.id,
      nodeId: ownerNodeId,
      friendlyName: "Red friendly machine",
    },
  });
  assert.equal(renamed.response.status, 204);
  const routesApproved = await jsonRequest(baseUrl, "/api/devices", {
    method: "PATCH",
    cookie: ownerCookie,
    body: {
      operation: "approve-routes",
      organisationId: linkedOrganisationId,
      nodeId: linkedNodeId,
      approvedRoutes: ["10.24.0.0/24"],
    },
  });
  assert.equal(routesApproved.response.status, 204);
  const crossTenantMutation = await jsonRequest(baseUrl, "/api/devices", {
    method: "PATCH",
    cookie: ownerCookie,
    body: {
      operation: "rename",
      organisationId: ownerOrganisation.id,
      nodeId: linkedNodeId,
      friendlyName: "Must not cross tenants",
    },
  });
  assert.equal(crossTenantMutation.response.status, 400);
  const nodeRevoked = await jsonRequest(baseUrl, "/api/devices", {
    method: "DELETE",
    cookie: ownerCookie,
    body: {
      organisationId: linkedOrganisationId,
      nodeId: linkedNodeId,
    },
  });
  assert.equal(nodeRevoked.response.status, 204);
  assert.deepEqual(coordinatorMutations, [
    { orgId: ownerOrganisation.coord_org_id, nodeId: ownerNodeId, operation: "rename" },
    { orgId: linkedCoordinatorOrgId, nodeId: linkedNodeId, operation: "approve-routes" },
    { orgId: linkedCoordinatorOrgId, nodeId: linkedNodeId, operation: "revoke" },
  ]);

  const linkReplay = await jsonRequest(baseUrl, "/api/identity-links", {
    cookie: ownerCookie,
    body: {
      operation: "complete",
      challenge: linkChallenge,
      currentPassword: owner.password,
      email: linkedIdentity.email,
      password: linkedIdentity.password,
    },
  });
  assert.equal(linkReplay.response.status, 400);

  const concurrentStarts = await Promise.all([
    jsonRequest(baseUrl, "/api/identity-links", {
      cookie: ownerCookie,
      body: { operation: "start" },
    }),
    jsonRequest(baseUrl, "/api/identity-links", {
      cookie: ownerCookie,
      body: { operation: "start" },
    }),
  ]);
  assert.deepEqual(
    concurrentStarts.map((result) => result.response.status).sort(),
    [201, 400],
  );
  const concurrentChallenge = concurrentStarts.find(
    (result) => result.response.status === 201,
  ).body.challenge;
  const alreadyOwned = await jsonRequest(baseUrl, "/api/identity-links", {
    cookie: ownerCookie,
    body: {
      operation: "complete",
      challenge: concurrentChallenge,
      currentPassword: owner.password,
      email: linkedIdentity.email,
      password: linkedIdentity.password,
    },
  });
  assert.equal(alreadyOwned.response.status, 400);

  const soleOwnerRevocation = await jsonRequest(baseUrl, "/api/identity-links", {
    method: "DELETE",
    cookie: ownerCookie,
    body: {
      operation: "revoke",
      identityUserId: linkedUserId,
      currentPassword: owner.password,
    },
  });
  assert.equal(soleOwnerRevocation.response.status, 400);

  const unlinked = await jsonRequest(baseUrl, "/api/identity-links", {
    method: "DELETE",
    cookie: ownerCookie,
    body: {
      operation: "unlink",
      identityUserId: linkedUserId,
      currentPassword: owner.password,
    },
  });
  assert.equal(unlinked.response.status, 204);
  const unlinkedMe = await fetch(`${baseUrl}/api/me`, {
    headers: { cookie: ownerCookie },
  });
  assert.equal((await unlinkedMe.json()).organisations.length, 1);

  const unlinkedDevices = await fetch(`${baseUrl}/api/devices`, {
    headers: { cookie: ownerCookie },
  });
  assert.equal(unlinkedDevices.status, 200);
  const unlinkedDeviceInventory = await unlinkedDevices.json();
  assert.deepEqual(
    unlinkedDeviceInventory.devices.map((device) => device.name),
    ["red-machine"],
  );
  const finalSignInUnlink = await jsonRequest(
    baseUrl,
    "/api/identity-links",
    {
      method: "DELETE",
      cookie: ownerCookie,
      body: {
        operation: "unlink",
        identityUserId: linkedMeBody.currentIdentity.userId,
        currentPassword: owner.password,
      },
    },
  );
  assert.equal(finalSignInUnlink.response.status, 400);

  const ownerContext = await fetch(`${baseUrl}/api/invitations`, {
    headers: { cookie: ownerCookie },
    redirect: "manual",
  });
  assert.equal(
    ownerContext.status,
    200,
    `owner context failed: ${await ownerContext.text()}`,
  );

  const crossOrigin = await jsonRequest(baseUrl, "/api/invitations", {
    cookie: ownerCookie,
    origin: "https://attacker.example",
    body: { email: "member@example.test", role: "member" },
  });
  assert.equal(crossOrigin.response.status, 403);

  const created = await jsonRequest(baseUrl, "/api/invitations", {
    cookie: ownerCookie,
    body: { email: "member@example.test", role: "member" },
  });
  assert.equal(
    created.response.status,
    201,
    `${JSON.stringify(created.body)}\n${consoleLog.value.slice(-3000)}`,
  );
  const invitationUrl = new URL(created.body.url);
  const invitationToken = invitationUrl.searchParams.get("token");
  assert.ok(invitationToken?.startsWith("bti_"));

  const invitationCannotLink = await jsonRequest(
    baseUrl,
    "/api/identity-links",
    {
      cookie: ownerCookie,
      body: {
        operation: "complete",
        challenge: invitationToken,
        currentPassword: owner.password,
        email: linkedIdentity.email,
        password: linkedIdentity.password,
      },
    },
  );
  assert.equal(invitationCannotLink.response.status, 400);

  const mismatch = await jsonRequest(baseUrl, "/api/invitations/accept", {
    body: {
      token: invitationToken,
      email: "different@example.test",
      name: "Wrong Recipient",
      password: "wrong-recipient-password",
    },
  });
  assert.equal(mismatch.response.status, 400);

  const accepted = await jsonRequest(baseUrl, "/api/invitations/accept", {
    body: {
      token: invitationToken,
      email: "member@example.test",
      name: "Invited Member",
      password: "invited-member-password",
    },
  });
  assert.equal(accepted.response.status, 201, JSON.stringify(accepted.body));
  const replay = await jsonRequest(baseUrl, "/api/invitations/accept", {
    body: {
      token: invitationToken,
      email: "member@example.test",
      name: "Invited Member",
      password: "invited-member-password",
    },
  });
  assert.equal(replay.response.status, 400);

  const memberSignIn = await jsonRequest(baseUrl, "/api/auth/sign-in/email", {
    body: {
      email: "member@example.test",
      password: "invited-member-password",
    },
  });
  assert.equal(memberSignIn.response.status, 200);
  const memberCookie = cookies(memberSignIn.response);
  const memberInvite = await jsonRequest(baseUrl, "/api/invitations", {
    cookie: memberCookie,
    body: { email: "forbidden@example.test", role: "member" },
  });
  assert.equal(memberInvite.response.status, 403);

  const secondOwnerPasswordHash = await hashPassword(secondOwner.password);
  await sql.begin(async (transaction) => {
    await transaction`
      INSERT INTO "user" (id, name, email, email_verified)
      VALUES (${secondOwner.id}, ${secondOwner.name}, ${secondOwner.email}, true)
    `;
    await transaction`
      INSERT INTO person (id, display_name)
      VALUES ('second-owner-person-http-e2e', ${secondOwner.name})
    `;
    await transaction`
      INSERT INTO person_login_identity (id, person_id, user_id)
      VALUES (
        'second-owner-identity-http-e2e',
        'second-owner-person-http-e2e', ${secondOwner.id}
      )
    `;
    await transaction`
      INSERT INTO account (
        id, issuer, account_id, provider_id, user_id, password
      ) VALUES (
        'second-owner-account-http-e2e', 'local:credential', ${secondOwner.id},
        'credential', ${secondOwner.id}, ${secondOwnerPasswordHash}
      )
    `;
    await transaction`
      INSERT INTO organisation (id, name, coord_org_id)
      VALUES (
        ${secondOwner.organisationId}, ${secondOwner.organisation},
        ${secondOwner.coordOrgId}
      )
    `;
    await transaction`
      INSERT INTO membership (id, organisation_id, user_id, role)
      VALUES (
        'second-owner-membership-http-e2e', ${secondOwner.organisationId},
        ${secondOwner.id}, 'owner'
      )
    `;
    await transaction`
      INSERT INTO network_account (
        id, membership_id, login_identity_user_id, organisation_id, name
      ) VALUES (
        'second-owner-network-http-e2e',
        'second-owner-membership-http-e2e', ${secondOwner.id},
        ${secondOwner.organisationId}, ${secondOwner.organisation}
      )
    `;
  });
  coordinatorNodes.set(secondOwner.coordOrgId, [
    node(`node-${secondOwner.coordOrgId}`, "ranger-field-laptop", "10.42.0.0/24"),
  ]);
  const secondOwnerSignIn = await jsonRequest(
    baseUrl,
    "/api/auth/sign-in/email",
    {
      body: {
        email: secondOwner.email,
        password: secondOwner.password,
      },
    },
  );
  assert.equal(secondOwnerSignIn.response.status, 200);
  const secondOwnerCookie = cookies(secondOwnerSignIn.response);
  const existingAccountInvitation = await jsonRequest(
    baseUrl,
    "/api/invitations",
    {
      cookie: secondOwnerCookie,
      body: { email: "member@example.test", role: "admin" },
    },
  );
  assert.equal(
    existingAccountInvitation.response.status,
    201,
    JSON.stringify(existingAccountInvitation.body),
  );
  const existingAccountToken = new URL(
    existingAccountInvitation.body.url,
  ).searchParams.get("token");
  const unauthenticatedExistingAcceptance = await jsonRequest(
    baseUrl,
    "/api/invitations/accept",
    {
      body: {
        token: existingAccountToken,
        email: "member@example.test",
        name: "Ignored Existing User",
        password: "ignored-existing-password",
      },
    },
  );
  assert.equal(unauthenticatedExistingAcceptance.response.status, 409);
  const existingAccountAcceptance = await jsonRequest(
    baseUrl,
    "/api/invitations/accept",
    {
      cookie: memberCookie,
      body: { token: existingAccountToken },
    },
  );
  assert.equal(
    existingAccountAcceptance.response.status,
    200,
    JSON.stringify(existingAccountAcceptance.body),
  );
  assert.equal(existingAccountAcceptance.body.accountCreated, false);
  const [membershipCount] = await sql`
    SELECT count(*)::int AS count FROM membership m
    JOIN "user" u ON u.id = m.user_id
    WHERE u.email = 'member@example.test'
  `;
  assert.equal(membershipCount.count, 2);

  const allNetworks = await fetch(`${baseUrl}/devices`, {
    headers: { cookie: memberCookie },
  });
  const allNetworksHtml = await allNetworks.text();
  assert.equal(allNetworks.status, 200, allNetworksHtml.slice(-2000));
  for (const visibleValue of [
    owner.organisation,
    secondOwner.organisation,
    "red-machine",
    "ranger-field-laptop",
  ]) {
    assert.ok(
      allNetworksHtml.includes(visibleValue),
      `all-networks inventory missing ${visibleValue}`,
    );
  }
  assert.match(allNetworksHtml, /Unmanaged WireGuard peers/u);
  assert.match(allNetworksHtml, /site-printer/u);
  assert.equal(allNetworksHtml.includes("Add unmanaged peer"), false);
  assert.equal(allNetworksHtml.includes("new public key"), false);
  const memberCreateUnmanaged = await jsonRequest(
    baseUrl,
    "/api/wg-only-peers",
    {
      cookie: memberCookie,
      body: {
        organisationId: ownerOrganisation.id,
        name: "member-router",
        wgPublicKey: "memberPublicKeyExample+/=",
        endpoint: "203.0.113.20:51820",
        allowedIps: ["10.8.0.20/32"],
      },
    },
  );
  assert.equal(memberCreateUnmanaged.response.status, 403);
  const revokedUnmanaged = await jsonRequest(baseUrl, "/api/wg-only-peers", {
    method: "DELETE",
    cookie: ownerCookie,
    body: {
      organisationId: ownerOrganisation.id,
      peerId: createdUnmanaged.body.id,
    },
  });
  assert.equal(revokedUnmanaged.response.status, 204);
  const afterRevoke = await fetch(`${baseUrl}/api/wg-only-peers`, {
    headers: { cookie: ownerCookie },
  });
  assert.equal((await afterRevoke.json()).peers[0].revoked_at !== null, true);

  const sessionCookieNames = [
    "better-auth.session_token",
    "__Secure-better-auth.session_token",
  ];
  const memberBearer = cookieValue(memberCookie, sessionCookieNames);
  const ownerBearer = cookieValue(ownerCookie, sessionCookieNames);
  assert.ok(memberBearer);
  assert.ok(ownerBearer);

  const cookieOnlyDesktopInventory = await fetch(
    `${baseUrl}/api/desktop/devices`,
    { headers: { cookie: memberCookie } },
  );
  assert.equal(cookieOnlyDesktopInventory.status, 401);

  const desktopMe = await jsonRequest(baseUrl, "/api/desktop/me", {
    method: "GET",
    bearer: memberBearer,
  });
  assert.equal(desktopMe.response.status, 200, JSON.stringify(desktopMe.body));
  assert.equal(desktopMe.body.organisations.length, 2);

  const desktopInventory = await jsonRequest(
    baseUrl,
    "/api/desktop/devices",
    { method: "GET", bearer: memberBearer },
  );
  assert.equal(
    desktopInventory.response.status,
    200,
    JSON.stringify(desktopInventory.body),
  );
  assert.equal(desktopInventory.body.devices.length, 2);
  assert.deepEqual(desktopInventory.body.errors, []);
  const memberNetworkDevice = desktopInventory.body.devices.find(
    (device) => device.organisation_name === owner.organisation,
  );
  const adminNetworkDevice = desktopInventory.body.devices.find(
    (device) => device.organisation_id === secondOwner.organisationId,
  );
  assert.ok(memberNetworkDevice);
  assert.ok(adminNetworkDevice);
  assert.equal(memberNetworkDevice.can_mutate, false);
  assert.equal(adminNetworkDevice.can_mutate, true);

  const deniedDesktopRename = await jsonRequest(
    baseUrl,
    `/api/desktop/devices/${memberNetworkDevice.id}`,
    {
      method: "PATCH",
      bearer: memberBearer,
      organisationId: memberNetworkDevice.organisation_id,
      body: { operation: "rename", friendlyName: "Not authorised" },
    },
  );
  assert.equal(deniedDesktopRename.response.status, 403);

  const crossNetworkDesktopRename = await jsonRequest(
    baseUrl,
    `/api/desktop/devices/${adminNetworkDevice.id}`,
    {
      method: "PATCH",
      bearer: ownerBearer,
      organisationId: secondOwner.organisationId,
      body: { operation: "rename", friendlyName: "Cross-network failure" },
    },
  );
  assert.equal(crossNetworkDesktopRename.response.status, 403);

  const desktopRename = await jsonRequest(
    baseUrl,
    `/api/desktop/devices/${adminNetworkDevice.id}`,
    {
      method: "PATCH",
      bearer: memberBearer,
      organisationId: secondOwner.organisationId,
      body: { operation: "rename", friendlyName: "Ranger MacBook" },
    },
  );
  assert.equal(desktopRename.response.status, 204);

  const desktopRoutes = await jsonRequest(
    baseUrl,
    `/api/desktop/devices/${adminNetworkDevice.id}`,
    {
      method: "PATCH",
      bearer: memberBearer,
      organisationId: secondOwner.organisationId,
      body: { operation: "routes", approvedRoutes: ["10.42.0.0/24"] },
    },
  );
  assert.equal(desktopRoutes.response.status, 204);

  const selectedNetworkJoin = await jsonRequest(
    baseUrl,
    "/api/desktop/join-key",
    {
      bearer: memberBearer,
      organisationId: secondOwner.organisationId,
      body: { expiresInSeconds: 600, singleUse: true, tags: [] },
    },
  );
  assert.equal(selectedNetworkJoin.response.status, 200);
  assert.equal(selectedNetworkJoin.body.key, "btj_http-e2e-single-use");

  const refreshedDesktopInventory = await jsonRequest(
    baseUrl,
    "/api/desktop/devices",
    { method: "GET", bearer: memberBearer },
  );
  const updatedAdminDevice = refreshedDesktopInventory.body.devices.find(
    (device) => device.organisation_id === secondOwner.organisationId,
  );
  assert.equal(updatedAdminDevice.display_name, "Ranger MacBook");
  assert.deepEqual(updatedAdminDevice.approved_routes, ["10.42.0.0/24"]);

  const desktopRevoke = await jsonRequest(
    baseUrl,
    `/api/desktop/devices/${adminNetworkDevice.id}`,
    {
      method: "DELETE",
      bearer: memberBearer,
      organisationId: secondOwner.organisationId,
    },
  );
  assert.equal(desktopRevoke.response.status, 204);

  const revokedDesktopInventory = await jsonRequest(
    baseUrl,
    "/api/desktop/devices",
    { method: "GET", bearer: memberBearer },
  );
  assert.equal(
    revokedDesktopInventory.body.devices.find(
      (device) => device.organisation_id === secondOwner.organisationId,
    ).revoked,
    true,
  );

  const switched = await jsonRequest(
    baseUrl,
    "/api/organisations/active",
    {
      cookie: memberCookie,
      body: { organisationId: secondOwner.organisationId },
    },
  );
  assert.equal(switched.response.status, 204);
  const switchedCookie = `${memberCookie}; ${cookies(switched.response)}`;
  const switchedSettings = await fetch(`${baseUrl}/settings`, {
    headers: { cookie: switchedCookie },
  });
  const switchedSettingsHtml = await switchedSettings.text();
  assert.equal(switchedSettings.status, 200);
  assert.ok(switchedSettingsHtml.includes(secondOwner.organisation));
  assert.ok(switchedSettingsHtml.includes("Accessible workspaces:"));
  const forbiddenSwitch = await jsonRequest(
    baseUrl,
    "/api/organisations/active",
    {
      cookie: memberCookie,
      body: { organisationId: "not-a-membership" },
    },
  );
  assert.equal(forbiddenSwitch.response.status, 403);

  const revokeCandidate = await jsonRequest(baseUrl, "/api/invitations", {
    cookie: ownerCookie,
    body: { email: "revoked@example.test", role: "admin" },
  });
  assert.equal(revokeCandidate.response.status, 201);
  const revokedToken = new URL(revokeCandidate.body.url).searchParams.get("token");
  const revoked = await jsonRequest(baseUrl, "/api/invitations", {
    method: "DELETE",
    cookie: ownerCookie,
    body: { invitationId: revokeCandidate.body.id },
  });
  assert.equal(revoked.response.status, 204);
  const revokedAcceptance = await jsonRequest(baseUrl, "/api/invitations/accept", {
    body: {
      token: revokedToken,
      email: "revoked@example.test",
      name: "Revoked Recipient",
      password: "revoked-recipient-password",
    },
  });
  assert.equal(revokedAcceptance.response.status, 400);

  const [memberUser] = await sql`SELECT id FROM "user" WHERE email = 'member@example.test'`;

  const blueBackupOwnerMembershipId = randomUUID();
  await sql`
    INSERT INTO membership (id, organisation_id, user_id, role)
    VALUES (
      ${blueBackupOwnerMembershipId}, ${linkedOrganisationId},
      ${memberUser.id}, 'owner'
    )
  `;
  await sql`
    INSERT INTO network_account (
      id, membership_id, login_identity_user_id, organisation_id, name
    ) VALUES (
      ${randomUUID()}, ${blueBackupOwnerMembershipId}, ${memberUser.id},
      ${linkedOrganisationId}, ${linkedIdentity.organisation}
    )
  `;

  const linkedSignIn = await jsonRequest(
    baseUrl,
    "/api/auth/sign-in/email",
    {
      body: {
        email: linkedIdentity.email,
        password: linkedIdentity.password,
      },
    },
  );
  assert.equal(linkedSignIn.response.status, 200);
  const linkedCookie = cookies(linkedSignIn.response);

  const relinkStart = await jsonRequest(baseUrl, "/api/identity-links", {
    cookie: ownerCookie,
    body: { operation: "start" },
  });
  assert.equal(relinkStart.response.status, 201);
  const relink = await jsonRequest(baseUrl, "/api/identity-links", {
    cookie: ownerCookie,
    body: {
      operation: "complete",
      challenge: relinkStart.body.challenge,
      currentPassword: owner.password,
      email: linkedIdentity.email,
      password: linkedIdentity.password,
    },
  });
  assert.equal(relink.response.status, 200);

  const identityRevoked = await jsonRequest(baseUrl, "/api/identity-links", {
    method: "DELETE",
    cookie: ownerCookie,
    body: {
      operation: "revoke",
      identityUserId: linkedUserId,
      currentPassword: owner.password,
    },
  });
  assert.equal(identityRevoked.response.status, 204);
  const revokedIdentitySession = await fetch(`${baseUrl}/api/me`, {
    headers: { cookie: linkedCookie },
  });
  assert.equal(revokedIdentitySession.status, 403);
  const afterIdentityRevocation = await fetch(`${baseUrl}/api/me`, {
    headers: { cookie: ownerCookie },
  });
  assert.equal((await afterIdentityRevocation.json()).organisations.length, 1);

  const identityRecovered = await jsonRequest(baseUrl, "/api/identity-links", {
    method: "DELETE",
    cookie: ownerCookie,
    body: {
      operation: "recover",
      identityUserId: linkedUserId,
      currentPassword: owner.password,
    },
  });
  assert.equal(identityRecovered.response.status, 204);
  const afterIdentityRecovery = await fetch(`${baseUrl}/api/me`, {
    headers: { cookie: ownerCookie },
  });
  assert.equal((await afterIdentityRecovery.json()).organisations.length, 2);

  const foreignGraphStart = await jsonRequest(
    baseUrl,
    "/api/identity-links",
    {
      cookie: memberCookie,
      body: { operation: "start" },
    },
  );
  assert.equal(foreignGraphStart.response.status, 201);
  const foreignGraphLink = await jsonRequest(
    baseUrl,
    "/api/identity-links",
    {
      cookie: memberCookie,
      body: {
        operation: "complete",
        challenge: foreignGraphStart.body.challenge,
        currentPassword: "invited-member-password",
        email: owner.email,
        password: owner.password,
      },
    },
  );
  assert.equal(foreignGraphLink.response.status, 400);

  const roleConflictStart = await jsonRequest(
    baseUrl,
    "/api/identity-links",
    {
      cookie: ownerCookie,
      body: { operation: "start" },
    },
  );
  assert.equal(roleConflictStart.response.status, 201);
  const roleConflict = await jsonRequest(baseUrl, "/api/identity-links", {
    cookie: ownerCookie,
    body: {
      operation: "complete",
      challenge: roleConflictStart.body.challenge,
      currentPassword: owner.password,
      email: "member@example.test",
      password: "invited-member-password",
    },
  });
  assert.equal(roleConflict.response.status, 202);
  assert.equal(roleConflict.body.ownerResolutionRequired, true);
  const [pendingConflict] = await sql`
    SELECT c.id
    FROM identity_link_conflict c
    JOIN identity_link_challenge ch ON ch.id = c.challenge_id
    WHERE ch.status = 'awaiting_owner'
  `;
  assert.ok(pendingConflict);
  const conflictResolution = await jsonRequest(
    baseUrl,
    "/api/identity-links",
    {
      cookie: ownerCookie,
      body: {
        operation: "resolve-role",
        conflictId: pendingConflict.id,
        resolvedRole: "owner",
      },
    },
  );
  assert.equal(conflictResolution.response.status, 200);
  assert.equal(conflictResolution.body.linked, true);
  const preservedRoles = await sql`
    SELECT role FROM membership
    WHERE organisation_id = ${ownerOrganisation.id}
    ORDER BY role
  `;
  assert.deepEqual(
    preservedRoles.map((membership) => membership.role),
    ["member", "owner"],
  );

  await sql`UPDATE session SET expires_at = timestamptz '1970-01-01 00:00:00+00' WHERE user_id = ${memberUser.id}`;
  const expiredSession = await fetch(`${baseUrl}/api/invitations`, {
    headers: { cookie: memberCookie },
    redirect: "manual",
  });
  assert.equal(expiredSession.status, 401);

  let rateLimited = false;
  for (let attempt = 0; attempt < 11; attempt += 1) {
    const response = await jsonRequest(baseUrl, "/api/invitations/accept", {
      body: {
        token: "bti_invalid-token-with-stable-rate-limit-key-000000000000",
        email: "unknown@example.test",
        name: "Unknown Recipient",
        password: "unknown-recipient-password",
      },
    });
    if (response.response.status === 429) rateLimited = true;
  }
  assert.equal(rateLimited, true);

  let signInRateLimited = false;
  for (let attempt = 0; attempt < 11; attempt += 1) {
    const response = await jsonRequest(baseUrl, "/api/auth/sign-in/email", {
      body: {
        email: "unknown-sign-in@example.test",
        password: "invalid-sign-in-password",
      },
    });
    if (response.response.status === 429) signInRateLimited = true;
  }
  assert.equal(signInRateLimited, true);

  const [scope] = await sql`
    SELECT i.organisation_id AS invitation_org, m.organisation_id AS member_org,
      m.role, i.status
    FROM invitation i JOIN "user" u ON u.email = i.email
    JOIN membership m
      ON m.user_id = u.id
      AND m.organisation_id = i.organisation_id
    WHERE i.email = 'member@example.test'
  `;
  assert.equal(scope.invitation_org, scope.member_org);
  assert.equal(scope.role, "member");
  assert.equal(scope.status, "accepted");

  const audit = await sql`SELECT action, result, details FROM console_audit_event ORDER BY created_at, id`;
  for (const action of [
    "bootstrap.completed",
    "invitation.created",
    "invitation.accepted",
    "invitation.revoked",
    "role.assigned",
    "identity_link.requested",
    "identity_link.succeeded",
    "identity_link.rejected",
    "identity_link.unlinked",
    "identity_link.revoked",
    "identity_link.recovered",
    "identity_link.role_conflict",
    "identity_link.role_conflict_resolved",
  ]) {
    assert.ok(audit.some((event) => event.action === action), `missing ${action}`);
  }
  assert.ok(audit.some((event) => event.result === "denied"));
  const evidence = JSON.stringify(audit) + consoleLog.value;
  for (const secret of [
    bootstrapToken,
    owner.password,
    invitationToken,
    "invited-member-password",
    linkedIdentity.password,
    linkChallenge,
    sessionOnlyStart.body.challenge,
    emailOnlyStart.body.challenge,
    relinkStart.body.challenge,
    expiringLink.body.challenge,
    staleSessionLink.body.challenge,
    concurrentChallenge,
    foreignGraphStart.body.challenge,
    roleConflictStart.body.challenge,
  ]) {
    assert.equal(evidence.includes(secret), false);
  }

  process.stdout.write(
    `${JSON.stringify({
      publicSignup: "disabled",
      csrf: "enforced",
      invitationReplay: "rejected",
      invitationRevocation: "enforced",
      existingAccountJoin: "same-session",
      allNetworksInventory: "two-workspaces",
      desktopEndpointManager: "multi-workspace-mutations-isolated",
      workspaceIsolation: "enforced",
      memberAuthorisation: "denied",
      identityLinkBothCredentials: "enforced",
      identityLinkReplay: "rejected",
      concurrentIdentityLink: "fail-closed",
      sameSessionNetworks: 2,
      identityRevocationRecovery: "enforced",
      linkExpiry: "rejected",
      staleLinkSession: "rejected",
      roleConflictOwnerDecision: "enforced",
      aggregateDevices: 2,
      owningOrganisationMutations: "isolated",
      sessionExpiry: "enforced",
      invitationRateLimit: "enforced",
      signInRateLimit: "enforced",
      audit: "redacted",
    })}\n`,
  );
} finally {
  if (consoleProcess) await stopChild(consoleProcess);
  await close(coordinator);
  await sql.close({ timeout: 5 });
}
