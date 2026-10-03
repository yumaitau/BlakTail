#!/usr/bin/env bun
// Proof for SCIM Groups (RFC 7644 shape and bearer auth), directory group ->
// role mapping with drift preview/apply, and the deprovision grace period,
// against a real Postgres. Calls the App Router handlers directly. Needs
// TEST_DATABASE_URL (it drops and recreates the public schema). Run with
// `bun scripts/scim-groups-e2e.mjs`.

import { SQL, plugin } from "bun";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";

const databaseUrl = process.env.TEST_DATABASE_URL;
if (!databaseUrl) throw new Error("TEST_DATABASE_URL is required");
process.env.DATABASE_URL = databaseUrl;
process.env.BETTER_AUTH_SECRET ??= "test-scim-groups-better-auth-secret-32-bytes";
process.env.BLAKTAIL_AUTH_HMAC_SECRET ??= "test-scim-groups-hmac-secret-at-least-32-bytes";
process.env.COORD_BASE_URL ??= "http://127.0.0.1:9";

// The server modules import `server-only`, which throws outside Next.js.
plugin({
  name: "server-only-stub",
  setup(build) {
    build.module("server-only", () => ({ contents: "export {};", loader: "js" }));
  },
});

const journal = JSON.parse(
  await readFile(new URL("../drizzle/meta/_journal.json", import.meta.url), "utf8"),
);
const sql = new SQL(databaseUrl, { max: 2, prepare: false });

async function resetDatabase() {
  await sql.unsafe("DROP SCHEMA public CASCADE; CREATE SCHEMA public");
  for (const { tag } of journal.entries) {
    const source = await readFile(new URL(`../drizzle/${tag}.sql`, import.meta.url), "utf8");
    for (const statement of source.split("--> statement-breakpoint")) {
      if (statement.trim()) await sql.unsafe(statement);
    }
  }
}

const base = "https://console.example.test/api/scim/v2";

function req(path, { method = "GET", token, body } = {}) {
  return new Request(`${base}${path}`, {
    method,
    headers: {
      "content-type": "application/scim+json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

const params = (id) => ({ params: Promise.resolve({ id }) });

async function json(response) {
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}

await resetDatabase();
const { hashScimToken, newScimToken } = await import("../src/lib/scim-core.ts");
const groups = await import("../src/app/api/scim/v2/Groups/route.ts");
const group = await import("../src/app/api/scim/v2/Groups/[id]/route.ts");
const users = await import("../src/app/api/scim/v2/Users/route.ts");
const user = await import("../src/app/api/scim/v2/Users/[id]/route.ts");
const mapping = await import("../src/lib/directory-mapping.ts");

try {
  const org = { id: randomUUID(), coord_org_id: randomUUID() };
  const owner = { user_id: randomUUID(), membership_id: randomUUID() };
  await sql.begin(async (tx) => {
    await tx`INSERT INTO organisation (id, name, coord_org_id) VALUES (${org.id}, 'SCIM Groups Org', ${org.coord_org_id})`;
    await tx`INSERT INTO "user" (id, name, email, email_verified) VALUES (${owner.user_id}, 'SCIM Owner', 'owner.scim@example.test', true)`;
    await tx`INSERT INTO person (id, display_name) VALUES (${owner.user_id}, 'SCIM Owner')`;
    await tx`INSERT INTO person_login_identity (id, person_id, user_id) VALUES (${randomUUID()}, ${owner.user_id}, ${owner.user_id})`;
    await tx`INSERT INTO membership (id, organisation_id, user_id, role) VALUES (${owner.membership_id}, ${org.id}, ${owner.user_id}, 'owner')`;
    await tx`INSERT INTO network_account (id, membership_id, login_identity_user_id, organisation_id, name) VALUES (${randomUUID()}, ${owner.membership_id}, ${owner.user_id}, ${org.id}, 'SCIM Groups Org')`;
    await tx`INSERT INTO account (id, issuer, account_id, provider_id, user_id, password) VALUES (${randomUUID()}, 'local:credential', ${owner.user_id}, 'credential', ${owner.user_id}, 'not-a-real-hash')`;
  });
  const otherOrgId = randomUUID();
  await sql`INSERT INTO organisation (id, name, coord_org_id) VALUES (${otherOrgId}, 'Other Org', ${randomUUID()})`;

  const minted = newScimToken();
  const other = newScimToken();
  await sql`INSERT INTO scim_token (id, organisation_id, token_hash, label) VALUES (${randomUUID()}, ${org.id}, ${minted.hash}, 'e2e')`;
  await sql`INSERT INTO scim_token (id, organisation_id, token_hash, label) VALUES (${randomUUID()}, ${otherOrgId}, ${other.hash}, 'e2e')`;
  assert.notEqual(minted.hash, hashScimToken(other.token));

  // Auth: missing, malformed and unknown tokens are refused with SCIM errors.
  for (const token of [undefined, "not-a-scim-token", "bts_unknown"]) {
    const response = await groups.GET(req("/Groups", { token }));
    assert.equal(response.status, 401);
    const body = await json(response);
    assert.deepEqual(body.schemas, ["urn:ietf:params:scim:api:messages:2.0:Error"]);
    assert.equal(body.status, "401");
  }

  // Provision two people and one in the other organisation.
  const provision = async (token, email) => {
    const response = await users.POST(
      req("/Users", { method: "POST", token, body: { userName: email, displayName: email } }),
    );
    assert.equal(response.status, 201);
    return (await json(response)).id;
  };
  const ranger = await provision(minted.token, "ranger@example.test");
  const admin = await provision(minted.token, "lead@example.test");
  const outsider = await provision(other.token, "outsider@example.test");

  // Create: RFC 7643 Group shape.
  const created = await groups.POST(
    req("/Groups", {
      method: "POST",
      token: minted.token,
      body: {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        displayName: "BlakTail Admins",
        externalId: "entra-group-1",
        members: [{ value: ranger }],
      },
    }),
  );
  assert.equal(created.status, 201);
  const resource = await json(created);
  assert.deepEqual(resource.schemas, ["urn:ietf:params:scim:schemas:core:2.0:Group"]);
  assert.equal(resource.displayName, "BlakTail Admins");
  assert.equal(resource.externalId, "entra-group-1");
  assert.equal(resource.meta.resourceType, "Group");
  assert.deepEqual(resource.members.map((m) => m.value), [ranger]);

  // Duplicate name, unknown member and cross-organisation member are refused.
  const duplicate = await groups.POST(
    req("/Groups", { method: "POST", token: minted.token, body: { displayName: "blaktail admins" } }),
  );
  assert.equal(duplicate.status, 409);
  const foreign = await groups.POST(
    req("/Groups", {
      method: "POST",
      token: minted.token,
      body: { displayName: "Mixed", members: [{ value: outsider }] },
    }),
  );
  assert.equal(foreign.status, 400);

  // Another organisation's token cannot read or change the group.
  assert.equal((await group.GET(req(`/Groups/${resource.id}`, { token: other.token }), params(resource.id))).status, 404);
  assert.equal(
    (
      await group.PATCH(
        req(`/Groups/${resource.id}`, {
          method: "PATCH",
          token: other.token,
          body: { Operations: [{ op: "add", path: "members", value: [{ value: outsider }] }] },
        }),
        params(resource.id),
      )
    ).status,
    404,
  );
  const otherList = await json(await groups.GET(req("/Groups", { token: other.token })));
  assert.equal(otherList.totalResults, 0);

  // List with filter.
  const listed = await json(
    await groups.GET(req(`/Groups?filter=${encodeURIComponent('displayName eq "BlakTail Admins"')}`, { token: minted.token })),
  );
  assert.deepEqual(listed.schemas, ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]);
  assert.equal(listed.totalResults, 1);
  assert.equal((await groups.GET(req(`/Groups?filter=${encodeURIComponent('displayName co "x"')}`, { token: minted.token }))).status, 400);

  // Entra-style PATCH: add lead, remove ranger.
  const patched = await group.PATCH(
    req(`/Groups/${resource.id}`, {
      method: "PATCH",
      token: minted.token,
      body: {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [
          { op: "Add", path: "members", value: [{ value: admin }] },
          { op: "Remove", path: `members[value eq "${ranger}"]` },
        ],
      },
    }),
    params(resource.id),
  );
  assert.equal(patched.status, 200);
  assert.deepEqual((await json(patched)).members.map((m) => m.value), [admin]);
  assert.equal(
    (
      await group.PATCH(
        req(`/Groups/${resource.id}`, {
          method: "PATCH",
          token: minted.token,
          body: { Operations: [{ op: "move", path: "members" }] },
        }),
        params(resource.id),
      )
    ).status,
    400,
  );

  // Group membership alone changes no role.
  const roleOf = async (userId) =>
    (await sql`SELECT role, status, role_source, deprovision_at, tombstoned_at FROM membership WHERE organisation_id = ${org.id} AND user_id = ${userId}`)[0];
  assert.equal((await roleOf(admin)).role, "member");

  // Owner mapping refused by default; admin mapping previewed then applied.
  const ctx = {
    organisationId: org.id,
    organisationName: "SCIM Groups Org",
    coordOrgId: org.coord_org_id,
    userId: owner.user_id,
    personId: owner.user_id,
    email: "owner.scim@example.test",
    name: "SCIM Owner",
    role: "owner",
    sessionId: randomUUID(),
    sessionCreatedAt: new Date(),
    sessionExpiresAt: new Date(Date.now() + 3_600_000),
  };
  await assert.rejects(
    mapping.addGroupMapping(ctx, { source: "scim", groupName: "BlakTail Admins", role: "owner" }),
    /cannot grant owner/,
  );
  await assert.rejects(
    mapping.addGroupMapping({ ...ctx, role: "admin" }, { source: "scim", groupName: "x", role: "member" }),
    /cannot change people/,
  );
  await mapping.addGroupMapping(ctx, { source: "scim", groupName: "BlakTail Admins", role: "admin" });
  const preview = await mapping.previewDirectoryDrift(ctx);
  assert.equal(preview.changes.length, 1);
  assert.equal(preview.changes[0].email, "lead@example.test");
  assert.equal(preview.changes[0].from, "member");
  assert.equal(preview.changes[0].to, "admin");
  assert.equal((await roleOf(admin)).role, "member", "preview does not apply");
  await assert.rejects(mapping.applyDirectoryDrift(ctx, "stale-signature"), /Preview again/);
  const applied = await mapping.applyDirectoryDrift(ctx, preview.signature);
  assert.equal(applied.applied.length, 1);
  assert.equal((await roleOf(admin)).role, "admin");
  assert.equal((await roleOf(admin)).role_source, "directory");
  const [mappedAudit] = await sql`
    SELECT details FROM console_audit_event WHERE action = 'membership.role_mapped' AND target_id = ${preview.changes[0].membershipId}
  `;
  assert.equal(mappedAudit.details.previous_role, "member");
  assert.equal(mappedAudit.details.role, "admin");

  // Removing the person from the group drifts them back to member.
  await group.PATCH(
    req(`/Groups/${resource.id}`, {
      method: "PATCH",
      token: minted.token,
      body: { Operations: [{ op: "replace", path: "members", value: [] }] },
    }),
    params(resource.id),
  );
  const back = await mapping.previewDirectoryDrift(ctx);
  assert.deepEqual(back.changes.map((c) => [c.email, c.to]), [["lead@example.test", "member"]]);

  // Deprovision grace: suspended now, tombstoned after the grace period.
  const deactivated = await user.PATCH(
    req(`/Users/${ranger}`, {
      method: "PATCH",
      token: minted.token,
      body: { Operations: [{ op: "replace", path: "active", value: false }] },
    }),
    params(ranger),
  );
  assert.equal(deactivated.status, 200);
  assert.equal((await json(deactivated)).active, false);
  let row = await roleOf(ranger);
  assert.equal(row.status, "suspended");
  const days = (new Date(row.deprovision_at).getTime() - Date.now()) / 86_400_000;
  assert.ok(days > 6.9 && days <= 7, `grace is seven days (${days})`);
  await sql`UPDATE membership SET deprovision_at = now() - interval '1 minute' WHERE organisation_id = ${org.id} AND user_id = ${ranger}`;
  await users.GET(req("/Users", { token: minted.token })); // any SCIM call sweeps
  row = await roleOf(ranger);
  assert.equal(row.status, "removed");
  assert.ok(row.tombstoned_at, "tombstoned");
  const reactivated = await user.PATCH(
    req(`/Users/${ranger}`, { method: "PATCH", token: minted.token, body: { active: true } }),
    params(ranger),
  );
  assert.equal(reactivated.status, 200);
  row = await roleOf(ranger);
  assert.equal(row.status, "active");
  assert.equal(row.role, "member");
  assert.equal(row.tombstoned_at, null);

  // SCIM never deactivates the owner.
  assert.equal(
    (
      await user.DELETE(req(`/Users/${owner.user_id}`, { method: "DELETE", token: minted.token }), params(owner.user_id))
    ).status,
    409,
  );

  // Delete the group.
  assert.equal((await group.DELETE(req(`/Groups/${resource.id}`, { method: "DELETE", token: minted.token }), params(resource.id))).status, 204);
  assert.equal((await group.GET(req(`/Groups/${resource.id}`, { token: minted.token }), params(resource.id))).status, 404);
  console.log("scim-groups-e2e: ok");
} catch (error) {
  console.error(error);
  process.exitCode = 1;
} finally {
  await sql.close();
  process.exit(process.exitCode ?? 0);
}
