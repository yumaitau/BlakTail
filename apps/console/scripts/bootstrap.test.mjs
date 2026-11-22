import { SQL } from "bun";
import { createHmac } from "node:crypto";
import { readdirSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  bootstrapStatus,
  claimBootstrap,
  hashSecret,
  initialiseBootstrap,
  recoverOwner,
  signServiceAssertion,
} from "./bootstrap.mjs";

const TEST_SECRET = "test-bootstrap-hmac-secret-at-least-32-bytes";
const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
const migrations = [
  "0000_init.sql",
  "0001_auth_membership_constraints.sql",
  "0002_account_issuer.sql",
  "0003_secure_bootstrap.sql",
  "0004_linked_identities.sql",
  "0005_oidc_and_membership_lifecycle.sql",
];

async function resetThrough(sql, selectedMigrations) {
  await sql.unsafe("DROP SCHEMA public CASCADE; CREATE SCHEMA public");
  for (const migration of selectedMigrations) {
    const source = await readFile(
      new URL(`../drizzle/${migration}`, import.meta.url),
      "utf8",
    );
    for (const statement of source.split("--> statement-breakpoint")) {
      if (statement.trim()) await sql.unsafe(statement);
    }
  }
}

function decodeAssertion(value) {
  const [payload, signature] = value.split(".");
  assert.ok(payload && signature);
  const expected = createHmac("sha256", TEST_SECRET)
    .update(payload)
    .digest("base64url");
  assert.equal(signature, expected);
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
}

test("service assertions bind actor, audience, action, lifetime, and nonce", () => {
  const assertion = signServiceAssertion({
    organisationId: "75cafc98-6f14-476f-b349-7d7e41df1cab",
    action: "bootstrap.prepare",
    actorEmail: "owner@example.test",
    now: 1_800_000_000,
    jti: "f39ce5f5-7605-410d-854b-a98f187134f9",
    secret: TEST_SECRET,
  });
  assert.deepEqual(decodeAssertion(assertion), {
    sub: "operator-cli",
    org_id: "75cafc98-6f14-476f-b349-7d7e41df1cab",
    role: "service",
    name: "BlakTail operator",
    email: "owner@example.test",
    iss: "blaktail-console",
    aud: "blaktail-coord",
    iat: 1_800_000_000,
    exp: 1_800_000_060,
    jti: "f39ce5f5-7605-410d-854b-a98f187134f9",
    action: "bootstrap.prepare",
  });
});

test("secret hashes are deterministic without retaining source material", () => {
  const source = "btb_do-not-store-this-value";
  assert.equal(hashSecret(source), hashSecret(source));
  assert.equal(hashSecret(source).length, 64);
  assert.equal(hashSecret(source).includes(source), false);
});

test(
  "concurrent bootstrap claims create one owner, lock once, and reject replay",
  { skip: !TEST_DATABASE_URL },
  async () => {
    const sql = new SQL(TEST_DATABASE_URL, {
      max: 10,
      prepare: false,
    });
    const coordinatorRequests = [];
    let expireNextClaim = false;
    let failNextPreparation = false;
    const server = createServer(async (request, response) => {
      let raw = "";
      for await (const chunk of request) raw += chunk;
      const authorization = request.headers.authorization ?? "";
      const claims = decodeAssertion(authorization.replace(/^Bearer\s+/u, ""));
      let id;
      let name;
      let status;
      if (request.url === "/v1/orgs") {
        const body = JSON.parse(raw);
        id = body.id;
        name = body.name;
        status = 202;
        assert.equal(claims.action, "bootstrap.prepare");
        if (failNextPreparation) {
          failNextPreparation = false;
          response.writeHead(503, { "content-type": "application/json" });
          response.end(JSON.stringify({ error: "temporary coordinator failure" }));
          return;
        }
        if (expireNextClaim) {
          expireNextClaim = false;
          await sql`
            UPDATE bootstrap_state
            SET token_expires_at = now() - interval '1 second'
            WHERE id = 'primary'
          `;
        }
      } else {
        const match = request.url?.match(
          /^\/v1\/orgs\/([^/]+)\/bootstrap-commit$/u,
        );
        assert.ok(match);
        id = match[1];
        name = "BlakPath Test";
        status = 201;
        assert.equal(claims.action, "bootstrap.commit");
      }
      assert.equal(claims.org_id, id);
      coordinatorRequests.push({ action: claims.action, id });
      response.writeHead(status, {
        "content-type": "application/json",
      });
      response.end(JSON.stringify({ id, name }));
    });

    await resetThrough(sql, migrations);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    assert.ok(address && typeof address === "object");
    process.env.COORD_BASE_URL = `http://127.0.0.1:${address.port}`;
    process.env.BLAKTAIL_AUTH_HMAC_SECRET = TEST_SECRET;

    try {
      const token = "btb_test-concurrent-claim-token-with-enough-entropy";
      const password = "test-password-not-for-production";
      await initialiseBootstrap(sql, { token, ttlSeconds: 600 });
      const input = {
        token,
        password,
        email: "first.owner@example.test",
        ownerName: "First Owner",
        organisationName: "BlakPath Test",
      };
      const claims = await Promise.allSettled([
        claimBootstrap(sql, input),
        claimBootstrap(sql, input),
      ]);
      const claimResults = claims.map((result) =>
        result.status === "fulfilled"
          ? "fulfilled"
          : result.reason instanceof Error
            ? result.reason.message
            : "unknown rejection",
      );
      assert.equal(
        claims.filter((result) => result.status === "fulfilled").length,
        1,
        JSON.stringify(claimResults),
      );
      assert.equal(
        claims.filter((result) => result.status === "rejected").length,
        1,
      );

      const [counts] = await sql`
      SELECT
        (SELECT count(*)::int FROM "user") AS users,
        (SELECT count(*)::int FROM account) AS accounts,
        (SELECT count(*)::int FROM organisation) AS organisations,
        (SELECT count(*)::int FROM person) AS people,
        (SELECT count(*)::int FROM person_login_identity) AS identities,
        (SELECT count(*)::int FROM network_account) AS network_accounts,
        (SELECT count(*)::int FROM membership WHERE role = 'owner') AS owners
    `;
      assert.deepEqual(
        {
          users: counts.users,
          accounts: counts.accounts,
          organisations: counts.organisations,
          people: counts.people,
          identities: counts.identities,
          networkAccounts: counts.network_accounts,
          owners: counts.owners,
        },
        {
          users: 1,
          accounts: 1,
          organisations: 1,
          people: 1,
          identities: 1,
          networkAccounts: 1,
          owners: 1,
        },
      );
      const status = await bootstrapStatus(sql);
      assert.equal(status.status, "locked");
      assert.equal(status.orphanedOrganisations.length, 0);
      await assert.rejects(
        () => claimBootstrap(sql, input),
        /consumed or invalid/u,
      );

      const audit =
        await sql`SELECT * FROM console_audit_event ORDER BY created_at, id`;
      const serializedAudit = JSON.stringify(audit);
      assert.equal(serializedAudit.includes(token), false);
      assert.equal(serializedAudit.includes(password), false);
      assert.ok(audit.some((event) => event.action === "bootstrap.created"));
      assert.ok(audit.some((event) => event.action === "bootstrap.completed"));
      assert.ok(
        audit
          .filter((event) => event.action.startsWith("bootstrap."))
          .every((event) => event.organisation_id !== null),
      );
      assert.ok(coordinatorRequests.length >= 1);

      await resetThrough(sql, migrations);
      const expiringToken = "btb_test-expiring-during-provisioning-token";
      await initialiseBootstrap(sql, { token: expiringToken, ttlSeconds: 600 });
      expireNextClaim = true;
      await assert.rejects(
        () =>
          claimBootstrap(sql, {
            ...input,
            token: expiringToken,
            email: "expired.owner@example.test",
          }),
        /consumed or state changed/u,
      );
      const [expiredState] = await sql`
        SELECT status,
          (SELECT count(*)::int FROM account) AS accounts,
          (SELECT count(*)::int FROM "user") AS users,
          (SELECT count(*)::int FROM organisation) AS organisations,
          (SELECT count(*)::int FROM membership) AS memberships
        FROM bootstrap_state WHERE id = 'primary'
      `;
      assert.equal(expiredState.status, "provisioning");
      assert.equal(expiredState.accounts, 0);
      assert.equal(expiredState.users, 0);
      assert.equal(expiredState.organisations, 0);
      assert.equal(expiredState.memberships, 0);

      await resetThrough(sql, migrations);
      const retryToken = "btb_test-retry-after-coordinator-failure-token";
      await initialiseBootstrap(sql, { token: retryToken, ttlSeconds: 600 });
      const retryInput = {
        ...input,
        token: retryToken,
        email: "retry.owner@example.test",
      };
      failNextPreparation = true;
      await assert.rejects(
        () => claimBootstrap(sql, retryInput),
        /preparation failed with HTTP 503/u,
      );
      const [beforeRetry] = await sql`
        SELECT
          (SELECT count(*)::int FROM "user") AS users,
          (SELECT count(*)::int FROM organisation) AS organisations,
          (SELECT count(*)::int FROM membership) AS memberships,
          (SELECT count(*)::int FROM account) AS accounts
      `;
      assert.deepEqual(beforeRetry, {
        users: 0,
        organisations: 0,
        memberships: 0,
        accounts: 0,
      });
      await claimBootstrap(sql, retryInput);
      assert.equal((await bootstrapStatus(sql)).status, "locked");
    } finally {
      await new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
      await sql.close({ timeout: 5 });
    }
  },
);

test(
  "migration locks existing owners and reports ownerless organisations",
  { skip: !TEST_DATABASE_URL },
  async () => {
    const sql = new SQL(TEST_DATABASE_URL, {
      max: 1,
      prepare: false,
    });
    try {
      await resetThrough(sql, migrations.slice(0, 3));
      await sql`
        INSERT INTO organisation (id, name, coord_org_id)
        VALUES ('ownerless-org', 'Ownerless Organisation',
          '73bb4e5b-c676-4d3d-8f08-25f5361093df')
      `;
      const secureMigration = await readFile(
        new URL("../drizzle/0003_secure_bootstrap.sql", import.meta.url),
        "utf8",
      );
      for (const statement of secureMigration.split("--> statement-breakpoint")) {
        if (statement.trim()) await sql.unsafe(statement);
      }
      const ownerlessStatus = await bootstrapStatus(sql);
      assert.equal(ownerlessStatus.status, "uninitialised");
      assert.equal(ownerlessStatus.orphanedOrganisations.length, 1);

      await resetThrough(sql, migrations.slice(0, 3));
      await sql`
        INSERT INTO "user" (id, name, email, email_verified)
        VALUES ('existing-owner', 'Existing Owner', 'existing@example.test', true)
      `;
      await sql`
        INSERT INTO organisation (id, name, coord_org_id)
        VALUES ('existing-org', 'Existing Organisation',
          'fe369171-67b0-4531-a663-fe8076193dca')
      `;
      await sql`
        INSERT INTO membership (id, organisation_id, user_id, role)
        VALUES ('existing-membership', 'existing-org', 'existing-owner', 'owner')
      `;
      for (const statement of secureMigration.split("--> statement-breakpoint")) {
        if (statement.trim()) await sql.unsafe(statement);
      }
      const ownedStatus = await bootstrapStatus(sql);
      assert.equal(ownedStatus.status, "locked");
      assert.equal(ownedStatus.orphanedOrganisations.length, 0);
      await assert.rejects(() => initialiseBootstrap(sql), /already locked/u);

      await sql`
        UPDATE bootstrap_state
        SET status = 'uninitialised', locked_at = NULL
        WHERE id = 'primary'
      `;
      await assert.rejects(
        () => initialiseBootstrap(sql),
        /existing owner detected/u,
      );
      const repairedStatus = await bootstrapStatus(sql);
      assert.equal(repairedStatus.status, "locked");

      const linkedIdentityMigration = await readFile(
        new URL("../drizzle/0004_linked_identities.sql", import.meta.url),
        "utf8",
      );
      for (const statement of linkedIdentityMigration.split(
        "--> statement-breakpoint",
      )) {
        if (statement.trim()) await sql.unsafe(statement);
      }
      const [linkedGraph] = await sql`
        SELECT
          (SELECT count(*)::int FROM person) AS people,
          (SELECT count(*)::int FROM person_login_identity) AS identities,
          (SELECT count(*)::int FROM network_account) AS network_accounts
      `;
      assert.deepEqual(
        {
          people: linkedGraph.people,
          identities: linkedGraph.identities,
          networkAccounts: linkedGraph.network_accounts,
        },
        { people: 1, identities: 1, networkAccounts: 1 },
      );
    } finally {
      await sql.close({ timeout: 5 });
    }
  },
);

test(
  "bootstrap claim attempts are rate limited before secret verification",
  { skip: !TEST_DATABASE_URL },
  async () => {
    const sql = new SQL(TEST_DATABASE_URL, {
      max: 1,
      prepare: false,
    });
    try {
      await resetThrough(sql, migrations);
      await initialiseBootstrap(sql, {
        token: "btb_rate-limit-valid-token",
        ttlSeconds: 600,
      });
      const invalidClaim = {
        token: "btb_rate-limit-invalid-token",
        password: "rate-limit-test-password",
        email: "rate.limit@example.test",
        ownerName: "Rate Limit Test",
        organisationName: "Rate Limit Test",
      };
      for (let attempt = 0; attempt < 10; attempt += 1) {
        await assert.rejects(
          () => claimBootstrap(sql, invalidClaim),
          /expired, or invalid/u,
        );
      }
      await assert.rejects(
        () => claimBootstrap(sql, invalidClaim),
        /too many bootstrap claim attempts/u,
      );
    } finally {
      await sql.close({ timeout: 5 });
    }
  },
);

test(
  "owner recovery removes SSO bindings, two-step and every linked session",
  { skip: !TEST_DATABASE_URL },
  async () => {
    const sql = new SQL(TEST_DATABASE_URL, {
      max: 1,
      prepare: false,
    });
    try {
      const all = readdirSync(new URL("../drizzle/", import.meta.url))
        .filter((name) => name.endsWith(".sql"))
        .sort();
      await resetThrough(sql, all);
      await sql`
        INSERT INTO bootstrap_state (id, status, locked_at)
        VALUES ('primary', 'locked', now())
        ON CONFLICT (id) DO UPDATE SET status = 'locked', locked_at = now()
      `;
      await sql`
        INSERT INTO organisation (id, name, coord_org_id)
        VALUES ('recover-org', 'Recover Org', 'a1b6f0b4-6f53-4c4b-9a52-4a0b0c4b7f10')
      `;
      for (const id of ["recover-owner", "recover-linked", "bystander"]) {
        await sql`
          INSERT INTO "user" (id, name, email, email_verified, two_factor_enabled)
          VALUES (${id}, ${id}, ${`${id}@example.test`}, true, true)
        `;
        await sql`
          INSERT INTO session (id, expires_at, token, user_id)
          VALUES (${`session-${id}`}, now() + interval '1 day', ${`token-${id}`}, ${id})
        `;
        await sql`
          INSERT INTO two_factor (id, secret, backup_codes, user_id)
          VALUES (${`tf-${id}`}, 'fake-secret', 'fake-codes', ${id})
        `;
      }
      await sql`
        INSERT INTO membership (id, organisation_id, user_id, role)
        VALUES ('recover-membership', 'recover-org', 'recover-owner', 'owner')
      `;
      await sql`
        INSERT INTO person (id, display_name) VALUES ('recover-person', 'Owner'),
          ('bystander-person', 'Bystander')
      `;
      await sql`
        INSERT INTO person_login_identity (id, person_id, user_id) VALUES
          ('pli-owner', 'recover-person', 'recover-owner'),
          ('pli-linked', 'recover-person', 'recover-linked'),
          ('pli-bystander', 'bystander-person', 'bystander')
      `;
      await sql`
        INSERT INTO identity_provider (id, organisation_id, issuer, client_id, client_secret, enabled)
        VALUES ('recover-idp', 'recover-org', 'https://idp.example.test', 'client', 'fake-client-secret', true)
      `;
      await sql`
        INSERT INTO external_identity (
          id, organisation_id, provider_id, issuer, subject, user_id, last_authenticated_at
        ) VALUES
          ('ext-owner', 'recover-org', 'recover-idp', 'https://idp.example.test', 'attacker-sub', 'recover-owner', now()),
          ('ext-bystander', 'recover-org', 'recover-idp', 'https://idp.example.test', 'bystander-sub', 'bystander', now())
      `;

      const result = await recoverOwner(sql, {
        email: "recover-owner@example.test",
        password: "fake-recovery-password",
      });
      assert.deepEqual(result, {
        sessionsRevoked: 2,
        linkedIdentitiesSignedOut: 2,
        ssoBindingsRemoved: 1,
        twoFactorSecretsRemoved: 1,
      });
      const sessions = await sql`SELECT user_id FROM session ORDER BY user_id`;
      assert.deepEqual(sessions.map((row) => row.user_id), ["bystander"]);
      const bindings = await sql`SELECT user_id FROM external_identity`;
      assert.deepEqual(bindings.map((row) => row.user_id), ["bystander"]);
      const [owner] = await sql`
        SELECT two_factor_enabled FROM "user" WHERE id = 'recover-owner'
      `;
      assert.equal(owner.two_factor_enabled, false);
      const secrets = await sql`SELECT user_id FROM two_factor ORDER BY user_id`;
      assert.deepEqual(
        secrets.map((row) => row.user_id),
        ["bystander", "recover-linked"],
      );
      const [audit] = await sql`
        SELECT details FROM console_audit_event WHERE action = 'owner.recovered'
      `;
      assert.equal(audit.details.sso_bindings_removed, 1);
      assert.equal(audit.details.sessions_revoked_count, 2);
      assert.equal(audit.details.two_factor_secrets_removed, 1);
    } finally {
      await sql.close({ timeout: 5 });
    }
  },
);
