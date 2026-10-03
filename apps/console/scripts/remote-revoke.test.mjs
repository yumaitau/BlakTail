import { describe, expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  REVOKE_USER_ACTION,
  needsRemoteRevoke,
  postUserRevoke,
  signRevokeAssertion,
} from "../src/lib/remote-revoke-core.ts";

const secret = "s".repeat(32);
const coordOrgId = "6f1c2c5e-4b8e-4c8a-9e57-0d3f2a1b9c10";

function decode(token) {
  const [payload, signature] = token.split(".");
  expect(createHmac("sha256", secret).update(payload).digest("base64url")).toBe(signature);
  return JSON.parse(Buffer.from(payload, "base64url").toString());
}

describe("remote session revoke on deprovisioning", () => {
  test("suspension, removal and roles without remote sessions all revoke", () => {
    expect(needsRemoteRevoke({ role: "admin", status: "suspended" })).toBe(true);
    expect(needsRemoteRevoke({ role: "owner", status: "removed" })).toBe(true);
    expect(needsRemoteRevoke({ role: "member", status: "active" })).toBe(true);
    expect(needsRemoteRevoke({ role: "auditor", status: "active" })).toBe(true);
    expect(needsRemoteRevoke({ role: "not-a-role", status: "active" })).toBe(true);
    expect(needsRemoteRevoke({ role: "admin", status: "active" })).toBe(false);
    expect(needsRemoteRevoke({ role: "network_admin", status: "active" })).toBe(false);
  });

  test("the service assertion is scoped to the revoke action and a system subject", () => {
    const claims = decode(
      signRevokeAssertion({ coordOrgId, source: "scim", secret, now: 1_000, jti: "j".repeat(36) }),
    );
    expect(claims).toMatchObject({
      sub: "system:scim",
      org_id: coordOrgId,
      role: "service",
      action: REVOKE_USER_ACTION,
      iss: "blaktail-console",
      aud: "blaktail-coord",
      iat: 1_000,
      exp: 1_060,
    });
    expect(() => signRevokeAssertion({ coordOrgId, source: "scim", secret: "short" })).toThrow();
  });

  test("posts the revoke for the person with a fresh assertion each time", async () => {
    const calls = [];
    const fakeFetch = async (url, init) => {
      calls.push({ url, init });
      return new Response(JSON.stringify({ revoked: 2 }), { status: 200 });
    };
    const deps = { baseUrl: "https://coord.example.au/", secret, fetch: fakeFetch };
    const input = { coordOrgId, userId: "user/1", source: "directory" };
    expect(await postUserRevoke(input, deps)).toBe(2);
    await postUserRevoke(input, deps);
    expect(calls[0].url).toBe(
      `https://coord.example.au/v1/orgs/${coordOrgId}/remote-access/users/user%2F1/revoke`,
    );
    expect(calls[0].init.method).toBe("POST");
    const tokens = calls.map((call) => call.init.headers.Authorization.replace("Bearer ", ""));
    expect(decode(tokens[0]).sub).toBe("system:directory");
    expect(decode(tokens[0]).jti).not.toBe(decode(tokens[1]).jti);
  });

  test("a coordinator refusal surfaces as an error", async () => {
    const deps = {
      baseUrl: "https://coord.example.au",
      secret,
      fetch: async () => new Response("{}", { status: 403 }),
    };
    await expect(
      postUserRevoke({ coordOrgId, userId: "u", source: "scim" }, deps),
    ).rejects.toThrow("403");
  });
});

function functionBody(file, name) {
  const source = readFileSync(new URL(`../src/${file}`, import.meta.url), "utf8");
  const start = source.indexOf(`function ${name}(`);
  expect(start).toBeGreaterThan(-1);
  const next = source.indexOf("\nexport ", start + 1);
  return source.slice(start, next === -1 ? undefined : next);
}

describe("every membership change path revokes remote sessions", () => {
  test.each([
    ["lib/scim.ts", "setScimActive", "revokeSessionsForUser("],
    ["lib/scim.ts", "provisionScimUser", "revokeSessionsForUser("],
    ["lib/directory-mapping.ts", "sweepDeprovisioned", "revokeSessionsForUser("],
    ["lib/directory-mapping.ts", "applyDirectoryDrift", "revokeSessionsForMembership("],
    ["app/actions.ts", "changeMembershipAction", "revokeSessionsForMembership("],
    ["app/api/memberships/route.ts", "PATCH", "revokeSessionsForMembership("],
  ])("%s %s", (file, name, call) => {
    expect(functionBody(file, name)).toContain(call);
  });
});
