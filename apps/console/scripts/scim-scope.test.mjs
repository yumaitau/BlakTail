import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

function source(file) {
  return readFileSync(new URL(`../src/${file}`, import.meta.url), "utf8");
}

function functionBody(file, name) {
  const text = source(file);
  const start = text.indexOf(`function ${name}(`);
  expect(start).toBeGreaterThan(-1);
  const next = text.indexOf("\nexport ", start + 1);
  return text.slice(start, next === -1 ? undefined : next);
}

describe("SCIM activation stays inside the token's organisation", () => {
  test("setScimActive never changes the shared login identity", () => {
    const body = functionBody("lib/scim.ts", "setScimActive");
    expect(body).not.toMatch(/UPDATE\s+person_login_identity/u);
    expect(body).toContain("applyActivation(");
  });

  test("the membership update is scoped to the organisation", () => {
    const body = functionBody("lib/scim.ts", "applyActivation");
    const update = body.slice(body.indexOf("UPDATE membership"));
    expect(update).toMatch(/WHERE id = \$\{membershipId\} AND organisation_id = \$\{organisationId\}/u);
  });

  test("sign-in ignores memberships that are not active", () => {
    const body = functionBody("lib/session.ts", "resolveSessionContext");
    expect(body).toContain("coalesce(m.status, 'active') = 'active'");
  });
});
