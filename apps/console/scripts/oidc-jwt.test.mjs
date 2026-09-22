import { createSign, generateKeyPairSync } from "node:crypto";
import { describe, expect, test } from "bun:test";
import {
  emailDomainAllowed,
  groupsAllowed,
  requireVerifiedEmail,
  subjectAllowed,
  syntheticOidcEmail,
  verifySignedJwt,
  OidcTokenError,
} from "../src/lib/oidc-jwt.ts";

function base64url(value) {
  return Buffer.from(value)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function signRs256(privateKey, claims) {
  const header = base64url(JSON.stringify({ alg: "RS256", kid: "test", typ: "JWT" }));
  const payload = base64url(JSON.stringify(claims));
  const signingInput = `${header}.${payload}`;
  const signature = createSign("RSA-SHA256").update(signingInput).end().sign(privateKey);
  return { token: `${signingInput}.${base64url(signature)}` };
}

describe("OIDC ID token verification", () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  const now = 1_700_000_000;
  const valid = {
    iss: "https://idp.example",
    aud: "console",
    sub: "user-1",
    exp: now + 300,
    iat: now,
    nonce: "nonce-1",
    email: "ranger@org.example",
    email_verified: true,
    name: "Ranger",
  };

  test("accepts a matching issuer, audience, nonce, and signature", () => {
    const { token } = signRs256(privateKey, valid);
    const claims = verifySignedJwt(token, jwk, {
      issuer: valid.iss,
      audience: valid.aud,
      nonce: valid.nonce,
      nowSeconds: now,
    });
    expect(claims.sub).toBe("user-1");
  });

  test("rejects the wrong issuer, audience, nonce, and expiry", () => {
    const cases = [
      [{ ...valid, iss: "https://other.example" }, "issuer"],
      [{ ...valid, aud: "other-client" }, "audience"],
      [{ ...valid, nonce: "nope" }, "nonce"],
      [{ ...valid, exp: now - 1 }, "expired"],
    ];
    for (const [claims] of cases) {
      const { token } = signRs256(privateKey, claims);
      expect(() =>
        verifySignedJwt(token, jwk, {
          issuer: valid.iss,
          audience: valid.aud,
          nonce: valid.nonce,
          nowSeconds: now,
        }),
      ).toThrow(OidcTokenError);
    }
  });

  test("domain and subject allow-lists default to empty-allow and never key accounts by email", () => {
    expect(emailDomainAllowed("ranger@org.example", [])).toBe(true);
    expect(emailDomainAllowed("ranger@org.example", ["org.example"])).toBe(true);
    expect(emailDomainAllowed("outsider@other.example", ["org.example"])).toBe(false);
    expect(subjectAllowed("user-1", [])).toBe(true);
    expect(subjectAllowed("user-1", ["user-2"])).toBe(false);
    expect(groupsAllowed({ ...valid, groups: ["rangers"] }, [])).toBe(true);
    expect(groupsAllowed({ ...valid, groups: ["rangers"] }, ["staff", "rangers"])).toBe(true);
    expect(groupsAllowed({ ...valid, groups: ["visitors"] }, ["staff"])).toBe(false);
    expect(groupsAllowed(valid, ["staff"])).toBe(false);
    expect(() =>
      requireVerifiedEmail(
        { ...valid, email_verified: false },
        ["org.example"],
      ),
    ).toThrow(OidcTokenError);
    expect(syntheticOidcEmail("https://idp.example", "user-1")).toMatch(
      /^oidc-[a-zA-Z0-9_-]+@users\.invalid$/,
    );
  });
});
