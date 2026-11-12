import { createSign, generateKeyPairSync } from "node:crypto";
import { describe, expect, test } from "bun:test";
import {
  emailDomainAllowed,
  groupsAllowed,
  mergeGroups,
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

  test("accepts a P-256 ES256 JWS and rejects DER, tampered and mismatched keys", () => {
    const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const ecJwk = ec.publicKey.export({ format: "jwk" });
    const expected = { issuer: valid.iss, audience: valid.aud, nonce: valid.nonce, nowSeconds: now };
    const sign = (claims, dsaEncoding) => {
      const header = base64url(JSON.stringify({ alg: "ES256", kid: "ec", typ: "JWT" }));
      const signingInput = `${header}.${base64url(JSON.stringify(claims))}`;
      const signature = createSign("SHA256")
        .update(signingInput)
        .end()
        .sign({ key: ec.privateKey, dsaEncoding });
      return `${signingInput}.${base64url(signature)}`;
    };
    const token = sign(valid, "ieee-p1363");
    expect(verifySignedJwt(token, ecJwk, expected).sub).toBe("user-1");
    // DER is not the JWS encoding.
    expect(() => verifySignedJwt(sign(valid, "der"), ecJwk, expected)).toThrow("signature");
    const [head, , signature] = token.split(".");
    const forged = `${head}.${base64url(JSON.stringify({ ...valid, sub: "user-2" }))}.${signature}`;
    expect(() => verifySignedJwt(forged, ecJwk, expected)).toThrow("signature");
    // An ES256 header with an RSA key, or RS256 with an EC key, is refused.
    expect(() => verifySignedJwt(token, jwk, expected)).toThrow("algorithm");
    expect(() => verifySignedJwt(signRs256(privateKey, valid).token, ecJwk, expected)).toThrow("algorithm");
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
    expect(mergeGroups({ ...valid, groups: ["staff"] }, { groups: ["other"] }).groups).toEqual([
      "staff",
    ]);
    expect(mergeGroups(valid, { groups: ["rangers", 1, ""] }).groups).toEqual(["rangers"]);
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
