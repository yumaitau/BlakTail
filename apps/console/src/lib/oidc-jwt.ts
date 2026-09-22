import { createHmac, createPublicKey, createHash, verify } from "node:crypto";

export class OidcTokenError extends Error {}

export type IdTokenClaims = {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  nbf?: number;
  iat?: number;
  nonce?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  groups?: string[];
};

export type JsonWebKey = {
  kid?: string;
  alg?: string;
  kty: string;
  [key: string]: unknown;
};

function decodeBase64Url(value: string): Buffer {
  const pad = "=".repeat((4 - (value.length % 4)) % 4);
  return Buffer.from(value.replaceAll("-", "+").replaceAll("_", "/") + pad, "base64");
}

export function parseJwt(token: string): {
  header: { alg?: string; kid?: string; typ?: string };
  payload: IdTokenClaims;
  signingInput: Buffer;
  signature: Buffer;
} {
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => !part)) {
    throw new OidcTokenError("Malformed ID token.");
  }
  try {
    const header = JSON.parse(decodeBase64Url(parts[0]!).toString("utf8")) as {
      alg?: string;
      kid?: string;
      typ?: string;
    };
    const payload = JSON.parse(
      decodeBase64Url(parts[1]!).toString("utf8"),
    ) as IdTokenClaims;
    return {
      header,
      payload,
      signingInput: Buffer.from(`${parts[0]}.${parts[1]}`),
      signature: decodeBase64Url(parts[2]!),
    };
  } catch {
    throw new OidcTokenError("Malformed ID token.");
  }
}

export function publicKeyFromJwk(jwk: JsonWebKey) {
  try {
    return createPublicKey({ key: jwk, format: "jwk" });
  } catch {
    throw new OidcTokenError("JWKS key could not be imported.");
  }
}

export function findJwk(
  keys: JsonWebKey[],
  kid: string | undefined,
  alg: string,
): JsonWebKey {
  const match = keys.find(
    (key) => (!kid || key.kid === kid) && (!key.alg || key.alg === alg),
  );
  if (!match) {
    throw new OidcTokenError("No matching JWKS key for the ID token.");
  }
  return match;
}

export function verifySignedJwt(
  token: string,
  key: JsonWebKey,
  expected: {
    issuer: string;
    audience: string;
    nonce: string;
    nowSeconds?: number;
  },
): IdTokenClaims {
  const parsed = parseJwt(token);
  const alg = parsed.header.alg;
  const publicKey = publicKeyFromJwk(key);
  let valid = false;
  if (alg === "RS256") {
    valid = verify("RSA-SHA256", parsed.signingInput, publicKey, parsed.signature);
  } else if (alg === "ES256") {
    valid = verify("SHA256", parsed.signingInput, publicKey, parsed.signature);
  } else {
    throw new OidcTokenError("Unsupported ID token algorithm.");
  }
  if (!valid) {
    throw new OidcTokenError("ID token signature is invalid.");
  }
  const claims = parsed.payload;
  const now = expected.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (claims.iss !== expected.issuer) {
    throw new OidcTokenError("ID token issuer does not match the configured provider.");
  }
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(expected.audience)) {
    throw new OidcTokenError("ID token audience does not match this console.");
  }
  if (claims.nonce !== expected.nonce) {
    throw new OidcTokenError("ID token nonce does not match the login start.");
  }
  if (typeof claims.exp !== "number" || claims.exp <= now) {
    throw new OidcTokenError("ID token has expired.");
  }
  if (typeof claims.nbf === "number" && claims.nbf > now + 60) {
    throw new OidcTokenError("ID token is not yet valid.");
  }
  if (typeof claims.sub !== "string" || claims.sub.length < 1 || claims.sub.length > 255) {
    throw new OidcTokenError("ID token subject is missing.");
  }
  return claims;
}

export function emailDomainAllowed(
  email: string | undefined,
  allowDomains: string[],
): boolean {
  if (allowDomains.length === 0) return true;
  const domain = email?.split("@")[1]?.toLowerCase();
  if (!domain) return false;
  return allowDomains.some((allowed) => allowed.toLowerCase() === domain);
}

export function subjectAllowed(subject: string, allowSubjects: string[]): boolean {
  if (allowSubjects.length === 0) return true;
  return allowSubjects.includes(subject);
}

export function groupsFromClaims(claims: IdTokenClaims): string[] {
  const raw = claims.groups;
  if (!Array.isArray(raw)) return [];
  return raw.filter((group): group is string => typeof group === "string" && group.length > 0);
}

/** Empty allow-list means group membership is not required. */
export function groupsAllowed(claims: IdTokenClaims, allowGroups: string[]): boolean {
  if (allowGroups.length === 0) return true;
  const present = new Set(groupsFromClaims(claims));
  return allowGroups.some((group) => present.has(group));
}

export function requireVerifiedEmail(
  claims: IdTokenClaims,
  allowDomains: string[],
): void {
  if (allowDomains.length === 0) return;
  if (!claims.email || claims.email_verified !== true) {
    throw new OidcTokenError("A verified email is required for this organisation's domain policy.");
  }
}

export function syntheticOidcEmail(issuer: string, subject: string): string {
  const digest = createHash("sha256")
    .update(`${issuer}\n${subject}`)
    .digest("base64url")
    .slice(0, 24);
  return `oidc-${digest}@users.invalid`;
}

export function signBetterAuthCookie(token: string, secret: string): string {
  const signature = createHmac("sha256", secret).update(token).digest("base64url");
  return `${token}.${signature}`;
}
