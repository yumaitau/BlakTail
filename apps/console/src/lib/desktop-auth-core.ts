import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Pure helpers for the desktop and mobile app sign-in bridge. No database or
 * Next.js imports so the logic can be tested with `bun test`.
 *
 * Protocol (PKCE, RFC 7636 S256):
 * 1. The app opens `/desktop/auth?redirect_uri=blaktail://auth/callback&state=…
 *    &code_challenge=…&code_challenge_method=S256`.
 * 2. The signed-in person presses Allow. The page POSTs (same-origin JSON) to
 *    `/api/desktop/auth/authorize`, which stores a 60-second single-use code
 *    (hashed, bound to the user, the approving browser session and the
 *    challenge) and returns `blaktail://auth/callback?code=…&state=…`.
 * 3. The app POSTs `{ code, code_verifier }` to `/api/desktop/auth/token` and
 *    receives a desktop credential (`btd_…`), never the browser session.
 */

/** The only callback the console hands codes to. */
export const DESKTOP_REDIRECT_URI = "blaktail://auth/callback";

/** Authorisation codes are short-lived and single use. */
export const DESKTOP_CODE_TTL_SECONDS = 60;

/**
 * Upper bound for a desktop credential. It also ends when the browser session
 * that approved it ends (sign-out, revoke-all, expiry) or the app signs out.
 */
export const DESKTOP_CREDENTIAL_TTL_SECONDS = 60 * 60 * 24 * 30;

export const DESKTOP_CODE_PREFIX = "btc_";
export const DESKTOP_CREDENTIAL_PREFIX = "btd_";

/**
 * Accepts exactly `blaktail://auth/callback` (no query, fragment, userinfo,
 * port or extra path). Anything else is refused rather than normalised.
 */
export function validDesktopRedirectUri(value: string | null | undefined): string | null {
  if (typeof value !== "string" || value !== DESKTOP_REDIRECT_URI) return null;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  if (
    parsed.protocol !== "blaktail:" ||
    parsed.host !== "auth" ||
    parsed.pathname !== "/callback" ||
    parsed.search ||
    parsed.hash ||
    parsed.username ||
    parsed.password
  ) {
    return null;
  }
  return DESKTOP_REDIRECT_URI;
}

/** Escapes text for an HTML attribute or text node. */
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const UNRESERVED = /^[A-Za-z0-9\-._~]+$/;

/** RFC 7636: 43-128 unreserved characters. */
export function validCodeVerifier(value: unknown): value is string {
  return typeof value === "string" && value.length >= 43 && value.length <= 128 && UNRESERVED.test(value);
}

/** An S256 challenge is base64url(SHA-256) without padding: 43 characters. */
export function validCodeChallenge(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

/** The app's CSRF token for the callback: opaque, URL-safe, bounded. */
export function validState(value: unknown): value is string {
  return typeof value === "string" && value.length >= 16 && value.length <= 256 && UNRESERVED.test(value);
}

export function s256Challenge(verifier: string): string {
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

export function verifyS256(verifier: unknown, challenge: string): boolean {
  if (!validCodeVerifier(verifier) || !validCodeChallenge(challenge)) return false;
  const actual = Buffer.from(s256Challenge(verifier));
  const expected = Buffer.from(challenge);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function hashDesktopSecret(secret: string): string {
  return createHash("sha256").update(secret).digest("hex");
}

export function newDesktopSecret(prefix: string): { secret: string; hash: string } {
  const secret = `${prefix}${randomBytes(32).toString("base64url")}`;
  return { secret, hash: hashDesktopSecret(secret) };
}

export type AuthoriseRequest = {
  redirectUri: string;
  state: string;
  codeChallenge: string;
};

/** Validates the app's sign-in parameters. Only S256 is supported. */
export function parseAuthoriseRequest(body: unknown): AuthoriseRequest | { error: string } {
  const record = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
  const redirectUri = validDesktopRedirectUri(
    typeof record.redirect_uri === "string" ? record.redirect_uri : null,
  );
  if (!redirectUri) return { error: "redirect_uri must be blaktail://auth/callback." };
  if (!validState(record.state)) return { error: "state is missing or malformed." };
  if (record.code_challenge_method !== "S256") {
    return { error: "code_challenge_method must be S256." };
  }
  if (!validCodeChallenge(record.code_challenge)) {
    return { error: "code_challenge is missing or malformed." };
  }
  return { redirectUri, state: record.state, codeChallenge: record.code_challenge };
}

export function desktopCallbackUrl(redirectUri: string, code: string, state: string): string {
  const url = new URL(redirectUri);
  url.searchParams.set("code", code);
  url.searchParams.set("state", state);
  return url.toString();
}

export function codeExpiresAt(now: Date): Date {
  return new Date(now.getTime() + DESKTOP_CODE_TTL_SECONDS * 1000);
}

/** A code is redeemable once, before it expires. */
export function codeRedeemable(
  code: { expiresAt: Date; usedAt: Date | null },
  now: Date,
): boolean {
  return code.usedAt === null && code.expiresAt.getTime() > now.getTime();
}

export function credentialExpiresAt(now: Date): Date {
  return new Date(now.getTime() + DESKTOP_CREDENTIAL_TTL_SECONDS * 1000);
}

/** Live only while unrevoked, unexpired, and its approving session is alive. */
export function credentialUsable(
  credential: { revokedAt: Date | null; expiresAt: Date; sessionExpiresAt: Date | null },
  now: Date,
): boolean {
  return (
    credential.revokedAt === null &&
    credential.expiresAt.getTime() > now.getTime() &&
    credential.sessionExpiresAt !== null &&
    credential.sessionExpiresAt.getTime() > now.getTime()
  );
}

/** Only desktop credentials are accepted as Bearer; browser session tokens are not. */
export function desktopBearer(header: string | null): string | null {
  const match = /^Bearer\s+(\S+)$/i.exec(header?.trim() ?? "");
  const token = match?.[1];
  if (!token?.startsWith(DESKTOP_CREDENTIAL_PREFIX)) return null;
  if (!/^[A-Za-z0-9_-]{36,100}$/.test(token)) return null;
  return token;
}
