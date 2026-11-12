// Pure single sign-on flow rules. No I/O here so bun tests can pin them.
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Browser binding for a pending sign-in. `/api/oidc/start` puts a random
 * secret in this cookie and stores only its hash with the state row, so a
 * callback URL captured from one browser cannot be completed in another.
 */
export const OIDC_BINDING_COOKIE = "blaktail_oidc_binding";
export const OIDC_BINDING_COOKIE_PATH = "/api/oidc/callback";
export const OIDC_STATE_TTL_SECONDS = 10 * 60;

export function newBindingSecret(): { secret: string; hash: string } {
  const secret = randomBytes(32).toString("base64url");
  return { secret, hash: hashBindingSecret(secret) };
}

export function hashBindingSecret(secret: string): string {
  return createHash("sha256").update(secret).digest("hex");
}

/** A missing, empty or foreign cookie never matches. */
export function bindingMatches(
  storedHash: string | null | undefined,
  presented: string | null | undefined,
): boolean {
  if (!storedHash || !presented) return false;
  const actual = Buffer.from(hashBindingSecret(presented));
  const expected = Buffer.from(storedHash);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function bindingCookie(value: string, secure: boolean) {
  return {
    name: OIDC_BINDING_COOKIE,
    value,
    httpOnly: true,
    secure,
    sameSite: "lax" as const,
    path: OIDC_BINDING_COOKIE_PATH,
    maxAge: value ? OIDC_STATE_TTL_SECONDS : 0,
  };
}

export const DEFAULT_SIGN_IN_REDIRECT = "/control-center";

/**
 * A post-sign-in destination is a same-origin path only. `//host` and
 * `/\host` are protocol-relative to browsers, and URL parsers strip tabs and
 * newlines, so `/\t/host` would become `//host`: control characters and
 * backslashes are refused outright.
 */
export function safeRedirectPath(
  value: string | null | undefined,
  fallback: string = DEFAULT_SIGN_IN_REDIRECT,
): string {
  if (typeof value !== "string" || value.length > 2048) return fallback;
  if (/[\u0000-\u001f\u007f\\]/.test(value)) return fallback;
  return /^\/(?!\/)/.test(value) ? value : fallback;
}

/** Resolve against `origin` and refuse anything that lands elsewhere. */
export function sameOriginRedirect(
  value: string | null | undefined,
  origin: string,
  fallback: string = DEFAULT_SIGN_IN_REDIRECT,
): URL {
  const target = new URL(safeRedirectPath(value, fallback), origin);
  return target.origin === new URL(origin).origin ? target : new URL(fallback, origin);
}

export type PendingLink = {
  linkUserId: string | null;
  linkSessionId: string | null;
};

export type CurrentSession = { userId: string; sessionId: string } | null;

/**
 * Linking is never inferred from whatever session the browser happens to
 * carry. Only a state row created by an explicit, authenticated link start
 * links, and only back into that same user and session. Every other
 * callback is a plain sign-in.
 */
export function oidcLinkDecision(
  pending: PendingLink,
  current: CurrentSession,
): { linkingUserId: string | null } | { refusal: string } {
  if (!pending.linkUserId && !pending.linkSessionId) {
    return { linkingUserId: null };
  }
  if (
    !pending.linkUserId ||
    !pending.linkSessionId ||
    !current ||
    current.userId !== pending.linkUserId ||
    current.sessionId !== pending.linkSessionId
  ) {
    return {
      refusal:
        "Linking was started from a different session. Sign in again, then link it from Settings.",
    };
  }
  return { linkingUserId: pending.linkUserId };
}
