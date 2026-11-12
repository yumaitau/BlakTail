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
