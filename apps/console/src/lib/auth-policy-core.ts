// Pure sign-in assurance rules. No I/O here so bun tests can pin them.
import type { OrgRole } from "./roles";

export type SignInPolicy = {
  /** Security changes need a sign-in at most this many minutes old. */
  stepUpMaxAgeMinutes: number | null;
  /** Owners and admins need a session that presented a second factor. */
  requireMfaForPrivileged: boolean;
  /**
   * Accept a single sign-on session as multi-factor, trusting the identity
   * provider's own MFA. Off unless an owner turns it on.
   */
  trustIdpMfa: boolean;
};

export const DEFAULT_SIGN_IN_POLICY: SignInPolicy = {
  stepUpMaxAgeMinutes: null,
  requireMfaForPrivileged: false,
  trustIdpMfa: false,
};

/**
 * How a session was created, recorded once at creation. `password_mfa` is a
 * password sign-in that also passed TOTP or a backup code; `sso` is an
 * identity-provider sign-in. Sessions created before this was recorded have
 * no method and never satisfy an MFA rule.
 */
export type SessionAuthMethod = "password" | "password_mfa" | "sso";

const SESSION_AUTH_METHODS: readonly SessionAuthMethod[] = ["password", "password_mfa", "sso"];

export function parseSessionAuthMethod(value: unknown): SessionAuthMethod | null {
  return SESSION_AUTH_METHODS.includes(value as SessionAuthMethod)
    ? (value as SessionAuthMethod)
    : null;
}

const SECOND_FACTOR_PATHS = [
  "/two-factor/verify-totp",
  "/two-factor/verify-backup-code",
  "/two-factor/verify-otp",
];

/**
 * The method for a session Better Auth is about to create. A second-factor
 * verification always records `password_mfa`; otherwise an explicit or
 * carried-over value (the OIDC callback, or a session reissued from the
 * current one) is kept; a bare password sign-in records `password`.
 */
export function sessionAuthMethodFor(
  path: string | null | undefined,
  existing: unknown,
): SessionAuthMethod | null {
  if (path && SECOND_FACTOR_PATHS.includes(path)) return "password_mfa";
  const carried = parseSessionAuthMethod(existing);
  if (carried) return carried;
  if (path === "/sign-in/email") return "password";
  return null;
}

export const STEP_UP_MIN_MINUTES = 5;
export const STEP_UP_MAX_MINUTES = 1440;

export const MFA_PRIVILEGED_ROLES: readonly OrgRole[] = ["owner", "admin"];

export class AssuranceError extends Error {
  constructor(
    message: string,
    readonly code: "step_up_required" | "mfa_required",
  ) {
    super(message);
  }
}

/**
 * Policy is per organisation and is read for the organisation the action
 * targets, so a session that satisfies a lax organisation never satisfies
 * a stricter one by association.
 */
export function stepUpRefusal(
  policy: SignInPolicy,
  sessionCreatedAt: Date,
  now: Date = new Date(),
): string | null {
  if (!policy.stepUpMaxAgeMinutes) return null;
  const ageMs = now.getTime() - sessionCreatedAt.getTime();
  if (Number.isFinite(ageMs) && ageMs >= 0 && ageMs <= policy.stepUpMaxAgeMinutes * 60_000) {
    return null;
  }
  return `This organisation requires a sign-in within the last ${policy.stepUpMaxAgeMinutes} minutes for security changes. Sign out and sign in again, then retry.`;
}

export type IdentityAssurance = { hasPassword: boolean; twoFactorEnabled: boolean };

/**
 * MFA for privileged roles is judged on the session making the request, not
 * on whether the account has TOTP enrolled: a session satisfies it only if
 * it presented a second factor at sign-in, or it is a single sign-on session
 * and the organisation explicitly trusts its identity provider's MFA.
 * Because each session is judged on how it signed in, a weaker linked
 * identity cannot borrow a privileged role either. `identity` only picks the
 * advice in the refusal.
 */
export function mfaRefusal(
  policy: SignInPolicy,
  role: OrgRole,
  session: { authMethod: SessionAuthMethod | null },
  identity: IdentityAssurance,
): string | null {
  if (!policy.requireMfaForPrivileged) return null;
  if (!MFA_PRIVILEGED_ROLES.includes(role)) return null;
  if (session.authMethod === "password_mfa") return null;
  if (session.authMethod === "sso") {
    if (policy.trustIdpMfa) return null;
    return identity.hasPassword && identity.twoFactorEnabled
      ? "This organisation requires two-step verification for owners and admins and does not accept single sign-on as proof of it. Sign in with your password and two-step code, then retry."
      : "This organisation requires two-step verification for owners and admins and does not accept single sign-on as proof of it. Ask an owner to trust identity-provider MFA, or sign in with a password and two-step verification.";
  }
  if (session.authMethod === null) {
    return "This organisation requires two-step verification for owners and admins, and this session predates how BlakTail records it. Sign out, sign in again, then retry.";
  }
  if (identity.hasPassword && identity.twoFactorEnabled) {
    return "This organisation requires two-step verification for owners and admins, and this session did not use it. Sign out, sign in again with your two-step code, then retry.";
  }
  return "This organisation requires two-step verification for owners and admins. Turn it on under Settings, Account security, then retry.";
}

/** Linking a new sign-in identity always needs a recent sign-in. */
export const LINK_MAX_AGE_MINUTES = 15;

/**
 * Linking a single sign-on identity to the signed-in account grants it the
 * account's roles, so a stale or stolen session must not be able to do it.
 * The organisation's step-up window applies when it is tighter.
 */
export function linkFreshnessRefusal(
  policy: SignInPolicy,
  sessionCreatedAt: Date,
  now: Date = new Date(),
): string | null {
  const maxAge = Math.min(
    policy.stepUpMaxAgeMinutes ?? LINK_MAX_AGE_MINUTES,
    LINK_MAX_AGE_MINUTES,
  );
  const ageMs = now.getTime() - sessionCreatedAt.getTime();
  if (Number.isFinite(ageMs) && ageMs >= 0 && ageMs <= maxAge * 60_000) {
    return null;
  }
  return `Linking a sign-in identity needs a sign-in within the last ${maxAge} minutes. Sign out and sign in again, then link it from Settings.`;
}

export function parseStepUpMinutes(value: unknown): number | null {
  const text = String(value ?? "").trim();
  if (!text || text === "0") return null;
  const minutes = Number(text);
  if (
    !Number.isInteger(minutes) ||
    minutes < STEP_UP_MIN_MINUTES ||
    minutes > STEP_UP_MAX_MINUTES
  ) {
    throw new Error(
      `Re-authentication window must be ${STEP_UP_MIN_MINUTES}-${STEP_UP_MAX_MINUTES} minutes, or empty for none.`,
    );
  }
  return minutes;
}

// Sign-in domain verification by DNS TXT.

export const DOMAIN_TXT_PREFIX = "_blaktail-challenge";
export const DOMAIN_TXT_VALUE_PREFIX = "blaktail-domain-verification=";

export function normaliseDomain(input: string): string {
  const domain = input.trim().toLowerCase().replace(/\.$/, "");
  if (
    domain.length < 3 ||
    domain.length > 253 ||
    !domain.includes(".") ||
    !domain
      .split(".")
      .every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) ||
    /^[0-9.]+$/.test(domain)
  ) {
    throw new Error("Enter a domain name such as example.org.au.");
  }
  return domain;
}

export function domainTxtName(domain: string): string {
  return `${DOMAIN_TXT_PREFIX}.${domain}`;
}

export function domainTxtValue(token: string): string {
  return `${DOMAIN_TXT_VALUE_PREFIX}${token}`;
}

/** TXT answers arrive as chunked strings; a record proves only when exact. */
export function txtRecordsProve(records: string[][], token: string): boolean {
  const expected = domainTxtValue(token);
  return records.some((chunks) => chunks.join("").trim() === expected);
}

export function emailDomain(email: string | undefined | null): string | null {
  const domain = email?.split("@")[1]?.trim().toLowerCase();
  return domain || null;
}

/**
 * Just-in-time membership by email domain. A domain verified by another
 * organisation is never claimable here. Once this organisation verifies any
 * domain, JIT accepts only provider-verified emails in its verified domains;
 * before that the provider's allow-list applies as it always has.
 */
export function jitDomainRefusal(
  email: string | undefined | null,
  verifiedHere: readonly string[],
  verifiedElsewhere: readonly string[],
  emailVerified: unknown = false,
): string | null {
  const domain = emailDomain(email);
  if (domain && verifiedElsewhere.includes(domain)) {
    return "That email domain is verified by another organisation.";
  }
  if (verifiedHere.length === 0) return null;
  // An unverified email proves nothing about domain ownership.
  if (emailVerified !== true) {
    return "Just-in-time membership needs an email address your identity provider has verified.";
  }
  if (!domain || !verifiedHere.includes(domain)) {
    return "Just-in-time membership needs an email in one of this organisation's verified domains.";
  }
  return null;
}
