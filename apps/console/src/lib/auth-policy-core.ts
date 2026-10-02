// Pure sign-in assurance rules. No I/O here so bun tests can pin them.
import type { OrgRole } from "./roles";

export type SignInPolicy = {
  /** Security changes need a sign-in at most this many minutes old. */
  stepUpMaxAgeMinutes: number | null;
  /** Owners and admins with a password sign-in must have TOTP enabled. */
  requireMfaForPrivileged: boolean;
};

export const DEFAULT_SIGN_IN_POLICY: SignInPolicy = {
  stepUpMaxAgeMinutes: null,
  requireMfaForPrivileged: false,
};

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

/**
 * MFA applies to password sign-ins of privileged roles. Single sign-on
 * identities authenticate at the organisation's identity provider, whose own
 * MFA policy applies; BlakTail cannot add a second factor to that flow.
 */
export function mfaRefusal(
  policy: SignInPolicy,
  role: OrgRole,
  identity: { hasPassword: boolean; twoFactorEnabled: boolean },
): string | null {
  if (!policy.requireMfaForPrivileged) return null;
  if (!MFA_PRIVILEGED_ROLES.includes(role)) return null;
  if (!identity.hasPassword || identity.twoFactorEnabled) return null;
  return "This organisation requires two-step verification for owners and admins. Turn it on under Settings, Account security, then retry.";
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
 * domain, JIT accepts only its verified domains; before that the provider's
 * allow-list applies as it always has.
 */
export function jitDomainRefusal(
  email: string | undefined | null,
  verifiedHere: readonly string[],
  verifiedElsewhere: readonly string[],
): string | null {
  const domain = emailDomain(email);
  if (domain && verifiedElsewhere.includes(domain)) {
    return "That email domain is verified by another organisation.";
  }
  if (verifiedHere.length === 0) return null;
  if (!domain || !verifiedHere.includes(domain)) {
    return "Just-in-time membership needs an email in one of this organisation's verified domains.";
  }
  return null;
}
