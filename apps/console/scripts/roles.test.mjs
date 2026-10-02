import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import {
  ORG_ROLES,
  PERMISSION_MATRIX,
  can,
  isOrgRole,
  membershipSignature,
  ownerChangeRefusal,
  permissionReason,
  resolveOrganisationRole,
} from "../src/lib/roles.ts";
import {
  domainTxtName,
  domainTxtValue,
  jitDomainRefusal,
  mfaRefusal,
  normaliseDomain,
  parseStepUpMinutes,
  stepUpRefusal,
  txtRecordsProve,
} from "../src/lib/auth-policy-core.ts";

const fixture = JSON.parse(
  readFileSync(new URL("../../../docs/permission-matrix.json", import.meta.url), "utf8"),
);

describe("permission matrix", () => {
  test("matches docs/permission-matrix.json, which the coordinator also tests", () => {
    expect([...ORG_ROLES].sort()).toEqual(Object.keys(fixture.roles).sort());
    for (const role of ORG_ROLES) {
      for (const permission of fixture.permissions) {
        expect([role, permission, can(role, permission)]).toEqual([
          role,
          permission,
          fixture.roles[role].includes(permission),
        ]);
      }
      expect([...PERMISSION_MATRIX[role]].sort()).toEqual([...fixture.roles[role]].sort());
    }
  });

  test("unknown roles fail closed", () => {
    for (const value of ["superuser", "Owner", "", "service", undefined]) {
      expect(isOrgRole(value)).toBe(false);
      expect(can(value, "view_network")).toBe(false);
    }
  });

  test("disabled controls explain who can", () => {
    expect(permissionReason("owner", "manage_security")).toBeNull();
    const reason = permissionReason("network_admin", "manage_security");
    expect(reason).toContain("network admin role cannot");
    expect(reason).toContain("owner");
    expect(permissionReason("auditor", "manage_peers")).toContain("network admin");
  });
});

describe("linked identities never escalate across organisations", () => {
  const rows = [
    // One person: owner of A through identity 1, member of B through identity 2.
    { organisationId: "A", membershipId: "a1", role: "owner", effectiveRole: null, membershipSignature: null },
    { organisationId: "B", membershipId: "b2", role: "member", effectiveRole: null, membershipSignature: null },
  ];

  test("each organisation sees only its own membership role", () => {
    expect(resolveOrganisationRole(rows, "A")).toBe("owner");
    expect(resolveOrganisationRole(rows, "B")).toBe("member");
    expect(resolveOrganisationRole(rows, "C")).toBeNull();
  });

  test("two identities in one organisation with different roles are blocked until an owner decides", () => {
    const conflict = [
      { organisationId: "B", membershipId: "b1", role: "auditor", effectiveRole: null, membershipSignature: null },
      { organisationId: "B", membershipId: "b2", role: "network_admin", effectiveRole: null, membershipSignature: null },
    ];
    expect(resolveOrganisationRole(conflict, "B")).toBe("blocked");
    const signature = membershipSignature(conflict);
    const decided = conflict.map((row) => ({
      ...row,
      effectiveRole: "auditor",
      membershipSignature: signature,
    }));
    expect(resolveOrganisationRole(decided, "B")).toBe("auditor");
    // A decision naming a role neither membership holds is ignored.
    const escalated = decided.map((row) => ({ ...row, effectiveRole: "owner" }));
    expect(resolveOrganisationRole(escalated, "B")).toBe("blocked");
    // A stale decision (memberships changed since) is ignored.
    const stale = decided.map((row) => ({ ...row, membershipSignature: "old" }));
    expect(resolveOrganisationRole(stale, "B")).toBe("blocked");
  });

  test("a step-up satisfied for a lax organisation does not satisfy a strict one", () => {
    const signedIn = new Date("2026-10-02T00:00:00Z");
    const now = new Date("2026-10-02T00:30:00Z");
    const lax = { stepUpMaxAgeMinutes: null, requireMfaForPrivileged: false };
    const strict = { stepUpMaxAgeMinutes: 10, requireMfaForPrivileged: false };
    expect(stepUpRefusal(lax, signedIn, now)).toBeNull();
    expect(stepUpRefusal(strict, signedIn, now)).toContain("10 minutes");
  });
});

describe("last-owner protection", () => {
  const seat = (membershipId, role, status = "active", hasPassword = false) => ({
    membershipId,
    role,
    status,
    hasPassword,
  });

  test("the last active owner cannot be demoted, suspended or removed", () => {
    const seats = [seat("o1", "owner", "active", true), seat("m1", "member")];
    expect(ownerChangeRefusal(seats, { membershipId: "o1", role: "admin" })).toContain("last active owner");
    expect(ownerChangeRefusal(seats, { membershipId: "o1", status: "suspended" })).toContain("last active owner");
    expect(ownerChangeRefusal(seats, { membershipId: "o1", status: "removed" })).toContain("last active owner");
    expect(ownerChangeRefusal(seats, { membershipId: "m1", role: "network_admin" })).toBeNull();
  });

  test("a suspended second owner does not count", () => {
    const seats = [seat("o1", "owner", "active", true), seat("o2", "owner", "suspended", true)];
    expect(ownerChangeRefusal(seats, { membershipId: "o1", role: "auditor" })).not.toBeNull();
  });

  test("the break-glass password owner is kept while one exists", () => {
    const seats = [seat("pw", "owner", "active", true), seat("sso", "owner", "active", false)];
    expect(ownerChangeRefusal(seats, { membershipId: "pw", role: "admin" })).toContain("password");
    expect(ownerChangeRefusal(seats, { membershipId: "sso", role: "admin" })).toBeNull();
    // Promoting another password owner first makes the demotion safe.
    const more = [...seats, seat("pw2", "owner", "active", true)];
    expect(ownerChangeRefusal(more, { membershipId: "pw", role: "admin" })).toBeNull();
  });

  test("organisations with only SSO owners can still rotate owners", () => {
    const seats = [seat("a", "owner"), seat("b", "owner")];
    expect(ownerChangeRefusal(seats, { membershipId: "a", role: "member" })).toBeNull();
  });
});

describe("step-up and MFA policy", () => {
  const signedIn = new Date("2026-10-02T00:00:00Z");
  const at = (minutes) => new Date(signedIn.getTime() + minutes * 60_000);
  const policy = { stepUpMaxAgeMinutes: 15, requireMfaForPrivileged: true };

  test("step-up allows a recent sign-in and refuses an old one", () => {
    expect(stepUpRefusal(policy, signedIn, at(14))).toBeNull();
    expect(stepUpRefusal(policy, signedIn, at(16))).not.toBeNull();
    // A clock-skewed future session is not treated as fresh.
    expect(stepUpRefusal(policy, at(5), signedIn)).not.toBeNull();
  });

  test("MFA is required for privileged password identities only", () => {
    const password = { hasPassword: true, twoFactorEnabled: false };
    expect(mfaRefusal(policy, "owner", password)).toContain("two-step");
    expect(mfaRefusal(policy, "admin", password)).toContain("two-step");
    expect(mfaRefusal(policy, "network_admin", password)).toBeNull();
    expect(mfaRefusal(policy, "owner", { hasPassword: true, twoFactorEnabled: true })).toBeNull();
    expect(mfaRefusal(policy, "owner", { hasPassword: false, twoFactorEnabled: false })).toBeNull();
    expect(mfaRefusal({ ...policy, requireMfaForPrivileged: false }, "owner", password)).toBeNull();
  });

  test("re-authentication window is bounded", () => {
    expect(parseStepUpMinutes("")).toBeNull();
    expect(parseStepUpMinutes("0")).toBeNull();
    expect(parseStepUpMinutes("30")).toBe(30);
    expect(() => parseStepUpMinutes("2")).toThrow();
    expect(() => parseStepUpMinutes("1441")).toThrow();
    expect(() => parseStepUpMinutes("7.5")).toThrow();
  });
});

describe("sign-in domains", () => {
  test("normalises and rejects non-domains", () => {
    expect(normaliseDomain(" Example.Org.AU. ")).toBe("example.org.au");
    for (const bad of ["localhost", "10.0.0.1", "-bad.example", "a..b", "exa mple.com", "x"]) {
      expect(() => normaliseDomain(bad)).toThrow();
    }
  });

  test("TXT proof must match exactly, chunks joined", () => {
    const token = "abc123";
    expect(domainTxtName("example.org.au")).toBe("_blaktail-challenge.example.org.au");
    expect(txtRecordsProve([["blaktail-domain-verification=", "abc123"]], token)).toBe(true);
    expect(txtRecordsProve([[domainTxtValue("abc1234")]], token)).toBe(false);
    expect(txtRecordsProve([["v=spf1 -all"]], token)).toBe(false);
    expect(txtRecordsProve([], token)).toBe(false);
  });

  test("JIT never claims a domain verified by another organisation", () => {
    expect(jitDomainRefusal("a@other.org", [], ["other.org"])).toContain("another organisation");
    expect(jitDomainRefusal("a@mine.org", ["mine.org"], [])).toBeNull();
    expect(jitDomainRefusal("a@gmail.com", ["mine.org"], [])).toContain("verified domains");
    // No verified domains yet: the provider allow-list applies as before.
    expect(jitDomainRefusal("a@anything.org", [], [])).toBeNull();
  });
});
