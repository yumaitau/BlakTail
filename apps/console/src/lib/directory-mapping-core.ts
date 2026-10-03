// Pure rules for directory group -> role mapping (draft 15). The database
// side lives in directory-mapping.ts; scripts/directory-mapping.test.mjs
// exercises this file directly.

import { ORG_ROLES, isOrgRole, ownerChangeRefusal, type OrgRole } from "./roles";

export type MappingSource = "scim" | "oidc";

export type GroupRoleMapping = {
  id?: string;
  source: MappingSource;
  groupName: string;
  role: OrgRole;
};

export type DirectorySettings = {
  /** Off by default: no directory group can make someone an owner. */
  allowOwnerMapping: boolean;
  /** Days a deprovisioned member stays suspended before the tombstone. */
  deprovisionGraceDays: number;
};

export const DEFAULT_DIRECTORY_SETTINGS: DirectorySettings = {
  allowOwnerMapping: false,
  deprovisionGraceDays: 7,
};

export const MAX_GRACE_DAYS = 90;

export type MemberState = {
  membershipId: string;
  email: string;
  role: OrgRole;
  status: string;
  /** "directory" once a mapping set the role; "manual" otherwise. */
  roleSource: "manual" | "directory";
  hasPassword: boolean;
  scimGroups: readonly string[];
  oidcGroups: readonly string[];
};

export type DriftChange = {
  membershipId: string;
  email: string;
  from: OrgRole;
  to: OrgRole;
  /** Mapped groups that produced `to`; empty when falling back to member. */
  groups: string[];
  /** Why the change will not be applied, or null. */
  blocked: string | null;
};

export function normaliseGroupName(name: string): string {
  return name.trim().toLowerCase();
}

export function parseGroupName(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 256 || /[\u0000-\u001f]/.test(trimmed)) return null;
  return trimmed;
}

export function parseGraceDays(value: unknown): number | null {
  const days = typeof value === "number" ? value : Number(String(value ?? "").trim());
  if (!Number.isInteger(days) || days < 0 || days > MAX_GRACE_DAYS) return null;
  return days;
}

/** Higher is more privileged. */
export function roleRank(role: OrgRole): number {
  return ORG_ROLES.length - ORG_ROLES.indexOf(role);
}

export function mappingRefusal(
  mapping: { role: OrgRole },
  settings: DirectorySettings,
): string | null {
  if (!isOrgRole(mapping.role)) return "Choose one of the listed roles.";
  if (mapping.role === "owner" && !settings.allowOwnerMapping) {
    return "Directory groups cannot grant owner unless an owner first allows owner mapping.";
  }
  return null;
}

/**
 * The role directory groups give this member: the highest mapped role wins.
 * With no matching group, a role a mapping set earlier falls back to member;
 * a role an owner set by hand is left alone (null).
 */
export function desiredRole(
  member: Pick<MemberState, "roleSource" | "scimGroups" | "oidcGroups">,
  mappings: readonly GroupRoleMapping[],
  settings: DirectorySettings,
): { role: OrgRole | null; groups: string[] } {
  const scim = new Set(member.scimGroups.map(normaliseGroupName));
  const oidc = new Set(member.oidcGroups.map(normaliseGroupName));
  const matched = mappings.filter((mapping) => {
    if (mappingRefusal(mapping, settings)) return false;
    const name = normaliseGroupName(mapping.groupName);
    return mapping.source === "scim" ? scim.has(name) : oidc.has(name);
  });
  if (matched.length === 0) {
    return { role: member.roleSource === "directory" ? "member" : null, groups: [] };
  }
  const top = Math.max(...matched.map((mapping) => roleRank(mapping.role)));
  const winners = matched.filter((mapping) => roleRank(mapping.role) === top);
  return {
    role: winners[0]!.role,
    groups: winners.map((mapping) => `${mapping.source}:${mapping.groupName}`).sort(),
  };
}

/**
 * What applying the mappings now would change. Owners are left alone unless
 * owner mapping is allowed, and no change may remove the last active owner
 * or the last active password owner (break-glass); those come back blocked.
 */
export function planDrift(
  members: readonly MemberState[],
  mappings: readonly GroupRoleMapping[],
  settings: DirectorySettings,
): DriftChange[] {
  let seats = members.map((member) => ({
    membershipId: member.membershipId,
    role: member.role,
    status: member.status,
    hasPassword: member.hasPassword,
  }));
  const ordered = [...members].sort(
    (a, b) => a.email.localeCompare(b.email) || a.membershipId.localeCompare(b.membershipId),
  );
  const changes: DriftChange[] = [];
  for (const member of ordered) {
    if (member.status !== "active" && member.status !== "suspended") continue;
    if (member.role === "owner" && !settings.allowOwnerMapping) continue;
    const desired = desiredRole(member, mappings, settings);
    if (!desired.role || desired.role === member.role) continue;
    const refusal = ownerChangeRefusal(seats, {
      membershipId: member.membershipId,
      role: desired.role,
    });
    if (!refusal) {
      seats = seats.map((seat) =>
        seat.membershipId === member.membershipId ? { ...seat, role: desired.role! } : seat,
      );
    }
    changes.push({
      membershipId: member.membershipId,
      email: member.email,
      from: member.role,
      to: desired.role,
      groups: desired.groups,
      blocked: refusal,
    });
  }
  return changes;
}

/** Stable token for the applicable part of a preview (optimistic check). */
export function planSignature(changes: readonly DriftChange[]): string {
  return changes
    .filter((change) => !change.blocked)
    .map((change) => `${change.membershipId}:${change.from}>${change.to}`)
    .sort()
    .join("|");
}

export type GraceState = "active" | "in_grace" | "expired" | "tombstoned" | "other";

export function deprovisionDeadline(now: Date, graceDays: number): Date {
  return new Date(now.getTime() + graceDays * 24 * 60 * 60 * 1000);
}

export function graceState(
  member: { status: string; deprovisionAt: Date | null; tombstonedAt: Date | null },
  now: Date,
): GraceState {
  if (member.tombstonedAt) return "tombstoned";
  if (member.status === "active") return "active";
  if (member.status !== "suspended" || !member.deprovisionAt) return "other";
  return member.deprovisionAt.getTime() <= now.getTime() ? "expired" : "in_grace";
}

/**
 * Membership update for a SCIM (de)activation. Deactivation suspends at once
 * (access stops immediately) and starts the grace period; reactivation inside
 * the grace keeps the role; reactivating a tombstone starts again as member.
 */
export function scimActivation(
  member: { role: OrgRole; status: string; deprovisionAt: Date | null; tombstonedAt: Date | null },
  active: boolean,
  settings: DirectorySettings,
  now: Date,
): {
  status: "active" | "suspended" | "removed";
  role: OrgRole;
  roleSource?: "manual";
  deprovisionAt: Date | null;
  tombstonedAt: Date | null;
} {
  if (active) {
    if (member.tombstonedAt) {
      return {
        status: "active",
        role: "member",
        roleSource: "manual",
        deprovisionAt: null,
        tombstonedAt: null,
      };
    }
    return { status: "active", role: member.role, deprovisionAt: null, tombstonedAt: null };
  }
  if (member.tombstonedAt) {
    return {
      status: "removed",
      role: member.role,
      deprovisionAt: member.deprovisionAt,
      tombstonedAt: member.tombstonedAt,
    };
  }
  if (settings.deprovisionGraceDays === 0) {
    return { status: "removed", role: member.role, deprovisionAt: now, tombstonedAt: now };
  }
  return {
    status: "suspended",
    role: member.role,
    deprovisionAt:
      member.status === "suspended" && member.deprovisionAt
        ? member.deprovisionAt
        : deprovisionDeadline(now, settings.deprovisionGraceDays),
    tombstonedAt: null,
  };
}
