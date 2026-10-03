export type OrgRole = "owner" | "admin" | "network_admin" | "auditor" | "member";

/** Every role, most to least privileged. */
export const ORG_ROLES: readonly OrgRole[] = [
  "owner",
  "admin",
  "network_admin",
  "auditor",
  "member",
];

// Mirrors blaktail-coord/src/permissions.rs. The coordinator and server
// actions enforce these; the console only uses them to label affordances.
export type Permission =
  | "view_network"
  | "manage_peers"
  | "manage_join_keys"
  | "manage_networks"
  | "manage_policy"
  | "manage_dns"
  | "manage_services"
  | "view_audit"
  | "export_audit"
  | "manage_integrations"
  | "manage_api_clients"
  | "manage_security"
  | "view_operations"
  | "manage_public_ingress";

const NETWORK_WRITE: readonly Permission[] = [
  "manage_peers",
  "manage_join_keys",
  "manage_networks",
  "manage_policy",
  "manage_dns",
  "manage_services",
];

// Pinned to docs/permission-matrix.json by scripts/roles.test.mjs, which the
// coordinator's permissions.rs test also reads.
export const PERMISSION_MATRIX: Readonly<Record<OrgRole, readonly Permission[]>> = {
  owner: [
    "view_network",
    ...NETWORK_WRITE,
    "view_audit",
    "export_audit",
    "manage_integrations",
    "manage_api_clients",
    "manage_security",
    "view_operations",
    "manage_public_ingress",
  ],
  admin: [
    "view_network",
    ...NETWORK_WRITE,
    "view_audit",
    "export_audit",
    "manage_integrations",
  ],
  network_admin: ["view_network", ...NETWORK_WRITE, "view_audit"],
  auditor: ["view_network", "view_audit", "export_audit", "view_operations"],
  member: ["view_network", "view_audit"],
};

export function isOrgRole(value: unknown): value is OrgRole {
  return typeof value === "string" && (ORG_ROLES as readonly string[]).includes(value);
}

/** Unknown roles fail closed. */
export function can(role: OrgRole, permission: Permission): boolean {
  return isOrgRole(role) && PERMISSION_MATRIX[role].includes(permission);
}

/** @deprecated Use `can(role, permission)` with the specific permission. */
export function canMutateTailnet(role: OrgRole): boolean {
  return can(role, "manage_peers");
}

const PERMISSION_TASK: Record<Permission, string> = {
  view_network: "view this network",
  manage_peers: "change devices",
  manage_join_keys: "mint or revoke join keys",
  manage_networks: "change routes and network resources",
  manage_policy: "change access policy",
  manage_dns: "change DNS",
  manage_services: "publish private services",
  view_audit: "read the audit log",
  export_audit: "export audit records",
  manage_integrations: "manage webhooks and integrations",
  manage_api_clients: "manage automation credentials",
  manage_security: "change people, sign-in and security settings",
  view_operations: "read operator health",
  manage_public_ingress: "publish services to the Internet",
};

const HOLDERS: Record<Permission, string> = Object.fromEntries(
  (Object.keys(PERMISSION_TASK) as Permission[]).map((permission) => [
    permission,
    ORG_ROLES.filter((role) => PERMISSION_MATRIX[role].includes(permission))
      .map((role) => roleLabel(role).toLowerCase())
      .join(", "),
  ]),
) as Record<Permission, string>;

export function permissionReason(role: OrgRole, permission: Permission): string | null {
  if (can(role, permission)) return null;
  return `Your ${roleLabel(role).toLowerCase()} role cannot ${PERMISSION_TASK[permission]}. Roles that can: ${HOLDERS[permission]}.`;
}

export function roleLabel(role: OrgRole): string {
  switch (role) {
    case "owner":
      return "Owner";
    case "admin":
      return "Admin";
    case "network_admin":
      return "Network admin";
    case "auditor":
      return "Auditor";
    case "member":
      return "Member";
    default:
      return "Unknown role";
  }
}

/** Plain-language impact shown before assigning a role. */
export function roleImpact(role: OrgRole): string {
  switch (role) {
    case "owner":
      return "Full control, including people, sign-in policy, single sign-on, directory sync and automation credentials.";
    case "admin":
      return "Runs the network and its integrations: devices, join keys, routes, policy, DNS, services, webhooks and audit export. Cannot change people, sign-in or automation credentials.";
    case "network_admin":
      return "Runs the network only: devices, join keys, routes, policy, DNS and services. Cannot manage people, security, integrations, automation credentials or export audit.";
    case "auditor":
      return "Read-only: sees the network, the audit log and operator health, and can export audit records. Cannot change anything.";
    case "member":
      return "Uses the network: sees devices and the audit log and can enrol their own devices. Cannot change shared settings.";
    default:
      return "";
  }
}

export type OwnerSeat = {
  membershipId: string;
  role: OrgRole;
  status: string;
  /** Has a password sign-in, so it survives an identity-provider outage. */
  hasPassword: boolean;
};

/**
 * Last-owner protection for a proposed role/status change. An organisation
 * must keep an active owner, and must keep an active password owner if it
 * has one, so an IdP outage cannot lock every owner out.
 */
export function ownerChangeRefusal(
  seats: readonly OwnerSeat[],
  change: { membershipId: string; role?: OrgRole; status?: string },
): string | null {
  const isActiveOwner = (seat: OwnerSeat) => seat.role === "owner" && seat.status === "active";
  const after = seats.map((seat) =>
    seat.membershipId === change.membershipId
      ? { ...seat, role: change.role ?? seat.role, status: change.status ?? seat.status }
      : seat,
  );
  if (!after.some(isActiveOwner)) {
    return "The last active owner cannot be demoted, suspended or removed.";
  }
  const passwordOwners = (list: readonly OwnerSeat[]) =>
    list.filter((seat) => isActiveOwner(seat) && seat.hasPassword).length;
  if (passwordOwners(seats) > 0 && passwordOwners(after) === 0) {
    return "Keep at least one active owner who can sign in with a password. It is the break-glass path if single sign-on is down.";
  }
  return null;
}

export type OrganisationRoleRow = {
  organisationId: string;
  membershipId: string;
  role: OrgRole;
  effectiveRole: OrgRole | null;
  membershipSignature: string | null;
};

export function membershipSignature(
  rows: readonly { membershipId: string; role: OrgRole }[],
): string {
  return rows
    .map((row) => `${row.membershipId}:${row.role}`)
    .sort()
    .join("|");
}

/**
 * The role a linked person holds in one organisation. Only that
 * organisation's memberships count: a higher role elsewhere never carries
 * over. Differing roles inside one organisation need an owner decision that
 * still matches the current memberships; otherwise access is blocked.
 */
export function resolveOrganisationRole(
  rows: readonly OrganisationRoleRow[],
  organisationId: string,
): OrgRole | "blocked" | null {
  const group = rows.filter((row) => row.organisationId === organisationId);
  if (group.length === 0) return null;
  if (group.some((row) => !isOrgRole(row.role))) return "blocked";
  const distinct = new Set(group.map((row) => row.role));
  const first = group[0]!;
  if (distinct.size === 1) return first.role;
  if (
    first.effectiveRole &&
    first.membershipSignature === membershipSignature(group) &&
    distinct.has(first.effectiveRole)
  ) {
    return first.effectiveRole;
  }
  return "blocked";
}
