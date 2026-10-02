export type OrgRole = "owner" | "admin" | "member";

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
  | "manage_security";

export function can(role: OrgRole, permission: Permission): boolean {
  switch (role) {
    case "owner":
      return true;
    case "admin":
      return permission !== "manage_security";
    case "member":
      return permission === "view_network" || permission === "view_audit";
  }
}

export function canMutateTailnet(role: OrgRole): boolean {
  return role === "owner" || role === "admin";
}

export function permissionReason(role: OrgRole, permission: Permission): string | null {
  return can(role, permission)
    ? null
    : `Your ${roleLabel(role).toLowerCase()} role cannot do this here. Ask an organisation owner.`;
}

export function roleLabel(role: OrgRole): string {
  switch (role) {
    case "owner":
      return "Owner";
    case "admin":
      return "Admin";
    case "member":
      return "Member";
  }
}
