// Task-based homes. Each link must be backed by a real page and API; add a
// link here only when its page ships. Icons are resolved in the client nav.

export type NavIcon =
  | "control-center"
  | "devices"
  | "join-keys"
  | "access"
  | "networks"
  | "dns"
  | "services"
  | "agents"
  | "remote"
  | "team"
  | "activity"
  | "settings"
  | "operations"
  | "status";

export type NavLink = { href: string; label: string };

export type NavEntry = {
  id: string;
  label: string;
  icon: NavIcon;
  /** A leaf entry links directly; a group lists children. */
  href?: string;
  children?: NavLink[];
};

export const PRIMARY_NAV: NavEntry[] = [
  { id: "control-center", label: "Control Center", icon: "control-center", href: "/control-center" },
  { id: "devices", label: "Devices", icon: "devices", href: "/devices" },
  { id: "join-keys", label: "Join keys", icon: "join-keys", href: "/join-keys" },
  {
    id: "access",
    label: "Access",
    icon: "access",
    children: [
      { href: "/acls", label: "Policies" },
      { href: "/posture", label: "Posture checks" },
      { href: "/tunnel-protection", label: "Tunnel protection" },
    ],
  },
  {
    id: "networks",
    label: "Networks",
    icon: "networks",
    children: [
      { href: "/networks", label: "Networks" },
      { href: "/networks/addresses", label: "Addresses" },
      { href: "/networks#routes", label: "Routes" },
      { href: "/changes", label: "Change drafts" },
    ],
  },
  { id: "dns", label: "DNS", icon: "dns", href: "/dns" },
  {
    id: "services",
    label: "Services",
    icon: "services",
    children: [
      { href: "/services", label: "Private services" },
      { href: "/ingress", label: "Public ingress" },
    ],
  },
  { id: "agents", label: "Agents", icon: "agents", href: "/agents" },
  {
    id: "remote",
    label: "Remote",
    icon: "remote",
    children: [
      { href: "/remote-access", label: "Remote access" },
      { href: "/remote-jobs", label: "Remote jobs" },
    ],
  },
  { id: "team", label: "Team", icon: "team", href: "/settings#members" },
  {
    id: "activity",
    label: "Activity",
    icon: "activity",
    children: [
      { href: "/audit", label: "Audit log" },
      { href: "/traffic", label: "Traffic events" },
    ],
  },
];

export const SECONDARY_NAV: NavEntry[] = [
  { id: "settings", label: "Settings", icon: "settings", href: "/settings" },
  { id: "operations", label: "Operator health", icon: "operations", href: "/operations" },
  { id: "status", label: "Status", icon: "status", href: "/status" },
];

/** Whether `href` is the page being shown. Fragment links never claim it. */
export function isCurrent(current: string, href: string): boolean {
  if (href.includes("#")) return false;
  if (href === "/networks" && current.startsWith("/networks/addresses")) return false;
  return current === href || current.startsWith(`${href}/`);
}
