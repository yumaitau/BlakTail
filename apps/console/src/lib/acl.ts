import { ORG_ROLES, type OrgRole } from "./roles";

export type AclTag = "office" | "ranger" | "store";

export const ACL_ROLES: OrgRole[] = [...ORG_ROLES];
export const ACL_TAGS: AclTag[] = ["office", "ranger", "store"];

export type AclPerson = {
  userId: string;
  email: string;
  name: string;
};

export const ACL_PROTOCOLS = ["tcp", "udp", "icmp"] as const;
export type AclProtocol = (typeof ACL_PROTOCOLS)[number];

export type AclRuleDraft = {
  action: "allow" | "deny";
  src_roles: OrgRole[];
  src_tags: AclTag[];
  src_groups: string[];
  dst_roles: OrgRole[];
  dst_tags: AclTag[];
  dst_groups: string[];
  dst_hosts: string[];
  dst_ports: string[];
  protocols: AclProtocol[];
};

export const ACL_SSH_ACTIONS = ["allow", "deny", "check"] as const;
export type AclSshAction = (typeof ACL_SSH_ACTIONS)[number];

export type AclSshDraft = {
  action: AclSshAction;
  src_roles: OrgRole[];
  src_tags: AclTag[];
  src_groups: string[];
  dst_roles: OrgRole[];
  dst_tags: AclTag[];
  dst_groups: string[];
  users: string[];
  check_period_secs: string;
};

export const ACL_DEFAULTS = ["same_tag", "deny"] as const;
export type AclDefaults = (typeof ACL_DEFAULTS)[number];

export type AclGeneratedRule = {
  kind: string;
  action?: string;
  applies?: string[];
  note?: string;
};

export type AclPolicyDraft = {
  version: number;
  defaults: AclDefaults;
  etag: string;
  revision: number;
  has_previous: boolean;
  generated: AclGeneratedRule[];
  groups: { name: string; members: string[] }[];
  hosts: { name: string; target: string }[];
  tag_owners: { tag: string; owners: string[] }[];
  rules: AclRuleDraft[];
  ssh: AclSshDraft[];
  tests: unknown[];
};

function asStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

function asRoleArray(value: unknown): OrgRole[] {
  return asStringArray(value).filter((item): item is OrgRole =>
    ACL_ROLES.includes(item as OrgRole),
  );
}

function asTagArray(value: unknown): AclTag[] {
  return asStringArray(value).filter((item): item is AclTag =>
    ACL_TAGS.includes(item as AclTag),
  );
}

export function emptyRule(): AclRuleDraft {
  return {
    action: "allow",
    src_roles: [],
    src_tags: [],
    src_groups: [],
    dst_roles: [],
    dst_tags: [],
    dst_groups: [],
    dst_hosts: [],
    dst_ports: [],
    protocols: [],
  };
}

export function emptySshRule(): AclSshDraft {
  return {
    action: "allow",
    src_roles: [],
    src_tags: [],
    src_groups: [],
    dst_roles: [],
    dst_tags: [],
    dst_groups: [],
    users: [],
    check_period_secs: "",
  };
}

export function parseAclPolicy(value: unknown): AclPolicyDraft {
  const source =
    value && typeof value === "object" ? (value as Record<string, unknown>) : {};
  const groupsValue = source.groups;
  const groups =
    groupsValue && typeof groupsValue === "object" && !Array.isArray(groupsValue)
      ? Object.entries(groupsValue as Record<string, unknown>).map(
          ([name, members]) => ({
            name,
            members: asStringArray(members),
          }),
        )
      : [];
  const rules = Array.isArray(source.rules)
    ? source.rules.map((rule) => {
        const row =
          rule && typeof rule === "object"
            ? (rule as Record<string, unknown>)
            : {};
        return {
          action: row.action === "deny" ? "deny" : "allow",
          src_roles: asRoleArray(row.src_roles),
          src_tags: asTagArray(row.src_tags),
          src_groups: asStringArray(row.src_groups),
          dst_roles: asRoleArray(row.dst_roles),
          dst_tags: asTagArray(row.dst_tags),
          dst_groups: asStringArray(row.dst_groups),
          dst_hosts: asStringArray(row.dst_hosts),
          dst_ports: asStringArray(row.dst_ports),
          protocols: asStringArray(row.protocols).filter((item): item is AclProtocol =>
            ACL_PROTOCOLS.includes(item as AclProtocol),
          ),
        } satisfies AclRuleDraft;
      })
    : [];
  const ssh = Array.isArray(source.ssh)
    ? source.ssh.map((rule) => {
        const row =
          rule && typeof rule === "object"
            ? (rule as Record<string, unknown>)
            : {};
        const action = ACL_SSH_ACTIONS.includes(row.action as AclSshAction)
          ? (row.action as AclSshAction)
          : "allow";
        return {
          action,
          src_roles: asRoleArray(row.src_roles),
          src_tags: asTagArray(row.src_tags),
          src_groups: asStringArray(row.src_groups),
          dst_roles: asRoleArray(row.dst_roles),
          dst_tags: asTagArray(row.dst_tags),
          dst_groups: asStringArray(row.dst_groups),
          users: asStringArray(row.users),
          check_period_secs:
            typeof row.check_period_secs === "number"
              ? String(row.check_period_secs)
              : typeof row.check_period_secs === "string"
                ? row.check_period_secs
                : "",
        } satisfies AclSshDraft;
      })
    : [];
  const tagOwnersValue = source.tag_owners;
  const tag_owners =
    tagOwnersValue && typeof tagOwnersValue === "object" && !Array.isArray(tagOwnersValue)
      ? Object.entries(tagOwnersValue as Record<string, unknown>).map(
          ([tag, owners]) => ({
            tag,
            owners: asStringArray(owners),
          }),
        )
      : [];
  const hostsValue = source.hosts;
  const hosts =
    hostsValue && typeof hostsValue === "object" && !Array.isArray(hostsValue)
      ? Object.entries(hostsValue as Record<string, unknown>).map(([name, target]) => ({
          name,
          target: typeof target === "string" ? target : "",
        }))
      : [];
  const tests = Array.isArray(source.tests) ? source.tests : [];
  const version = source.version === 1 || source.version === undefined ? 1 : Number(source.version);
  const generated = Array.isArray(source.generated)
    ? source.generated.flatMap((entry) => {
        if (!entry || typeof entry !== "object") {
          return [];
        }
        const row = entry as Record<string, unknown>;
        return [
          {
            kind: typeof row.kind === "string" ? row.kind : "legacy_same_tag",
            action: typeof row.action === "string" ? row.action : undefined,
            applies: asStringArray(row.applies),
            note: typeof row.note === "string" ? row.note : undefined,
          } satisfies AclGeneratedRule,
        ];
      })
    : [];
  return {
    version: Number.isFinite(version) ? version : 1,
    defaults: source.defaults === "deny" ? "deny" : "same_tag",
    etag: typeof source.etag === "string" ? source.etag : "",
    revision: typeof source.revision === "number" ? source.revision : 1,
    has_previous: source.has_previous === true,
    generated,
    groups,
    hosts,
    tag_owners,
    rules,
    ssh,
    tests,
  };
}

export function validGroupName(name: string): boolean {
  return /^[a-z][a-z0-9-]{0,31}$/u.test(name);
}

export function personLabel(person: AclPerson): string {
  return person.name ? `${person.name} (${person.email})` : person.email;
}

export function memberLabel(member: string, people: AclPerson[]): string {
  const match = people.find(
    (person) =>
      person.userId === member ||
      person.email.toLowerCase() === member.toLowerCase(),
  );
  return match ? personLabel(match) : member;
}

export function expandGroupMembers(
  selected: string[],
  people: AclPerson[],
): string[] {
  const members = new Set<string>();
  for (const value of selected) {
    const trimmed = value.trim();
    if (!trimmed) continue;
    members.add(trimmed);
    const person = people.find(
      (candidate) =>
        candidate.userId === trimmed ||
        candidate.email.toLowerCase() === trimmed.toLowerCase(),
    );
    if (!person) continue;
    members.add(person.email);
    members.add(person.userId);
  }
  return [...members];
}

function compact<T>(key: string, values: T[]): Record<string, T[]> {
  return values.length > 0 ? { [key]: values } : {};
}

export function serializeAclPolicy(policy: AclPolicyDraft): Record<string, unknown> {
  const groups = Object.fromEntries(
    policy.groups
      .map((group) => [
        group.name.trim(),
        [...new Set(group.members.map((member) => member.trim()).filter(Boolean))],
      ])
      .filter(([name, members]) => name && (members as string[]).length > 0),
  );
  const tag_owners = Object.fromEntries(
    policy.tag_owners
      .map((entry) => [
        entry.tag.trim(),
        [...new Set(entry.owners.map((owner) => owner.trim()).filter(Boolean))],
      ])
      .filter(([tag, owners]) => tag && (owners as string[]).length > 0),
  );
  const hosts = Object.fromEntries(
    policy.hosts
      .map((entry) => [entry.name.trim(), entry.target.trim()])
      .filter(([name, target]) => name && target),
  );
  return {
    version: policy.version || 1,
    defaults: policy.defaults,
    groups,
    ...(Object.keys(tag_owners).length > 0 ? { tag_owners } : {}),
    ...(Object.keys(hosts).length > 0 ? { hosts } : {}),
    ...(policy.tests.length > 0 ? { tests: policy.tests } : {}),
    ...(policy.ssh.length > 0
      ? {
          ssh: policy.ssh.map((rule) => {
            const period = Number.parseInt(rule.check_period_secs, 10);
            return {
              action: rule.action,
              ...compact("src_roles", rule.src_roles),
              ...compact("src_tags", rule.src_tags),
              ...compact("src_groups", rule.src_groups),
              ...compact("dst_roles", rule.dst_roles),
              ...compact("dst_tags", rule.dst_tags),
              ...compact("dst_groups", rule.dst_groups),
              users: rule.users.map((user) => user.trim()).filter(Boolean),
              ...(rule.action === "check" && Number.isFinite(period) && period > 0
                ? { check_period_secs: period }
                : {}),
            };
          }),
        }
      : {}),
    rules: policy.rules.map((rule) => ({
      action: rule.action,
      ...compact("src_roles", rule.src_roles),
      ...compact("src_tags", rule.src_tags),
      ...compact("src_groups", rule.src_groups),
      ...compact("dst_roles", rule.dst_roles),
      ...compact("dst_tags", rule.dst_tags),
      ...compact("dst_groups", rule.dst_groups),
      ...compact("dst_hosts", rule.dst_hosts),
      ...compact("dst_ports", rule.dst_ports),
      ...compact("protocols", rule.protocols),
    })),
  };
}
