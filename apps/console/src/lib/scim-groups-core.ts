// SCIM 2.0 Group resource (RFC 7643 section 4.2) and the PATCH forms that
// Entra ID, Okta and similar providers send (RFC 7644 section 3.5.2).

export const GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group";
export const PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
export const LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
export const MAX_GROUP_MEMBERS = 5_000;

export type ScimGroupInput = {
  displayName: string;
  externalId: string | null;
  memberIds: string[];
};

export type GroupPatchOp =
  | { kind: "add" | "remove" | "replace"; memberIds: string[] }
  | { kind: "rename"; displayName: string }
  | { kind: "externalId"; externalId: string | null };

function displayName(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 256 || /[\u0000-\u001f]/.test(trimmed)) return null;
  return trimmed;
}

function memberValues(value: unknown): string[] | null {
  if (value === undefined || value === null) return [];
  const list = Array.isArray(value) ? value : [value];
  const ids: string[] = [];
  for (const entry of list) {
    const id =
      entry && typeof entry === "object" ? (entry as { value?: unknown }).value : undefined;
    if (typeof id !== "string" || !id.trim() || id.length > 255) return null;
    ids.push(id.trim());
  }
  return ids.length > MAX_GROUP_MEMBERS ? null : [...new Set(ids)];
}

export function parseScimGroup(body: unknown): ScimGroupInput | null {
  if (!body || typeof body !== "object") return null;
  const record = body as Record<string, unknown>;
  const name = displayName(record.displayName);
  if (!name) return null;
  const memberIds = memberValues(record.members);
  if (!memberIds) return null;
  const externalId =
    typeof record.externalId === "string" && record.externalId.trim()
      ? record.externalId.trim().slice(0, 255)
      : null;
  return { displayName: name, externalId, memberIds };
}

/** `members[value eq "id"]` -> id */
function memberFilterPath(path: string): string | null {
  const match = path.match(/^members\[\s*value\s+eq\s+"([^"]+)"\s*\]$/i);
  return match?.[1]?.trim() ?? null;
}

/** Parsed operations, or null when any operation is unsupported. */
export function parseGroupPatch(body: unknown): GroupPatchOp[] | null {
  if (!body || typeof body !== "object") return null;
  const operations = (body as { Operations?: unknown }).Operations;
  if (!Array.isArray(operations) || operations.length === 0) return null;
  const out: GroupPatchOp[] = [];
  for (const operation of operations) {
    if (!operation || typeof operation !== "object") return null;
    const op = String((operation as { op?: unknown }).op ?? "").toLowerCase();
    const rawPath = (operation as { path?: unknown }).path;
    const path = typeof rawPath === "string" ? rawPath.trim() : "";
    const value = (operation as { value?: unknown }).value;
    if (op !== "add" && op !== "remove" && op !== "replace") return null;
    if (path.toLowerCase() === "members") {
      const ids = memberValues(value);
      if (!ids) return null;
      if (op === "remove" && ids.length === 0) {
        out.push({ kind: "replace", memberIds: [] });
      } else {
        out.push({ kind: op, memberIds: ids });
      }
      continue;
    }
    const filtered = path ? memberFilterPath(path) : null;
    if (filtered) {
      if (op !== "remove") return null;
      out.push({ kind: "remove", memberIds: [filtered] });
      continue;
    }
    if (path.toLowerCase() === "displayname") {
      if (op === "remove") return null;
      const name = displayName(value);
      if (!name) return null;
      out.push({ kind: "rename", displayName: name });
      continue;
    }
    if (path.toLowerCase() === "externalid") {
      out.push({
        kind: "externalId",
        externalId: op === "remove" || typeof value !== "string" ? null : value.trim().slice(0, 255),
      });
      continue;
    }
    if (!path && op !== "remove" && value && typeof value === "object") {
      const record = value as Record<string, unknown>;
      for (const key of Object.keys(record)) {
        if (key === "displayName") {
          const name = displayName(record.displayName);
          if (!name) return null;
          out.push({ kind: "rename", displayName: name });
        } else if (key === "members") {
          const ids = memberValues(record.members);
          if (!ids) return null;
          out.push({ kind: op as "add" | "replace", memberIds: ids });
        } else if (key === "externalId") {
          out.push({
            kind: "externalId",
            externalId: typeof record.externalId === "string" ? record.externalId.trim() : null,
          });
        } else if (key !== "id" && key !== "schemas") {
          return null;
        }
      }
      continue;
    }
    return null;
  }
  return out;
}

/** Apply parsed member operations to a current member list. */
export function applyMemberOps(current: readonly string[], ops: readonly GroupPatchOp[]): string[] {
  let members = new Set(current);
  for (const op of ops) {
    if (op.kind === "add") op.memberIds.forEach((id) => members.add(id));
    else if (op.kind === "remove") op.memberIds.forEach((id) => members.delete(id));
    else if (op.kind === "replace") members = new Set(op.memberIds);
  }
  return [...members].sort();
}

export function scimGroupResource(input: {
  id: string;
  displayName: string;
  externalId: string | null;
  members: { value: string; display: string }[];
  created: Date;
  lastModified: Date;
}) {
  return {
    schemas: [GROUP_SCHEMA],
    id: input.id,
    ...(input.externalId ? { externalId: input.externalId } : {}),
    displayName: input.displayName,
    members: input.members.map((member) => ({
      value: member.value,
      display: member.display,
      $ref: `../Users/${member.value}`,
      type: "User",
    })),
    meta: {
      resourceType: "Group",
      created: input.created.toISOString(),
      lastModified: input.lastModified.toISOString(),
      location: `/api/scim/v2/Groups/${input.id}`,
    },
  };
}

export function scimListResponse<T>(resources: T[], startIndex = 1, total = resources.length) {
  return {
    schemas: [LIST_SCHEMA],
    totalResults: total,
    startIndex,
    itemsPerPage: resources.length,
    Resources: resources,
  };
}

/** `displayName eq "x"` -> x; any other filter is unsupported (null). */
export function displayNameFilter(filter: string | null): string | null {
  if (!filter) return null;
  const match = filter.match(/^displayName\s+eq\s+"([^"]+)"$/i);
  return match?.[1]?.trim() ?? null;
}

/** RFC 7644 pagination: 1-based startIndex, count capped at 200. */
export function pagination(params: URLSearchParams): { startIndex: number; count: number } {
  const start = Number(params.get("startIndex") ?? 1);
  const count = Number(params.get("count") ?? 100);
  return {
    startIndex: Number.isInteger(start) && start > 0 ? start : 1,
    count: Number.isInteger(count) && count >= 0 ? Math.min(count, 200) : 100,
  };
}

export function scimErrorBody(detail: string, status: number, scimType?: string) {
  return {
    schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
    status: String(status),
    ...(scimType ? { scimType } : {}),
    detail,
  };
}
