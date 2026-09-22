import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export type ScimUserInput = {
  userName: string;
  displayName: string;
  externalId: string;
  active: boolean;
};

export function hashScimToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function newScimToken(): { token: string; hash: string } {
  const token = `bts_${randomBytes(32).toString("base64url")}`;
  return { token, hash: hashScimToken(token) };
}

export function bearerToken(header: string | null): string | null {
  const match = header?.match(/^Bearer\s+(\S+)$/i);
  return match?.[1] ?? null;
}

export function tokenMatches(presented: string, expectedHash: string): boolean {
  const actual = Buffer.from(hashScimToken(presented));
  const expected = Buffer.from(expectedHash);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function parseScimUser(body: unknown): ScimUserInput | null {
  if (!body || typeof body !== "object") return null;
  const record = body as Record<string, unknown>;
  const userName = typeof record.userName === "string" ? record.userName.trim().toLowerCase() : "";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(userName)) return null;
  const name = record.name;
  const formatted =
    name && typeof name === "object" && typeof (name as { formatted?: unknown }).formatted === "string"
      ? (name as { formatted: string }).formatted.trim()
      : "";
  const displayName =
    (typeof record.displayName === "string" ? record.displayName.trim() : "") ||
    formatted ||
    userName;
  const externalId =
    typeof record.externalId === "string" && record.externalId.trim()
      ? record.externalId.trim()
      : userName;
  return {
    userName,
    displayName: displayName.slice(0, 128),
    externalId: externalId.slice(0, 255),
    active: record.active !== false,
  };
}

export function patchDeactivates(body: unknown): boolean | null {
  if (!body || typeof body !== "object") return null;
  const operations = (body as { Operations?: unknown }).Operations;
  if (!Array.isArray(operations)) {
    const active = (body as { active?: unknown }).active;
    return typeof active === "boolean" ? !active : null;
  }
  for (const operation of operations) {
    if (!operation || typeof operation !== "object") continue;
    const op = String((operation as { op?: unknown }).op ?? "").toLowerCase();
    if (op !== "replace") continue;
    const path = (operation as { path?: unknown }).path;
    const value = (operation as { value?: unknown }).value;
    if (path === "active" && typeof value === "boolean") return !value;
    if (
      (path === undefined || path === "") &&
      value &&
      typeof value === "object" &&
      typeof (value as { active?: unknown }).active === "boolean"
    ) {
      return !(value as { active: boolean }).active;
    }
  }
  return null;
}

export function scimUser(input: {
  id: string;
  userName: string;
  displayName: string;
  externalId: string;
  active: boolean;
}) {
  return {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    id: input.id,
    externalId: input.externalId,
    userName: input.userName,
    displayName: input.displayName,
    name: { formatted: input.displayName },
    active: input.active,
  };
}

export function scimList(resources: ReturnType<typeof scimUser>[]) {
  return {
    schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    totalResults: resources.length,
    startIndex: 1,
    itemsPerPage: resources.length,
    Resources: resources,
  };
}

export function userNameFilter(filter: string | null): string | null {
  if (!filter) return null;
  const match = filter.match(/^userName\s+eq\s+"([^"]+)"$/i);
  return match?.[1]?.trim().toLowerCase() ?? null;
}
