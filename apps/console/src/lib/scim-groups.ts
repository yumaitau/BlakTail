import { writeConsoleAudit } from "./console-audit";
import { rawSqlClient } from "./db/client";
import { ScimError } from "./scim";
import {
  applyMemberOps,
  scimGroupResource,
  scimListResponse,
  type GroupPatchOp,
  type ScimGroupInput,
} from "./scim-groups-core";

type Sql = ReturnType<typeof rawSqlClient>;

type GroupRow = {
  id: string;
  display_name: string;
  external_id: string | null;
  created_at: Date | string;
  updated_at: Date | string;
};

async function membersOf(sql: Sql, groupIds: string[]) {
  if (groupIds.length === 0) return new Map<string, { value: string; display: string }[]>();
  const rows = await sql`
    SELECT gm.group_id, u.id, u.email
    FROM scim_group_member gm JOIN "user" u ON u.id = gm.user_id
    WHERE gm.group_id IN (SELECT jsonb_array_elements_text(CAST(${JSON.stringify(groupIds)} AS jsonb)))
    ORDER BY lower(u.email)
  `;
  const out = new Map<string, { value: string; display: string }[]>();
  for (const row of rows as Array<Record<string, unknown>>) {
    const list = out.get(String(row.group_id)) ?? [];
    list.push({ value: String(row.id), display: String(row.email) });
    out.set(String(row.group_id), list);
  }
  return out;
}

function resource(row: GroupRow, members: { value: string; display: string }[]) {
  return scimGroupResource({
    id: row.id,
    displayName: row.display_name,
    externalId: row.external_id,
    members,
    created: new Date(row.created_at),
    lastModified: new Date(row.updated_at),
  });
}

export async function listScimGroups(
  organisationId: string,
  displayName: string | null,
  page: { startIndex: number; count: number },
) {
  const sql = rawSqlClient();
  const rows = (displayName
    ? await sql`
        SELECT id, display_name, external_id, created_at, updated_at FROM scim_group
        WHERE organisation_id = ${organisationId} AND lower(display_name) = lower(${displayName})
        ORDER BY lower(display_name), id
      `
    : await sql`
        SELECT id, display_name, external_id, created_at, updated_at FROM scim_group
        WHERE organisation_id = ${organisationId}
        ORDER BY lower(display_name), id
      `) as GroupRow[];
  const slice = rows.slice(page.startIndex - 1, page.startIndex - 1 + page.count);
  const members = await membersOf(sql, slice.map((row) => row.id));
  return scimListResponse(
    slice.map((row) => resource(row, members.get(row.id) ?? [])),
    page.startIndex,
    rows.length,
  );
}

async function loadGroup(sql: Sql, organisationId: string, groupId: string): Promise<GroupRow> {
  const [row] = (await sql`
    SELECT id, display_name, external_id, created_at, updated_at FROM scim_group
    WHERE id = ${groupId} AND organisation_id = ${organisationId}
  `) as GroupRow[];
  if (!row) throw new ScimError("Group was not found.", 404);
  return row;
}

export async function getScimGroup(organisationId: string, groupId: string) {
  const sql = rawSqlClient();
  const row = await loadGroup(sql, organisationId, groupId);
  const members = await membersOf(sql, [row.id]);
  return resource(row, members.get(row.id) ?? []);
}

/** Members must already be provisioned into this organisation. */
async function requireOrgMembers(sql: Sql, organisationId: string, userIds: string[]) {
  if (userIds.length === 0) return;
  const rows = await sql`
    SELECT user_id FROM membership
    WHERE organisation_id = ${organisationId}
      AND user_id IN (SELECT jsonb_array_elements_text(CAST(${JSON.stringify(userIds)} AS jsonb)))
  `;
  const known = new Set((rows as Array<{ user_id: string }>).map((row) => row.user_id));
  const missing = userIds.filter((id) => !known.has(id));
  if (missing.length > 0) {
    throw new ScimError(
      `Group members must be users provisioned in this organisation (unknown: ${missing.slice(0, 3).join(", ")}).`,
      400,
    );
  }
}

async function setMembers(sql: Sql, groupId: string, userIds: string[]) {
  await sql`DELETE FROM scim_group_member WHERE group_id = ${groupId}`;
  for (const userId of userIds) {
    await sql`
      INSERT INTO scim_group_member (group_id, user_id) VALUES (${groupId}, ${userId})
      ON CONFLICT DO NOTHING
    `;
  }
}

function audit(organisationId: string, action: string, groupId: string, details: Record<string, unknown>) {
  return writeConsoleAudit({
    organisationId,
    actorUserId: "system",
    actorEmail: "",
    actorRole: "system",
    source: "scim",
    action,
    result: "ok",
    targetType: "scim_group",
    targetId: groupId,
    details,
  });
}

function uniqueViolation(error: unknown): boolean {
  return String(error).includes("scim_group_org_name_unique");
}

export async function createScimGroup(organisationId: string, input: ScimGroupInput) {
  const sql = rawSqlClient();
  const id = crypto.randomUUID();
  try {
    await sql.begin(async (tx) => {
      const t = tx as unknown as Sql;
      await requireOrgMembers(t, organisationId, input.memberIds);
      await t`
        INSERT INTO scim_group (id, organisation_id, display_name, external_id)
        VALUES (${id}, ${organisationId}, ${input.displayName}, ${input.externalId})
      `;
      await setMembers(t, id, input.memberIds);
    });
  } catch (error) {
    if (uniqueViolation(error)) {
      throw new ScimError("A group with that displayName already exists.", 409);
    }
    throw error;
  }
  await audit(organisationId, "scim.group_created", id, {
    display_name: input.displayName,
    members: input.memberIds.length,
  });
  return getScimGroup(organisationId, id);
}

export async function patchScimGroup(organisationId: string, groupId: string, ops: GroupPatchOp[]) {
  const sql = rawSqlClient();
  let summary: Record<string, unknown> = {};
  try {
    await sql.begin(async (tx) => {
      const t = tx as unknown as Sql;
      const row = await loadGroup(t, organisationId, groupId);
      const current = (await t`
        SELECT user_id FROM scim_group_member WHERE group_id = ${groupId}
      `) as Array<{ user_id: string }>;
      const before = current.map((entry) => entry.user_id);
      const after = applyMemberOps(before, ops);
      const added = after.filter((id) => !before.includes(id));
      await requireOrgMembers(t, organisationId, added);
      let name = row.display_name;
      let externalId = row.external_id;
      for (const op of ops) {
        if (op.kind === "rename") name = op.displayName;
        if (op.kind === "externalId") externalId = op.externalId;
      }
      await t`
        UPDATE scim_group SET display_name = ${name}, external_id = ${externalId}, updated_at = now()
        WHERE id = ${groupId}
      `;
      await setMembers(t, groupId, after);
      summary = {
        display_name: name,
        previous_display_name: row.display_name === name ? undefined : row.display_name,
        added: added.length,
        removed: before.filter((id) => !after.includes(id)).length,
      };
    });
  } catch (error) {
    if (uniqueViolation(error)) {
      throw new ScimError("A group with that displayName already exists.", 409);
    }
    throw error;
  }
  await audit(organisationId, "scim.group_updated", groupId, summary);
  return getScimGroup(organisationId, groupId);
}

export async function replaceScimGroup(organisationId: string, groupId: string, input: ScimGroupInput) {
  return patchScimGroup(organisationId, groupId, [
    { kind: "rename", displayName: input.displayName },
    { kind: "externalId", externalId: input.externalId },
    { kind: "replace", memberIds: input.memberIds },
  ]);
}

export async function deleteScimGroup(organisationId: string, groupId: string) {
  const sql = rawSqlClient();
  const [deleted] = await sql`
    DELETE FROM scim_group WHERE id = ${groupId} AND organisation_id = ${organisationId}
    RETURNING display_name
  `;
  if (!deleted) throw new ScimError("Group was not found.", 404);
  await audit(organisationId, "scim.group_deleted", groupId, {
    display_name: deleted.display_name,
  });
}
