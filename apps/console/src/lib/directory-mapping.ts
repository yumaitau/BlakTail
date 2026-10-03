import "server-only";

import { requireSecurityAssurance } from "./auth-policy";
import { emitMembershipUpdated } from "./coord";
import { writeConsoleAudit } from "./console-audit";
import { rawSqlClient } from "./db/client";
import {
  DEFAULT_DIRECTORY_SETTINGS,
  graceState,
  mappingRefusal,
  parseGraceDays,
  parseGroupName,
  planDrift,
  planSignature,
  type DirectorySettings,
  type DriftChange,
  type GroupRoleMapping,
  type MappingSource,
  type MemberState,
} from "./directory-mapping-core";
import { isOrgRole, permissionReason, type OrgRole } from "./roles";
import type { ConsoleContext } from "./session";

type Sql = ReturnType<typeof rawSqlClient>;

export class DirectoryMappingError extends Error {}

function requireOwner(ctx: ConsoleContext) {
  const denied = permissionReason(ctx.role, "manage_security");
  if (denied) throw new DirectoryMappingError(denied);
}

export async function getDirectorySettings(
  organisationId: string,
  sql: Sql = rawSqlClient(),
): Promise<DirectorySettings> {
  const [row] = await sql`
    SELECT allow_owner_mapping, deprovision_grace_days
    FROM directory_sync_settings WHERE organisation_id = ${organisationId}
  `;
  if (!row) return { ...DEFAULT_DIRECTORY_SETTINGS };
  return {
    allowOwnerMapping: row.allow_owner_mapping === true,
    deprovisionGraceDays: Number(row.deprovision_grace_days),
  };
}

export async function listGroupMappings(organisationId: string): Promise<GroupRoleMapping[]> {
  const rows = await rawSqlClient()`
    SELECT id, source, group_name, role FROM directory_group_role_mapping
    WHERE organisation_id = ${organisationId}
    ORDER BY source, lower(group_name)
  `;
  return (rows as Array<Record<string, unknown>>).map((row) => ({
    id: String(row.id),
    source: row.source as MappingSource,
    groupName: String(row.group_name),
    role: row.role as OrgRole,
  }));
}

function audit(ctx: ConsoleContext, action: string, details: Record<string, unknown>, targetId?: string) {
  return writeConsoleAudit({
    organisationId: ctx.organisationId,
    actorUserId: ctx.userId,
    actorEmail: ctx.email,
    actorRole: ctx.role,
    source: "console",
    action,
    result: "ok",
    targetType: "directory_mapping",
    targetId,
    details,
  });
}

export async function saveDirectorySettings(
  ctx: ConsoleContext,
  input: { allowOwnerMapping: boolean; deprovisionGraceDays: unknown },
): Promise<void> {
  requireOwner(ctx);
  await requireSecurityAssurance(ctx);
  const graceDays = parseGraceDays(input.deprovisionGraceDays);
  if (graceDays === null) {
    throw new DirectoryMappingError("Grace period must be a whole number of days from 0 to 90.");
  }
  const previous = await getDirectorySettings(ctx.organisationId);
  await rawSqlClient()`
    INSERT INTO directory_sync_settings (
      organisation_id, allow_owner_mapping, deprovision_grace_days, updated_by_user_id, updated_at
    ) VALUES (${ctx.organisationId}, ${input.allowOwnerMapping}, ${graceDays}, ${ctx.userId}, now())
    ON CONFLICT (organisation_id) DO UPDATE SET
      allow_owner_mapping = EXCLUDED.allow_owner_mapping,
      deprovision_grace_days = EXCLUDED.deprovision_grace_days,
      updated_by_user_id = EXCLUDED.updated_by_user_id,
      updated_at = now()
  `;
  await audit(ctx, "directory.settings_updated", {
    allow_owner_mapping: input.allowOwnerMapping,
    deprovision_grace_days: graceDays,
    previous_allow_owner_mapping: previous.allowOwnerMapping,
    previous_deprovision_grace_days: previous.deprovisionGraceDays,
  });
}

export async function addGroupMapping(
  ctx: ConsoleContext,
  input: { source: unknown; groupName: unknown; role: unknown },
): Promise<void> {
  requireOwner(ctx);
  await requireSecurityAssurance(ctx);
  const source = input.source === "scim" || input.source === "oidc" ? input.source : null;
  if (!source) throw new DirectoryMappingError("Choose SCIM groups or OIDC groups claim.");
  const groupName = parseGroupName(input.groupName);
  if (!groupName) throw new DirectoryMappingError("Enter the group name exactly as the identity provider sends it.");
  if (!isOrgRole(input.role)) throw new DirectoryMappingError("Choose one of the listed roles.");
  const refusal = mappingRefusal({ role: input.role }, await getDirectorySettings(ctx.organisationId));
  if (refusal) throw new DirectoryMappingError(refusal);
  const id = crypto.randomUUID();
  try {
    await rawSqlClient()`
      INSERT INTO directory_group_role_mapping (id, organisation_id, source, group_name, role, created_by_user_id)
      VALUES (${id}, ${ctx.organisationId}, ${source}, ${groupName}, ${input.role}, ${ctx.userId})
    `;
  } catch (error) {
    if (String(error).includes("directory_group_role_mapping_unique")) {
      throw new DirectoryMappingError("That group already has a mapping. Remove it first.");
    }
    throw error;
  }
  await audit(ctx, "directory.mapping_added", { source, group_name: groupName, role: input.role }, id);
}

export async function removeGroupMapping(ctx: ConsoleContext, mappingId: string): Promise<void> {
  requireOwner(ctx);
  await requireSecurityAssurance(ctx);
  const [removed] = await rawSqlClient()`
    DELETE FROM directory_group_role_mapping
    WHERE id = ${mappingId} AND organisation_id = ${ctx.organisationId}
    RETURNING source, group_name, role
  `;
  if (!removed) throw new DirectoryMappingError("Mapping was not found.");
  await audit(
    ctx,
    "directory.mapping_removed",
    { source: removed.source, group_name: removed.group_name, role: removed.role },
    mappingId,
  );
}

async function loadMemberStates(sql: Sql, organisationId: string): Promise<MemberState[]> {
  const rows = await sql`
    SELECT m.id, m.role, m.status, m.role_source, m.idp_groups_json, u.email,
      EXISTS (
        SELECT 1 FROM account a
        WHERE a.user_id = m.user_id AND a.provider_id = 'credential' AND a.password IS NOT NULL
      ) AS has_password,
      COALESCE((
        SELECT jsonb_agg(g.display_name)
        FROM scim_group_member gm JOIN scim_group g ON g.id = gm.group_id
        WHERE gm.user_id = m.user_id AND g.organisation_id = m.organisation_id
      ), '[]'::jsonb) AS scim_groups
    FROM membership m JOIN "user" u ON u.id = m.user_id
    WHERE m.organisation_id = ${organisationId} AND m.tombstoned_at IS NULL
  `;
  const list = (value: unknown): string[] => {
    const parsed = typeof value === "string" ? JSON.parse(value) : value;
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
  };
  return (rows as Array<Record<string, unknown>>).map((row) => ({
    membershipId: String(row.id),
    email: String(row.email),
    role: row.role as OrgRole,
    status: String(row.status),
    roleSource: row.role_source === "directory" ? "directory" : "manual",
    hasPassword: row.has_password === true,
    scimGroups: list(row.scim_groups),
    oidcGroups: list(row.idp_groups_json),
  }));
}

export type DeprovisionRow = {
  membershipId: string;
  email: string;
  role: OrgRole;
  deprovisionAt: string | null;
  tombstonedAt: string | null;
  state: "in_grace" | "expired" | "tombstoned";
};

async function listDeprovisioned(organisationId: string): Promise<DeprovisionRow[]> {
  const rows = await rawSqlClient()`
    SELECT m.id, m.role, m.status, m.deprovision_at, m.tombstoned_at, u.email
    FROM membership m JOIN "user" u ON u.id = m.user_id
    WHERE m.organisation_id = ${organisationId}
      AND (m.deprovision_at IS NOT NULL OR m.tombstoned_at IS NOT NULL)
    ORDER BY m.deprovision_at NULLS LAST, u.email
    LIMIT 200
  `;
  const now = new Date();
  const out: DeprovisionRow[] = [];
  for (const row of rows as Array<Record<string, unknown>>) {
    const deprovisionAt = row.deprovision_at ? new Date(String(row.deprovision_at)) : null;
    const tombstonedAt = row.tombstoned_at ? new Date(String(row.tombstoned_at)) : null;
    const state = graceState({ status: String(row.status), deprovisionAt, tombstonedAt }, now);
    if (state !== "in_grace" && state !== "expired" && state !== "tombstoned") continue;
    out.push({
      membershipId: String(row.id),
      email: String(row.email),
      role: row.role as OrgRole,
      deprovisionAt: deprovisionAt?.toISOString() ?? null,
      tombstonedAt: tombstonedAt?.toISOString() ?? null,
      state,
    });
  }
  return out;
}

/**
 * Turns suspended members whose grace period has passed into tombstones
 * (status removed, row kept for audit). Owners are never tombstoned here.
 */
export async function sweepDeprovisioned(organisationId: string): Promise<number> {
  const rows = await rawSqlClient()`
    UPDATE membership SET status = 'removed', tombstoned_at = now()
    WHERE organisation_id = ${organisationId}
      AND status = 'suspended' AND role <> 'owner'
      AND deprovision_at IS NOT NULL AND deprovision_at <= now()
      AND tombstoned_at IS NULL
    RETURNING id
  `;
  for (const row of rows as Array<{ id: string }>) {
    await writeConsoleAudit({
      organisationId,
      actorUserId: "system",
      actorEmail: "",
      actorRole: "system",
      source: "scim",
      action: "membership.tombstoned",
      result: "ok",
      targetType: "membership",
      targetId: row.id,
      details: { reason: "deprovision grace period ended" },
    });
  }
  return rows.length;
}

export type DriftPreview = {
  settings: DirectorySettings;
  changes: DriftChange[];
  signature: string;
  deprovisioned: DeprovisionRow[];
};

export async function previewDirectoryDrift(ctx: ConsoleContext): Promise<DriftPreview> {
  requireOwner(ctx);
  await sweepDeprovisioned(ctx.organisationId);
  const sql = rawSqlClient();
  const [settings, mappings, members, deprovisioned] = await Promise.all([
    getDirectorySettings(ctx.organisationId, sql),
    listGroupMappings(ctx.organisationId),
    loadMemberStates(sql, ctx.organisationId),
    listDeprovisioned(ctx.organisationId),
  ]);
  const changes = planDrift(members, mappings, settings);
  return { settings, changes, signature: planSignature(changes), deprovisioned };
}

/**
 * Applies exactly the previewed changes. The plan is recomputed inside a
 * serializable transaction; if it no longer matches the preview the owner
 * must preview again. Blocked changes (last owner) are never applied.
 */
export async function applyDirectoryDrift(
  ctx: ConsoleContext,
  previewSignature: string,
): Promise<{ applied: DriftChange[]; blocked: DriftChange[] }> {
  requireOwner(ctx);
  await requireSecurityAssurance(ctx);
  const mappings = await listGroupMappings(ctx.organisationId);
  const outcome = await rawSqlClient().begin("isolation level serializable", async (tx) => {
    const settings = await getDirectorySettings(ctx.organisationId, tx as unknown as Sql);
    const members = await loadMemberStates(tx as unknown as Sql, ctx.organisationId);
    const changes = planDrift(members, mappings, settings);
    const statuses = new Map(members.map((member) => [member.membershipId, member.status]));
    if (planSignature(changes) !== previewSignature) {
      return { stale: true as const };
    }
    const applied = changes.filter((change) => !change.blocked);
    for (const change of applied) {
      await tx`
        UPDATE membership SET role = ${change.to}, role_source = 'directory'
        WHERE id = ${change.membershipId} AND organisation_id = ${ctx.organisationId}
          AND role = ${change.from}
      `;
    }
    return {
      stale: false as const,
      applied,
      blocked: changes.filter((change) => change.blocked),
      statuses,
    };
  });
  if (outcome.stale) {
    throw new DirectoryMappingError(
      "Memberships or directory groups changed since the preview. Preview again before applying.",
    );
  }
  for (const change of outcome.applied) {
    await writeConsoleAudit({
      organisationId: ctx.organisationId,
      actorUserId: ctx.userId,
      actorEmail: ctx.email,
      actorRole: ctx.role,
      source: "console",
      action: "membership.role_mapped",
      result: "ok",
      targetType: "membership",
      targetId: change.membershipId,
      details: { previous_role: change.from, role: change.to, groups: change.groups },
    });
    await emitMembershipUpdated(ctx, {
      membership_id: change.membershipId,
      role: change.to,
      status: outcome.statuses.get(change.membershipId) ?? "active",
      previous_role: change.from,
    });
  }
  await audit(ctx, "directory.mapping_applied", {
    applied: outcome.applied.length,
    blocked: outcome.blocked.map((change) => ({
      membership_id: change.membershipId,
      to: change.to,
      reason: change.blocked,
    })),
  });
  return { applied: outcome.applied, blocked: outcome.blocked };
}
