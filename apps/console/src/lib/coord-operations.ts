import "server-only";

import { readFile } from "node:fs/promises";
import path from "node:path";
import { coordFetch, readError } from "./coord";
import { rawSqlClient } from "./db/client";
import { permissionReason } from "./roles";
import type { ConsoleContext } from "./session";

export type RelayHealth = {
  endpoint: string;
  region: string;
  status: "reachable" | "unreachable" | "unresolved" | "not_probed";
  round_trip_ms: number | null;
};

export type OperationsHealth = {
  generated_at: number;
  coordinator: { version: string; region: string; database_backend: string };
  schema: {
    applied_version: number;
    supported_version: number;
    latest_migration: string;
    status: "current" | "behind" | "ahead";
  };
  relays: RelayHealth[];
  webhooks: {
    pending: number;
    due_now: number;
    dead_letters: number;
    oldest_pending_age_seconds: number | null;
  };
  expiry: {
    node_credentials_expired: number;
    node_credentials_expiring_14_days: number;
    service_certificates_expiring_30_days: number;
    service_ca_expiring_30_days: number;
    api_clients_expiring_14_days: number;
  };
  backup: {
    status: "recorded" | "not_recorded" | "unreadable";
    completed_at: number | null;
    restore_verified_at: number | null;
    label: string | null;
  };
};

export type ConsoleOperations = {
  version: string;
  migrations: { applied: number | null; packaged: number | null };
  sso: { configured: number; enabled: number };
};

function requireOperationsPermission(ctx: ConsoleContext) {
  const denied = permissionReason(ctx.role, "view_operations");
  if (denied) throw new Error(denied);
}

export async function getOperationsHealth(ctx: ConsoleContext): Promise<OperationsHealth> {
  requireOperationsPermission(ctx);
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}/operations/health`, {
    method: "GET",
    ctx,
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json() as Promise<OperationsHealth>;
}

async function packagedMigrations(): Promise<number | null> {
  try {
    const journal = JSON.parse(
      await readFile(path.join(process.cwd(), "drizzle", "meta", "_journal.json"), "utf8"),
    ) as { entries?: unknown[] };
    return Array.isArray(journal.entries) ? journal.entries.length : null;
  } catch {
    return null;
  }
}

/** Console-side facts: version, Drizzle migration count, and this
 * organisation's SSO provider count. No issuer, client id or secret. */
export async function getConsoleOperations(ctx: ConsoleContext): Promise<ConsoleOperations> {
  requireOperationsPermission(ctx);
  const sql = rawSqlClient();
  let applied: number | null = null;
  try {
    const rows = (await sql`SELECT COUNT(*)::int AS count FROM drizzle.__drizzle_migrations`) as {
      count: number;
    }[];
    applied = rows[0]?.count ?? null;
  } catch {
    applied = null;
  }
  const providers = (await sql`
    SELECT COUNT(*)::int AS configured,
           COUNT(*) FILTER (WHERE enabled)::int AS enabled
    FROM identity_provider
    WHERE organisation_id = ${ctx.organisationId}
  `) as { configured: number; enabled: number }[];
  return {
    version: process.env.BLAKTAIL_CONSOLE_VERSION?.trim() || process.env.npm_package_version || "unknown",
    migrations: { applied, packaged: await packagedMigrations() },
    sso: {
      configured: providers[0]?.configured ?? 0,
      enabled: providers[0]?.enabled ?? 0,
    },
  };
}
