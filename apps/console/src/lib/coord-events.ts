import "server-only";

import type { AuditFilters } from "./audit-view";
import { coordFetch, readError, type AuditEvent } from "./coord";
import { permissionReason } from "./roles";
import type { ConsoleContext } from "./session";

export type ChainReport = {
  intact: boolean;
  chained_events: number;
  unchained_events: number;
  first_seq: number | null;
  last_seq: number | null;
  head_seq: number;
  problems: string[];
  note: string;
};

export type TrafficSettings = {
  enabled: boolean;
  sampling_rate: number;
  retention_days: number;
  updated_at: number | null;
  updated_by: string;
};

export type TrafficCounter = { bytes: number; packets: number; records: number };

export type TrafficSummary = {
  settings: TrafficSettings;
  state: "disabled" | "no_data" | "stale" | "current";
  window_hours: number;
  generated_at: number;
  last_received_at: number | null;
  allowed: TrafficCounter;
  denied: TrafficCounter;
  by_transport: Record<string, TrafficCounter>;
  by_service: Record<string, TrafficCounter>;
  /** `inbound`, `outbound` or `unknown` (records that do not say). */
  by_direction?: Record<string, TrafficCounter>;
  buckets: { start: number; allowed: TrafficCounter; denied: TrafficCounter }[];
  confidence: {
    source: string;
    level: "none" | "low" | "partial" | "high";
    sampling_rate: number;
    reporting_devices: number;
    active_devices: number;
    detail: string;
  };
};

export type EventKind = {
  event_type: string;
  severity: "info" | "notice" | "warning";
  summary: string;
};

async function json<T>(ctx: ConsoleContext, path: string, init: RequestInit = {}): Promise<T> {
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}${path}`, { ...init, ctx });
  if (!res.ok) throw new Error(await readError(res));
  return res.json() as Promise<T>;
}

export function listAuditPage(ctx: ConsoleContext, query: URLSearchParams): Promise<AuditEvent[]> {
  return json(ctx, `/audit?${query.toString()}`, { method: "GET" });
}

/** Coordinator export; the coordinator checks export_audit and audits it. */
export async function exportCoordinatorAudit(
  ctx: ConsoleContext,
  filters: AuditFilters,
): Promise<{ data: AuditEvent[]; truncated: boolean }> {
  const denied = permissionReason(ctx.role, "export_audit");
  if (denied) throw new Error(denied);
  const query = new URLSearchParams({ format: "json" });
  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined && value !== "") query.set(key, String(value));
  }
  return json(ctx, `/audit/export?${query.toString()}`, { method: "GET" });
}

export function verifyAuditChain(ctx: ConsoleContext): Promise<ChainReport> {
  return json(ctx, "/audit/verify", { method: "GET" });
}

export function getTrafficSummary(ctx: ConsoleContext, hours: number): Promise<TrafficSummary> {
  return json(ctx, `/traffic/summary?hours=${hours}`, { method: "GET" });
}

export function putTrafficSettings(
  ctx: ConsoleContext,
  input: { enabled: boolean; sampling_rate: number; retention_days: number },
): Promise<TrafficSettings> {
  const denied = permissionReason(ctx.role, "manage_security");
  if (denied) throw new Error(denied);
  return json(ctx, "/traffic/settings", { method: "PUT", body: JSON.stringify(input) });
}

export function deleteTrafficRecords(ctx: ConsoleContext): Promise<{ deleted: number }> {
  const denied = permissionReason(ctx.role, "manage_security");
  if (denied) throw new Error(denied);
  return json(ctx, "/traffic/records", { method: "DELETE" });
}

export function listEventCatalogue(ctx: ConsoleContext): Promise<EventKind[]> {
  return json(ctx, "/events/catalogue", { method: "GET" });
}

export function setWebhookSubscriptions(
  ctx: ConsoleContext,
  destinationId: string,
  eventTypes: string[],
): Promise<{ destination_id: string; event_types: string[] }> {
  const denied = permissionReason(ctx.role, "manage_integrations");
  if (denied) throw new Error(denied);
  return json(ctx, `/webhooks/${encodeURIComponent(destinationId)}/subscriptions`, {
    method: "PUT",
    body: JSON.stringify({ event_types: eventTypes }),
  });
}
