import "server-only";

import { coordFetch } from "./coord";
import type { ConsoleContext } from "./session";

export type ProviderKind = "intune" | "crowdstrike" | "sentinelone" | "fleetdm" | "huntress";

export type ProviderField = {
  name: "tenant_id" | "client_id" | "region" | "console_url" | "server_url" | "api_key";
  label: string;
  help: string;
  options?: string[];
};

/** Implemented providers only, served by the coordinator. */
export type ProviderInfo = {
  kind: ProviderKind;
  label: string;
  fields: ProviderField[];
  secret_label: string;
  access: string;
  data_collected: string;
  compliance_rule: string;
  residency: string;
};

export type ProviderConfig = Partial<Record<ProviderField["name"], string>> & {
  match_hostname?: boolean;
};

export type PostureIntegration = {
  id: string;
  kind: ProviderKind;
  provider: string;
  name: string;
  /** Configuration and credential metadata come only to security managers. */
  config?: ProviderConfig;
  /** A short hash so rotations are visible. The secret itself is write-only. */
  secret_fingerprint?: string;
  interval_secs: number;
  enabled: boolean;
  privacy_acknowledged_at: number;
  privacy_acknowledged_by?: string;
  created_at: number;
  updated_at: number;
  next_sync_at: number;
  last_attempt_at: number | null;
  last_success_at: number | null;
  consecutive_failures: number;
  outage_since: number | null;
  last_error: string | null;
  provider_devices: number;
  matched_devices: number;
  ambiguous_devices: number;
  /** Devices whose provider record a device that reported first keeps. */
  contested_devices: number;
  /** Devices whose changed hardware identifiers await approval. */
  identity_changes_pending: number;
  unmatched_devices: number;
  unmatched_records: number;
  referenced_by: string[];
};

export type IntegrationList = {
  residency_notice: string;
  providers: ProviderInfo[];
  integrations: PostureIntegration[];
};

export type SyncReport = {
  ok: boolean;
  devices: number;
  error_code?: string;
  error?: string;
  next_sync_at: number;
};

export type DeviceMatch =
  | { state: "unmatched" }
  | { state: "ambiguous"; candidates: number }
  | { state: "identity_changed" }
  | { state: "contested" }
  | {
      state: "matched";
      external_id: string;
      matched_by: "serial_number" | "mac_address" | "hostname";
      compliant: boolean | null;
      status: string;
      last_seen_at: number | null;
      synced_at: number;
    };

/** One integration's view of one device, as shown in device assessments. */
export type IntegrationFact = {
  integration_id: string;
  kind: ProviderKind;
  provider: string;
  name: string;
  enabled: boolean;
  last_success_at: number | null;
  outage_since: number | null;
  match: DeviceMatch;
  source: "provider_reported";
};

export type IntegrationRequirement = {
  integration_id: string;
  max_age_secs?: number;
  max_last_seen_secs?: number;
  on_outage?: "fail" | "pass";
};

async function request<T>(ctx: ConsoleContext, path: string, init: RequestInit = {}): Promise<T> {
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}/posture-integrations${path}`, {
    ...init,
    ctx,
  });
  if (!res.ok) {
    let message = `Coordinator returned ${res.status}`;
    try {
      const body = (await res.json()) as { error?: string };
      if (body.error) message = body.error;
    } catch {
      /* keep status message */
    }
    throw new Error(message);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export function listPostureIntegrations(ctx: ConsoleContext): Promise<IntegrationList> {
  return request(ctx, "", { method: "GET" });
}

export function createPostureIntegration(
  ctx: ConsoleContext,
  input: {
    kind: ProviderKind;
    name: string;
    config: ProviderConfig;
    secret: string;
    interval_secs: number;
    privacy_acknowledged: boolean;
  },
): Promise<{ id: string }> {
  return request(ctx, "", { method: "POST", body: JSON.stringify(input) });
}

export function updatePostureIntegration(
  ctx: ConsoleContext,
  id: string,
  input: { enabled?: boolean; secret?: string; interval_secs?: number },
): Promise<{ id: string }> {
  return request(ctx, `/${encodeURIComponent(id)}`, {
    method: "PUT",
    body: JSON.stringify(input),
  });
}

export function deletePostureIntegration(ctx: ConsoleContext, id: string): Promise<void> {
  return request(ctx, `/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export function syncPostureIntegration(ctx: ConsoleContext, id: string): Promise<SyncReport> {
  return request(ctx, `/${encodeURIComponent(id)}/sync`, { method: "POST" });
}

/** Accepts a device's changed serial number or MAC addresses as its new pins. */
export function approveDeviceHardware(ctx: ConsoleContext, nodeId: string): Promise<void> {
  return request(ctx, `/devices/${encodeURIComponent(nodeId)}/approve-hardware`, { method: "POST" });
}
