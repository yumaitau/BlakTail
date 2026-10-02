import "server-only";

import { coordFetch, type DeviceTag } from "./coord";
import type { ConsoleContext } from "./session";

export type ExplainProtocol = "tcp" | "udp" | "icmp";

export type ExplainRequest = {
  source_node_id?: string;
  source?: { user: string; role?: "owner" | "admin" | "member"; tags: DeviceTag[] };
  destination_node_id?: string;
  dst_host?: string;
  protocol?: ExplainProtocol;
  port?: number;
  ssh_user?: string;
};

export type ExplainSubject = {
  kind: "device" | "person" | "host";
  node_id?: string;
  name?: string;
  role: string;
  tags: DeviceTag[];
  user_id: string;
  groups: string[];
  posture?: { check: string; passed: boolean; reasons: string[] }[];
  os?: string;
  agent_version?: string;
  capabilities?: string[];
};

export type ExplainRule = {
  section: "rules" | "ssh";
  index: number;
  action: string;
  outcome: "matched" | "skipped_posture" | "skipped_check_expired";
  detail: string;
};

export type EnforcementState = "device_enforced" | "peer_map" | "not_enforced" | "unknown";

export type ExplainResult = {
  simulated: boolean;
  evaluated_at: number;
  policy: { revision: number; etag: string; defaults: string; published: boolean };
  source: ExplainSubject;
  destination: ExplainSubject;
  dst_host?: string;
  protocol: ExplainProtocol | null;
  port: number | null;
  ssh_user?: string;
  decision: "allow" | "deny";
  basis: string;
  deny_precedence: boolean;
  rules: ExplainRule[];
  pairing?: {
    source_map_includes_destination: boolean;
    destination_map_includes_source: boolean;
  };
  compiled_ingress?: Record<string, unknown>;
  enforcement: {
    state: EnforcementState;
    detail: string;
    destination: { packet_filter: string; ssh_users: boolean; detail: string };
  };
  reasons: string[];
};

export type PostureDefinition = {
  description?: string;
  min_agent_version?: string;
  os_families?: string[];
  min_os_versions?: Record<string, string>;
  max_credential_age_secs?: number;
  max_report_age_secs?: number;
  require_approved_peer?: boolean;
  on_missing_data?: "fail" | "pass";
};

export type PostureCheck = {
  id: string;
  name: string;
  version: number;
  definition: PostureDefinition;
  created_at: number;
  updated_at: number;
  referenced_by: string[];
};

export type PostureReason = { text: string; source: "agent_reported" | "coordinator_observed" };

export type DeviceAssessment = {
  node_id: string;
  name: string;
  display_name: string | null;
  os: string | null;
  os_version: string | null;
  agent_version: string | null;
  capabilities: string[];
  inventory_reported_at: number;
  credential_issued_at: number;
  enforcement: { packet_filter: string; ssh_users: boolean; detail: string };
  assessments: {
    check: string;
    version: number;
    passed: boolean;
    missing_data: boolean;
    reasons: PostureReason[];
    expires_at: number | null;
    affected_rules: string[];
  }[];
};

export type AssessmentReport = {
  evaluated_at: number;
  notice: string;
  devices: DeviceAssessment[];
};

async function request<T>(
  ctx: ConsoleContext,
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}${path}`, {
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
    if (res.status === 412) {
      message = "Someone else changed this posture check. Reload and try again.";
    }
    throw new Error(message);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export function explainAccess(ctx: ConsoleContext, input: ExplainRequest): Promise<ExplainResult> {
  return request(ctx, "/policy/explain", { method: "POST", body: JSON.stringify(input) });
}

export function listPostureChecks(ctx: ConsoleContext): Promise<PostureCheck[]> {
  return request(ctx, "/posture-checks", { method: "GET" });
}

export function createPostureCheck(
  ctx: ConsoleContext,
  name: string,
  definition: PostureDefinition,
): Promise<{ id: string; name: string; version: number }> {
  return request(ctx, "/posture-checks", {
    method: "POST",
    body: JSON.stringify({ name, definition }),
  });
}

export function updatePostureCheck(
  ctx: ConsoleContext,
  id: string,
  version: number,
  definition: PostureDefinition,
): Promise<{ id: string; name: string; version: number }> {
  return request(ctx, `/posture-checks/${encodeURIComponent(id)}`, {
    method: "PUT",
    body: JSON.stringify({ version, definition }),
  });
}

export function deletePostureCheck(ctx: ConsoleContext, id: string): Promise<void> {
  return request(ctx, `/posture-checks/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export function listPostureAssessments(ctx: ConsoleContext): Promise<AssessmentReport> {
  return request(ctx, "/posture-assessments", { method: "GET" });
}

export function getNodePosture(ctx: ConsoleContext, nodeId: string): Promise<AssessmentReport> {
  return request(ctx, `/nodes/${encodeURIComponent(nodeId)}/posture`, { method: "GET" });
}
