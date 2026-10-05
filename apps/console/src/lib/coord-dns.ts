import "server-only";

import {
  coordFetch,
  coordError,
  type DeviceTag,
  type OrgDnsResponse,
  type OrgDnsSettings,
  type ZoneRecordType,
} from "./coord";
import { can } from "./roles";
import type { ConsoleContext } from "./session";

export const DNS_CONFLICT_MESSAGE =
  "Someone else published a newer revision; reload to see it before publishing again.";

export type DnsRevisionSummary = {
  split: number;
  records: number;
  nameserver_groups: number;
  zones: number;
  zone_records: number;
};

export type DnsRevision = {
  revision: number;
  created_at: number;
  current: boolean;
  summary: DnsRevisionSummary;
};

export type DnsRevisionDocument = {
  revision: number;
  created_at: number;
  dns: OrgDnsSettings;
};

export type DnsValidation = {
  dns: OrgDnsSettings;
  warnings: string[];
};

export type DnsAnswerKind =
  | "magic_dns"
  | "zone"
  | "zone_nxdomain"
  | "legacy_record"
  | "forward"
  | "not_handled"
  | "unmanaged";

export type DnsPreview = {
  name: string;
  node_id: string | null;
  node_name: string | null;
  tags: DeviceTag[];
  managed: boolean;
  answer: DnsAnswerKind;
  matched_suffix: string | null;
  zone: string | null;
  nameserver_group: string | null;
  resolvers: string[];
  records: { name: string; type: ZoneRecordType; value: string; ttl: number }[];
  detail: string;
  candidates: {
    suffix: string;
    source: "zone" | "group" | "split";
    label: string;
    applies: boolean;
  }[];
};

export type DnsPublishBody =
  | { dns: OrgDnsSettings }
  | { rollback: true }
  | { rollback_to: number };

function dnsPath(ctx: ConsoleContext, suffix = ""): string {
  return `/v1/orgs/${ctx.coordOrgId}/dns${suffix}`;
}

export async function publishDns(
  ctx: ConsoleContext,
  body: DnsPublishBody,
  etag: string,
): Promise<OrgDnsResponse> {
  if (!can(ctx.role, "manage_dns")) {
    throw new Error("Your role cannot publish DNS settings.");
  }
  const res = await coordFetch(dnsPath(ctx), {
    method: "PUT",
    ctx,
    headers: { "If-Match": etag },
    body: JSON.stringify(body),
  });
  if (res.status === 412) {
    throw new Error(DNS_CONFLICT_MESSAGE);
  }
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json() as Promise<OrgDnsResponse>;
}

export async function listDnsRevisions(
  ctx: ConsoleContext,
): Promise<DnsRevision[]> {
  const res = await coordFetch(dnsPath(ctx, "/revisions"), {
    method: "GET",
    ctx,
  });
  if (!res.ok) {
    throw await coordError(res);
  }
  const body = (await res.json()) as { revisions: DnsRevision[] };
  return body.revisions;
}

export async function getDnsRevision(
  ctx: ConsoleContext,
  revision: number,
): Promise<DnsRevisionDocument> {
  const res = await coordFetch(
    dnsPath(ctx, `/revisions/${encodeURIComponent(String(revision))}`),
    { method: "GET", ctx },
  );
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json() as Promise<DnsRevisionDocument>;
}

export async function validateDns(
  ctx: ConsoleContext,
  dns: OrgDnsSettings,
): Promise<DnsValidation> {
  const res = await coordFetch(dnsPath(ctx, "/validate"), {
    method: "POST",
    ctx,
    body: JSON.stringify({ dns }),
  });
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json() as Promise<DnsValidation>;
}

export async function previewDns(
  ctx: ConsoleContext,
  input: { name: string; nodeId?: string; tags?: DeviceTag[] },
): Promise<DnsPreview> {
  const params = new URLSearchParams({ name: input.name });
  if (input.nodeId) {
    params.set("node_id", input.nodeId);
  } else if (input.tags && input.tags.length > 0) {
    params.set("tags", input.tags.join(","));
  }
  const res = await coordFetch(dnsPath(ctx, `/preview?${params.toString()}`), {
    method: "GET",
    ctx,
  });
  if (!res.ok) {
    throw await coordError(res);
  }
  return res.json() as Promise<DnsPreview>;
}
