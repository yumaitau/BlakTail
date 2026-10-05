"use server";

import { errorText } from "@/lib/server-errors";
import { revalidatePath } from "next/cache";
import type { ActionResult } from "@/app/actions";
import type { DeviceTag, OrgDnsSettings } from "@/lib/coord";
import {
  getDnsRevision,
  previewDns,
  publishDns,
  validateDns,
  type DnsPreview,
  type DnsRevisionDocument,
  type DnsValidation,
} from "@/lib/coord-dns";
import { can } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

const DEVICE_TAGS: readonly DeviceTag[] = ["office", "ranger", "store"];

function message(error: unknown, fallback: string): string {
  return errorText(error, fallback);
}

function parseDocument(raw: string): OrgDnsSettings {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("not an object");
    }
    return parsed as OrgDnsSettings;
  } catch {
    throw new Error("DNS settings must be a valid JSON object.");
  }
}

export async function publishDnsAction(
  dnsJson: string,
  etag: string,
): Promise<ActionResult> {
  try {
    const ctx = await requireConsoleContext();
    if (!can(ctx.role, "manage_dns")) {
      return { ok: false, error: "Only owners and admins can publish DNS settings." };
    }
    await publishDns(ctx, { dns: parseDocument(dnsJson) }, etag);
    revalidatePath("/dns");
    return { ok: true, data: undefined };
  } catch (error) {
    return { ok: false, error: message(error, "Could not publish DNS settings.") };
  }
}

export async function rollbackDnsAction(
  etag: string,
  revision: number | null,
): Promise<ActionResult> {
  try {
    const ctx = await requireConsoleContext();
    if (!can(ctx.role, "manage_dns")) {
      return { ok: false, error: "Only owners and admins can roll back DNS settings." };
    }
    if (revision !== null && (!Number.isInteger(revision) || revision < 0)) {
      return { ok: false, error: "Choose a valid revision to restore." };
    }
    await publishDns(
      ctx,
      revision === null ? { rollback: true } : { rollback_to: revision },
      etag,
    );
    revalidatePath("/dns");
    return { ok: true, data: undefined };
  } catch (error) {
    return { ok: false, error: message(error, "Could not roll back DNS settings.") };
  }
}

export async function validateDnsAction(
  dnsJson: string,
): Promise<ActionResult<DnsValidation>> {
  try {
    const ctx = await requireConsoleContext();
    return { ok: true, data: await validateDns(ctx, parseDocument(dnsJson)) };
  } catch (error) {
    return { ok: false, error: message(error, "Could not check DNS settings.") };
  }
}

export async function previewDnsAction(input: {
  name: string;
  nodeId: string;
  tags: string[];
}): Promise<ActionResult<DnsPreview>> {
  try {
    const ctx = await requireConsoleContext();
    const name = input.name.trim();
    if (!name) {
      return { ok: false, error: "Enter a name to preview." };
    }
    const tags = input.tags.filter((tag): tag is DeviceTag =>
      DEVICE_TAGS.includes(tag as DeviceTag),
    );
    return {
      ok: true,
      data: await previewDns(ctx, {
        name,
        nodeId: input.nodeId || undefined,
        tags,
      }),
    };
  } catch (error) {
    return { ok: false, error: message(error, "Could not preview this name.") };
  }
}

export async function loadDnsRevisionAction(
  revision: number,
): Promise<ActionResult<DnsRevisionDocument>> {
  try {
    const ctx = await requireConsoleContext();
    return { ok: true, data: await getDnsRevision(ctx, revision) };
  } catch (error) {
    return { ok: false, error: message(error, "Could not load that revision.") };
  }
}
