"use server";

import { revalidatePath } from "next/cache";
import type { ActionResult } from "@/app/actions";
import type { DeviceTag } from "@/lib/coord";
import {
  createService,
  deleteService,
  previewService,
  updateService,
  type ServiceInput,
  type ServicePreview,
} from "@/lib/coord-services";
import { can } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

const DEVICE_TAGS: readonly DeviceTag[] = ["office", "ranger", "store"];

function message(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

function readInput(formData: FormData): ServiceInput {
  const port = Number(formData.get("port") ?? 0);
  const protocol = String(formData.get("protocol") ?? "http");
  return {
    name: String(formData.get("name") ?? "").trim(),
    target_node_id: String(formData.get("targetNodeId") ?? "").trim(),
    port: Number.isInteger(port) ? port : 0,
    protocol: protocol === "https" ? "https" : "http",
    access_tags: formData
      .getAll("accessTags")
      .map(String)
      .filter((tag): tag is DeviceTag => DEVICE_TAGS.includes(tag as DeviceTag)),
    description: String(formData.get("description") ?? "").trim(),
  };
}

export async function previewServiceAction(
  formData: FormData,
): Promise<ActionResult<ServicePreview>> {
  try {
    const ctx = await requireConsoleContext();
    return { ok: true, data: await previewService(ctx, readInput(formData)) };
  } catch (error) {
    return { ok: false, error: message(error, "Could not preview this service.") };
  }
}

export async function createServiceAction(formData: FormData): Promise<ActionResult> {
  try {
    const ctx = await requireConsoleContext();
    if (!can(ctx.role, "manage_services")) {
      return { ok: false, error: "Only owners and admins can create private services." };
    }
    await createService(ctx, readInput(formData));
    revalidatePath("/services");
    return { ok: true, data: undefined };
  } catch (error) {
    return { ok: false, error: message(error, "Could not create this service.") };
  }
}

export async function setServiceEnabledAction(
  serviceId: string,
  revision: number,
  enabled: boolean,
): Promise<ActionResult> {
  try {
    const ctx = await requireConsoleContext();
    if (!can(ctx.role, "manage_services")) {
      return { ok: false, error: "Only owners and admins can change private services." };
    }
    await updateService(ctx, serviceId, { revision, enabled });
    revalidatePath("/services");
    return { ok: true, data: undefined };
  } catch (error) {
    return { ok: false, error: message(error, "Could not update this service.") };
  }
}

export async function deleteServiceAction(serviceId: string): Promise<ActionResult> {
  try {
    const ctx = await requireConsoleContext();
    if (!can(ctx.role, "manage_services")) {
      return { ok: false, error: "Only owners and admins can delete private services." };
    }
    await deleteService(ctx, serviceId);
    revalidatePath("/services");
    return { ok: true, data: undefined };
  } catch (error) {
    return { ok: false, error: message(error, "Could not delete this service.") };
  }
}
