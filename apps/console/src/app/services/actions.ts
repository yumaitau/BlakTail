"use server";

import { actionFailure, type ActionFailure } from "@/lib/server-errors";
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

const SERVICE_FIELDS = {
  name: ["name"],
  port: ["port"],
  targetNodeId: ["target"],
  description: ["description"],
};

function failure(error: unknown, fallback: string): ActionFailure {
  return actionFailure(error, fallback, "services", { fields: SERVICE_FIELDS });
}

function invalid(field: string, error: string): ActionFailure {
  return { ok: false, error, fieldErrors: { [field]: error } };
}

/** Catches obvious gaps before asking the coordinator. */
function checkInput(input: ServiceInput): ActionFailure | null {
  if (!input.name) return invalid("name", "Give the service a name.");
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/u.test(input.name) || input.name.length < 3 || input.name.length > 63) {
    return invalid(
      "name",
      "Use 3 to 63 lowercase letters, digits or hyphens, starting and ending with a letter or digit.",
    );
  }
  if (!input.target_node_id) return invalid("targetNodeId", "Choose the device that serves it.");
  if (input.port < 1 || input.port > 65535) {
    return invalid("port", "Enter a port from 1 to 65535.");
  }
  return null;
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
    const input = readInput(formData);
    const problem = checkInput(input);
    if (problem) return problem;
    return { ok: true, data: await previewService(ctx, input) };
  } catch (error) {
    return failure(error, "Could not preview this service.");
  }
}

export async function createServiceAction(formData: FormData): Promise<ActionResult> {
  try {
    const ctx = await requireConsoleContext();
    if (!can(ctx.role, "manage_services")) {
      return { ok: false, error: "Only owners and admins can create private services." };
    }
    const input = readInput(formData);
    const problem = checkInput(input);
    if (problem) return problem;
    await createService(ctx, input);
    revalidatePath("/services");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not create this service.");
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
    return failure(error, "Could not update this service.");
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
    return failure(error, "Could not delete this service.");
  }
}
