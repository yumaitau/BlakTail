"use server";

import { revalidatePath } from "next/cache";
import type { DeviceTag } from "@/lib/coord";
import {
  createNetworkResource,
  deleteNetworkResource,
  getNetworkResource,
  resourceInput,
  updateNetworkResource,
  type NetworkResource,
  type NetworkResourceInput,
  type ResourceProtocol,
} from "@/lib/coord-networks";
import { releaseReservation, reserveAddress } from "@/lib/coord-ipam";
import { can, type OrgRole } from "@/lib/roles";
import { requireOrganisationContext } from "@/lib/session";

export type NetworkActionResult<T = void> =
  | { ok: true; data: T }
  | { ok: false; error: string };

const ROLES: OrgRole[] = ["owner", "admin", "member"];
const TAGS: DeviceTag[] = ["office", "ranger", "store"];
const PROTOCOLS: ResourceProtocol[] = ["tcp", "udp", "icmp"];

function list(value: FormDataEntryValue | null): string[] {
  return String(value ?? "")
    .split(/[\s,]+/u)
    .map((item) => item.trim())
    .filter(Boolean);
}

function inputFromForm(formData: FormData): NetworkResourceInput {
  const target = String(formData.get("target") ?? "").trim();
  const kind = String(formData.get("kind") ?? "cidr");
  const peerIds = formData.getAll("routingPeer").map(String).filter(Boolean);
  return {
    name: String(formData.get("name") ?? ""),
    description: String(formData.get("description") ?? ""),
    ...(kind === "dns" ? { dns_target: target } : { cidr: target }),
    ports: list(formData.get("ports")),
    protocols: formData
      .getAll("protocols")
      .map(String)
      .filter((value): value is ResourceProtocol =>
        PROTOCOLS.includes(value as ResourceProtocol),
      ),
    routing_peers: peerIds.map((nodeId) => ({
      node_id: nodeId,
      metric: Number(formData.get(`metric:${nodeId}`) ?? 100) || 100,
    })),
    access: {
      roles: formData
        .getAll("accessRoles")
        .map(String)
        .filter((value): value is OrgRole => ROLES.includes(value as OrgRole)),
      tags: formData
        .getAll("accessTags")
        .map(String)
        .filter((value): value is DeviceTag => TAGS.includes(value as DeviceTag)),
      groups: formData.getAll("accessGroups").map(String).filter(Boolean),
    },
    enabled: formData.get("enabled") !== "false",
    allow_nested_overlap: formData.get("allowNestedOverlap") === "on",
    confirm_public_route: formData.get("confirmPublicRoute") === "on",
  };
}

async function managedContext(formData: FormData) {
  const ctx = await requireOrganisationContext(
    String(formData.get("organisationId") ?? ""),
  );
  if (!can(ctx.role, "manage_networks")) {
    throw new Error("Only owners and admins can change network resources.");
  }
  return ctx;
}

function failure(error: unknown, fallback: string): { ok: false; error: string } {
  return { ok: false, error: error instanceof Error ? error.message : fallback };
}

/** Validates against the coordinator (overlap, access, routing peers) without saving. */
export async function previewNetworkResourceAction(
  formData: FormData,
): Promise<NetworkActionResult<NetworkResource>> {
  try {
    const ctx = await managedContext(formData);
    const id = String(formData.get("resourceId") ?? "");
    const input = { ...inputFromForm(formData), dry_run: true };
    if (id) {
      input.etag = String(formData.get("etag") ?? "");
      return { ok: true, data: await updateNetworkResource(ctx, id, input) };
    }
    return { ok: true, data: await createNetworkResource(ctx, input) };
  } catch (error) {
    return failure(error, "Could not check this resource.");
  }
}

export async function saveNetworkResourceAction(
  formData: FormData,
): Promise<NetworkActionResult<{ id: string }>> {
  try {
    const ctx = await managedContext(formData);
    const id = String(formData.get("resourceId") ?? "");
    const input = inputFromForm(formData);
    const saved = id
      ? await updateNetworkResource(ctx, id, {
          ...input,
          etag: String(formData.get("etag") ?? ""),
        })
      : await createNetworkResource(ctx, input);
    revalidatePath("/networks");
    return { ok: true, data: { id: saved.id } };
  } catch (error) {
    return failure(error, "Could not save this resource.");
  }
}

export async function setNetworkResourceEnabledAction(
  formData: FormData,
): Promise<NetworkActionResult> {
  try {
    const ctx = await managedContext(formData);
    const id = String(formData.get("resourceId") ?? "");
    const current = await getNetworkResource(ctx, id);
    if (!current) return { ok: false, error: "This resource no longer exists." };
    if (current.etag !== String(formData.get("etag") ?? "")) {
      return {
        ok: false,
        error: "Someone else changed this resource. Reload to see the latest version.",
      };
    }
    await updateNetworkResource(ctx, id, {
      ...resourceInput(current),
      enabled: formData.get("enabled") === "true",
    });
    revalidatePath("/networks");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not change this resource.");
  }
}

export async function reserveAddressAction(
  formData: FormData,
): Promise<NetworkActionResult> {
  try {
    const ctx = await managedContext(formData);
    const optional = (key: string) => {
      const value = String(formData.get(key) ?? "").trim();
      return value ? value : undefined;
    };
    await reserveAddress(ctx, {
      address: String(formData.get("address") ?? "").trim(),
      bound_name: optional("boundName"),
      bound_wg_public_key: optional("boundKey"),
      reason: String(formData.get("reason") ?? ""),
    });
    revalidatePath("/networks/addresses");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not reserve this address.");
  }
}

export async function releaseReservationAction(
  formData: FormData,
): Promise<NetworkActionResult> {
  try {
    const ctx = await managedContext(formData);
    await releaseReservation(
      ctx,
      String(formData.get("reservationId") ?? ""),
      String(formData.get("etag") ?? ""),
    );
    revalidatePath("/networks/addresses");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not release this reservation.");
  }
}

export async function deleteNetworkResourceAction(
  formData: FormData,
): Promise<NetworkActionResult> {
  try {
    const ctx = await managedContext(formData);
    await deleteNetworkResource(
      ctx,
      String(formData.get("resourceId") ?? ""),
      String(formData.get("etag") ?? ""),
    );
    revalidatePath("/networks");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not delete this resource.");
  }
}
