"use server";

import { redirect } from "next/navigation";
import {
  createDraft,
  discardDraft,
  publishDraft,
  rebaseDraft,
  updateDraft,
  type ChangeSurface,
  type DraftPayload,
} from "@/lib/coord-changes";
import { can, type Permission } from "@/lib/roles";
import { requireOrganisationContext } from "@/lib/session";

const SURFACE_PERMISSION: Record<ChangeSurface, Permission> = {
  policy: "manage_policy",
  dns: "manage_dns",
  resources: "manage_networks",
};

function surfacesFrom(formData: FormData): ChangeSurface[] {
  return formData
    .getAll("surfaces")
    .map(String)
    .filter((value): value is ChangeSurface => value in SURFACE_PERMISSION);
}

/**
 * The organisation comes from the form that rendered the draft, never from
 * the switcher cookie, so changing organisation cannot retarget a mutation.
 */
async function contextFor(formData: FormData, surfaces: ChangeSurface[]) {
  const ctx = await requireOrganisationContext(String(formData.get("organisationId") ?? ""));
  for (const surface of surfaces) {
    if (!can(ctx.role, SURFACE_PERMISSION[surface])) {
      throw new Error(`Your role in ${ctx.organisationName} cannot change ${surface}.`);
    }
  }
  return ctx;
}

function back(path: string, params: Record<string, string>): never {
  const query = new URLSearchParams(params).toString();
  redirect(query ? `${path}?${query}` : path);
}

function failure(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

function parseObject(raw: string, label: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${label} must be valid JSON.`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${label} must be a JSON object.`);
  }
  return parsed as Record<string, unknown>;
}

export async function createDraftAction(formData: FormData): Promise<void> {
  const surfaces = surfacesFrom(formData);
  let id: string;
  try {
    if (surfaces.length === 0) throw new Error("Choose at least one thing to change.");
    const ctx = await contextFor(formData, surfaces);
    id = (await createDraft(ctx, String(formData.get("title") ?? ""), surfaces)).id;
  } catch (error) {
    back("/changes", { error: failure(error, "Could not create the draft.") });
  }
  back(`/changes/${id}`, { notice: "Draft created from the current live state." });
}

export async function saveDraftAction(formData: FormData): Promise<void> {
  const id = String(formData.get("draftId") ?? "");
  const surfaces = surfacesFrom(formData);
  try {
    const ctx = await contextFor(formData, surfaces);
    const payload: DraftPayload = {};
    if (surfaces.includes("policy")) {
      payload.policy = parseObject(String(formData.get("policy") ?? ""), "Policy");
    }
    if (surfaces.includes("dns")) {
      payload.dns = parseObject(String(formData.get("dns") ?? ""), "DNS");
    }
    if (surfaces.includes("resources")) {
      const raw = String(formData.get("resources") ?? "");
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        throw new Error("Network resources must be valid JSON.");
      }
      if (!Array.isArray(parsed)) throw new Error("Network resources must be a JSON array.");
      payload.resources = parsed as Record<string, unknown>[];
    }
    await updateDraft(
      ctx,
      id,
      Number(formData.get("version")),
      String(formData.get("title") ?? ""),
      payload,
    );
  } catch (error) {
    back(`/changes/${id}`, { error: failure(error, "Could not save the draft.") });
  }
  back(`/changes/${id}`, { notice: "Draft saved. Preview it before publishing." });
}

export async function rebaseDraftAction(formData: FormData): Promise<void> {
  const id = String(formData.get("draftId") ?? "");
  try {
    const ctx = await contextFor(formData, surfacesFrom(formData));
    await rebaseDraft(ctx, id, Number(formData.get("version")));
  } catch (error) {
    back(`/changes/${id}`, { error: failure(error, "Could not rebase the draft.") });
  }
  back(`/changes/${id}`, {
    notice: "Rebased on the live state. Your proposed documents are unchanged; preview to see what they now replace.",
    preview: "1",
  });
}

export async function discardDraftAction(formData: FormData): Promise<void> {
  const id = String(formData.get("draftId") ?? "");
  try {
    const ctx = await contextFor(formData, surfacesFrom(formData));
    await discardDraft(ctx, id, Number(formData.get("version")));
  } catch (error) {
    back(`/changes/${id}`, { error: failure(error, "Could not discard the draft.") });
  }
  back(`/changes/${id}`, { notice: "Draft discarded. Nothing was published." });
}

export async function publishDraftAction(formData: FormData): Promise<void> {
  const id = String(formData.get("draftId") ?? "");
  try {
    if (formData.get("confirm") !== "on") {
      throw new Error("Tick the confirmation to publish.");
    }
    const ctx = await contextFor(formData, surfacesFrom(formData));
    await publishDraft(
      ctx,
      id,
      Number(formData.get("version")),
      formData.getAll("risk").map(String),
    );
  } catch (error) {
    back(`/changes/${id}`, { error: failure(error, "Could not publish the draft."), preview: "1" });
  }
  back(`/changes/${id}`, { notice: "Published. Every surface changed in one transaction." });
}
