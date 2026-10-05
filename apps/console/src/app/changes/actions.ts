"use server";

import { actionFailure, type ActionFailure } from "@/lib/server-errors";
import { revalidatePath } from "next/cache";
import type { ActionResult } from "@/app/actions";
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

const SURFACE_NAME: Record<ChangeSurface, string> = {
  policy: "the access policy",
  dns: "DNS",
  resources: "network resources",
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
      throw new Error(`Your role in ${ctx.organisationName} cannot change ${SURFACE_NAME[surface]}.`);
    }
  }
  return ctx;
}

function invalid(field: string, error: string): ActionFailure {
  return { ok: false, error, fieldErrors: { [field]: error } };
}

function parseJson(raw: string): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(raw) };
  } catch {
    return { ok: false };
  }
}

function titleProblem(title: string): string | null {
  if (!title) return "Give the draft a title.";
  if ([...title].length > 120) return "Titles must be 120 characters or fewer.";
  return null;
}

export async function createDraftAction(
  formData: FormData,
): Promise<ActionResult<{ id: string }>> {
  try {
    const title = String(formData.get("title") ?? "").trim();
    const problem = titleProblem(title);
    if (problem) return invalid("title", problem);
    const surfaces = surfacesFrom(formData);
    if (surfaces.length === 0) {
      return invalid("surfaces", "Choose at least one thing to change.");
    }
    const ctx = await contextFor(formData, surfaces);
    const draft = await createDraft(ctx, title, surfaces);
    revalidatePath("/changes");
    return { ok: true, data: { id: draft.id } };
  } catch (error) {
    return actionFailure(error, "Could not create the draft.", "changes", {
      fields: { title: ["title"] },
    });
  }
}

export async function saveDraftAction(formData: FormData): Promise<ActionResult> {
  const id = String(formData.get("draftId") ?? "");
  try {
    const title = String(formData.get("title") ?? "").trim();
    const problem = titleProblem(title);
    if (problem) return invalid("title", problem);
    const surfaces = surfacesFrom(formData);
    const payload: DraftPayload = {};
    for (const [field, label] of [
      ["policy", "The access policy"],
      ["dns", "DNS"],
    ] as const) {
      if (!surfaces.includes(field)) continue;
      const parsed = parseJson(String(formData.get(field) ?? ""));
      if (!parsed.ok) return invalid(field, `${label} must be valid JSON.`);
      if (!parsed.value || typeof parsed.value !== "object" || Array.isArray(parsed.value)) {
        return invalid(field, `${label} must be a JSON object.`);
      }
      payload[field] = parsed.value as Record<string, unknown>;
    }
    if (surfaces.includes("resources")) {
      const parsed = parseJson(String(formData.get("resources") ?? ""));
      if (!parsed.ok) return invalid("resources", "Network resources must be valid JSON.");
      if (!Array.isArray(parsed.value)) {
        return invalid("resources", "Network resources must be a JSON array.");
      }
      payload.resources = parsed.value as Record<string, unknown>[];
    }
    const ctx = await contextFor(formData, surfaces);
    await updateDraft(ctx, id, Number(formData.get("version")), title, payload);
    revalidatePath(`/changes/${id}`);
    revalidatePath("/changes");
    return { ok: true, data: undefined };
  } catch (error) {
    return actionFailure(error, "Could not save the draft.", "changes", {
      fields: { title: ["title"] },
    });
  }
}

export async function rebaseDraftAction(formData: FormData): Promise<ActionResult> {
  const id = String(formData.get("draftId") ?? "");
  try {
    const ctx = await contextFor(formData, surfacesFrom(formData));
    await rebaseDraft(ctx, id, Number(formData.get("version")));
    revalidatePath(`/changes/${id}`);
    return { ok: true, data: undefined };
  } catch (error) {
    return actionFailure(error, "Could not rebase the draft.", "changes");
  }
}

export async function discardDraftAction(formData: FormData): Promise<ActionResult> {
  const id = String(formData.get("draftId") ?? "");
  try {
    const ctx = await contextFor(formData, surfacesFrom(formData));
    await discardDraft(ctx, id, Number(formData.get("version")));
    revalidatePath(`/changes/${id}`);
    revalidatePath("/changes");
    return { ok: true, data: undefined };
  } catch (error) {
    return actionFailure(error, "Could not discard the draft.", "changes");
  }
}

export async function publishDraftAction(formData: FormData): Promise<ActionResult> {
  const id = String(formData.get("draftId") ?? "");
  try {
    if (formData.get("confirm") !== "on") {
      return { ok: false, error: "Confirm the publish to continue." };
    }
    const ctx = await contextFor(formData, surfacesFrom(formData));
    await publishDraft(
      ctx,
      id,
      Number(formData.get("version")),
      formData.getAll("risk").map(String),
    );
    revalidatePath(`/changes/${id}`);
    revalidatePath("/changes");
    return { ok: true, data: undefined };
  } catch (error) {
    return actionFailure(error, "Could not publish the draft.", "changes");
  }
}
