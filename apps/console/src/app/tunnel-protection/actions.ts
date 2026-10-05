"use server";

import { actionFailure } from "@/lib/server-errors";
import { revalidatePath } from "next/cache";
import { requireSecurityAssurance } from "@/lib/auth-policy";
import type { DeviceTag } from "@/lib/coord";
import { putPqPolicy, type PqMode, type PqRule } from "@/lib/coord-pq";
import { permissionReason } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

export type PqActionResult = { ok: true; message: string } | { ok: false; error: string };

const MODES: PqMode[] = ["off", "prefer", "require"];
const TAGS: DeviceTag[] = ["office", "ranger", "store"];

function mode(value: FormDataEntryValue | null): PqMode | null {
  return MODES.find((candidate) => candidate === value) ?? null;
}

function tag(value: FormDataEntryValue | null): DeviceTag | null {
  return TAGS.find((candidate) => candidate === value) ?? null;
}

export async function savePqPolicyAction(formData: FormData): Promise<PqActionResult> {
  try {
    const ctx = await requireConsoleContext();
    const denied = permissionReason(ctx.role, "manage_security");
    if (denied) return { ok: false, error: denied };
    await requireSecurityAssurance(ctx);
    const defaultMode = mode(formData.get("mode"));
    if (!defaultMode) return { ok: false, error: "Choose off, prefer or require." };
    const revision = Number(formData.get("revision"));
    if (!Number.isInteger(revision) || revision < 0) {
      return { ok: false, error: "Reload the page and try again." };
    }
    const rules: PqRule[] = [];
    const count = Math.min(Number(formData.get("rule_count")) || 0, 32);
    for (let index = 0; index < count; index += 1) {
      if (formData.get(`rule_${index}_remove`) === "on") continue;
      const a = tag(formData.get(`rule_${index}_a`));
      const b = tag(formData.get(`rule_${index}_b`));
      const ruleMode = mode(formData.get(`rule_${index}_mode`));
      if (!a || !b || !ruleMode) return { ok: false, error: `Rule ${index + 1} is incomplete.` };
      rules.push({ tags: [a, b], mode: ruleMode });
    }
    const newA = tag(formData.get("new_a"));
    const newB = tag(formData.get("new_b"));
    const newMode = mode(formData.get("new_mode"));
    if (newA && newB && newMode) rules.push({ tags: [newA, newB], mode: newMode });
    const saved = await putPqPolicy(ctx, {
      mode: defaultMode,
      block_unestablished: formData.get("block_unestablished") === "on",
      rules,
      expected_revision: revision,
    });
    revalidatePath("/tunnel-protection");
    return {
      ok: true,
      message:
        saved.mode === "off" && saved.rules.length === 0
          ? "Post-quantum PSKs are off. Devices return to classical WireGuard on their next update."
          : "Saved. Devices pick up the policy on their next update; check each peer below for what was actually negotiated.",
    };
  } catch (error) {
    return actionFailure(error, "Could not save the post-quantum policy.");
  }
}
