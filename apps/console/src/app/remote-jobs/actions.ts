"use server";

import { actionFailure, type ActionFailure } from "@/lib/server-errors";
import { revalidatePath } from "next/cache";
import {
  createJobTemplate,
  decideJobRun,
  disableJobTemplate,
  requestJobRun,
} from "@/lib/coord-remote";
import { requireConsoleContext } from "@/lib/session";

export type JobActionResult = { ok: true; message: string } | ActionFailure;

const UUID = /^[0-9a-f-]{36}$/i;
const TAGS = ["office", "ranger", "store"];

function failure(error: unknown, fallback: string): JobActionResult {
  return actionFailure(error, fallback);
}

/**
 * Arguments are entered one per line and stored as a list. Nothing is ever
 * split on spaces or passed to a shell, so quoting has no meaning here.
 */
export async function createJobTemplateAction(formData: FormData): Promise<JobActionResult> {
  try {
    const ctx = await requireConsoleContext();
    const name = String(formData.get("name") ?? "").trim();
    const program = String(formData.get("program") ?? "").trim();
    const args = String(formData.get("args") ?? "")
      .split(/\r?\n/)
      .map((line) => line.trimEnd())
      .filter((line) => line.length > 0);
    const timeout = Number(formData.get("timeoutSecs"));
    const cap = Number(formData.get("outputCapBytes"));
    const tags = formData.getAll("tags").map(String).filter((tag) => TAGS.includes(tag));
    const nodeIds = formData.getAll("nodeIds").map(String).filter((id) => UUID.test(id));
    if (!name) return { ok: false, error: "Name the template." };
    if (!program.startsWith("/")) {
      return { ok: false, error: "The program must be an absolute path, such as /usr/bin/uptime." };
    }
    if (!Number.isInteger(timeout) || timeout < 1 || timeout > 600) {
      return { ok: false, error: "Timeout must be 1 to 600 seconds." };
    }
    if (!Number.isInteger(cap) || cap < 1 || cap > 65536) {
      return { ok: false, error: "Output cap must be 1 to 65536 bytes." };
    }
    if (tags.length === 0 && nodeIds.length === 0) {
      return { ok: false, error: "Choose at least one target tag or device." };
    }
    await createJobTemplate(ctx, {
      name,
      argv: [program, ...args],
      timeout_secs: timeout,
      output_cap_bytes: cap,
      target: { tags, node_ids: nodeIds },
    });
    revalidatePath("/remote-jobs");
    return { ok: true, message: `Template ${name} saved.` };
  } catch (error) {
    return failure(error, "Could not save the template.");
  }
}

export async function disableJobTemplateAction(formData: FormData): Promise<JobActionResult> {
  try {
    const ctx = await requireConsoleContext();
    const id = String(formData.get("templateId") ?? "");
    if (!UUID.test(id)) return { ok: false, error: "Choose a template." };
    await disableJobTemplate(ctx, id);
    revalidatePath("/remote-jobs");
    return { ok: true, message: "Template disabled. Pending runs of it can no longer be approved." };
  } catch (error) {
    return failure(error, "Could not disable the template.");
  }
}

export async function requestJobRunAction(formData: FormData): Promise<JobActionResult> {
  try {
    const ctx = await requireConsoleContext();
    const templateId = String(formData.get("templateId") ?? "");
    const nodeId = String(formData.get("nodeId") ?? "");
    const reason = String(formData.get("reason") ?? "").trim();
    if (!UUID.test(templateId)) return { ok: false, error: "Choose a template." };
    if (!UUID.test(nodeId)) return { ok: false, error: "Choose a device." };
    if (reason.length < 4) return { ok: false, error: "Say why the job should run." };
    await requestJobRun(ctx, { template_id: templateId, node_id: nodeId, reason });
    revalidatePath("/remote-jobs");
    return { ok: true, message: "Run requested. An owner must approve it before the device runs it." };
  } catch (error) {
    return failure(error, "Could not request the run.");
  }
}

export async function decideJobRunAction(formData: FormData): Promise<JobActionResult> {
  try {
    const ctx = await requireConsoleContext();
    const runId = String(formData.get("runId") ?? "");
    const decision = String(formData.get("decision") ?? "");
    if (!UUID.test(runId)) return { ok: false, error: "Choose a run." };
    if (decision !== "approve" && decision !== "reject" && decision !== "cancel") {
      return { ok: false, error: "Choose approve, reject or cancel." };
    }
    await decideJobRun(ctx, runId, decision);
    revalidatePath("/remote-jobs");
    return {
      ok: true,
      message:
        decision === "approve"
          ? "Approved. The device picks it up within about 15 seconds."
          : decision === "reject"
            ? "Rejected."
            : "Cancel requested. A running job is stopped within a few seconds.",
    };
  } catch (error) {
    return failure(error, "Could not update the run.");
  }
}
