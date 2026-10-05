"use server";

import { actionFailure } from "@/lib/server-errors";
import { revalidatePath } from "next/cache";
import {
  createNotificationChannel,
  sendTestNotification,
  setNotificationSchedule,
  type ChannelKind,
  type QuietHours,
} from "@/lib/coord-notifications";
import { permissionReason } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

type Result<T = void> = { ok: true; data: T } | { ok: false; error: string };

function failure(error: unknown, fallback: string): { ok: false; error: string } {
  return actionFailure(error, fallback);
}

const KINDS: readonly ChannelKind[] = ["email", "slack", "teams"];

function quietHours(formData: FormData): QuietHours | null {
  if (formData.get("quiet") !== "on") return null;
  return {
    timezone: String(formData.get("timezone") ?? "Australia/Sydney"),
    start: String(formData.get("quietStart") ?? ""),
    end: String(formData.get("quietEnd") ?? ""),
  };
}

function digestMinutes(formData: FormData): number {
  const value = Number(formData.get("digestMinutes") ?? 0);
  return Number.isFinite(value) ? value : 0;
}

export async function createNotificationChannelAction(formData: FormData): Promise<Result> {
  try {
    const ctx = await requireConsoleContext();
    const denied = permissionReason(ctx.role, "manage_integrations");
    if (denied) return { ok: false, error: denied };
    const kind = String(formData.get("kind") ?? "") as ChannelKind;
    if (!KINDS.includes(kind)) return { ok: false, error: "Choose email, Slack or Teams." };
    const offshore = kind !== "email";
    if (offshore) {
      if (permissionReason(ctx.role, "manage_security")) {
        return {
          ok: false,
          error: "Only an owner can send alerts to an offshore service such as Slack or Teams.",
        };
      }
      if (formData.get("residencyAcknowledged") !== "on") {
        return {
          ok: false,
          error: "Acknowledge that alert content will leave Australia before adding this channel.",
        };
      }
    }
    const name = String(formData.get("name") ?? "").trim();
    if (!name) return { ok: false, error: "Name the channel." };
    const warningsOnly = formData.get("events") === "warnings";
    await createNotificationChannel(ctx, {
      kind,
      name,
      ...(offshore
        ? { url: String(formData.get("url") ?? "").trim() }
        : {
            recipients: String(formData.get("recipients") ?? "")
              .split(/[\s,;]+/)
              .map((value) => value.trim())
              .filter(Boolean),
          }),
      event_types: warningsOnly ? formData.getAll("warningTypes").map(String) : ["*"],
      quiet_hours: quietHours(formData),
      digest_minutes: digestMinutes(formData),
      residency_acknowledged: offshore,
    });
    revalidatePath("/settings");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not add the notification channel.");
  }
}

export async function setNotificationScheduleAction(formData: FormData): Promise<Result> {
  try {
    const ctx = await requireConsoleContext();
    const denied = permissionReason(ctx.role, "manage_integrations");
    if (denied) return { ok: false, error: denied };
    const destinationId = String(formData.get("destinationId") ?? "");
    if (!destinationId) return { ok: false, error: "Choose a channel." };
    await setNotificationSchedule(ctx, destinationId, {
      quiet_hours: quietHours(formData),
      digest_minutes: digestMinutes(formData),
    });
    revalidatePath("/settings");
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not save quiet hours.");
  }
}

export async function sendTestNotificationAction(formData: FormData): Promise<Result> {
  try {
    const ctx = await requireConsoleContext();
    const denied = permissionReason(ctx.role, "manage_integrations");
    if (denied) return { ok: false, error: denied };
    const destinationId = String(formData.get("destinationId") ?? "");
    if (!destinationId) return { ok: false, error: "Choose a channel." };
    await sendTestNotification(ctx, destinationId);
    return { ok: true, data: undefined };
  } catch (error) {
    return failure(error, "Could not queue the test notification.");
  }
}
