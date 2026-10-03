import "server-only";

import { coordFetch, readError, type WebhookDestination } from "./coord";
import { permissionReason } from "./roles";
import type { ConsoleContext } from "./session";

export type ChannelKind = "email" | "slack" | "teams";

export type QuietHours = { timezone: string; start: string; end: string };

export type NotificationCapabilities = {
  email_configured: boolean;
  email_from: string | null;
  email_tls: "starttls" | "tls" | "none" | null;
  offshore_kinds: string[];
  default_timezone: string;
};

export type CreateChannelInput = {
  kind: ChannelKind;
  name: string;
  url?: string;
  recipients?: string[];
  event_types?: string[];
  quiet_hours?: QuietHours | null;
  digest_minutes?: number;
  residency_acknowledged?: boolean;
};

async function json<T>(ctx: ConsoleContext, path: string, init: RequestInit): Promise<T> {
  const denied = permissionReason(ctx.role, "manage_integrations");
  if (denied) throw new Error(denied);
  const res = await coordFetch(`/v1/orgs/${ctx.coordOrgId}${path}`, { ...init, ctx });
  if (!res.ok) throw new Error(await readError(res));
  return res.json() as Promise<T>;
}

export function getNotificationCapabilities(
  ctx: ConsoleContext,
): Promise<NotificationCapabilities> {
  return json(ctx, "/notification-channels/capabilities", { method: "GET" });
}

/** The coordinator also requires an owner and acknowledgement for Slack/Teams. */
export function createNotificationChannel(
  ctx: ConsoleContext,
  input: CreateChannelInput,
): Promise<WebhookDestination> {
  return json(ctx, "/notification-channels", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function setNotificationSchedule(
  ctx: ConsoleContext,
  destinationId: string,
  input: { quiet_hours: QuietHours | null; digest_minutes: number },
): Promise<{ destination_id: string; quiet_hours: QuietHours | null; digest_minutes: number }> {
  return json(ctx, `/notification-channels/${encodeURIComponent(destinationId)}/schedule`, {
    method: "PUT",
    body: JSON.stringify(input),
  });
}

export function sendTestNotification(
  ctx: ConsoleContext,
  destinationId: string,
): Promise<{ delivery_id: string }> {
  return json(ctx, `/notification-channels/${encodeURIComponent(destinationId)}/test`, {
    method: "POST",
  });
}
