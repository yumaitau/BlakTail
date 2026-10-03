"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { disableWebhookAction, listWebhookDeliveriesAction } from "@/app/actions";
import {
  createNotificationChannelAction,
  sendTestNotificationAction,
  setNotificationScheduleAction,
} from "@/app/settings/notification-actions";
import type { WebhookDelivery, WebhookDestination } from "@/lib/coord";
import type { EventKind } from "@/lib/coord-events";
import type { NotificationCapabilities } from "@/lib/coord-notifications";

const TIMEZONES = [
  "Australia/Sydney",
  "Australia/Melbourne",
  "Australia/Brisbane",
  "Australia/Adelaide",
  "Australia/Darwin",
  "Australia/Perth",
  "Australia/Hobart",
  "Australia/Lord_Howe",
  "Australia/Eucla",
  "UTC",
];

const DIGESTS = [
  { value: 0, label: "Send each alert" },
  { value: 15, label: "Every 15 minutes" },
  { value: 60, label: "Hourly" },
  { value: 240, label: "Every 4 hours" },
  { value: 1440, label: "Daily" },
];

const KIND_LABEL: Record<string, string> = {
  email: "Email",
  slack: "Slack",
  teams: "Microsoft Teams",
};

function scheduleSummary(channel: WebhookDestination): string {
  const quiet = channel.quiet_hours
    ? `Quiet ${channel.quiet_hours.start}–${channel.quiet_hours.end} ${channel.quiet_hours.timezone}`
    : "No quiet hours";
  const digest = DIGESTS.find((option) => option.value === (channel.digest_minutes ?? 0));
  return `${quiet}; ${digest?.label.toLowerCase() ?? `digest every ${channel.digest_minutes} minutes`}`;
}

function ScheduleFields({
  defaultTimezone,
  current,
}: {
  defaultTimezone: string;
  current?: WebhookDestination;
}) {
  const [quiet, setQuiet] = useState(Boolean(current?.quiet_hours));
  return (
    <fieldset>
      <legend>Quiet hours and digest</legend>
      <label className="row">
        <input
          type="checkbox"
          name="quiet"
          checked={quiet}
          onChange={(event) => setQuiet(event.currentTarget.checked)}
        />
        Hold routine alerts during quiet hours. Warnings always send at once.
      </label>
      {quiet ? (
        <div className="row">
          <label>
            From
            <input
              name="quietStart"
              type="time"
              required
              defaultValue={current?.quiet_hours?.start ?? "22:00"}
            />
          </label>
          <label>
            Until
            <input
              name="quietEnd"
              type="time"
              required
              defaultValue={current?.quiet_hours?.end ?? "07:00"}
            />
          </label>
          <label>
            Time zone
            <select
              name="timezone"
              defaultValue={current?.quiet_hours?.timezone ?? defaultTimezone}
            >
              {TIMEZONES.map((zone) => (
                <option key={zone} value={zone}>
                  {zone}
                </option>
              ))}
            </select>
          </label>
        </div>
      ) : null}
      <label>
        Routine alerts
        <select name="digestMinutes" defaultValue={String(current?.digest_minutes ?? 0)}>
          {DIGESTS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
    </fieldset>
  );
}

export function NotificationChannels({
  channels,
  catalogue,
  capabilities,
  canAcknowledgeResidency,
  organisationName,
  roleLabel,
}: {
  channels: WebhookDestination[];
  catalogue: EventKind[];
  capabilities: NotificationCapabilities | null;
  canAcknowledgeResidency: boolean;
  organisationName: string;
  roleLabel: string;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [kind, setKind] = useState<"email" | "slack" | "teams">("email");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
  const [deliveries, setDeliveries] = useState<WebhookDelivery[]>([]);
  const editing = channels.find((channel) => channel.id === editingId);
  const warnings = catalogue.filter((event) => event.severity === "warning");
  const defaultTimezone = capabilities?.default_timezone ?? "Australia/Sydney";
  const offshore = kind !== "email";
  const emailUnavailable = kind === "email" && !capabilities?.email_configured;
  const offshoreBlocked = offshore && !canAcknowledgeResidency;

  const run = (work: () => Promise<{ ok: boolean; error?: string }>, done?: string) => {
    setError(null);
    setNotice(null);
    startTransition(async () => {
      const result = await work();
      if (!result.ok) {
        setError(result.error ?? "The request failed.");
        return;
      }
      if (done) setNotice(done);
      router.refresh();
    });
  };

  return (
    <section className="panel stack" aria-labelledby="notifications-heading">
      <div>
        <h2 id="notifications-heading">Notification channels</h2>
        <p className="muted">
          Send catalogued events to people by email, Slack or Microsoft Teams,
          through the same outbox, retries and dead-letter as webhooks. Alerts
          are best effort, not a safety control. Changing {organisationName} as{" "}
          {roleLabel.toLowerCase()}.
        </p>
      </div>
      {capabilities === null ? (
        <p className="error">Channel settings could not be loaded from the coordinator.</p>
      ) : capabilities.email_configured ? (
        <p className="muted">
          Email goes through the operator&apos;s relay as{" "}
          <span className="mono">{capabilities.email_from}</span> (
          {capabilities.email_tls === "none" ? "no TLS, local relay" : capabilities.email_tls}
          ). Relay credentials stay with the operator and are never stored here.
        </p>
      ) : (
        <p className="muted">
          Email is not available: the operator has not configured an SMTP relay
          on the coordinator.
        </p>
      )}
      <form
        className="stack"
        aria-label="Add a notification channel"
        onSubmit={(event) => {
          event.preventDefault();
          const formEl = event.currentTarget;
          const form = new FormData(formEl);
          run(async () => {
            const result = await createNotificationChannelAction(form);
            if (result.ok) formEl.reset();
            return result;
          }, "Channel added. Send a test to check it.");
        }}
      >
        <div className="row">
          <label>
            Channel type
            <select
              name="kind"
              value={kind}
              onChange={(event) =>
                setKind(event.currentTarget.value as "email" | "slack" | "teams")
              }
            >
              <option value="email">Email</option>
              <option value="slack">Slack (offshore)</option>
              <option value="teams">Microsoft Teams (offshore)</option>
            </select>
          </label>
          <label>
            Name
            <input name="name" required maxLength={64} />
          </label>
        </div>
        {kind === "email" ? (
          <label>
            Recipients (up to 10, separated by commas)
            <input name="recipients" required placeholder="ops@example.org.au" />
          </label>
        ) : (
          <>
            <label>
              Incoming webhook URL
              <input
                name="url"
                type="url"
                required
                autoComplete="off"
                placeholder={
                  kind === "slack"
                    ? "https://hooks.slack.com/services/…"
                    : "https://….webhook.office.com/… or a Workflows URL"
                }
              />
            </label>
            <div className="callout warn" role="note">
              <p>
                <strong>Data leaves Australia.</strong>{" "}
                {kind === "slack" ? "Slack" : "Microsoft Teams"} stores and
                processes message content outside BlakTail&apos;s onshore
                boundary, under the vendor&apos;s terms. Alerts carry event
                names, device and person identifiers and redacted details. The
                URL is stored sealed and never shown again.
              </p>
              <label className="row">
                <input
                  type="checkbox"
                  name="residencyAcknowledged"
                  required
                  disabled={!canAcknowledgeResidency}
                />
                I am an owner and accept that these alerts leave Australia.
              </label>
              {offshoreBlocked ? (
                <p className="muted">
                  Only an owner can acknowledge offshore delivery. Ask an owner
                  to add this channel.
                </p>
              ) : null}
            </div>
          </>
        )}
        <label>
          Events
          <select name="events" defaultValue="all">
            <option value="all">All events</option>
            <option value="warnings">Warnings only</option>
          </select>
        </label>
        {warnings.map((event) => (
          <input key={event.event_type} type="hidden" name="warningTypes" value={event.event_type} />
        ))}
        <ScheduleFields defaultTimezone={defaultTimezone} />
        <div>
          <button
            type="submit"
            disabled={pending || emailUnavailable || offshoreBlocked}
            title={
              emailUnavailable
                ? "The operator has not configured an SMTP relay."
                : offshoreBlocked
                  ? "Only an owner can add an offshore channel."
                  : undefined
            }
          >
            {pending ? "Saving…" : "Add channel"}
          </button>
        </div>
      </form>
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
      {notice ? (
        <p className="muted" role="status">
          {notice}
        </p>
      ) : null}
      {channels.length === 0 ? (
        <p className="muted">No notification channels yet.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Sends to</th>
                <th>Schedule</th>
                <th>State</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {channels.map((channel) => (
                <tr key={channel.id}>
                  <td>{channel.name}</td>
                  <td>
                    {KIND_LABEL[channel.kind ?? ""] ?? channel.kind}
                    {channel.residency_acknowledged_at ? (
                      <span className="badge warn">offshore, acknowledged</span>
                    ) : null}
                  </td>
                  <td className="mono">
                    {channel.kind === "email" ? channel.recipients?.join(", ") : channel.url}
                  </td>
                  <td>{scheduleSummary(channel)}</td>
                  <td>
                    <span className={channel.enabled ? "badge online" : "badge revoked"}>
                      {channel.enabled ? "Active" : "Disabled"}
                    </span>
                  </td>
                  <td>
                    {channel.enabled ? (
                      <>
                        <button
                          type="button"
                          disabled={pending}
                          onClick={() => {
                            const form = new FormData();
                            form.set("destinationId", channel.id);
                            run(
                              () => sendTestNotificationAction(form),
                              `Test queued for ${channel.name}. Check Deliveries for the result.`,
                            );
                          }}
                        >
                          Send test
                        </button>
                        <button
                          type="button"
                          className="secondary"
                          disabled={pending}
                          onClick={() =>
                            setEditingId(editingId === channel.id ? null : channel.id)
                          }
                        >
                          {editingId === channel.id ? "Close schedule" : "Quiet hours"}
                        </button>
                      </>
                    ) : null}
                    <button
                      type="button"
                      className="secondary"
                      disabled={pending}
                      onClick={() => {
                        const next = openId === channel.id ? null : channel.id;
                        setOpenId(next);
                        setDeliveries([]);
                        if (!next) return;
                        startTransition(async () => {
                          const result = await listWebhookDeliveriesAction(next);
                          if (!result.ok) {
                            setError(result.error);
                            return;
                          }
                          setDeliveries(result.data.deliveries);
                        });
                      }}
                    >
                      {openId === channel.id ? "Hide deliveries" : "Deliveries"}
                    </button>
                    {channel.enabled ? (
                      <button
                        type="button"
                        className="danger"
                        disabled={pending}
                        onClick={() => {
                          const form = new FormData();
                          form.set("destinationId", channel.id);
                          run(() => disableWebhookAction(form), `${channel.name} disabled.`);
                        }}
                      >
                        Disable
                      </button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {editing ? (
        <form
          className="stack"
          aria-label={`Quiet hours for ${editing.name}`}
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            form.set("destinationId", editing.id);
            run(async () => {
              const result = await setNotificationScheduleAction(form);
              if (result.ok) setEditingId(null);
              return result;
            }, "Schedule saved.");
          }}
        >
          <h3>Quiet hours for {editing.name}</h3>
          <ScheduleFields key={editing.id} defaultTimezone={defaultTimezone} current={editing} />
          <div>
            <button type="submit" disabled={pending}>
              {pending ? "Saving…" : "Save schedule"}
            </button>
          </div>
        </form>
      ) : null}
      {openId && deliveries.length ? (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Event</th>
                <th>Attempts</th>
                <th>State</th>
              </tr>
            </thead>
            <tbody>
              {deliveries.map((delivery) => (
                <tr key={delivery.id}>
                  <td className="mono">{delivery.event_type}</td>
                  <td>{delivery.attempts}</td>
                  <td>
                    {delivery.delivered_at
                      ? "Delivered"
                      : delivery.dead_lettered_at
                        ? `Dead-lettered${delivery.last_error ? `: ${delivery.last_error}` : ""}`
                        : (delivery.last_error ?? "Pending (held, queued or retrying)")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : openId && !pending ? (
        <p className="muted">No deliveries recorded for this channel.</p>
      ) : null}
    </section>
  );
}
