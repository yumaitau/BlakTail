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
import { Alert } from "./ui/alert";
import { StatusPill } from "./ui/badge";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormField } from "./ui/form-field";
import { Section } from "./ui/section";
import { SkeletonTable } from "./ui/skeleton";
import { EmptyRow, Table, Td } from "./ui/table";
import { toastResult } from "./ui/toast";
import { deliveryState } from "./webhook-manager";

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
    <fieldset className="form-fieldset">
      <legend>Quiet hours and digest</legend>
      <label className="check-option">
        <input
          type="checkbox"
          name="quiet"
          checked={quiet}
          onChange={(event) => setQuiet(event.currentTarget.checked)}
        />
        <span>Hold routine alerts during quiet hours. Warnings always send straight away.</span>
      </label>
      {quiet ? (
        <div className="form-grid">
          <FormField label="From" required>
            <input name="quietStart" type="time" defaultValue={current?.quiet_hours?.start ?? "22:00"} />
          </FormField>
          <FormField label="Until" required>
            <input name="quietEnd" type="time" defaultValue={current?.quiet_hours?.end ?? "07:00"} />
          </FormField>
          <FormField label="Time zone">
            <select name="timezone" defaultValue={current?.quiet_hours?.timezone ?? defaultTimezone}>
              {TIMEZONES.map((zone) => (
                <option key={zone} value={zone}>
                  {zone}
                </option>
              ))}
            </select>
          </FormField>
        </div>
      ) : null}
      <FormField label="Routine alerts" className="field-narrow">
        <select name="digestMinutes" defaultValue={String(current?.digest_minutes ?? 0)}>
          {DIGESTS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </FormField>
    </fieldset>
  );
}

export function NotificationChannels({
  channels,
  catalogue,
  capabilities,
  loadError = null,
  canAcknowledgeResidency,
  organisationName,
  roleLabel,
}: {
  channels: WebhookDestination[];
  catalogue: EventKind[];
  capabilities: NotificationCapabilities | null;
  loadError?: string | null;
  canAcknowledgeResidency: boolean;
  organisationName: string;
  roleLabel: string;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState<string | null>(null);
  const [kind, setKind] = useState<"email" | "slack" | "teams">("email");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
  const [deliveries, setDeliveries] = useState<WebhookDelivery[] | null>(null);
  const [disabling, setDisabling] = useState<WebhookDestination | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const editing = channels.find((channel) => channel.id === editingId);
  const open = channels.find((channel) => channel.id === openId);
  const warnings = catalogue.filter((event) => event.severity === "warning");
  const defaultTimezone = capabilities?.default_timezone ?? "Australia/Sydney";
  const offshore = kind !== "email";
  const emailUnavailable = kind === "email" && !capabilities?.email_configured;
  const offshoreBlocked = offshore && !canAcknowledgeResidency;

  function run(
    key: string,
    work: () => Promise<{ ok: true } | { ok: false; error: string; ref?: string; fieldErrors?: Record<string, string> }>,
    done: string,
    after?: () => void,
    description?: string,
  ) {
    setBusy(key);
    startTransition(async () => {
      const result = await work();
      setBusy(null);
      const fields = toastResult(result, { success: done, successDescription: description });
      setErrors(fields);
      if (!result.ok) return;
      after?.();
      router.refresh();
    });
  }

  const description = `Send events to people by email, Slack or Microsoft Teams, with the same queue and retries as webhooks. Alerts are best effort, not a safety control. You're changing ${organisationName} as ${roleLabel.toLowerCase()}.`;
  if (loadError) {
    return (
      <Section id="notifications" headingLevel={3} title="Notification channels" description={description}>
        <Alert tone="error" title="Notification channels couldn't be loaded">
          {loadError}
        </Alert>
      </Section>
    );
  }

  return (
    <Section id="notifications" headingLevel={3} title="Notification channels" description={description}>
      {capabilities?.email_configured ? (
        <p className="muted">
          Email goes through the operator&apos;s relay as{" "}
          <span className="mono">{capabilities.email_from}</span> (
          {capabilities.email_tls === "none" ? "local relay, no TLS" : capabilities.email_tls}). Relay
          passwords stay with the operator and are never stored here.
        </p>
      ) : capabilities ? (
        <Alert tone="info" title="Email isn't available">
          The operator hasn&apos;t set up an email relay on the coordinator. Slack and Teams channels
          still work.
        </Alert>
      ) : null}

      <Table label="Notification channels" mobile="stack">
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Sends to</th>
            <th scope="col">Schedule</th>
            <th scope="col">State</th>
            <th scope="col">
              <span className="visually-hidden">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {channels.length === 0 ? (
            <EmptyRow colSpan={5}>
              {loadError ? "Channels couldn't be loaded." : "No notification channels yet. Add one below."}
            </EmptyRow>
          ) : (
            channels.map((channel) => (
              <tr key={channel.id}>
                <Td label="Name">
                  {channel.name}
                  <span className="cell-sub">
                    {KIND_LABEL[channel.kind ?? ""] ?? channel.kind}
                    {channel.residency_acknowledged_at ? " · offshore, accepted by an owner" : ""}
                  </span>
                </Td>
                <Td label="Sends to">
                  <span className="mono cell-break">
                    {channel.kind === "email" ? channel.recipients?.join(", ") : channel.url}
                  </span>
                </Td>
                <Td label="Schedule">{scheduleSummary(channel)}</Td>
                <Td label="State">
                  <StatusPill tone={channel.enabled ? "success" : "muted"}>
                    {channel.enabled ? "Active" : "Disabled"}
                  </StatusPill>
                </Td>
                <Td>
                  <div className="cell-actions">
                    {channel.enabled ? (
                      <>
                        <Button
                          size="sm"
                          variant="secondary"
                          loading={busy === `test-${channel.id}`}
                          loadingLabel="Sending…"
                          disabled={pending}
                          onClick={() => {
                            const form = new FormData();
                            form.set("destinationId", channel.id);
                            run(
                              `test-${channel.id}`,
                              () => sendTestNotificationAction(form),
                              "Test queued",
                              undefined,
                              `Check Deliveries on ${channel.name} for the result.`,
                            );
                          }}
                        >
                          Send test
                        </Button>
                        <Button
                          size="sm"
                          variant="secondary"
                          aria-expanded={editingId === channel.id}
                          disabled={pending}
                          onClick={() => setEditingId(editingId === channel.id ? null : channel.id)}
                        >
                          {editingId === channel.id ? "Close schedule" : "Quiet hours"}
                        </Button>
                      </>
                    ) : null}
                    <Button
                      size="sm"
                      variant="secondary"
                      aria-expanded={openId === channel.id}
                      disabled={pending && openId !== channel.id}
                      onClick={() => {
                        if (openId === channel.id) {
                          setOpenId(null);
                          return;
                        }
                        setOpenId(channel.id);
                        setDeliveries(null);
                        startTransition(async () => {
                          const result = await listWebhookDeliveriesAction(channel.id);
                          if (!result.ok) {
                            toastResult(result);
                            setOpenId(null);
                            return;
                          }
                          setDeliveries(result.data.deliveries);
                        });
                      }}
                    >
                      {openId === channel.id ? "Hide deliveries" : "Deliveries"}
                    </Button>
                    {channel.enabled ? (
                      <Button size="sm" variant="quiet-danger" disabled={pending} onClick={() => setDisabling(channel)}>
                        Disable
                      </Button>
                    ) : null}
                  </div>
                </Td>
              </tr>
            ))
          )}
        </tbody>
      </Table>

      {editing ? (
        <form
          className="ui-subsection"
          aria-labelledby="channel-schedule-title"
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            form.set("destinationId", editing.id);
            run("schedule", () => setNotificationScheduleAction(form), "Schedule saved", () => setEditingId(null), editing.name);
          }}
        >
          <div className="ui-subsection-head">
            <h4 id="channel-schedule-title" className="card-heading">
              Quiet hours for {editing.name}
            </h4>
          </div>
          <ScheduleFields key={editing.id} defaultTimezone={defaultTimezone} current={editing} />
          <div className="actions">
            <Button type="submit" loading={busy === "schedule"} loadingLabel="Saving…" disabled={pending}>
              Save schedule
            </Button>
            <Button variant="secondary" disabled={pending} onClick={() => setEditingId(null)}>
              Cancel
            </Button>
          </div>
        </form>
      ) : null}

      {open ? (
        <div className="ui-subsection" aria-live="polite">
          <div className="ui-subsection-head">
            <h4 className="card-heading">Recent deliveries to {open.name}</h4>
          </div>
          {deliveries === null ? (
            <SkeletonTable rows={3} label="Loading deliveries" />
          ) : (
            <Table label={`Deliveries to ${open.name}`} mobile="stack">
              <thead>
                <tr>
                  <th scope="col">Event</th>
                  <th scope="col">Attempts</th>
                  <th scope="col">State</th>
                </tr>
              </thead>
              <tbody>
                {deliveries.length === 0 ? (
                  <EmptyRow colSpan={3}>No deliveries recorded yet.</EmptyRow>
                ) : (
                  deliveries.map((delivery) => {
                    const state = deliveryState(delivery);
                    return (
                      <tr key={delivery.id}>
                        <Td label="Event" className="mono">
                          {delivery.event_type}
                        </Td>
                        <Td label="Attempts">{delivery.attempts}</Td>
                        <Td label="State">
                          <StatusPill tone={state.tone}>{state.label}</StatusPill>
                        </Td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </Table>
          )}
        </div>
      ) : null}

      <details className="form-disclosure" open={channels.length === 0 && !loadError}>
        <summary>Add a channel</summary>
        <form
          className="ui-form"
          aria-label="Add a notification channel"
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            const formEl = event.currentTarget;
            const form = new FormData(formEl);
            const next: Record<string, string> = {};
            if (!String(form.get("name") ?? "").trim()) next.name = "Name the channel, for example On-call email.";
            if (kind === "email" && !String(form.get("recipients") ?? "").includes("@")) {
              next.recipients = "Enter at least one email address.";
            }
            if (kind !== "email" && !/^https:\/\//u.test(String(form.get("url") ?? ""))) {
              next.url = "Paste the incoming webhook address. It starts with https://.";
            }
            if (kind !== "email" && form.get("residencyAcknowledged") !== "on") {
              next.residencyAcknowledged = "Tick this to accept that alerts leave Australia.";
            }
            setErrors(next);
            if (Object.keys(next).length) return;
            run("create", () => createNotificationChannelAction(form), "Channel added", () => formEl.reset(), "Send a test to check it.");
          }}
        >
          <div className="form-grid">
            <FormField label="Channel type">
              <select
                name="kind"
                value={kind}
                onChange={(event) => setKind(event.currentTarget.value as "email" | "slack" | "teams")}
              >
                <option value="email">Email</option>
                <option value="slack">Slack (offshore)</option>
                <option value="teams">Microsoft Teams (offshore)</option>
              </select>
            </FormField>
            <FormField label="Name" required error={errors.name}>
              <input name="name" maxLength={64} autoComplete="off" />
            </FormField>
          </div>
          {kind === "email" ? (
            <FormField label="Recipients" hint="Up to 10, separated by commas." required error={errors.recipients}>
              <input name="recipients" placeholder="ops@example.org.au" autoComplete="off" />
            </FormField>
          ) : (
            <>
              <FormField label="Incoming webhook URL" hint="Stored sealed and never shown again." required error={errors.url}>
                <input
                  name="url"
                  type="url"
                  autoComplete="off"
                  placeholder={
                    kind === "slack"
                      ? "https://hooks.slack.com/services/…"
                      : "https://….webhook.office.com/… or a Workflows URL"
                  }
                />
              </FormField>
              <Alert tone="warning" title="Alerts leave Australia">
                {kind === "slack" ? "Slack" : "Microsoft Teams"} stores and processes message content
                outside BlakTail&apos;s onshore boundary, under the vendor&apos;s terms. Alerts carry event
                names, device and person identifiers and redacted details.
              </Alert>
              <label className="check-option">
                <input type="checkbox" name="residencyAcknowledged" disabled={!canAcknowledgeResidency} />
                <span>
                  I&apos;m an owner and I accept that these alerts leave Australia.
                  {offshoreBlocked ? (
                    <span className="muted">Only an owner can accept this. Ask an owner to add the channel.</span>
                  ) : null}
                </span>
              </label>
              {errors.residencyAcknowledged ? (
                <p className="ui-field-error" role="alert">
                  {errors.residencyAcknowledged}
                </p>
              ) : null}
            </>
          )}
          <FormField label="Events" className="field-narrow">
            <select name="events" defaultValue="all">
              <option value="all">All events</option>
              <option value="warnings">Warnings only</option>
            </select>
          </FormField>
          {warnings.map((event) => (
            <input key={event.event_type} type="hidden" name="warningTypes" value={event.event_type} />
          ))}
          <ScheduleFields defaultTimezone={defaultTimezone} />
          <div className="actions">
            <Button
              type="submit"
              loading={busy === "create"}
              loadingLabel="Adding…"
              disabled={pending || emailUnavailable || offshoreBlocked}
              title={
                emailUnavailable
                  ? "The operator hasn't set up an email relay."
                  : offshoreBlocked
                    ? "Only an owner can add an offshore channel."
                    : undefined
              }
            >
              Add channel
            </Button>
            {emailUnavailable ? <span className="muted">Email needs an operator relay first.</span> : null}
          </div>
        </form>
      </details>

      <ConfirmDialog
        open={disabling !== null}
        title="Disable this channel?"
        description={
          disabling
            ? `${disabling.name} stops receiving alerts. There's no way to turn it back on; add it again as a new channel if you need it.`
            : null
        }
        confirmText={disabling?.name}
        confirmLabel="Disable channel"
        pending={pending}
        onCancel={() => setDisabling(null)}
        onConfirm={() => {
          if (!disabling) return;
          const form = new FormData();
          form.set("destinationId", disabling.id);
          run("disable", () => disableWebhookAction(form), `${disabling.name} disabled`, undefined);
          setDisabling(null);
        }}
      />
    </Section>
  );
}
