"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  createWebhookAction,
  disableWebhookAction,
  listWebhookDeliveriesAction,
  replayWebhookDeliveryAction,
} from "@/app/actions";
import { setWebhookSubscriptionsAction } from "@/app/settings/actions";
import type { WebhookDelivery, WebhookDestination } from "@/lib/coord";
import type { EventKind } from "@/lib/coord-events";
import { Alert } from "./ui/alert";
import { StatusPill } from "./ui/badge";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormField } from "./ui/form-field";
import { SecretPanel } from "./ui/secret-panel";
import { Section } from "./ui/section";
import { SkeletonTable } from "./ui/skeleton";
import { EmptyRow, Table, Td } from "./ui/table";
import { toast, toastResult } from "./ui/toast";

function subscriptionSummary(eventTypes: string[] | undefined): string {
  if (!eventTypes || eventTypes.includes("*")) return "All events";
  if (eventTypes.length <= 2) return eventTypes.join(", ");
  return `${eventTypes.length} event types`;
}

/** Delivery state for people: never raw response bodies. */
export function deliveryState(delivery: WebhookDelivery): { label: string; tone: "success" | "danger" | "warning" } {
  if (delivery.delivered_at) return { label: "Delivered", tone: "success" };
  if (delivery.dead_lettered_at) return { label: "Gave up after retries", tone: "danger" };
  if (delivery.last_error) return { label: "Retrying", tone: "warning" };
  return { label: "Queued", tone: "warning" };
}

export function WebhookManager({
  destinations,
  catalogue,
  loadError = null,
  catalogueError = null,
}: {
  destinations: WebhookDestination[];
  catalogue: EventKind[];
  loadError?: string | null;
  catalogueError?: string | null;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState<string | null>(null);
  const [shownOnce, setShownOnce] = useState<{ name: string; secret: string } | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
  const [deliveries, setDeliveries] = useState<WebhookDelivery[] | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [disabling, setDisabling] = useState<WebhookDestination | null>(null);
  const [errors, setErrors] = useState<{ name?: string; url?: string; events?: string }>({});
  const editing = destinations.find((destination) => destination.id === editingId);
  const open = destinations.find((destination) => destination.id === openId);

  function loadDeliveries(id: string) {
    setDeliveries(null);
    startTransition(async () => {
      const result = await listWebhookDeliveriesAction(id);
      if (!result.ok) {
        toastResult(result);
        setOpenId(null);
        return;
      }
      setDeliveries(result.data.deliveries);
    });
  }

  const description =
    "HTTPS endpoints that receive signed events. Loopback, private, overlay and cloud metadata addresses are refused. Delivery is best effort with limited retries, so don't rely on it as a safety control.";
  if (loadError) {
    return (
      <Section id="webhooks" headingLevel={3} title="Webhooks" description={description}>
        <Alert tone="error" title="Webhooks couldn't be loaded">
          {loadError}
        </Alert>
      </Section>
    );
  }

  return (
    <Section id="webhooks" headingLevel={3} title="Webhooks" description={description}>
      {shownOnce ? (
        <SecretPanel
          title={`Copy the signing secret for ${shownOnce.name} now`}
          label="Signing secret"
          secret={shownOnce.secret}
          description="Your endpoint uses it to check each event's signature. It's shown only once and stored sealed."
          onDone={() => setShownOnce(null)}
        />
      ) : null}
      <Table label="Webhook destinations" mobile="stack">
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">URL</th>
            <th scope="col">Events</th>
            <th scope="col">State</th>
            <th scope="col">
              <span className="visually-hidden">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {destinations.length === 0 ? (
            <EmptyRow colSpan={5}>
              {loadError ? "Webhooks couldn't be loaded." : "No webhooks yet. Add one below to send events to another system."}
            </EmptyRow>
          ) : (
            destinations.map((destination) => (
              <tr key={destination.id}>
                <Td label="Name">
                  {destination.name}
                  <span className="cell-sub mono">{destination.secret_prefix}</span>
                </Td>
                <Td label="URL">
                  <span className="mono cell-break">{destination.url}</span>
                </Td>
                <Td label="Events">{subscriptionSummary(destination.event_types)}</Td>
                <Td label="State">
                  <StatusPill tone={destination.enabled ? "success" : "muted"}>
                    {destination.enabled ? "Active" : "Disabled"}
                  </StatusPill>
                </Td>
                <Td>
                  <div className="cell-actions">
                    <Button
                      size="sm"
                      variant="secondary"
                      aria-expanded={openId === destination.id}
                      disabled={pending && openId !== destination.id}
                      onClick={() => {
                        if (openId === destination.id) {
                          setOpenId(null);
                          return;
                        }
                        setOpenId(destination.id);
                        loadDeliveries(destination.id);
                      }}
                    >
                      {openId === destination.id ? "Hide deliveries" : "Deliveries"}
                    </Button>
                    {destination.enabled ? (
                      <>
                        <Button
                          size="sm"
                          variant="secondary"
                          aria-expanded={editingId === destination.id}
                          disabled={pending}
                          onClick={() => setEditingId(editingId === destination.id ? null : destination.id)}
                        >
                          {editingId === destination.id ? "Close events" : "Choose events"}
                        </Button>
                        <Button
                          size="sm"
                          variant="quiet-danger"
                          disabled={pending}
                          onClick={() => setDisabling(destination)}
                        >
                          Disable
                        </Button>
                      </>
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
          aria-labelledby="webhook-events-title"
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            if (form.get("all") !== "on" && form.getAll("event_types").length === 0) {
              setErrors({ events: "Choose at least one event, or all events." });
              return;
            }
            setErrors({});
            form.set("destinationId", editing.id);
            setBusy("events");
            startTransition(async () => {
              const result = await setWebhookSubscriptionsAction(form);
              setBusy(null);
              toastResult(result, { success: "Events saved", successDescription: editing.name });
              if (!result.ok) return;
              setEditingId(null);
              router.refresh();
            });
          }}
        >
          <div className="ui-subsection-head">
            <h4 id="webhook-events-title" className="card-heading">
              Events sent to {editing.name}
            </h4>
          </div>
          <label className="check-option">
            <input type="checkbox" name="all" defaultChecked={!editing.event_types || editing.event_types.includes("*")} />
            <span>All events, including types added in later releases</span>
          </label>
          {catalogueError ? (
            <Alert tone="error">{catalogueError}</Alert>
          ) : (
            <fieldset className="check-grid">
              <legend>Or only these events</legend>
              {catalogue.map((kind) => (
                <label key={kind.event_type} className="check-option">
                  <input
                    type="checkbox"
                    name="event_types"
                    value={kind.event_type}
                    defaultChecked={editing.event_types?.includes(kind.event_type)}
                  />
                  <span>
                    <span className="mono">{kind.event_type}</span>
                    {kind.severity === "warning" ? " (warning)" : ""}
                    <span className="muted">{kind.summary}</span>
                  </span>
                </label>
              ))}
            </fieldset>
          )}
          {errors.events ? (
            <p className="ui-field-error" role="alert">
              {errors.events}
            </p>
          ) : null}
          <div className="actions">
            <Button type="submit" loading={busy === "events"} loadingLabel="Saving…" disabled={pending}>
              Save events
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
                  <th scope="col">
                    <span className="visually-hidden">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {deliveries.length === 0 ? (
                  <EmptyRow colSpan={4}>No deliveries recorded yet.</EmptyRow>
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
                        <Td>
                          {delivery.delivered_at ? null : (
                            <div className="cell-actions">
                              <Button
                                size="sm"
                                variant="secondary"
                                loading={busy === delivery.id}
                                disabled={pending}
                                onClick={() => {
                                  const form = new FormData();
                                  form.set("deliveryId", delivery.id);
                                  setBusy(delivery.id);
                                  startTransition(async () => {
                                    const result = await replayWebhookDeliveryAction(form);
                                    setBusy(null);
                                    toastResult(result, { success: "Delivery queued again" });
                                    if (result.ok) loadDeliveries(open.id);
                                  });
                                }}
                              >
                                Replay
                              </Button>
                            </div>
                          )}
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

      <details className="form-disclosure" open={destinations.length === 0 && !loadError}>
        <summary>Add a webhook</summary>
        <form
          className="ui-form"
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            const formEl = event.currentTarget;
            const form = new FormData(formEl);
            const name = String(form.get("name") ?? "").trim();
            const url = String(form.get("url") ?? "").trim();
            const next: typeof errors = {};
            if (!name) next.name = "Name the webhook, for example SIEM ingest.";
            if (!/^https:\/\/[^\s]+$/u.test(url)) next.url = "Enter an address that starts with https://.";
            setErrors(next);
            if (Object.keys(next).length) return;
            setShownOnce(null);
            setBusy("create");
            startTransition(async () => {
              const result = await createWebhookAction(form);
              setBusy(null);
              if (!result.ok) {
                if (result.ref) toastResult(result);
                else setErrors({ url: result.error });
                return;
              }
              formEl.reset();
              setShownOnce({ name, secret: result.data.secret });
              toast.success("Webhook added");
              router.refresh();
            });
          }}
        >
          <div className="form-grid">
            <FormField label="Name" required error={errors.name}>
              <input name="name" maxLength={64} autoComplete="off" />
            </FormField>
            <FormField label="HTTPS URL" required error={errors.url}>
              <input name="url" type="url" placeholder="https://example.com/hooks/blaktail" autoComplete="off" />
            </FormField>
          </div>
          <div className="actions">
            <Button type="submit" loading={busy === "create"} loadingLabel="Adding…" disabled={pending}>
              Add webhook
            </Button>
          </div>
        </form>
      </details>

      <ConfirmDialog
        open={disabling !== null}
        title="Disable this webhook?"
        description={
          disabling
            ? `${disabling.name} stops receiving events. There's no way to turn it back on; to send events there again, add it as a new webhook.`
            : null
        }
        confirmText={disabling?.name}
        confirmLabel="Disable webhook"
        pending={pending}
        onCancel={() => setDisabling(null)}
        onConfirm={() => {
          if (!disabling) return;
          const form = new FormData();
          form.set("destinationId", disabling.id);
          const name = disabling.name;
          startTransition(async () => {
            const result = await disableWebhookAction(form);
            setDisabling(null);
            toastResult(result, { success: `${name} disabled` });
            if (result.ok) router.refresh();
          });
        }}
      />
    </Section>
  );
}
