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

function subscriptionSummary(eventTypes: string[] | undefined): string {
  if (!eventTypes || eventTypes.includes("*")) return "All events";
  return eventTypes.join(", ");
}

export function WebhookManager({
  destinations,
  catalogue,
}: {
  destinations: WebhookDestination[];
  catalogue: EventKind[];
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [shownOnce, setShownOnce] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
  const [deliveries, setDeliveries] = useState<WebhookDelivery[]>([]);
  const [editingId, setEditingId] = useState<string | null>(null);
  const editing = destinations.find((destination) => destination.id === editingId);

  return (
    <div className="panel stack">
      <div>
        <h2>Webhook destinations</h2>
        <p className="muted">
          HTTPS endpoints that receive signed events from the catalogue below.
          The signing secret is shown once and stored sealed. Loopback,
          private, overlay and cloud metadata targets are rejected. Email,
          Slack and Teams alerts are set up under Notification channels.
          Delivery is best effort with bounded retries — not a safety
          control.
        </p>
      </div>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          const formEl = event.currentTarget;
          const form = new FormData(formEl);
          setError(null);
          setShownOnce(null);
          startTransition(async () => {
            const result = await createWebhookAction(form);
            if (!result.ok) {
              setError(result.error);
              return;
            }
            setShownOnce(result.data.secret);
            formEl.reset();
            router.refresh();
          });
        }}
      >
        <label>
          Name
          <input name="name" required maxLength={64} />
        </label>
        <label>
          HTTPS URL
          <input
            name="url"
            type="url"
            required
            placeholder="https://example.com/hooks/blaktail"
          />
        </label>
        <button type="submit" disabled={pending}>
          {pending ? "Creating…" : "Create destination"}
        </button>
      </form>
      {shownOnce ? (
        <label>
          Signing secret — shown once
          <input className="mono" value={shownOnce} readOnly />
        </label>
      ) : null}
      {error ? <p className="error">{error}</p> : null}
      {destinations.length ? (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>URL</th>
                <th>Prefix</th>
                <th>Events</th>
                <th>State</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {destinations.map((destination) => (
                <tr key={destination.id}>
                  <td>{destination.name}</td>
                  <td className="mono">{destination.url}</td>
                  <td className="mono">{destination.secret_prefix}</td>
                  <td>{subscriptionSummary(destination.event_types)}</td>
                  <td>
                    <span
                      className={
                        destination.enabled ? "badge online" : "badge revoked"
                      }
                    >
                      {destination.enabled ? "Active" : "Disabled"}
                    </span>
                  </td>
                  <td>
                    <button
                      type="button"
                      disabled={pending}
                      onClick={() => {
                        const next =
                          openId === destination.id ? null : destination.id;
                        setOpenId(next);
                        if (!next) {
                          setDeliveries([]);
                          return;
                        }
                        startTransition(async () => {
                          const result = await listWebhookDeliveriesAction(
                            destination.id,
                          );
                          if (!result.ok) {
                            setError(result.error);
                            return;
                          }
                          setDeliveries(result.data.deliveries);
                        });
                      }}
                    >
                      {openId === destination.id
                        ? "Hide deliveries"
                        : "Deliveries"}
                    </button>
                    {destination.enabled ? (
                      <button
                        type="button"
                        className="secondary"
                        disabled={pending}
                        onClick={() =>
                          setEditingId(editingId === destination.id ? null : destination.id)
                        }
                      >
                        {editingId === destination.id ? "Close events" : "Choose events"}
                      </button>
                    ) : null}
                    {destination.enabled ? (
                      <button
                        type="button"
                        className="danger"
                        disabled={pending}
                        onClick={() => {
                          const form = new FormData();
                          form.set("destinationId", destination.id);
                          startTransition(async () => {
                            const result = await disableWebhookAction(form);
                            if (!result.ok) {
                              setError(result.error);
                              return;
                            }
                            router.refresh();
                          });
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
      ) : null}
      {editing ? (
        <form
          className="stack"
          aria-label={`Events sent to ${editing.name}`}
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            form.set("destinationId", editing.id);
            setError(null);
            startTransition(async () => {
              const result = await setWebhookSubscriptionsAction(form);
              if (!result.ok) {
                setError(result.error);
                return;
              }
              setEditingId(null);
              router.refresh();
            });
          }}
        >
          <h3>Events sent to {editing.name}</h3>
          <label className="row">
            <input
              type="checkbox"
              name="all"
              defaultChecked={!editing.event_types || editing.event_types.includes("*")}
            />
            All events, including types added in later releases
          </label>
          {catalogue.length === 0 ? (
            <p className="muted">The event catalogue could not be loaded.</p>
          ) : (
            <fieldset>
              <legend>Or only these events</legend>
              {catalogue.map((kind) => (
                <label key={kind.event_type} className="row">
                  <input
                    type="checkbox"
                    name="event_types"
                    value={kind.event_type}
                    defaultChecked={editing.event_types?.includes(kind.event_type)}
                  />
                  <span className="mono">{kind.event_type}</span>
                  <span className={kind.severity === "warning" ? "badge warn" : "badge"}>
                    {kind.severity}
                  </span>
                  <span className="muted">{kind.summary}</span>
                </label>
              ))}
            </fieldset>
          )}
          <div>
            <button type="submit" disabled={pending}>
              {pending ? "Saving…" : "Save events"}
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
                <th />
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
                        : delivery.last_error ?? "Pending"}
                  </td>
                  <td>
                    {delivery.delivered_at ? null : (
                      <button
                        type="button"
                        disabled={pending}
                        onClick={() => {
                          const form = new FormData();
                          form.set("deliveryId", delivery.id);
                          startTransition(async () => {
                            const result =
                              await replayWebhookDeliveryAction(form);
                            if (!result.ok) {
                              setError(result.error);
                              return;
                            }
                            const listed = await listWebhookDeliveriesAction(
                              openId,
                            );
                            if (!listed.ok) {
                              setError(listed.error);
                              return;
                            }
                            setDeliveries(listed.data.deliveries);
                          });
                        }}
                      >
                        Replay
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : openId && !pending ? (
        <p className="muted">No deliveries recorded for this destination.</p>
      ) : null}
    </div>
  );
}
