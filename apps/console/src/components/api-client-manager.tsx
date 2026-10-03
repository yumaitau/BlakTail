"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  createApiClientAction,
  revokeApiClientAction,
} from "@/app/actions";
import {
  rotateApiClientAction,
  setApiClientSuspendedAction,
} from "@/app/settings/actions";
import type { ApiClient } from "@/lib/coord";

const SCOPES = [
  "devices:read",
  "devices:write",
  "keys:read",
  "keys:write",
  "routes:write",
  "policy:write",
  "dns:write",
  "audit:read",
  "audit:export",
  "status:read",
  "webhooks:read",
  "webhooks:write",
] as const;

export function ApiClientManager({ clients }: { clients: ApiClient[] }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [shownOnce, setShownOnce] = useState<string | null>(null);

  return (
    <div className="panel stack">
      <div>
        <h2>Automation credentials</h2>
        <p className="muted">
          Organisation-scoped service users for the versioned admin API. The
          secret is shown once and stored as a hash. Send{" "}
          <span className="mono">X-BlakTail-Organisation</span> with every
          request. Service users cannot sign in to this console; their changes
          appear in the audit log as <span className="mono">api:&lt;id&gt;</span>.
          Suspending or rotating stops the old secret and every access token
          minted from it on their next request.
        </p>
      </div>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          setError(null);
          setShownOnce(null);
          startTransition(async () => {
            const result = await createApiClientAction(form);
            if (!result.ok) {
              setError(result.error);
              return;
            }
            setShownOnce(result.data.token);
            router.refresh();
          });
        }}
      >
        <label>
          Name
          <input name="name" required maxLength={64} />
        </label>
        <fieldset>
          <legend>Scopes</legend>
          {SCOPES.map((scope) => (
            <label key={scope} className="route-option mono">
              <input type="checkbox" name="scopes" value={scope} defaultChecked={scope === "status:read" || scope === "devices:read"} />
              {scope}
            </label>
          ))}
        </fieldset>
        <button type="submit" disabled={pending}>
          {pending ? "Creating…" : "Create credential"}
        </button>
      </form>
      {shownOnce ? (
        <label>
          Token — shown once
          <input className="mono" value={shownOnce} readOnly />
        </label>
      ) : null}
      {error ? <p className="error">{error}</p> : null}
      {clients.length ? (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Prefix</th>
                <th>Scopes</th>
                <th>State</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {clients.map((client) => (
                <tr key={client.id}>
                  <td>{client.name}</td>
                  <td className="mono">{client.token_prefix}</td>
                  <td className="mono">{client.scopes.join(", ")}</td>
                  <td>
                    <span
                      className={
                        client.revoked
                          ? "badge revoked"
                          : client.suspended
                            ? "badge pending"
                            : "badge online"
                      }
                    >
                      {client.revoked ? "Revoked" : client.suspended ? "Suspended" : "Active"}
                    </span>
                    {client.expires_at ? (
                      <div className="muted">
                        Expires {new Date(client.expires_at * 1000).toLocaleDateString("en-AU")}
                      </div>
                    ) : null}
                    {client.rotated_at ? (
                      <div className="muted">
                        Rotated {new Date(client.rotated_at * 1000).toLocaleDateString("en-AU")}
                      </div>
                    ) : null}
                  </td>
                  <td>
                    {client.revoked ? null : (
                      <div className="stack">
                      <button
                        type="button"
                        className="secondary"
                        disabled={pending}
                        onClick={() => {
                          const form = new FormData();
                          form.set("clientId", client.id);
                          setError(null);
                          setShownOnce(null);
                          startTransition(async () => {
                            const result = await rotateApiClientAction(form);
                            if (!result.ok) {
                              setError(result.error);
                              return;
                            }
                            setShownOnce(result.data.token);
                            router.refresh();
                          });
                        }}
                      >
                        Rotate secret
                      </button>
                      <button
                        type="button"
                        className="secondary"
                        disabled={pending}
                        onClick={() => {
                          const form = new FormData();
                          form.set("clientId", client.id);
                          form.set("suspended", client.suspended ? "false" : "true");
                          setError(null);
                          startTransition(async () => {
                            const result = await setApiClientSuspendedAction(form);
                            if (!result.ok) {
                              setError(result.error);
                              return;
                            }
                            router.refresh();
                          });
                        }}
                      >
                        {client.suspended ? "Resume" : "Suspend"}
                      </button>
                      <button
                        type="button"
                        className="danger"
                        disabled={pending}
                        onClick={() => {
                          const form = new FormData();
                          form.set("clientId", client.id);
                          startTransition(async () => {
                            const result = await revokeApiClientAction(form);
                            if (!result.ok) {
                              setError(result.error);
                              return;
                            }
                            router.refresh();
                          });
                        }}
                      >
                        Revoke
                      </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}
