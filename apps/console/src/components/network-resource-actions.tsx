"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  deleteNetworkResourceAction,
  setNetworkResourceEnabledAction,
} from "@/app/networks/actions";
import { can, permissionReason, roleLabel, type OrgRole } from "@/lib/roles";

export function NetworkResourceActions({
  organisationId,
  organisationName,
  role,
  resourceId,
  resourceName,
  etag,
  enabled,
}: {
  organisationId: string;
  organisationName: string;
  role: OrgRole;
  resourceId: string;
  resourceName: string;
  etag: string;
  enabled: boolean;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const allowed = can(role, "manage_networks");
  const reason = permissionReason(role, "manage_networks");

  function payload(extra: Record<string, string> = {}): FormData {
    const data = new FormData();
    data.set("organisationId", organisationId);
    data.set("resourceId", resourceId);
    data.set("etag", etag);
    for (const [key, value] of Object.entries(extra)) data.set(key, value);
    return data;
  }

  return (
    <div className="stack">
      <div className="row">
        <span className="badge network">{organisationName}</span>
        <span className="muted">Acting as {roleLabel(role)}</span>
      </div>
      <div className="actions">
        <button
          type="button"
          className="secondary"
          disabled={!allowed || pending}
          title={reason ?? undefined}
          onClick={() => {
            setError(null);
            startTransition(async () => {
              const result = await setNetworkResourceEnabledAction(
                payload({ enabled: String(!enabled) }),
              );
              if (!result.ok) setError(result.error);
              else router.refresh();
            });
          }}
        >
          {enabled ? "Disable and withdraw routes" : "Enable"}
        </button>
        {confirming ? (
          <>
            <button
              type="button"
              className="danger"
              disabled={!allowed || pending}
              onClick={() => {
                setError(null);
                startTransition(async () => {
                  const result = await deleteNetworkResourceAction(payload());
                  if (!result.ok) {
                    setError(result.error);
                    return;
                  }
                  router.push("/networks");
                  router.refresh();
                });
              }}
            >
              Delete {resourceName}
            </button>
            <button type="button" className="secondary" onClick={() => setConfirming(false)}>
              Keep it
            </button>
          </>
        ) : (
          <button
            type="button"
            className="quiet-danger"
            disabled={!allowed || pending}
            title={reason ?? undefined}
            onClick={() => setConfirming(true)}
          >
            Delete…
          </button>
        )}
      </div>
      {confirming ? (
        <p className="muted" role="alert">
          Deleting withdraws this route from every client on their next sync
          (within about 25 seconds). This cannot be undone.
        </p>
      ) : null}
      {reason ? <p className="muted">{reason}</p> : null}
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}
