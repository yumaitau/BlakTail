"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { revokeDeviceAction, tombstoneDeviceAction } from "@/app/actions";
import { setDeviceSuspendedAction } from "@/app/devices/actions";
import { can, permissionReason, roleLabel, type OrgRole } from "@/lib/roles";

type Kind = "suspend" | "resume" | "revoke" | "delete";

const titles: Record<Kind, string> = {
  suspend: "Suspend device",
  resume: "Resume device",
  revoke: "Revoke device",
  delete: "Delete from inventory",
};

export function PeerLifecycle({
  nodeId,
  label,
  organisationId,
  organisationName,
  role,
  state,
  approvedRoutes,
  tags,
}: {
  nodeId: string;
  label: string;
  organisationId: string;
  organisationName: string;
  role: OrgRole;
  state: "active" | "suspended" | "revoked" | "deleted";
  approvedRoutes: string[];
  tags: string[];
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [confirm, setConfirm] = useState<Kind | null>(null);
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState<{ text: string; error: boolean } | null>(null);
  const denied = permissionReason(role, "manage_peers");
  const allowed = can(role, "manage_peers");
  const ended = state === "revoked" || state === "deleted";

  const routes =
    approvedRoutes.length > 0
      ? approvedRoutes.map((route) => (route === "0.0.0.0/0" ? "exit node" : route)).join(", ")
      : "no approved routes";

  const impact: Record<Kind, string> = {
    suspend: `${label} leaves every peer map in ${organisationName} at the next update and cannot fetch updates or renew its credential. Traffic through it stops, including ${routes}. Its name, addresses, tags (${tags.join(", ") || "none"}), route approvals and owner are kept, so Resume restores it without re-enrolment.`,
    resume: `${label} rejoins peer maps in ${organisationName} with the same identity, addresses, tags and route approvals (${routes}). Access policy still decides which peers can reach it. If its credential has expired, it still needs reauth with a fresh join key.`,
    revoke: `${label} permanently loses access to ${organisationName}. Its credential stops working and ${routes} stop being served. Re-enrolling creates a new device record. This cannot be undone.`,
    delete: `${label} is removed from the ${organisationName} inventory and also revoked. An audit tombstone is kept for seven days. This cannot be undone.`,
  };

  function run(kind: Kind) {
    const formData = new FormData();
    formData.set("nodeId", nodeId);
    formData.set("organisationId", organisationId);
    if (kind === "suspend" || kind === "resume") {
      formData.set("suspend", String(kind === "suspend"));
      formData.set("reason", reason);
    }
    setConfirm(null);
    setMessage(null);
    startTransition(async () => {
      const result =
        kind === "revoke"
          ? await revokeDeviceAction(formData)
          : kind === "delete"
            ? await tombstoneDeviceAction(formData)
            : await setDeviceSuspendedAction(formData);
      const done: Record<Kind, string> = {
        suspend: `${label} is suspended.`,
        resume: `${label} is active again.`,
        revoke: `${label} is revoked.`,
        delete: `${label} was removed from the inventory.`,
      };
      setMessage({ text: result.ok ? done[kind] : result.error, error: !result.ok });
      if (result.ok) {
        setReason("");
        router.refresh();
      }
    });
  }

  return (
    <section className="panel stack" aria-labelledby="lifecycle-title">
      <div>
        <p className="eyebrow">Lifecycle</p>
        <h2 id="lifecycle-title">Access for this device</h2>
        <p className="muted">
          Acting in <span className="badge network">{organisationName}</span> as{" "}
          {roleLabel(role)}.
        </p>
      </div>
      <dl className="details">
        <div>
          <dt>Suspend</dt>
          <dd>Temporary. Keeps identity, routes and tags; Resume restores it.</dd>
        </div>
        <div>
          <dt>Revoke</dt>
          <dd>Permanent. The credential stops working; re-enrolment is a new device.</dd>
        </div>
        <div>
          <dt>Delete</dt>
          <dd>Revokes and hides it from the inventory, keeping an audit tombstone.</dd>
        </div>
      </dl>
      {ended ? (
        <p className="muted">
          This device is {state}. Lifecycle changes are no longer available.
        </p>
      ) : (
        <div className="actions">
          {state === "suspended" ? (
            <button
              type="button"
              className="secondary"
              disabled={!allowed || pending}
              title={denied ?? undefined}
              onClick={() => setConfirm("resume")}
            >
              Resume
            </button>
          ) : (
            <button
              type="button"
              className="secondary"
              disabled={!allowed || pending}
              title={denied ?? undefined}
              onClick={() => setConfirm("suspend")}
            >
              Suspend
            </button>
          )}
          <button
            type="button"
            className="danger"
            disabled={!allowed || pending}
            title={denied ?? undefined}
            onClick={() => setConfirm("revoke")}
          >
            Revoke access
          </button>
          <button
            type="button"
            className="quiet-danger"
            disabled={!allowed || pending}
            title={denied ?? undefined}
            onClick={() => setConfirm("delete")}
          >
            Delete from inventory
          </button>
        </div>
      )}
      {denied && !ended ? <p className="muted">{denied}</p> : null}
      {message ? (
        <p
          className={message.error ? "error" : "muted"}
          role={message.error ? "alert" : "status"}
          aria-live="polite"
        >
          {message.text}
        </p>
      ) : null}
      {confirm ? (
        <div className="confirm-backdrop">
          <div
            className="confirm-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="lifecycle-confirm-title"
            aria-describedby="lifecycle-confirm-impact"
            onKeyDown={(event) => {
              if (event.key === "Escape") setConfirm(null);
            }}
          >
            <h2 id="lifecycle-confirm-title">{titles[confirm]}</h2>
            <p id="lifecycle-confirm-impact">{impact[confirm]}</p>
            {confirm === "suspend" ? (
              <label>
                Reason (recorded in the audit log)
                <input
                  type="text"
                  maxLength={200}
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                />
              </label>
            ) : null}
            <div className="actions">
              <button
                type="button"
                className="secondary"
                autoFocus
                onClick={() => setConfirm(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className={confirm === "resume" || confirm === "suspend" ? undefined : "danger"}
                disabled={pending}
                onClick={() => run(confirm)}
              >
                {titles[confirm]}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}
