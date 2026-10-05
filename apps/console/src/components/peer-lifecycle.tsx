"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { revokeDeviceAction, tombstoneDeviceAction } from "@/app/actions";
import { setDeviceSuspendedAction } from "@/app/devices/actions";
import { permissionReason, roleLabel, type OrgRole } from "@/lib/roles";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormField } from "./ui/form-field";
import { PermissionNotice } from "./ui/permission-notice";
import { Section } from "./ui/section";
import { toastResult } from "./ui/toast";

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
  const denied = permissionReason(role, "manage_peers");
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
    startTransition(async () => {
      const result =
        kind === "revoke"
          ? await revokeDeviceAction(formData)
          : kind === "delete"
            ? await tombstoneDeviceAction(formData)
            : await setDeviceSuspendedAction(formData);
      const done: Record<Kind, [string, string]> = {
        suspend: ["Device suspended", `${label} is out of every peer map until you resume it.`],
        resume: ["Device resumed", `${label} is active again.`],
        revoke: ["Device access revoked", `${label} can no longer use ${organisationName}.`],
        delete: ["Device removed from inventory", `${label} was revoked and removed. The audit tombstone remains.`],
      };
      toastResult(result, { success: done[kind][0], successDescription: done[kind][1] });
      setConfirm(null);
      if (result.ok) {
        setReason("");
        router.refresh();
      }
    });
  }

  return (
    <Section
      id="lifecycle"
      title="Access for this device"
      description={
        <>
          Acting in <span className="badge network">{organisationName}</span> as {roleLabel(role)}.
        </>
      }
    >
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
      ) : denied ? (
        <PermissionNotice reason={denied} />
      ) : (
        <div className="actions">
          {state === "suspended" ? (
            <Button
              variant="secondary"
              loading={pending && confirm === "resume"}
              disabled={pending}
              onClick={() => setConfirm("resume")}
            >
              Resume
            </Button>
          ) : (
            <Button
              variant="secondary"
              disabled={pending}
              onClick={() => setConfirm("suspend")}
            >
              Suspend
            </Button>
          )}
          <Button variant="danger" disabled={pending} onClick={() => setConfirm("revoke")}>
            Revoke access
          </Button>
          <Button variant="quiet-danger" disabled={pending} onClick={() => setConfirm("delete")}>
            Delete from inventory
          </Button>
        </div>
      )}
      <ConfirmDialog
        open={confirm !== null}
        title={confirm ? titles[confirm] : ""}
        description={confirm ? impact[confirm] : null}
        confirmLabel={confirm ? titles[confirm] : ""}
        tone={confirm === "resume" || confirm === "suspend" ? "primary" : "danger"}
        confirmText={confirm === "revoke" || confirm === "delete" ? label : undefined}
        pending={pending}
        onCancel={() => setConfirm(null)}
        onConfirm={() => {
          if (confirm) run(confirm);
        }}
      >
        {confirm === "suspend" ? (
          <FormField label="Reason" hint="Optional. Recorded in the audit log.">
            <input
              type="text"
              maxLength={200}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
            />
          </FormField>
        ) : null}
      </ConfirmDialog>
    </Section>
  );
}
