"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  deleteNetworkResourceAction,
  setNetworkResourceEnabledAction,
} from "@/app/networks/actions";
import { can, type OrgRole } from "@/lib/roles";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { toastResult } from "./ui/toast";

/** Enable, disable and delete for one network resource (page header actions). */
export function NetworkResourceActions({
  organisationId,
  role,
  resourceId,
  resourceName,
  etag,
  enabled,
}: {
  organisationId: string;
  role: OrgRole;
  resourceId: string;
  resourceName: string;
  etag: string;
  enabled: boolean;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [confirm, setConfirm] = useState<"disable" | "delete" | null>(null);
  if (!can(role, "manage_networks")) return null;

  function payload(extra: Record<string, string> = {}): FormData {
    const data = new FormData();
    data.set("organisationId", organisationId);
    data.set("resourceId", resourceId);
    data.set("etag", etag);
    for (const [key, value] of Object.entries(extra)) data.set(key, value);
    return data;
  }

  function setEnabled(next: boolean) {
    startTransition(async () => {
      const result = await setNetworkResourceEnabledAction(payload({ enabled: String(next) }));
      toastResult(result, {
        success: next ? "Resource enabled" : "Resource disabled",
        successDescription: next
          ? `${resourceName} is offered to clients again on their next sync.`
          : `${resourceName} is withdrawn from clients on their next sync.`,
      });
      setConfirm(null);
      if (result.ok) router.refresh();
    });
  }

  return (
    <>
      {enabled ? (
        <Button variant="secondary" disabled={pending} onClick={() => setConfirm("disable")}>
          Disable
        </Button>
      ) : (
        <Button
          variant="secondary"
          loading={pending && confirm === null}
          loadingLabel="Enabling…"
          onClick={() => setEnabled(true)}
        >
          Enable
        </Button>
      )}
      <Button variant="quiet-danger" disabled={pending} onClick={() => setConfirm("delete")}>
        Delete
      </Button>
      <ConfirmDialog
        open={confirm === "disable"}
        title="Disable this resource?"
        description={`${resourceName} is withdrawn from every client on its next sync (within about 25 seconds). You can enable it again later.`}
        confirmLabel="Disable resource"
        tone="primary"
        pending={pending}
        onCancel={() => setConfirm(null)}
        onConfirm={() => setEnabled(false)}
      />
      <ConfirmDialog
        open={confirm === "delete"}
        title="Delete network resource"
        description={`${resourceName} is withdrawn from every client on its next sync and its settings are removed. This can't be undone.`}
        confirmText={resourceName}
        confirmLabel="Delete resource"
        pending={pending}
        onCancel={() => setConfirm(null)}
        onConfirm={() => {
          startTransition(async () => {
            const result = await deleteNetworkResourceAction(payload());
            toastResult(result, {
              success: "Resource deleted",
              successDescription: `${resourceName} is no longer routed.`,
            });
            setConfirm(null);
            if (!result.ok) return;
            router.push("/networks");
            router.refresh();
          });
        }}
      />
    </>
  );
}
