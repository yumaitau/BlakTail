"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  acknowledgeHostKeyAction,
  endRemoteSessionAction,
  saveRemoteSettingsAction,
  type RemoteActionResult,
} from "@/app/remote-access/actions";
import { Alert } from "./ui/alert";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormField } from "./ui/form-field";
import { toast } from "./ui/toast";

/** Runs a remote-access action: toast on success with its message, mapped error toast on failure. */
function useAction(success: string) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const run = (action: () => Promise<RemoteActionResult>, after?: () => void) => {
    startTransition(async () => {
      const result = await action();
      after?.();
      if (!result.ok) {
        toast.error(result.error, { reference: result.ref });
        return;
      }
      toast.success(success, { description: result.message });
      router.refresh();
    });
  };
  return { pending, run };
}

export function GatewaySettingsForm({
  devices,
  gatewayNodeId,
  gatewayUrl,
  disabledReason,
}: {
  devices: { id: string; label: string }[];
  gatewayNodeId: string | null;
  gatewayUrl: string;
  disabledReason: string | null;
}) {
  const { pending, run } = useAction("Gateway saved");
  const [urlError, setUrlError] = useState<string | null>(null);
  const locked = pending || disabledReason !== null;
  return (
    <form
      className="ui-form"
      aria-label="Remote access gateway"
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        const form = new FormData(event.currentTarget);
        const url = String(form.get("gatewayUrl") ?? "").trim();
        if (form.get("gatewayNodeId") && !/^wss:\/\/[^\s/]+/u.test(url)) {
          setUrlError("Enter the address browsers use, starting with wss://.");
          return;
        }
        setUrlError(null);
        run(() => saveRemoteSettingsAction(form));
      }}
    >
      {disabledReason ? <Alert tone="info">{disabledReason}</Alert> : null}
      <div className="form-grid">
        <FormField label="Gateway device">
          <select name="gatewayNodeId" defaultValue={gatewayNodeId ?? ""} disabled={locked}>
            <option value="">No gateway (browser sessions off)</option>
            {devices.map((device) => (
              <option key={device.id} value={device.id}>
                {device.label}
              </option>
            ))}
          </select>
        </FormField>
        <FormField label="Address browsers connect to" error={urlError}>
          <input
            name="gatewayUrl"
            type="url"
            defaultValue={gatewayUrl}
            placeholder="wss://remote.example.org.au"
            disabled={locked}
          />
        </FormField>
      </div>
      <div className="actions">
        <Button type="submit" loading={pending} loadingLabel="Saving…" disabled={locked}>
          Save gateway
        </Button>
      </div>
    </form>
  );
}

export function AcceptHostKeyButton({
  nodeId,
  fingerprint,
  deviceName,
  disabledReason,
}: {
  nodeId: string;
  fingerprint: string;
  deviceName: string;
  disabledReason: string | null;
}) {
  const { pending, run } = useAction("New host key accepted");
  const [open, setOpen] = useState(false);
  return (
    <>
      <div className="actions">
        <Button
          size="sm"
          disabled={pending || disabledReason !== null}
          title={disabledReason ?? undefined}
          loading={pending}
          onClick={() => setOpen(true)}
        >
          Check and accept
        </Button>
      </div>
      {disabledReason ? <span className="cell-sub">{disabledReason}</span> : null}
      <ConfirmDialog
        open={open}
        title={`Accept the new host key for ${deviceName}?`}
        description={
          <>
            <p>
              Only accept after checking the key on the device itself. Run{" "}
              <span className="mono">ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</span> there and
              compare:
            </p>
            <p className="mono cell-break">{fingerprint}</p>
          </>
        }
        confirmLabel="Accept key"
        tone="primary"
        pending={pending}
        onCancel={() => setOpen(false)}
        onConfirm={() => {
          const form = new FormData();
          form.set("nodeId", nodeId);
          form.set("fingerprint", fingerprint);
          run(() => acknowledgeHostKeyAction(form), () => setOpen(false));
        }}
      />
    </>
  );
}

export function RevokeSessionButton({ sessionId, label }: { sessionId: string; label: string }) {
  const { pending, run } = useAction("Session ended");
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button size="sm" variant="quiet-danger" loading={pending} onClick={() => setOpen(true)}>
        End session
      </Button>
      <ConfirmDialog
        open={open}
        title="End this session?"
        description={`The connection to ${label} closes straight away. The person can start a new session if their role allows.`}
        confirmLabel="End session"
        pending={pending}
        onCancel={() => setOpen(false)}
        onConfirm={() => {
          const form = new FormData();
          form.set("sessionId", sessionId);
          run(() => endRemoteSessionAction(form), () => setOpen(false));
        }}
      />
    </>
  );
}
