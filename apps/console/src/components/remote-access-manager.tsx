"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  acknowledgeHostKeyAction,
  endRemoteSessionAction,
  saveRemoteSettingsAction,
  type RemoteActionResult,
} from "@/app/remote-access/actions";

function useAction() {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const run = (action: () => Promise<RemoteActionResult>) => {
    setNotice(null);
    setError(null);
    startTransition(async () => {
      const result = await action();
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setNotice(result.message);
      router.refresh();
    });
  };
  const messages = (
    <>
      {notice ? (
        <p className="muted" role="status">
          {notice}
        </p>
      ) : null}
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
    </>
  );
  return { pending, run, messages };
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
  const { pending, run, messages } = useAction();
  const locked = pending || disabledReason !== null;
  return (
    <form
      className="stack"
      aria-label="Remote access gateway"
      onSubmit={(event) => {
        event.preventDefault();
        const form = new FormData(event.currentTarget);
        run(() => saveRemoteSettingsAction(form));
      }}
    >
      <label>
        Gateway device
        <select name="gatewayNodeId" defaultValue={gatewayNodeId ?? ""} disabled={locked}>
          <option value="">No gateway (browser sessions off)</option>
          {devices.map((device) => (
            <option key={device.id} value={device.id}>
              {device.label}
            </option>
          ))}
        </select>
      </label>
      <label>
        Gateway address browsers connect to
        <input
          name="gatewayUrl"
          type="url"
          defaultValue={gatewayUrl}
          placeholder="wss://remote.example.org.au"
          disabled={locked}
        />
      </label>
      <div className="row">
        <button type="submit" disabled={locked}>
          {pending ? "Saving…" : "Save gateway"}
        </button>
      </div>
      {disabledReason ? <p className="muted">{disabledReason}</p> : null}
      {messages}
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
  const { pending, run, messages } = useAction();
  return (
    <div className="stack">
      <button
        type="button"
        disabled={pending || disabledReason !== null}
        title={disabledReason ?? undefined}
        onClick={() => {
          if (
            !window.confirm(
              `Accept ${fingerprint} as the SSH host key for ${deviceName}? Only do this after checking the key on the device itself (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub).`,
            )
          ) {
            return;
          }
          const form = new FormData();
          form.set("nodeId", nodeId);
          form.set("fingerprint", fingerprint);
          run(() => acknowledgeHostKeyAction(form));
        }}
      >
        {pending ? "Accepting…" : "Accept new key"}
      </button>
      {disabledReason ? <span className="muted">{disabledReason}</span> : null}
      {messages}
    </div>
  );
}

export function RevokeSessionButton({ sessionId }: { sessionId: string }) {
  const { pending, run, messages } = useAction();
  return (
    <div className="stack">
      <button
        type="button"
        className="danger"
        disabled={pending}
        onClick={() => {
          const form = new FormData();
          form.set("sessionId", sessionId);
          run(() => endRemoteSessionAction(form));
        }}
      >
        {pending ? "Revoking…" : "Revoke"}
      </button>
      {messages}
    </div>
  );
}
