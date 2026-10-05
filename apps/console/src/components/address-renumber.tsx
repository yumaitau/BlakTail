"use client";

import { useEffect, useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  finishRenumberAction,
  previewRenumberAction,
  startRenumberAction,
} from "@/app/networks/actions";
import type { RenumberMove, RenumberPlan, RenumberPreview } from "@/lib/coord-ipam";
import { permissionReason, type OrgRole } from "@/lib/roles";
import { Alert } from "./ui/alert";
import { StatusPill } from "./ui/badge";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormField } from "./ui/form-field";
import { LocalTime } from "./ui/local-time";
import { MonoValue } from "./ui/mono-value";
import { PermissionNotice } from "./ui/permission-notice";
import { Table, Td } from "./ui/table";
import { toastResult } from "./ui/toast";

export type RenumberDevice = { nodeId: string; name: string; address: string };

function addresses(list: string[]): string {
  return list.map((address) => address.split("/")[0]).join(", ");
}

function MovesTable({ moves }: { moves: RenumberMove[] }) {
  return (
    <Table label="Address moves" mobile="stack">
      <thead>
        <tr>
          <th>Device</th>
          <th>Current</th>
          <th>New</th>
        </tr>
      </thead>
      <tbody>
        {moves.map((move) => (
          <tr key={move.node_id}>
            <Td label="Device">{move.name}</Td>
            <Td label="Current">
              <MonoValue value={addresses(move.old_addresses)} wrap />
            </Td>
            <Td label="New">
              <MonoValue value={addresses(move.new_addresses)} wrap />
            </Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function PreviewSummary({ preview }: { preview: RenumberPreview }) {
  const hours = Math.round((preview.window_seconds / 3600) * 10) / 10;
  return (
    <div className="stack" aria-live="polite">
      <h3>Impact</h3>
      <ul className="stack">
        <li>
          Pool <span className="mono">{preview.current_pool}</span>
          {preview.target_pool !== preview.current_pool ? (
            <>
              {" "}
              becomes <span className="mono">{preview.target_pool}</span>
            </>
          ) : null}
          .
        </li>
        <li>
          {preview.moves.length === 0
            ? "No device changes address; the change completes at once."
            : `${preview.moves.length} device${preview.moves.length === 1 ? "" : "s"} move; ${preview.unchanged_devices} keep their address.`}
        </li>
        {preview.moves.length ? (
          <>
            <li>
              For {hours} hour{hours === 1 ? "" : "s"}, moved devices answer on both addresses.{" "}
              {preview.peer_maps} peer map{preview.peer_maps === 1 ? "" : "s"} and{" "}
              {preview.forward_allow_lists} routing-peer allow list
              {preview.forward_allow_lists === 1 ? "" : "s"} carry both.
            </li>
            <li>
              MagicDNS switches at once:{" "}
              {preview.magic_dns_names.length ? (
                <span className="mono">{preview.magic_dns_names.join(", ")}</span>
              ) : (
                "no names"
              )}
              . IPv6 addresses follow their IPv4 address.
            </li>
          </>
        ) : null}
      </ul>
      {preview.moves.length ? <MovesTable moves={preview.moves} /> : null}
      {preview.blockers.length ? (
        <Alert tone="error" title="This plan can't start until these are fixed">
          <ul className="stack">
            {preview.blockers.map((blocker) => (
              <li key={`${blocker.kind}:${blocker.detail}`}>
                <StatusPill tone="danger">{blocker.kind.replaceAll("_", " ")}</StatusPill>{" "}
                {blocker.detail}
              </li>
            ))}
          </ul>
        </Alert>
      ) : null}
    </div>
  );
}

export function RenumberPlanForm({
  organisationId,
  role,
  currentPool,
  prefixRange,
  defaultWindowSeconds,
  minWindowSeconds,
  devices,
}: {
  organisationId: string;
  role: OrgRole;
  currentPool: string;
  prefixRange: [number, number];
  defaultWindowSeconds: number;
  minWindowSeconds: number;
  devices: RenumberDevice[];
}) {
  const router = useRouter();
  const formRef = useRef<HTMLFormElement>(null);
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState<"preview" | "start" | null>(null);
  const [mode, setMode] = useState<"pool" | "devices">("pool");
  const [preview, setPreview] = useState<RenumberPreview | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const denied = permissionReason(role, "manage_networks");
  const [widest, narrowest] = prefixRange;
  if (denied) return <PermissionNotice reason={denied} />;

  const formData = () => {
    const data = new FormData(formRef.current ?? undefined);
    data.set("organisationId", organisationId);
    data.set("mode", mode);
    return data;
  };

  const start = () => {
    const data = formData();
    setBusy("start");
    startTransition(async () => {
      const result = await startRenumberAction(data);
      setBusy(null);
      setConfirming(false);
      toastResult(result, {
        success: preview && preview.moves.length === 0 ? "Pool changed" : "Renumber started",
        successDescription:
          preview && preview.moves.length > 0
            ? "Moved devices answer on both addresses until you complete or roll back."
            : undefined,
      });
      if (!result.ok) return;
      setPreview(null);
      formRef.current?.reset();
      router.refresh();
    });
  };

  return (
    <>
      <form
        ref={formRef}
        className="ui-form wide"
        noValidate
        // Any edit invalidates the preview, so Start always matches what was shown.
        onChange={() => setPreview(null)}
        onSubmit={(event) => {
          event.preventDefault();
          const data = formData();
          if (mode === "pool" && !String(data.get("pool") ?? "").trim()) {
            setFieldErrors({ pool: "Enter the new IPv4 pool, such as 100.64.0.0/16." });
            formRef.current?.querySelector<HTMLInputElement>('[name="pool"]')?.focus();
            return;
          }
          setFieldErrors({});
          setBusy("preview");
          startTransition(async () => {
            const result = await previewRenumberAction(data);
            setBusy(null);
            if (!result.ok) {
              setFieldErrors(toastResult(result, { errorToast: true }));
              return;
            }
            setPreview(result.data);
          });
        }}
      >
        <fieldset className="ui-fieldset" disabled={pending}>
          <legend>What changes</legend>
          <div className="ui-choices vertical">
            <label>
              <input
                type="radio"
                name="modeChoice"
                checked={mode === "pool"}
                onChange={() => setMode("pool")}
              />
              Change the IPv4 pool (grow it, or move to another range)
            </label>
            <label>
              <input
                type="radio"
                name="modeChoice"
                checked={mode === "devices"}
                onChange={() => setMode("devices")}
              />
              Move selected devices to new addresses
            </label>
          </div>
        </fieldset>
        {mode === "pool" ? (
          <FormField
            label="New IPv4 pool"
            required
            error={fieldErrors.pool}
            className="field-sm"
            hint={
              <>
                A /{narrowest} to /{widest} inside 100.64.0.0/10. Growing{" "}
                <span className="mono">{currentPool}</span> to a larger pool that contains it moves
                nobody.
              </>
            }
          >
            <input
              name="pool"
              className="mono"
              placeholder={currentPool}
              autoComplete="off"
              disabled={pending}
            />
          </FormField>
        ) : (
          <fieldset className="ui-fieldset" disabled={pending}>
            <legend>Devices to move</legend>
            {devices.length === 0 ? (
              <p className="ui-field-hint">No active device to move.</p>
            ) : (
              <Table label="Devices to move" mobile="stack">
                <thead>
                  <tr>
                    <th>Move</th>
                    <th>Device</th>
                    <th>New address</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((device) => (
                    <tr key={device.nodeId}>
                      <Td label="Move">
                        <input
                          type="checkbox"
                          name="device"
                          value={device.nodeId}
                          aria-label={`Move ${device.name}`}
                        />
                      </Td>
                      <Td label="Device">
                        <div>
                          {device.name}
                          <div className="cell-sub mono">{device.address}</div>
                        </div>
                      </Td>
                      <Td label="New address">
                        <input
                          name={`address:${device.nodeId}`}
                          className="mono"
                          inputMode="decimal"
                          placeholder="Reservation or next free"
                          aria-label={`New address for ${device.name} (optional)`}
                        />
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </fieldset>
        )}
        <FormField
          label="Dual-address window (hours)"
          className="field-md"
          hint="Moved devices keep their old address too until you complete the plan or the window ends. You can roll back until then."
        >
          <input
            name="windowHours"
            type="number"
            min={minWindowSeconds / 3600}
            max={720}
            step="any"
            defaultValue={defaultWindowSeconds / 3600}
            disabled={pending}
          />
        </FormField>
        <FormField label="Reason" hint="Recorded in the plan history." className="field-lg">
          <input name="reason" maxLength={256} disabled={pending} />
        </FormField>
        {preview ? <PreviewSummary preview={preview} /> : null}
        <div className="ui-form-actions">
          {preview ? (
            <Button
              disabled={pending || preview.blockers.length > 0}
              loading={busy === "start"}
              loadingLabel="Starting…"
              onClick={() => setConfirming(true)}
            >
              {preview.moves.length === 0 ? "Apply pool change" : "Start renumber"}
            </Button>
          ) : null}
          <Button
            type="submit"
            variant={preview ? "secondary" : "primary"}
            loading={busy === "preview"}
            loadingLabel="Checking…"
            disabled={pending}
          >
            {preview ? "Preview again" : "Preview impact"}
          </Button>
        </div>
      </form>
      <ConfirmDialog
        open={confirming}
        tone="primary"
        title={preview && preview.moves.length === 0 ? "Apply the pool change?" : "Start this renumber?"}
        description={
          preview && preview.moves.length > 0
            ? `${preview.moves.length} device${preview.moves.length === 1 ? "" : "s"} get a new address. MagicDNS switches straight away; old addresses keep working until the window ends.`
            : "No device changes address. The pool change applies at once."
        }
        confirmLabel={preview && preview.moves.length === 0 ? "Apply change" : "Start renumber"}
        pending={busy === "start"}
        onCancel={() => setConfirming(false)}
        onConfirm={start}
      />
    </>
  );
}

export function StagedRenumber({
  organisationId,
  role,
  plan,
  now,
}: {
  organisationId: string;
  role: OrgRole;
  plan: RenumberPlan;
  /** Unix seconds when the page was rendered, so hydration matches; ticks on in the browser. */
  now: number;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState<"complete" | "rollback" | null>(null);
  const [confirmRollback, setConfirmRollback] = useState(false);
  const [nowSeconds, setNowSeconds] = useState(now);
  const denied = permissionReason(role, "manage_networks");

  useEffect(() => {
    const timer = setInterval(() => setNowSeconds(Math.floor(Date.now() / 1000)), 30_000);
    return () => clearInterval(timer);
  }, []);

  const elapsed = Math.min(Math.max(nowSeconds - plan.created_at, 0), plan.window_seconds);
  const remainingMinutes = Math.max(Math.ceil((plan.window_ends_at - nowSeconds) / 60), 0);

  const finish = (how: "complete" | "rollback") => {
    const data = new FormData();
    data.set("organisationId", organisationId);
    data.set("planId", plan.id);
    data.set("etag", plan.etag);
    data.set("how", how);
    setBusy(how);
    startTransition(async () => {
      const result = await finishRenumberAction(data);
      setBusy(null);
      setConfirmRollback(false);
      toastResult(result, {
        success: how === "complete" ? "Renumber completed" : "Renumber rolled back",
        successDescription:
          how === "complete"
            ? "Old addresses now wait out the reuse grace period."
            : "Every moved device is back on its old address.",
      });
      if (result.ok) router.refresh();
    });
  };

  return (
    <div className="stack">
      <div className="row">
        <h3>Renumber in progress</h3>
        <StatusPill tone="warning">Dual-address window</StatusPill>
      </div>
      <p>
        {plan.kind === "pool" ? (
          <>
            Pool <span className="mono">{plan.previous_pool}</span> →{" "}
            <span className="mono">{plan.target_pool}</span>.{" "}
          </>
        ) : null}
        {plan.moves.length} device{plan.moves.length === 1 ? "" : "s"} answer on both addresses
        until <LocalTime value={plan.window_ends_at} />; MagicDNS already returns the new ones.
        {plan.reason ? ` Reason: ${plan.reason}.` : null}
      </p>
      <FormField
        label="Window elapsed"
        hint={
          remainingMinutes > 0
            ? `${remainingMinutes >= 120 ? `${Math.round(remainingMinutes / 60)} hours` : `${remainingMinutes} minutes`} left; it completes automatically at the end.`
            : "Window ended; the coordinator completes it on the next device check-in."
        }
        className="field-lg"
      >
        <progress max={plan.window_seconds} value={elapsed} />
      </FormField>
      <MovesTable moves={plan.moves} />
      <p className="muted">
        Complete once devices work on their new address; the old address then waits out the
        reuse grace period. Roll back returns every moved device to its old address.
      </p>
      {denied ? (
        <PermissionNotice reason={denied} />
      ) : (
        <div className="ui-form-actions">
          <Button
            disabled={pending}
            loading={busy === "complete"}
            loadingLabel="Completing…"
            onClick={() => finish("complete")}
          >
            Complete now
          </Button>
          <Button variant="quiet-danger" disabled={pending} onClick={() => setConfirmRollback(true)}>
            Roll back
          </Button>
        </div>
      )}
      <ConfirmDialog
        open={confirmRollback}
        title="Roll back this renumber?"
        description="Every moved device returns to its old address, and MagicDNS switches back."
        confirmLabel="Roll back"
        pending={busy === "rollback"}
        onCancel={() => setConfirmRollback(false)}
        onConfirm={() => finish("rollback")}
      />
    </div>
  );
}
