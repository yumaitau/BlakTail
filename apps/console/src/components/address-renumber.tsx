"use client";

import { useEffect, useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  finishRenumberAction,
  previewRenumberAction,
  startRenumberAction,
} from "@/app/networks/actions";
import type { RenumberMove, RenumberPlan, RenumberPreview } from "@/lib/coord-ipam";
import { permissionReason, roleLabel, type OrgRole } from "@/lib/roles";

export type RenumberDevice = { nodeId: string; name: string; address: string };

function addresses(list: string[]): string {
  return list.map((address) => address.split("/")[0]).join(", ");
}

function MovesTable({ moves }: { moves: RenumberMove[] }) {
  return (
    <div className="table-wrap">
      <table className="table">
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
              <td>{move.name}</td>
              <td className="mono">{addresses(move.old_addresses)}</td>
              <td className="mono">{addresses(move.new_addresses)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
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
        <div className="stack" role="alert">
          <p className="error">This plan cannot start until these are fixed:</p>
          <ul className="stack">
            {preview.blockers.map((blocker) => (
              <li key={`${blocker.kind}:${blocker.detail}`}>
                <span className="badge warn">{blocker.kind.replaceAll("_", " ")}</span>{" "}
                {blocker.detail}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

export function RenumberPlanForm({
  organisationId,
  organisationName,
  role,
  currentPool,
  prefixRange,
  defaultWindowSeconds,
  minWindowSeconds,
  devices,
}: {
  organisationId: string;
  organisationName: string;
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
  const [mode, setMode] = useState<"pool" | "devices">("pool");
  const [preview, setPreview] = useState<RenumberPreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const denied = permissionReason(role, "manage_networks");
  const disabled = Boolean(denied) || pending;
  const [widest, narrowest] = prefixRange;

  const formData = () => {
    const data = new FormData(formRef.current ?? undefined);
    data.set("organisationId", organisationId);
    data.set("mode", mode);
    return data;
  };

  return (
    <form
      ref={formRef}
      className="stack"
      // Any edit invalidates the preview, so Start always matches what was shown.
      onChange={() => setPreview(null)}
      onSubmit={(event) => {
        event.preventDefault();
        setError(null);
        const data = formData();
        startTransition(async () => {
          const result = await previewRenumberAction(data);
          if (!result.ok) setError(result.error);
          else setPreview(result.data);
        });
      }}
    >
      <div className="row">
        <h3>Plan a renumber</h3>
        <span className="badge network">{organisationName}</span>
        <span className="muted">Acting as {roleLabel(role)}</span>
      </div>
      <fieldset className="stack" disabled={disabled}>
        <legend>What changes</legend>
        <label>
          <input
            type="radio"
            name="modeChoice"
            checked={mode === "pool"}
            onChange={() => setMode("pool")}
          />{" "}
          Change the IPv4 pool (grow it, or move to another range)
        </label>
        <label>
          <input
            type="radio"
            name="modeChoice"
            checked={mode === "devices"}
            onChange={() => setMode("devices")}
          />{" "}
          Move selected devices to new addresses
        </label>
      </fieldset>
      {mode === "pool" ? (
        <label>
          New IPv4 pool
          <input
            name="pool"
            required
            className="mono"
            placeholder={currentPool}
            disabled={disabled}
          />
          <span className="muted">
            A /{narrowest} to /{widest} inside 100.64.0.0/10. Growing{" "}
            <span className="mono">{currentPool}</span> to a larger pool that contains it
            moves nobody.
          </span>
        </label>
      ) : (
        <fieldset className="stack" disabled={disabled}>
          <legend>Devices to move</legend>
          {devices.length === 0 ? (
            <p className="muted">No active device to move.</p>
          ) : (
            devices.map((device) => (
              <div className="row" key={device.nodeId}>
                <label>
                  <input type="checkbox" name="device" value={device.nodeId} /> {device.name}{" "}
                  <span className="mono muted">{device.address}</span>
                </label>
                <label>
                  New address (optional)
                  <input
                    name={`address:${device.nodeId}`}
                    className="mono"
                    inputMode="decimal"
                    placeholder="Reservation or next free"
                  />
                </label>
              </div>
            ))
          )}
        </fieldset>
      )}
      <label>
        Dual-address window (hours)
        <input
          name="windowHours"
          type="number"
          min={minWindowSeconds / 3600}
          max={720}
          step="any"
          defaultValue={defaultWindowSeconds / 3600}
          disabled={disabled}
        />
        <span className="muted">
          Moved devices keep their old address as well until you complete the plan or the
          window ends. You can roll back until then.
        </span>
      </label>
      <label>
        Reason
        <input name="reason" maxLength={256} disabled={disabled} />
      </label>
      <div className="actions">
        <button type="submit" className="secondary" disabled={disabled} title={denied ?? undefined}>
          {pending && !preview ? "Checking…" : "Preview impact"}
        </button>
        <button
          type="button"
          disabled={disabled || !preview || preview.blockers.length > 0}
          title={denied ?? (preview ? undefined : "Preview the plan first")}
          onClick={() => {
            setError(null);
            const data = formData();
            startTransition(async () => {
              const result = await startRenumberAction(data);
              if (!result.ok) {
                setError(result.error);
                return;
              }
              setPreview(null);
              formRef.current?.reset();
              router.refresh();
            });
          }}
        >
          {preview && preview.moves.length === 0 ? "Apply pool change" : "Start renumber"}
        </button>
      </div>
      {denied ? <p className="muted">{denied}</p> : null}
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
      {preview ? <PreviewSummary preview={preview} /> : null}
    </form>
  );
}

function when(at: number): string {
  return new Date(at * 1000).toLocaleString("en-AU", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "Australia/Sydney",
  });
}

export function StagedRenumber({
  organisationId,
  organisationName,
  role,
  plan,
}: {
  organisationId: string;
  organisationName: string;
  role: OrgRole;
  plan: RenumberPlan;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [nowSeconds, setNowSeconds] = useState(() => Math.floor(Date.now() / 1000));
  const denied = permissionReason(role, "manage_networks");

  useEffect(() => {
    const timer = setInterval(() => setNowSeconds(Math.floor(Date.now() / 1000)), 30_000);
    return () => clearInterval(timer);
  }, []);

  const elapsed = Math.min(Math.max(nowSeconds - plan.created_at, 0), plan.window_seconds);
  const remainingMinutes = Math.max(Math.ceil((plan.window_ends_at - nowSeconds) / 60), 0);

  const finish = (how: "complete" | "rollback") => {
    setError(null);
    const data = new FormData();
    data.set("organisationId", organisationId);
    data.set("planId", plan.id);
    data.set("etag", plan.etag);
    data.set("how", how);
    startTransition(async () => {
      const result = await finishRenumberAction(data);
      if (!result.ok) setError(result.error);
      else router.refresh();
    });
  };

  return (
    <div className="stack">
      <div className="row">
        <h3>Renumber in progress</h3>
        <span className="badge pending">Dual-address window</span>
        <span className="badge network">{organisationName}</span>
        <span className="muted">Acting as {roleLabel(role)}</span>
      </div>
      <p>
        {plan.kind === "pool" ? (
          <>
            Pool <span className="mono">{plan.previous_pool}</span> →{" "}
            <span className="mono">{plan.target_pool}</span>.{" "}
          </>
        ) : null}
        {plan.moves.length} device{plan.moves.length === 1 ? "" : "s"} answer on both addresses
        until {when(plan.window_ends_at)}; MagicDNS already returns the new ones.
        {plan.reason ? ` Reason: ${plan.reason}.` : null}
      </p>
      <label>
        Window elapsed
        <progress max={plan.window_seconds} value={elapsed} />
        <span className="muted">
          {remainingMinutes > 0
            ? `${remainingMinutes >= 120 ? `${Math.round(remainingMinutes / 60)} hours` : `${remainingMinutes} minutes`} left; it completes automatically at the end.`
            : "Window ended; the coordinator completes it on the next device check-in."}
        </span>
      </label>
      <MovesTable moves={plan.moves} />
      <div className="actions">
        <button
          type="button"
          disabled={Boolean(denied) || pending}
          title={denied ?? undefined}
          onClick={() => finish("complete")}
        >
          {pending ? "Working…" : "Complete now"}
        </button>
        <button
          type="button"
          className="quiet-danger"
          disabled={Boolean(denied) || pending}
          title={denied ?? undefined}
          onClick={() => finish("rollback")}
        >
          Roll back
        </button>
      </div>
      <p className="muted">
        Complete once devices work on their new address; the old address then waits out the
        reuse grace period. Roll back returns every moved device to its old address.
      </p>
      {denied ? <p className="muted">{denied}</p> : null}
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}
