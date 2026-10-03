"use client";

import { useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  releaseReservationAction,
  reserveAddressAction,
} from "@/app/networks/actions";
import { permissionReason, roleLabel, type OrgRole } from "@/lib/roles";

export function ReserveAddressForm({
  organisationId,
  organisationName,
  role,
  suggested,
}: {
  organisationId: string;
  organisationName: string;
  role: OrgRole;
  suggested: string | null;
}) {
  const router = useRouter();
  const formRef = useRef<HTMLFormElement>(null);
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const denied = permissionReason(role, "manage_networks");

  return (
    <form
      ref={formRef}
      className="stack"
      onSubmit={(event) => {
        event.preventDefault();
        setError(null);
        const data = new FormData(formRef.current ?? undefined);
        data.set("organisationId", organisationId);
        startTransition(async () => {
          const result = await reserveAddressAction(data);
          if (!result.ok) {
            setError(result.error);
            return;
          }
          formRef.current?.reset();
          router.refresh();
        });
      }}
    >
      <div className="row">
        <h3>Reserve an address</h3>
        <span className="badge network">{organisationName}</span>
        <span className="muted">Acting as {roleLabel(role)}</span>
      </div>
      <label>
        IPv4 address
        <input
          name="address"
          required
          inputMode="decimal"
          placeholder={suggested ?? "100.64.0.20"}
          disabled={Boolean(denied) || pending}
        />
      </label>
      <label>
        Device name (optional)
        <input name="boundName" disabled={Boolean(denied) || pending} />
        <span className="muted">
          The device enrolling with this exact name receives the address. Leave
          both binding fields empty to keep the address out of automatic use.
        </span>
      </label>
      <label>
        WireGuard public key (optional)
        <input name="boundKey" className="mono" disabled={Boolean(denied) || pending} />
      </label>
      <label>
        Reason
        <input name="reason" maxLength={256} disabled={Boolean(denied) || pending} />
      </label>
      <div className="actions">
        <button type="submit" disabled={Boolean(denied) || pending} title={denied ?? undefined}>
          {pending ? "Reserving…" : "Reserve address"}
        </button>
      </div>
      {denied ? <p className="muted">{denied}</p> : null}
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
    </form>
  );
}

export function ReleaseReservationButton({
  organisationId,
  role,
  reservationId,
  etag,
  address,
}: {
  organisationId: string;
  role: OrgRole;
  reservationId: string;
  etag: string;
  address: string;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const denied = permissionReason(role, "manage_networks");

  return (
    <div className="stack">
      <button
        type="button"
        className="quiet-danger"
        disabled={Boolean(denied) || pending}
        title={denied ?? undefined}
        aria-label={`Release reservation for ${address}`}
        onClick={() => {
          setError(null);
          const data = new FormData();
          data.set("organisationId", organisationId);
          data.set("reservationId", reservationId);
          data.set("etag", etag);
          startTransition(async () => {
            const result = await releaseReservationAction(data);
            if (!result.ok) setError(result.error);
            else router.refresh();
          });
        }}
      >
        {pending ? "Releasing…" : "Release"}
      </button>
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}
