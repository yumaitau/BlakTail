"use client";

import { useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  releaseReservationAction,
  reserveAddressAction,
} from "@/app/networks/actions";
import { permissionReason, type OrgRole } from "@/lib/roles";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormField } from "./ui/form-field";
import { PermissionNotice } from "./ui/permission-notice";
import { toastResult } from "./ui/toast";

export function ReserveAddressForm({
  organisationId,
  role,
  suggested,
}: {
  organisationId: string;
  role: OrgRole;
  suggested: string | null;
}) {
  const router = useRouter();
  const formRef = useRef<HTMLFormElement>(null);
  const [pending, startTransition] = useTransition();
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const denied = permissionReason(role, "manage_networks");
  if (denied) return <PermissionNotice reason={denied} />;

  return (
    <form
      ref={formRef}
      className="ui-form"
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        const data = new FormData(formRef.current ?? undefined);
        data.set("organisationId", organisationId);
        const address = String(data.get("address") ?? "").trim();
        if (!address) {
          setFieldErrors({ address: "Enter the IPv4 address to reserve." });
          formRef.current?.querySelector<HTMLInputElement>('[name="address"]')?.focus();
          return;
        }
        startTransition(async () => {
          const result = await reserveAddressAction(data);
          setFieldErrors(
            toastResult(result, {
              success: "Address reserved",
              successDescription: `${address} is kept out of automatic allocation.`,
              errorToast: false,
            }),
          );
          if (!result.ok) return;
          formRef.current?.reset();
          router.refresh();
        });
      }}
    >
      <FormField
        label="IPv4 address"
        className="field-sm"
        required
        hint={suggested ? `Next free: ${suggested}` : undefined}
        error={fieldErrors.address}
      >
        <input
          name="address"
          className="mono"
          inputMode="decimal"
          autoComplete="off"
          placeholder={suggested ?? "100.64.0.20"}
          disabled={pending}
        />
      </FormField>
      <FormField
        label="Device name"
        hint="Optional. The device that enrols with this exact name gets the address."
        className="field-md"
      >
        <input name="boundName" autoComplete="off" disabled={pending} />
      </FormField>
      <FormField
        label="WireGuard public key"
        hint="Optional. Leave both binding fields empty to keep the address out of automatic use."
        error={fieldErrors.boundKey}
      >
        <input name="boundKey" className="mono" autoComplete="off" spellCheck={false} disabled={pending} />
      </FormField>
      <FormField label="Reason" hint="Recorded with the reservation." className="field-lg">
        <input name="reason" maxLength={256} disabled={pending} />
      </FormField>
      <div className="ui-form-actions">
        <Button type="submit" loading={pending} loadingLabel="Reserving…">
          Reserve address
        </Button>
      </div>
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
  const [open, setOpen] = useState(false);
  const denied = permissionReason(role, "manage_networks");
  if (denied) return null;

  return (
    <>
      <Button
        variant="quiet-danger"
        size="sm"
        disabled={pending}
        aria-label={`Release reservation for ${address}`}
        onClick={() => setOpen(true)}
      >
        Release
      </Button>
      <ConfirmDialog
        open={open}
        title="Release this reservation?"
        description={`${address} returns to the pool once any grace period ends, and may be given to another device.`}
        confirmLabel="Release address"
        pending={pending}
        onCancel={() => setOpen(false)}
        onConfirm={() => {
          const data = new FormData();
          data.set("organisationId", organisationId);
          data.set("reservationId", reservationId);
          data.set("etag", etag);
          startTransition(async () => {
            const result = await releaseReservationAction(data);
            toastResult(result, { success: "Reservation released" });
            setOpen(false);
            if (result.ok) router.refresh();
          });
        }}
      />
    </>
  );
}
