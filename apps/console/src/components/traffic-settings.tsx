"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { deleteTrafficRecordsAction, saveTrafficSettingsAction } from "@/app/traffic/actions";
import type { TrafficSettings } from "@/lib/coord-events";
import { Alert } from "./ui/alert";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormField } from "./ui/form-field";
import { toast } from "./ui/toast";

type Field = "sampling" | "retention";

export function TrafficSettingsForm({
  settings,
  disabledReason,
}: {
  settings: TrafficSettings;
  disabledReason: string | null;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState<"save" | "delete" | null>(null);
  const [errors, setErrors] = useState<Partial<Record<Field, string>>>({});
  const [confirmDelete, setConfirmDelete] = useState(false);
  const locked = pending || disabledReason !== null;

  return (
    <>
      {disabledReason ? <Alert tone="info">{disabledReason}</Alert> : null}
      <form
        className="ui-form"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          const percent = Number(form.get("sampling_percent"));
          const retention = Number(form.get("retention_days"));
          const next: Partial<Record<Field, string>> = {};
          if (!Number.isFinite(percent) || percent < 1 || percent > 100) {
            next.sampling = "Use a number from 1 to 100.";
          }
          if (!Number.isInteger(retention) || retention < 1 || retention > 30) {
            next.retention = "Use a whole number of days from 1 to 30.";
          }
          setErrors(next);
          if (Object.keys(next).length) return;
          setBusy("save");
          startTransition(async () => {
            const result = await saveTrafficSettingsAction(form);
            setBusy(null);
            if (!result.ok) {
              toast.error(result.error, { reference: result.ref });
              return;
            }
            toast.success("Traffic settings saved", { description: result.message });
            router.refresh();
          });
        }}
      >
        <label className="check-option">
          <input type="checkbox" name="enabled" defaultChecked={settings.enabled} disabled={locked} />
          <span>Collect per-connection traffic events and totals for this organisation</span>
        </label>
        <div className="form-grid">
          <FormField label="Sampling (% of connections kept)" error={errors.sampling}>
            <input
              type="number"
              name="sampling_percent"
              inputMode="numeric"
              min={1}
              max={100}
              step={1}
              defaultValue={Math.round(settings.sampling_rate * 100)}
              disabled={locked}
            />
          </FormField>
          <FormField label="Keep events for (days, 1–30)" error={errors.retention}>
            <input
              type="number"
              name="retention_days"
              inputMode="numeric"
              min={1}
              max={30}
              step={1}
              defaultValue={settings.retention_days}
              disabled={locked}
            />
          </FormField>
        </div>
        <div className="actions">
          <Button type="submit" loading={busy === "save"} loadingLabel="Saving…" disabled={locked}>
            Save traffic settings
          </Button>
          <Button variant="quiet-danger" disabled={locked} onClick={() => setConfirmDelete(true)}>
            Delete stored records
          </Button>
        </div>
      </form>
      <ConfirmDialog
        open={confirmDelete}
        title="Delete every stored traffic record?"
        description="All traffic events and totals kept for this organisation are deleted now. Collection settings stay as they are. This can't be undone."
        confirmText="delete records"
        confirmLabel="Delete records"
        pending={busy === "delete"}
        onCancel={() => setConfirmDelete(false)}
        onConfirm={() => {
          setBusy("delete");
          startTransition(async () => {
            const result = await deleteTrafficRecordsAction();
            setBusy(null);
            setConfirmDelete(false);
            if (!result.ok) {
              toast.error(result.error, { reference: result.ref });
              return;
            }
            toast.success("Traffic records deleted", { description: result.message });
            router.refresh();
          });
        }}
      />
    </>
  );
}
