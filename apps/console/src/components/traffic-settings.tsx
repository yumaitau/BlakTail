"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { deleteTrafficRecordsAction, saveTrafficSettingsAction } from "@/app/traffic/actions";
import type { TrafficSettings } from "@/lib/coord-events";

export function TrafficSettingsForm({
  settings,
  disabledReason,
}: {
  settings: TrafficSettings;
  disabledReason: string | null;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const locked = pending || disabledReason !== null;

  return (
    <div className="stack">
      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          setError(null);
          setNotice(null);
          startTransition(async () => {
            const result = await saveTrafficSettingsAction(form);
            if (!result.ok) {
              setError(result.error);
              return;
            }
            setNotice(result.message);
            router.refresh();
          });
        }}
      >
        <label className="row">
          <input type="checkbox" name="enabled" defaultChecked={settings.enabled} disabled={locked} />
          Collect per-flow traffic events and aggregate counters for this organisation
        </label>
        <label>
          Sampling (per cent of connections kept)
          <input
            type="number"
            name="sampling_percent"
            min={1}
            max={100}
            step={1}
            defaultValue={Math.round(settings.sampling_rate * 100)}
            disabled={locked}
          />
        </label>
        <label>
          Retention (days, 1–30)
          <input
            type="number"
            name="retention_days"
            min={1}
            max={30}
            step={1}
            defaultValue={settings.retention_days}
            disabled={locked}
          />
        </label>
        <div className="row">
          <button type="submit" disabled={locked}>
            {pending ? "Saving…" : "Save traffic settings"}
          </button>
          <button
            type="button"
            className="danger"
            disabled={locked}
            onClick={() => {
              if (!window.confirm("Delete every stored traffic event and record for this organisation?")) {
                return;
              }
              setError(null);
              setNotice(null);
              startTransition(async () => {
                const result = await deleteTrafficRecordsAction();
                if (!result.ok) {
                  setError(result.error);
                  return;
                }
                setNotice(result.message);
                router.refresh();
              });
            }}
          >
            Delete stored records
          </button>
        </div>
      </form>
      {disabledReason ? <p className="muted">{disabledReason}</p> : null}
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
    </div>
  );
}
