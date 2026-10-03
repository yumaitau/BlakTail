"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  createJobTemplateAction,
  decideJobRunAction,
  disableJobTemplateAction,
  requestJobRunAction,
  type JobActionResult,
} from "@/app/remote-jobs/actions";

function useJobAction() {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const run = (action: () => Promise<JobActionResult>, after?: () => void) => {
    setNotice(null);
    setError(null);
    startTransition(async () => {
      const result = await action();
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setNotice(result.message);
      after?.();
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

export function JobTemplateForm({
  devices,
  disabledReason,
}: {
  devices: { id: string; label: string }[];
  disabledReason: string | null;
}) {
  const { pending, run, messages } = useJobAction();
  const locked = pending || disabledReason !== null;
  return (
    <form
      className="stack"
      aria-label="New job template"
      onSubmit={(event) => {
        event.preventDefault();
        const element = event.currentTarget;
        const form = new FormData(element);
        run(() => createJobTemplateAction(form), () => element.reset());
      }}
    >
      <label>
        Name
        <input name="name" required maxLength={64} placeholder="Disk usage" disabled={locked} />
      </label>
      <label>
        Program (absolute path; shells and interpreters are refused)
        <input
          name="program"
          required
          spellCheck={false}
          placeholder="/usr/bin/df"
          disabled={locked}
          className="mono"
        />
      </label>
      <label>
        Arguments, one per line (passed exactly as written; no shell, no quoting)
        <textarea name="args" rows={3} spellCheck={false} placeholder="-h" disabled={locked} className="mono" />
      </label>
      <div className="row">
        <label>
          Timeout (seconds, up to 600)
          <input name="timeoutSecs" type="number" min={1} max={600} defaultValue={60} disabled={locked} />
        </label>
        <label>
          Output cap (bytes, up to 65536)
          <input
            name="outputCapBytes"
            type="number"
            min={1}
            max={65536}
            defaultValue={16384}
            disabled={locked}
          />
        </label>
      </div>
      <fieldset className="stack" disabled={locked}>
        <legend>Targets</legend>
        <div className="row">
          {["office", "ranger", "store"].map((tag) => (
            <label key={tag} className="row">
              <input type="checkbox" name="tags" value={tag} /> Devices tagged {tag}
            </label>
          ))}
        </div>
        <label>
          Specific devices
          <select name="nodeIds" multiple size={Math.min(6, Math.max(2, devices.length))}>
            {devices.map((device) => (
              <option key={device.id} value={device.id}>
                {device.label}
              </option>
            ))}
          </select>
        </label>
      </fieldset>
      <div className="row">
        <button type="submit" disabled={locked}>
          {pending ? "Saving…" : "Save template"}
        </button>
      </div>
      {disabledReason ? <p className="muted">{disabledReason}</p> : null}
      {messages}
    </form>
  );
}

export function DisableTemplateButton({ templateId, name }: { templateId: string; name: string }) {
  const { pending, run, messages } = useJobAction();
  return (
    <div className="stack">
      <button
        type="button"
        className="danger"
        disabled={pending}
        onClick={() => {
          if (!window.confirm(`Disable the ${name} template?`)) return;
          const form = new FormData();
          form.set("templateId", templateId);
          run(() => disableJobTemplateAction(form));
        }}
      >
        {pending ? "Disabling…" : "Disable"}
      </button>
      {messages}
    </div>
  );
}

export function RequestRunForm({
  templates,
  devices,
  disabledReason,
}: {
  templates: { id: string; label: string }[];
  devices: { id: string; label: string }[];
  disabledReason: string | null;
}) {
  const { pending, run, messages } = useJobAction();
  const locked = pending || disabledReason !== null || templates.length === 0;
  return (
    <form
      className="stack"
      aria-label="Request a job run"
      onSubmit={(event) => {
        event.preventDefault();
        const element = event.currentTarget;
        const form = new FormData(element);
        run(() => requestJobRunAction(form), () => element.reset());
      }}
    >
      <div className="row">
        <label>
          Template
          <select name="templateId" required disabled={locked}>
            {templates.map((template) => (
              <option key={template.id} value={template.id}>
                {template.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          Device
          <select name="nodeId" required disabled={locked}>
            {devices.map((device) => (
              <option key={device.id} value={device.id}>
                {device.label}
              </option>
            ))}
          </select>
        </label>
      </div>
      <label>
        Reason (recorded in the audit log)
        <input name="reason" required minLength={4} maxLength={200} disabled={locked} />
      </label>
      <div className="row">
        <button type="submit" disabled={locked}>
          {pending ? "Requesting…" : "Request run"}
        </button>
      </div>
      {templates.length === 0 ? <p className="muted">No templates yet. An owner defines them above.</p> : null}
      {disabledReason ? <p className="muted">{disabledReason}</p> : null}
      {messages}
    </form>
  );
}

export function RunDecision({
  runId,
  decisions,
}: {
  runId: string;
  decisions: ("approve" | "reject" | "cancel")[];
}) {
  const { pending, run, messages } = useJobAction();
  const labels = { approve: "Approve", reject: "Reject", cancel: "Cancel" } as const;
  return (
    <div className="stack">
      <div className="row">
        {decisions.map((decision) => (
          <button
            key={decision}
            type="button"
            className={decision === "approve" ? undefined : "danger"}
            disabled={pending}
            onClick={() => {
              const form = new FormData();
              form.set("runId", runId);
              form.set("decision", decision);
              run(() => decideJobRunAction(form));
            }}
          >
            {labels[decision]}
          </button>
        ))}
      </div>
      {messages}
    </div>
  );
}
