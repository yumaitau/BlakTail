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
import { Alert } from "./ui/alert";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormField } from "./ui/form-field";
import { toast } from "./ui/toast";

/** Toast the outcome of a job action (success carries the action's own message). */
function useJobAction() {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const run = (action: () => Promise<JobActionResult>, success: string, after?: () => void) => {
    startTransition(async () => {
      const result = await action();
      if (!result.ok) {
        toast.error(result.error, { reference: result.ref });
        return;
      }
      toast.success(success, { description: result.message });
      after?.();
      router.refresh();
    });
  };
  return { pending, run };
}

export function JobTemplateForm({
  devices,
  disabledReason,
}: {
  devices: { id: string; label: string }[];
  disabledReason: string | null;
}) {
  const { pending, run } = useJobAction();
  const [errors, setErrors] = useState<Record<string, string>>({});
  const locked = pending || disabledReason !== null;
  return (
    <form
      className="ui-form"
      aria-label="New job template"
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        const element = event.currentTarget;
        const form = new FormData(element);
        const next: Record<string, string> = {};
        if (!String(form.get("name") ?? "").trim()) next.name = "Name the template, for example Disk usage.";
        if (!String(form.get("program") ?? "").trim().startsWith("/")) {
          next.program = "Enter the program's full path, such as /usr/bin/uptime.";
        }
        if (form.getAll("tags").length === 0 && form.getAll("nodeIds").length === 0) {
          next.targets = "Choose at least one tag or device.";
        }
        setErrors(next);
        if (Object.keys(next).length) return;
        run(() => createJobTemplateAction(form), "Template saved", () => element.reset());
      }}
    >
      {disabledReason ? <Alert tone="info">{disabledReason}</Alert> : null}
      <div className="form-grid">
        <FormField label="Name" required error={errors.name}>
          <input name="name" maxLength={64} placeholder="Disk usage" disabled={locked} />
        </FormField>
        <FormField label="Program" hint="Full path. Shells and interpreters are refused." required error={errors.program}>
          <input name="program" spellCheck={false} placeholder="/usr/bin/df" disabled={locked} className="mono" />
        </FormField>
      </div>
      <FormField label="Arguments" hint="One per line, passed exactly as written. There's no shell, so quoting has no effect.">
        <textarea name="args" rows={3} spellCheck={false} placeholder="-h" disabled={locked} className="mono" />
      </FormField>
      <div className="form-grid">
        <FormField label="Time limit (seconds, up to 600)">
          <input name="timeoutSecs" type="number" min={1} max={600} defaultValue={60} disabled={locked} />
        </FormField>
        <FormField label="Output limit (bytes, up to 65,536)">
          <input name="outputCapBytes" type="number" min={1} max={65536} defaultValue={16384} disabled={locked} />
        </FormField>
      </div>
      <fieldset className="form-fieldset" disabled={locked}>
        <legend>Targets</legend>
        <div className="check-grid flush">
          {["office", "ranger", "store"].map((tag) => (
            <label key={tag} className="check-option">
              <input type="checkbox" name="tags" value={tag} />
              <span>Devices tagged {tag}</span>
            </label>
          ))}
        </div>
        <FormField label="Specific devices" hint="Hold Ctrl or Command to choose several.">
          <select name="nodeIds" multiple size={Math.min(6, Math.max(2, devices.length))}>
            {devices.map((device) => (
              <option key={device.id} value={device.id}>
                {device.label}
              </option>
            ))}
          </select>
        </FormField>
        {errors.targets ? (
          <p className="ui-field-error" role="alert">
            {errors.targets}
          </p>
        ) : null}
      </fieldset>
      <div className="actions">
        <Button type="submit" loading={pending} loadingLabel="Saving…" disabled={locked}>
          Save template
        </Button>
      </div>
    </form>
  );
}

export function DisableTemplateButton({ templateId, name }: { templateId: string; name: string }) {
  const { pending, run } = useJobAction();
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button size="sm" variant="quiet-danger" loading={pending} onClick={() => setOpen(true)}>
        Disable
      </Button>
      <ConfirmDialog
        open={open}
        title={`Disable ${name}?`}
        description="Devices stop accepting new runs of this template, and runs waiting for approval can no longer be approved."
        confirmLabel="Disable template"
        pending={pending}
        onCancel={() => setOpen(false)}
        onConfirm={() => {
          const form = new FormData();
          form.set("templateId", templateId);
          run(() => disableJobTemplateAction(form), `${name} disabled`, () => setOpen(false));
        }}
      />
    </>
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
  const { pending, run } = useJobAction();
  const [reasonError, setReasonError] = useState<string | null>(null);
  const locked = pending || disabledReason !== null || templates.length === 0;
  return (
    <form
      className="ui-form"
      aria-label="Request a job run"
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        const element = event.currentTarget;
        const form = new FormData(element);
        if (String(form.get("reason") ?? "").trim().length < 4) {
          setReasonError("Say why the job should run. It's recorded in the audit log.");
          return;
        }
        setReasonError(null);
        run(() => requestJobRunAction(form), "Run requested", () => element.reset());
      }}
    >
      {templates.length === 0 ? (
        <Alert tone="info">No templates yet. An owner defines them above.</Alert>
      ) : null}
      {disabledReason ? <Alert tone="info">{disabledReason}</Alert> : null}
      <div className="form-grid">
        <FormField label="Template">
          <select name="templateId" disabled={locked}>
            {templates.map((template) => (
              <option key={template.id} value={template.id}>
                {template.label}
              </option>
            ))}
          </select>
        </FormField>
        <FormField label="Device">
          <select name="nodeId" disabled={locked}>
            {devices.map((device) => (
              <option key={device.id} value={device.id}>
                {device.label}
              </option>
            ))}
          </select>
        </FormField>
      </div>
      <FormField label="Reason" hint="Recorded in the audit log and shown to the approver." required error={reasonError}>
        <input name="reason" maxLength={200} disabled={locked} />
      </FormField>
      <div className="actions">
        <Button type="submit" loading={pending} loadingLabel="Requesting…" disabled={locked}>
          Request run
        </Button>
      </div>
    </form>
  );
}

const DECISION_COPY = {
  approve: { label: "Approve", toast: "Run approved" },
  reject: { label: "Reject", toast: "Run rejected" },
  cancel: { label: "Cancel run", toast: "Cancel requested" },
} as const;

export function RunDecision({
  runId,
  name,
  decisions,
}: {
  runId: string;
  name: string;
  decisions: ("approve" | "reject" | "cancel")[];
}) {
  const { pending, run } = useJobAction();
  const [busy, setBusy] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<"reject" | "cancel" | null>(null);
  if (decisions.length === 0) return null;
  function decide(decision: "approve" | "reject" | "cancel") {
    const form = new FormData();
    form.set("runId", runId);
    form.set("decision", decision);
    setBusy(decision);
    run(() => decideJobRunAction(form), DECISION_COPY[decision].toast, () => setConfirm(null));
  }
  return (
    <div className="actions">
      {decisions.map((decision) => (
        <Button
          key={decision}
          size="sm"
          variant={decision === "approve" ? "primary" : "quiet-danger"}
          loading={pending && busy === decision}
          disabled={pending}
          onClick={() => (decision === "approve" ? decide("approve") : setConfirm(decision))}
        >
          {DECISION_COPY[decision].label}
        </Button>
      ))}
      <ConfirmDialog
        open={confirm !== null}
        title={confirm === "reject" ? `Reject this run of ${name}?` : `Cancel this run of ${name}?`}
        description={
          confirm === "reject"
            ? "The device won't run it. The person who asked can request it again."
            : "If it's already running, the device stops it within a few seconds."
        }
        confirmLabel={confirm === "reject" ? "Reject run" : "Cancel run"}
        cancelLabel="Keep it"
        pending={pending}
        onCancel={() => setConfirm(null)}
        onConfirm={() => confirm && decide(confirm)}
      />
    </div>
  );
}
