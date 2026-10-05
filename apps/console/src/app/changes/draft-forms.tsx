"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useRef, useState, useTransition } from "react";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { FormField } from "@/components/ui/form-field";
import { StatusPill } from "@/components/ui/badge";
import { toastResult } from "@/components/ui/toast";
import type { ChangeSurface, RiskFlag } from "@/lib/coord-changes";
import {
  createDraftAction,
  discardDraftAction,
  publishDraftAction,
  rebaseDraftAction,
  saveDraftAction,
} from "./actions";

type DraftRef = {
  organisationId: string;
  id: string;
  version: number;
  surfaces: ChangeSurface[];
};

function draftForm(draft: DraftRef, form?: HTMLFormElement): FormData {
  const data = form ? new FormData(form) : new FormData();
  data.set("organisationId", draft.organisationId);
  data.set("draftId", draft.id);
  data.set("version", String(draft.version));
  data.delete("surfaces");
  for (const surface of draft.surfaces) data.append("surfaces", surface);
  return data;
}

export type SurfaceChoice = {
  value: ChangeSurface;
  label: string;
  permitted: boolean;
  reason: string | null;
};

/** Create a draft from the live state of the chosen surfaces. */
export function NewDraftForm({
  organisationId,
  organisationName,
  surfaces,
}: {
  organisationId: string;
  organisationName: string;
  surfaces: SurfaceChoice[];
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [errors, setErrors] = useState<Record<string, string>>({});
  return (
    <form
      className="ui-form"
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        const data = new FormData(event.currentTarget);
        data.set("organisationId", organisationId);
        setErrors({});
        startTransition(async () => {
          const result = await createDraftAction(data);
          setErrors(
            toastResult(result, {
              success: "Draft created",
              successDescription:
                "It starts from the current live state. Nothing changes until you publish.",
              errorToast: false,
            }),
          );
          if (result.ok) router.push(`/changes/${result.data.id}`);
        });
      }}
    >
      <FormField label="Title" required error={errors.title}>
        <input
          name="title"
          type="text"
          maxLength={120}
          placeholder="Open the office NAS to rangers"
        />
      </FormField>
      <fieldset
        className="ui-fieldset"
        aria-describedby={errors.surfaces ? "surfaces-error" : undefined}
      >
        <legend>Start from the live state of</legend>
        <div className="ui-choices vertical">
          {surfaces.map((surface) => (
            <label key={surface.value}>
              <input
                type="checkbox"
                name="surfaces"
                value={surface.value}
                disabled={!surface.permitted}
                defaultChecked={surface.permitted && surface.value === "policy"}
              />
              <span>
                {surface.label}
                {surface.reason ? <span className="cell-sub">{surface.reason}</span> : null}
              </span>
            </label>
          ))}
        </div>
        {errors.surfaces ? (
          <p id="surfaces-error" className="ui-field-error" role="alert">
            {errors.surfaces}
          </p>
        ) : null}
      </fieldset>
      <div className="ui-form-actions">
        <Button type="submit" loading={pending} loadingLabel="Creating…">
          Create draft in {organisationName}
        </Button>
      </div>
    </form>
  );
}

/** Title and proposed documents. */
export function DraftEditor({
  draft,
  title,
  documents,
}: {
  draft: DraftRef;
  title: string;
  documents: {
    field: "policy" | "resources" | "dns";
    label: string;
    hint: string;
    href: string;
    link: string;
    value: string;
  }[];
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [errors, setErrors] = useState<Record<string, string>>({});
  return (
    <form
      className="ui-form wide"
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        const data = draftForm(draft, event.currentTarget);
        setErrors({});
        startTransition(async () => {
          const result = await saveDraftAction(data);
          setErrors(
            toastResult(result, {
              success: "Draft saved",
              successDescription: "Run a preview before publishing.",
              errorToast: false,
            }),
          );
          if (result.ok) router.refresh();
        });
      }}
    >
      <FormField label="Title" required error={errors.title} className="field-lg">
        <input name="title" type="text" maxLength={120} defaultValue={title} />
      </FormField>
      {documents.map((doc) => (
        <FormField
          key={doc.field}
          label={doc.label}
          hint={
            <>
              {doc.hint} Also editable on <Link href={doc.href}>{doc.link}</Link>.
            </>
          }
          error={errors[doc.field]}
        >
          <textarea
            name={doc.field}
            className="mono"
            rows={14}
            spellCheck={false}
            defaultValue={doc.value}
          />
        </FormField>
      ))}
      <div className="ui-form-actions">
        <Button type="submit" loading={pending} loadingLabel="Saving…">
          Save draft
        </Button>
        <span className="muted">Saves as version {draft.version + 1}.</span>
      </div>
    </form>
  );
}

/** GET form for the preview: navigates with the chosen test pair. */
export function PreviewForm({
  draftId,
  nodes,
  initial,
}: {
  draftId: string;
  nodes: { id: string; label: string }[];
  initial: { src?: string; dst?: string; protocol?: string; port?: string };
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [portError, setPortError] = useState<string | null>(null);
  return (
    <form
      className="ui-form wide"
      aria-label="Preview options"
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        const data = new FormData(event.currentTarget);
        const port = String(data.get("port") ?? "").trim();
        if (port && (!/^\d+$/u.test(port) || Number(port) < 1 || Number(port) > 65535)) {
          setPortError("Use a port from 1 to 65535, or leave it blank.");
          return;
        }
        setPortError(null);
        const query = new URLSearchParams({ preview: "1" });
        for (const key of ["src", "dst", "protocol"]) {
          const value = String(data.get(key) ?? "");
          if (value) query.set(key, value);
        }
        if (port) query.set("port", port);
        startTransition(() => router.push(`/changes/${draftId}?${query.toString()}`));
      }}
    >
      <p className="muted">
        Optionally name a source and destination device to test one path before and after.
      </p>
      <div className="ui-form-grid preview-grid">
        <FormField label="Test source">
          <select name="src" defaultValue={initial.src ?? ""}>
            <option value="">None</option>
            {nodes.map((node) => (
              <option key={node.id} value={node.id}>
                {node.label}
              </option>
            ))}
          </select>
        </FormField>
        <FormField label="Test destination">
          <select name="dst" defaultValue={initial.dst ?? ""}>
            <option value="">None</option>
            {nodes.map((node) => (
              <option key={node.id} value={node.id}>
                {node.label}
              </option>
            ))}
          </select>
        </FormField>
        <FormField label="Protocol">
          <select name="protocol" defaultValue={initial.protocol ?? ""}>
            <option value="">Any</option>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
            <option value="icmp">ICMP</option>
          </select>
        </FormField>
        <FormField label="Port" error={portError}>
          <input
            name="port"
            inputMode="numeric"
            maxLength={5}
            placeholder="Any"
            defaultValue={initial.port ?? ""}
          />
        </FormField>
      </div>
      <div className="ui-form-actions">
        <Button type="submit" loading={pending} loadingLabel="Running preview…">
          Run preview
        </Button>
      </div>
    </form>
  );
}

export function RebaseButton({ draft }: { draft: DraftRef }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  return (
    <Button
      loading={pending}
      loadingLabel="Rebasing…"
      onClick={() => {
        startTransition(async () => {
          const result = await rebaseDraftAction(draftForm(draft));
          toastResult(result, {
            success: "Draft rebased",
            successDescription:
              "Your proposed documents are unchanged. The preview now compares them with the latest live state.",
          });
          if (result.ok) router.refresh();
        });
      }}
    >
      Rebase on live state
    </Button>
  );
}

/** Risk acknowledgements, then a confirm dialog that publishes. */
export function PublishForm({
  draft,
  organisationName,
  surfaceLabels,
  risks,
}: {
  draft: DraftRef;
  organisationName: string;
  surfaceLabels: string;
  risks: RiskFlag[];
}) {
  const router = useRouter();
  const formRef = useRef<HTMLFormElement>(null);
  const [pending, startTransition] = useTransition();
  const [open, setOpen] = useState(false);
  const [riskError, setRiskError] = useState<string | null>(null);
  return (
    <>
      <form
        ref={formRef}
        className="ui-form wide"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          const ticked = new FormData(event.currentTarget).getAll("risk").length;
          if (ticked < risks.length) {
            setRiskError("Tick each risk to confirm you have read it.");
            return;
          }
          setRiskError(null);
          setOpen(true);
        }}
      >
        <fieldset className="ui-fieldset">
          <legend>Risks to confirm</legend>
          {risks.length === 0 ? (
            <p className="muted">No risk flags for this draft.</p>
          ) : (
            <div className="ui-choices vertical">
              {risks.map((risk) => (
                <label key={risk.code}>
                  <input type="checkbox" name="risk" value={risk.code} />
                  <span>
                    <StatusPill tone={risk.severity === "high" ? "danger" : "warning"}>
                      {risk.severity === "high" ? "High risk" : "Warning"}
                    </StatusPill>{" "}
                    {risk.message}
                  </span>
                </label>
              ))}
            </div>
          )}
          {riskError ? (
            <p className="ui-field-error" role="alert">
              {riskError}
            </p>
          ) : null}
        </fieldset>
        <div className="ui-form-actions">
          <Button type="submit">Publish…</Button>
        </div>
      </form>
      <ConfirmDialog
        open={open}
        tone="primary"
        title={`Publish to ${organisationName}?`}
        description={
          <p>
            Version {draft.version} replaces {surfaceLabels} in one transaction. Devices pick it up
            on their next poll. To undo it, publish another change.
          </p>
        }
        confirmLabel="Publish now"
        pending={pending}
        onCancel={() => setOpen(false)}
        onConfirm={() => {
          const data = draftForm(draft, formRef.current ?? undefined);
          data.set("confirm", "on");
          startTransition(async () => {
            const result = await publishDraftAction(data);
            toastResult(result, {
              success: "Draft published",
              successDescription: `Every change went live in ${organisationName} together.`,
            });
            setOpen(false);
            if (result.ok) router.replace(`/changes/${draft.id}`);
          });
        }}
      />
    </>
  );
}

export function DiscardButton({ draft, title }: { draft: DraftRef; title: string }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button variant="quiet-danger" onClick={() => setOpen(true)} disabled={pending}>
        Discard draft
      </Button>
      <ConfirmDialog
        open={open}
        title="Discard this draft?"
        description={
          <p>
            “{title}” is closed and can&apos;t be edited or published again. Nothing live changes.
          </p>
        }
        confirmLabel="Discard draft"
        pending={pending}
        onCancel={() => setOpen(false)}
        onConfirm={() => {
          startTransition(async () => {
            const result = await discardDraftAction(draftForm(draft));
            toastResult(result, {
              success: "Draft discarded",
              successDescription: "Nothing was published.",
            });
            setOpen(false);
            if (result.ok) router.replace(`/changes/${draft.id}`);
          });
        }}
      />
    </>
  );
}
