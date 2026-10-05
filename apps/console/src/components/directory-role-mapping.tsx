"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  addGroupMappingAction,
  applyDirectoryDriftAction,
  previewDirectoryDriftAction,
  removeGroupMappingAction,
  saveDirectorySettingsAction,
} from "@/app/settings/directory-actions";
import type { DriftPreview } from "@/lib/directory-mapping";
import type { DirectorySettings, GroupRoleMapping } from "@/lib/directory-mapping-core";
import { LocalTime } from "./ui/local-time";
import { ORG_ROLES, roleLabel } from "@/lib/roles";
import { StatusPill } from "./ui/badge";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormField } from "./ui/form-field";
import { Section } from "./ui/section";
import { EmptyRow, Table, Td } from "./ui/table";
import { toast, toastResult } from "./ui/toast";

const SOURCE_LABEL = { scim: "SCIM group", oidc: "OIDC groups claim" } as const;

type Busy = "settings" | "add" | "preview" | "apply" | string | null;

export function DirectoryRoleMapping({
  settings,
  mappings,
  organisationName,
}: {
  settings: DirectorySettings;
  mappings: GroupRoleMapping[];
  organisationName: string;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState<Busy>(null);
  const [errors, setErrors] = useState<{ grace?: string; groupName?: string }>({});
  const [preview, setPreview] = useState<DriftPreview | null>(null);
  const [removing, setRemoving] = useState<GroupRoleMapping | null>(null);
  const roles = ORG_ROLES.filter((role) => role !== "owner" || settings.allowOwnerMapping);
  const applicable = preview?.changes.filter((change) => !change.blocked) ?? [];

  function run(
    key: Busy,
    work: () => Promise<{ ok: true } | { ok: false; error: string; ref?: string }>,
    done: string,
    after?: () => void,
  ) {
    setBusy(key);
    startTransition(async () => {
      const result = await work();
      setBusy(null);
      after?.();
      if (!result.ok) {
        toastResult(result);
        return;
      }
      toast.success(done);
      setPreview(null);
      router.refresh();
    });
  }

  return (
    <Section
      id="directory-roles"
      headingLevel={3}
      title="Directory group roles"
      description={`Map identity provider groups to roles in ${organisationName}. The highest mapped role wins. Group changes never change a role on their own: preview the difference, then apply it. Owners are left alone, and no change can remove the last password owner.`}
    >
      <form
        className="ui-form"
        aria-label="Directory sync settings"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          const days = String(form.get("deprovisionGraceDays") ?? "");
          if (!/^\d+$/u.test(days) || Number(days) > 90) {
            setErrors({ grace: "Use a whole number of days from 0 to 90." });
            return;
          }
          setErrors({});
          run("settings", () => saveDirectorySettingsAction(form), "Directory settings saved");
        }}
      >
        <FormField
          label="Grace period after deprovisioning (days)"
          hint="When the provider deactivates someone they're suspended at once, then removed after this many days (their record is kept). Reactivating them inside the period restores their role. Zero removes them straight away."
          error={errors.grace}
          className="field-narrow"
        >
          <input
            name="deprovisionGraceDays"
            type="number"
            inputMode="numeric"
            min={0}
            max={90}
            defaultValue={settings.deprovisionGraceDays}
          />
        </FormField>
        <label className="check-option">
          <input type="checkbox" name="allowOwnerMapping" defaultChecked={settings.allowOwnerMapping} />
          <span>Allow a directory group to grant the owner role</span>
        </label>
        <div className="actions">
          <Button type="submit" variant="secondary" loading={busy === "settings"} loadingLabel="Saving…" disabled={pending}>
            Save directory settings
          </Button>
        </div>
      </form>

      <div className="ui-subsection">
        <div className="ui-subsection-head">
          <h4 className="card-heading">Group mappings</h4>
        </div>
        <form
          className="form-row"
          aria-label="Add a group mapping"
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            const formEl = event.currentTarget;
            const form = new FormData(formEl);
            if (!String(form.get("groupName") ?? "").trim()) {
              setErrors({ groupName: "Enter the group's name exactly as your identity provider sends it." });
              return;
            }
            setErrors({});
            run("add", () => addGroupMappingAction(form), "Mapping added", () => formEl.reset());
          }}
        >
          <FormField label="Source" className="field-narrow">
            <select name="source" defaultValue="scim">
              <option value="scim">{SOURCE_LABEL.scim}</option>
              <option value="oidc">{SOURCE_LABEL.oidc}</option>
            </select>
          </FormField>
          <FormField label="Group name" error={errors.groupName}>
            <input name="groupName" maxLength={256} placeholder="BlakTail Admins" />
          </FormField>
          <FormField label="Role" className="field-narrow">
            <select name="role" defaultValue="member">
              {roles.map((role) => (
                <option key={role} value={role}>
                  {roleLabel(role)}
                </option>
              ))}
            </select>
          </FormField>
          <Button type="submit" loading={busy === "add"} loadingLabel="Adding…" disabled={pending}>
            Add mapping
          </Button>
        </form>
        <Table label="Group mappings" mobile="stack">
          <thead>
            <tr>
              <th scope="col">Source</th>
              <th scope="col">Group</th>
              <th scope="col">Role</th>
              <th scope="col">
                <span className="visually-hidden">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {mappings.length === 0 ? (
              <EmptyRow colSpan={4}>No group mappings. Roles stay as owners set them.</EmptyRow>
            ) : (
              mappings.map((mapping) => (
                <tr key={mapping.id}>
                  <Td label="Source">{SOURCE_LABEL[mapping.source]}</Td>
                  <Td label="Group" className="mono">
                    {mapping.groupName}
                  </Td>
                  <Td label="Role">{roleLabel(mapping.role)}</Td>
                  <Td>
                    <div className="cell-actions">
                      <Button size="sm" variant="quiet-danger" disabled={pending} onClick={() => setRemoving(mapping)}>
                        Remove
                      </Button>
                    </div>
                  </Td>
                </tr>
              ))
            )}
          </tbody>
        </Table>
        <div className="actions">
          <Button
            variant="secondary"
            loading={busy === "preview"}
            loadingLabel="Checking…"
            disabled={pending}
            onClick={() => {
              setBusy("preview");
              startTransition(async () => {
                const result = await previewDirectoryDriftAction();
                setBusy(null);
                if (!result.ok) {
                  toastResult(result);
                  return;
                }
                setPreview(result.data);
              });
            }}
          >
            Preview role changes
          </Button>
        </div>
      </div>

      {preview ? (
        <div className="ui-subsection" aria-live="polite">
          <div className="ui-subsection-head">
            <h4 className="card-heading">Preview</h4>
            <p className="muted">
              {preview.changes.length === 0
                ? "Everyone already holds the role their groups map to."
                : `${applicable.length} of ${preview.changes.length} change${preview.changes.length === 1 ? "" : "s"} can be applied.`}
            </p>
          </div>
          {preview.changes.length > 0 ? (
            <Table label="Role changes" mobile="stack">
              <thead>
                <tr>
                  <th scope="col">Person</th>
                  <th scope="col">Change</th>
                  <th scope="col">Because of</th>
                  <th scope="col">Outcome</th>
                </tr>
              </thead>
              <tbody>
                {preview.changes.map((change) => (
                  <tr key={change.membershipId}>
                    <Td label="Person">
                      <span className="cell-break">{change.email}</span>
                    </Td>
                    <Td label="Change">
                      {roleLabel(change.from)} → {roleLabel(change.to)}
                    </Td>
                    <Td label="Because of" className="mono">
                      {change.groups.length ? change.groups.join(", ") : "No mapped group (back to member)"}
                    </Td>
                    <Td label="Outcome">
                      {change.blocked ? (
                        <StatusPill tone="warning" title={change.blocked}>
                          Blocked: {change.blocked}
                        </StatusPill>
                      ) : (
                        <StatusPill tone="info">Will change</StatusPill>
                      )}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          ) : null}
          {preview.deprovisioned.length > 0 ? (
            <>
              <h4 className="card-heading">Deprovisioned members</h4>
              <ul className="stack tight">
                {preview.deprovisioned.map((row) => (
                  <li key={row.membershipId}>
                    {row.email} ({roleLabel(row.role)}):{" "}
                    {row.state === "tombstoned" ? (
                      <>
                        removed <LocalTime value={row.tombstonedAt} dateOnly fallback="—" />
                      </>
                    ) : (
                      <>
                        suspended, removed after <LocalTime value={row.deprovisionAt} dateOnly fallback="—" />
                      </>
                    )}
                  </li>
                ))}
              </ul>
            </>
          ) : null}
          <div className="actions">
            {applicable.length > 0 ? (
              <Button loading={busy === "apply"} loadingLabel="Applying…" disabled={pending} onClick={() => {
                const form = new FormData();
                form.set("signature", preview.signature);
                run(
                  "apply",
                  () => applyDirectoryDriftAction(form),
                  `Applied ${applicable.length} role change${applicable.length === 1 ? "" : "s"}`,
                );
              }}>
                Apply {applicable.length} change{applicable.length === 1 ? "" : "s"}
              </Button>
            ) : null}
            <Button variant="ghost" disabled={pending} onClick={() => setPreview(null)}>
              Close preview
            </Button>
          </div>
        </div>
      ) : null}

      <ConfirmDialog
        open={removing !== null}
        title="Remove this mapping?"
        description={
          removing
            ? `${SOURCE_LABEL[removing.source]} “${removing.groupName}” stops granting ${roleLabel(removing.role).toLowerCase()}. Nobody's role changes until you preview and apply.`
            : null
        }
        confirmLabel="Remove mapping"
        pending={pending}
        onCancel={() => setRemoving(null)}
        onConfirm={() => {
          if (!removing) return;
          const form = new FormData();
          form.set("mappingId", removing.id ?? "");
          run("remove", () => removeGroupMappingAction(form), "Mapping removed", () => setRemoving(null));
        }}
      />
    </Section>
  );
}
