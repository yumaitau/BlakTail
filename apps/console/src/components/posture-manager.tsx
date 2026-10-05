"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  createPostureCheckAction,
  deletePostureCheckAction,
  updatePostureCheckAction,
  type PostureActionResult,
} from "@/app/posture/actions";
import type { PostureCheck, PostureDefinition } from "@/lib/coord-policy";
import { EmptyState } from "./empty-state";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormField } from "./ui/form-field";
import { Section } from "./ui/section";
import { toastResult } from "./ui/toast";

const OS_FAMILIES = ["linux", "macos", "ios", "android", "windows"];
const OS_LABEL: Record<string, string> = {
  linux: "Linux",
  macos: "macOS",
  ios: "iOS",
  android: "Android",
  windows: "Windows",
};

export type IntegrationOption = { id: string; name: string; provider: string };

function hours(seconds: number | undefined): string {
  return seconds === undefined ? "" : String(Math.round((seconds / 3600) * 100) / 100);
}

function describeDefinition(
  definition: PostureDefinition,
  integrations: IntegrationOption[],
): string[] {
  const parts: string[] = [];
  const requirement = definition.integration;
  if (requirement) {
    const found = integrations.find((option) => option.id === requirement.integration_id);
    parts.push(
      `${found ? `${found.provider} (${found.name})` : "Removed integration"} reports the device healthy, confirmed within ${Math.round((requirement.max_age_secs ?? 3600) / 60)} min`,
    );
    if (requirement.max_last_seen_secs !== undefined) {
      parts.push(`Provider saw the device within ${hours(requirement.max_last_seen_secs)} h`);
    }
    parts.push(
      requirement.on_outage === "pass"
        ? "Provider outage: last known passing devices keep access (fail-open)"
        : "Provider outage: stale data fails (fail-closed)",
    );
  }
  if (definition.require_approved_peer) parts.push("Device active with an unexpired credential");
  if (definition.min_agent_version) parts.push(`Agent ${definition.min_agent_version} or later`);
  if (definition.os_families?.length) {
    parts.push(`OS is ${definition.os_families.map((family) => OS_LABEL[family] ?? family).join(" or ")}`);
  }
  for (const [family, version] of Object.entries(definition.min_os_versions ?? {})) {
    parts.push(`${OS_LABEL[family] ?? family} ${version} or later`);
  }
  if (definition.max_credential_age_secs !== undefined) {
    parts.push(`Credential renewed within ${hours(definition.max_credential_age_secs)} h`);
  }
  if (definition.max_report_age_secs !== undefined) {
    parts.push(`Inventory reported within ${hours(definition.max_report_age_secs)} h`);
  }
  parts.push(
    definition.on_missing_data === "pass"
      ? "Missing data passes (fail-open)"
      : "Missing data fails (fail-closed)",
  );
  return parts;
}

function CheckForm({
  check,
  disabled,
  integrations,
  onDone,
  onCancel,
}: {
  check?: PostureCheck;
  disabled: boolean;
  integrations: IntegrationOption[];
  onDone: () => void;
  onCancel?: () => void;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [errors, setErrors] = useState<Record<string, string>>({});
  const definition = check?.definition ?? { on_missing_data: "fail" };
  const prefix = check ? `edit-${check.id}` : "new";
  return (
    <form
      className="ui-form wide"
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        const formElement = event.currentTarget;
        const form = new FormData(formElement);
        setErrors({});
        startTransition(async () => {
          const result: PostureActionResult = check
            ? await updatePostureCheckAction(form)
            : await createPostureCheckAction(form);
          setErrors(
            toastResult(result, {
              success: check ? "Posture check updated" : "Posture check created",
              successDescription: check
                ? `${check.name} is now version ${check.version + 1}.`
                : "Name it in an allow or SSH rule to start gating access.",
              errorToast: false,
            }),
          );
          if (!result.ok) return;
          if (!check) formElement.reset();
          onDone();
          router.refresh();
        });
      }}
    >
      {check ? (
        <>
          <input type="hidden" name="id" value={check.id} />
          <input type="hidden" name="version" value={check.version} />
        </>
      ) : null}
      <div className="ui-form-grid">
        {check ? null : (
          <FormField
            label="Name"
            hint="Lowercase letters, digits and hyphens. Rules refer to it by this name."
            required
            error={errors.name}
          >
            <input
              name="name"
              className="mono"
              maxLength={32}
              placeholder="baseline"
              autoComplete="off"
              spellCheck={false}
              disabled={disabled}
            />
          </FormField>
        )}
        <FormField label="Description" hint="Optional. Shown to admins." error={errors.description}>
          <input
            name="description"
            maxLength={200}
            defaultValue={definition.description ?? ""}
            disabled={disabled}
          />
        </FormField>
      </div>

      <fieldset className="ui-fieldset" disabled={disabled}>
        <legend>Device reports</legend>
        <div className="ui-form-grid">
          <FormField label="Minimum agent version" error={errors.min_agent_version}>
            <input
              name="min_agent_version"
              className="mono"
              placeholder="0.2.0"
              defaultValue={definition.min_agent_version ?? ""}
            />
          </FormField>
          <FormField
            label="Minimum OS versions"
            hint="Comma-separated, for example macos=14.0, linux=22.04."
            error={errors.min_os_versions}
          >
            <input
              name="min_os_versions"
              className="mono"
              placeholder="macos=14.0, linux=22.04"
              defaultValue={Object.entries(definition.min_os_versions ?? {})
                .map(([family, version]) => `${family}=${version}`)
                .join(", ")}
            />
          </FormField>
        </div>
        <fieldset className="acl-selector">
          <legend>Allowed operating systems</legend>
          <div className="ui-choices">
            {OS_FAMILIES.map((family) => (
              <label key={family}>
                <input
                  type="checkbox"
                  name="os_families"
                  value={family}
                  defaultChecked={definition.os_families?.includes(family)}
                />
                {OS_LABEL[family]}
              </label>
            ))}
          </div>
        </fieldset>
      </fieldset>

      <fieldset className="ui-fieldset" disabled={disabled}>
        <legend>Freshness</legend>
        <div className="ui-form-grid">
          <FormField
            label="Credential renewed within"
            hint="Hours. Leave blank for no limit."
            error={errors.max_credential_age_hours}
          >
            <input
              name="max_credential_age_hours"
              inputMode="decimal"
              placeholder="168"
              defaultValue={hours(definition.max_credential_age_secs)}
            />
          </FormField>
          <FormField
            label="Inventory reported within"
            hint="Hours. Leave blank for no limit."
            error={errors.max_report_age_hours}
          >
            <input
              name="max_report_age_hours"
              inputMode="decimal"
              placeholder="24"
              defaultValue={hours(definition.max_report_age_secs)}
            />
          </FormField>
          <FormField label="When data is missing or stale">
            <select name="on_missing_data" defaultValue={definition.on_missing_data ?? "fail"}>
              <option value="fail">Fail the check (fail-closed)</option>
              <option value="pass">Pass the check (fail-open)</option>
            </select>
          </FormField>
        </div>
        <label>
          <input
            type="checkbox"
            name="require_approved_peer"
            defaultChecked={definition.require_approved_peer ?? false}
          />
          Require an active device with an unexpired credential
        </label>
      </fieldset>

      {integrations.length ? (
        <fieldset className="ui-fieldset" disabled={disabled}>
          <legend>Device-health provider</legend>
          <div className="ui-form-grid">
            <FormField label="Require a healthy record from">
              <select
                name="integration_id"
                defaultValue={definition.integration?.integration_id ?? ""}
              >
                <option value="">No provider requirement</option>
                {integrations.map((option) => (
                  <option key={option.id} value={option.id}>
                    {option.provider} ({option.name})
                  </option>
                ))}
              </select>
            </FormField>
            <FormField
              label="Provider data confirmed within"
              hint="Minutes."
              error={errors.integration_max_age_minutes}
            >
              <input
                name="integration_max_age_minutes"
                type="number"
                min={1}
                defaultValue={Math.round((definition.integration?.max_age_secs ?? 3600) / 60)}
              />
            </FormField>
            <FormField
              label="Provider last saw the device within"
              hint="Hours, optional."
              error={errors.integration_last_seen_hours}
            >
              <input
                name="integration_last_seen_hours"
                inputMode="decimal"
                placeholder="24"
                defaultValue={hours(definition.integration?.max_last_seen_secs)}
              />
            </FormField>
            <FormField label="During a provider outage">
              <select
                name="integration_on_outage"
                defaultValue={definition.integration?.on_outage ?? "fail"}
              >
                <option value="fail">Fail once data is stale (fail-closed)</option>
                <option value="pass">Keep last known passing devices (fail-open)</option>
              </select>
            </FormField>
          </div>
        </fieldset>
      ) : null}

      <div className="ui-form-actions">
        <Button
          type="submit"
          disabled={disabled}
          loading={pending}
          loadingLabel="Saving…"
          id={`${prefix}-submit`}
        >
          {check ? `Save version ${check.version + 1}` : "Create posture check"}
        </Button>
        {onCancel ? (
          <Button variant="secondary" onClick={onCancel} disabled={pending}>
            Cancel
          </Button>
        ) : null}
      </div>
    </form>
  );
}

export function PostureManager({
  checks,
  canManage,
  integrations = [],
}: {
  checks: PostureCheck[];
  canManage: boolean;
  integrations?: IntegrationOption[];
}) {
  const router = useRouter();
  const [editing, setEditing] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<PostureCheck | null>(null);
  const [pending, startTransition] = useTransition();
  return (
    <>
      <Section
        id="checks"
        title="Checks"
        description="A check does nothing until an allow or SSH rule names it."
        actions={
          checks.length > 0 ? (
            <Badge dot={false}>
              {checks.length} {checks.length === 1 ? "check" : "checks"}
            </Badge>
          ) : null
        }
      >
        {checks.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No posture checks yet"
            body={
              canManage
                ? "Create one below, then name it in an allow rule on the Access page."
                : "When an admin creates one, it shows here with the devices it affects."
            }
          />
        ) : (
          <ul className="acl-rule-list">
            {checks.map((check) => (
              <li key={check.id} className="acl-rule">
                <div className="acl-rule-head">
                  <h3 className="posture-name">
                    <span className="mono">{check.name}</span>
                    <Badge dot={false}>Version {check.version}</Badge>
                    {check.referenced_by.length ? (
                      <Badge tone="success">In use</Badge>
                    ) : (
                      <Badge tone="muted">Not used</Badge>
                    )}
                  </h3>
                  {canManage ? (
                    <div className="cell-actions">
                      <Button
                        variant="secondary"
                        size="sm"
                        aria-expanded={editing === check.id}
                        onClick={() => setEditing(editing === check.id ? null : check.id)}
                      >
                        {editing === check.id ? "Close editor" : "Edit"}
                      </Button>
                      <Button
                        variant="quiet-danger"
                        size="sm"
                        disabled={pending || check.referenced_by.length > 0}
                        title={
                          check.referenced_by.length > 0
                            ? "Remove it from the access policy before deleting."
                            : undefined
                        }
                        onClick={() => setConfirmDelete(check)}
                      >
                        Delete
                      </Button>
                    </div>
                  ) : null}
                </div>
                {check.definition.description ? (
                  <p className="posture-description">{check.definition.description}</p>
                ) : null}
                <ul className="audit-details">
                  {describeDefinition(check.definition, integrations).map((part) => (
                    <li key={part}>{part}</li>
                  ))}
                </ul>
                <p className="muted small">
                  {check.referenced_by.length
                    ? `Gates ${check.referenced_by.join(", ")} in the published policy. Remove it there before deleting.`
                    : "Not referenced by the published policy."}
                </p>
                {editing === check.id ? (
                  <CheckForm
                    check={check}
                    disabled={!canManage}
                    integrations={integrations}
                    onDone={() => setEditing(null)}
                    onCancel={() => setEditing(null)}
                  />
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </Section>

      {canManage ? (
        <Section
          id="new-check"
          title="New posture check"
          description="Set at least one requirement. Leave the rest blank."
        >
          <CheckForm disabled={false} integrations={integrations} onDone={() => undefined} />
        </Section>
      ) : null}

      <ConfirmDialog
        open={confirmDelete !== null}
        title="Delete posture check"
        description={
          confirmDelete
            ? `${confirmDelete.name} and all its versions are deleted. No rule uses it, so access doesn't change.`
            : null
        }
        confirmText={confirmDelete?.name}
        confirmLabel="Delete check"
        pending={pending}
        onCancel={() => setConfirmDelete(null)}
        onConfirm={() => {
          if (!confirmDelete) return;
          const check = confirmDelete;
          startTransition(async () => {
            const result = await deletePostureCheckAction(check.id);
            toastResult(result, {
              success: "Posture check deleted",
              successDescription: `${check.name} is gone.`,
            });
            setConfirmDelete(null);
            if (result.ok) router.refresh();
          });
        }}
      />
    </>
  );
}
