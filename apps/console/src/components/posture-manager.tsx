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

const OS_FAMILIES = ["linux", "macos", "ios", "android", "windows"];

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
  if (definition.os_families?.length) parts.push(`OS is ${definition.os_families.join(" or ")}`);
  for (const [family, version] of Object.entries(definition.min_os_versions ?? {})) {
    parts.push(`${family} ${version} or later`);
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
}: {
  check?: PostureCheck;
  disabled: boolean;
  integrations: IntegrationOption[];
  onDone: () => void;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const definition = check?.definition ?? { on_missing_data: "fail" };
  const prefix = check ? `edit-${check.id}` : "new";
  return (
    <form
      className="stack"
      onSubmit={(event) => {
        event.preventDefault();
        const form = new FormData(event.currentTarget);
        setError(null);
        startTransition(async () => {
          const result: PostureActionResult = check
            ? await updatePostureCheckAction(form)
            : await createPostureCheckAction(form);
          if (!result.ok) {
            setError(result.error);
            return;
          }
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
      ) : (
        <label>
          Name
          <input name="name" required pattern="[a-z][a-z0-9-]{0,31}" placeholder="baseline" disabled={disabled} />
        </label>
      )}
      <label>
        Description
        <input name="description" maxLength={200} defaultValue={definition.description ?? ""} disabled={disabled} />
      </label>
      <div className="acl-rule-grid">
        <label className="acl-selector">
          <span>Minimum agent version</span>
          <input name="min_agent_version" placeholder="0.2.0" defaultValue={definition.min_agent_version ?? ""} disabled={disabled} />
        </label>
        <fieldset className="acl-selector" disabled={disabled}>
          <legend>Allowed operating systems</legend>
          <div className="acl-options">
            {OS_FAMILIES.map((family) => (
              <label key={family}>
                <input
                  type="checkbox"
                  name="os_families"
                  value={family}
                  defaultChecked={definition.os_families?.includes(family)}
                />
                {family}
              </label>
            ))}
          </div>
        </fieldset>
        <label className="acl-selector">
          <span>Minimum OS versions</span>
          <input
            name="min_os_versions"
            placeholder="macos=14.0, linux=22.04"
            defaultValue={Object.entries(definition.min_os_versions ?? {})
              .map(([family, version]) => `${family}=${version}`)
              .join(", ")}
            disabled={disabled}
          />
        </label>
        <label className="acl-selector">
          <span>Credential renewed within (hours)</span>
          <input
            name="max_credential_age_hours"
            inputMode="decimal"
            placeholder="168"
            defaultValue={hours(definition.max_credential_age_secs)}
            disabled={disabled}
          />
        </label>
        <label className="acl-selector">
          <span>Inventory reported within (hours)</span>
          <input
            name="max_report_age_hours"
            inputMode="decimal"
            placeholder="24"
            defaultValue={hours(definition.max_report_age_secs)}
            disabled={disabled}
          />
        </label>
        <label className="acl-selector">
          <span>When data is missing or stale</span>
          <select name="on_missing_data" defaultValue={definition.on_missing_data ?? "fail"} disabled={disabled}>
            <option value="fail">Fail the check (fail-closed)</option>
            <option value="pass">Pass the check (fail-open)</option>
          </select>
        </label>
      </div>
      {integrations.length ? (
        <fieldset className="acl-rule-grid" disabled={disabled}>
          <legend>Device-health provider</legend>
          <label className="acl-selector">
            <span>Require a healthy record from</span>
            <select name="integration_id" defaultValue={definition.integration?.integration_id ?? ""}>
              <option value="">No provider requirement</option>
              {integrations.map((option) => (
                <option key={option.id} value={option.id}>
                  {option.provider} ({option.name})
                </option>
              ))}
            </select>
          </label>
          <label className="acl-selector">
            <span>Provider data confirmed within (minutes)</span>
            <input
              name="integration_max_age_minutes"
              type="number"
              min={1}
              defaultValue={Math.round((definition.integration?.max_age_secs ?? 3600) / 60)}
            />
          </label>
          <label className="acl-selector">
            <span>Provider last saw the device within (hours, optional)</span>
            <input
              name="integration_last_seen_hours"
              inputMode="decimal"
              placeholder="24"
              defaultValue={hours(definition.integration?.max_last_seen_secs)}
            />
          </label>
          <label className="acl-selector">
            <span>During a provider outage</span>
            <select name="integration_on_outage" defaultValue={definition.integration?.on_outage ?? "fail"}>
              <option value="fail">Fail once data is stale (fail-closed)</option>
              <option value="pass">Keep last known passing devices (fail-open)</option>
            </select>
          </label>
        </fieldset>
      ) : null}
      <label>
        <input
          type="checkbox"
          name="require_approved_peer"
          defaultChecked={definition.require_approved_peer ?? false}
          disabled={disabled}
        />{" "}
        Require an active device with an unexpired credential
      </label>
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
      <div className="actions">
        <button type="submit" disabled={disabled || pending} id={`${prefix}-submit`}>
          {pending ? "Saving…" : check ? `Save version ${check.version + 1}` : "Create posture check"}
        </button>
      </div>
    </form>
  );
}

export function PostureManager({
  checks,
  canManage,
  reason,
  integrations = [],
}: {
  checks: PostureCheck[];
  canManage: boolean;
  reason: string | null;
  integrations?: IntegrationOption[];
}) {
  const router = useRouter();
  const [editing, setEditing] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  return (
    <div className="stack">
      {checks.length === 0 ? (
        <p className="muted">
          No posture checks yet. A check does nothing until an allow rule names it.
        </p>
      ) : (
        <ul className="acl-rule-list">
          {checks.map((check) => (
            <li key={check.id} className="acl-rule">
              <div className="acl-rule-head">
                <h3>
                  {check.name} <span className="badge">version {check.version}</span>
                </h3>
                {canManage ? (
                  <div className="row">
                    <button
                      type="button"
                      className="secondary"
                      onClick={() => setEditing(editing === check.id ? null : check.id)}
                    >
                      {editing === check.id ? "Cancel" : "Edit"}
                    </button>
                    <button
                      type="button"
                      className="secondary"
                      disabled={pending || check.referenced_by.length > 0}
                      title={
                        check.referenced_by.length > 0
                          ? "Remove it from access policy before deleting."
                          : undefined
                      }
                      onClick={() => {
                        setError(null);
                        startTransition(async () => {
                          const result = await deletePostureCheckAction(check.id);
                          if (!result.ok) setError(result.error);
                          else router.refresh();
                        });
                      }}
                    >
                      Delete
                    </button>
                  </div>
                ) : null}
              </div>
              {check.definition.description ? <p>{check.definition.description}</p> : null}
              <ul className="audit-details">
                {describeDefinition(check.definition, integrations).map((part) => (
                  <li key={part}>{part}</li>
                ))}
              </ul>
              <p className="muted">
                {check.referenced_by.length
                  ? `Gates ${check.referenced_by.join(", ")} in the published policy.`
                  : "Not referenced by the published policy."}
              </p>
              {editing === check.id ? (
                <CheckForm
                  check={check}
                  disabled={!canManage}
                  integrations={integrations}
                  onDone={() => setEditing(null)}
                />
              ) : null}
            </li>
          ))}
        </ul>
      )}
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
      <div>
        <h2>New posture check</h2>
        {reason ? <p className="muted">{reason}</p> : null}
        <CheckForm disabled={!canManage} integrations={integrations} onDone={() => undefined} />
      </div>
    </div>
  );
}
