"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  approveHardwareAction,
  createIntegrationAction,
  deleteIntegrationAction,
  rotateIntegrationSecretAction,
  setIntegrationEnabledAction,
  syncIntegrationAction,
  type IntegrationActionResult,
} from "@/app/posture/actions";
import type {
  PostureIntegration,
  ProviderInfo,
  ProviderKind,
  SyncReport,
} from "@/lib/coord-posture-integrations";
import { EmptyState } from "./empty-state";
import { Badge, type BadgeTone } from "./ui/badge";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormField } from "./ui/form-field";
import { MonoValue } from "./ui/mono-value";
import { toast, toastResult } from "./ui/toast";

function whenText(seconds: number | null): string {
  if (!seconds) return "never";
  return new Date(seconds * 1000).toLocaleString("en-AU", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

/** Server and browser format dates differently; the browser's text wins. */
function when(seconds: number | null) {
  if (!seconds) return "never";
  return (
    <time dateTime={new Date(seconds * 1000).toISOString()} suppressHydrationWarning>
      {whenText(seconds)}
    </time>
  );
}

/** Toast the outcome of a connection test that the action itself survived. */
function toastReport(report: SyncReport | undefined, success: string) {
  if (!report) {
    toast.success(success);
    return;
  }
  if (report.ok) {
    toast.success(success, {
      description: `Connected. ${report.devices} provider device${report.devices === 1 ? "" : "s"} synced.`,
    });
  } else {
    toast.warning("The provider didn't accept the connection", {
      description:
        "Check the credential and the access it was granted, then test again. The last error is shown on the integration.",
    });
  }
}

function ProviderNotice({ provider }: { provider: ProviderInfo }) {
  return (
    <div className="stack" role="note">
      <p>
        <strong>Access to create.</strong> {provider.access}
      </p>
      <p>
        <strong>Data BlakTail pulls and stores.</strong> {provider.data_collected} Nothing else from
        the response is kept; only the latest record per device is stored.
      </p>
      <p>
        <strong>Passing rule.</strong> {provider.compliance_rule}
      </p>
      <p>
        <strong>Where the data comes from.</strong> {provider.residency}
      </p>
    </div>
  );
}

function AddIntegration({
  providers,
  residencyNotice,
}: {
  providers: ProviderInfo[];
  residencyNotice: string;
}) {
  const router = useRouter();
  const [kind, setKind] = useState<ProviderKind | "">("");
  const [pending, startTransition] = useTransition();
  const [errors, setErrors] = useState<Record<string, string>>({});
  const provider = providers.find((candidate) => candidate.kind === kind);
  return (
    <form
      className="ui-form wide"
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        const form = event.currentTarget;
        const data = new FormData(form);
        if (data.get("privacy_acknowledged") !== "on") {
          setErrors({
            privacy_acknowledged: "Read the data notice and confirm the organisation approved it.",
          });
          return;
        }
        setErrors({});
        startTransition(async () => {
          const result: IntegrationActionResult = await createIntegrationAction(data);
          if (!result.ok) {
            setErrors(toastResult(result));
            return;
          }
          form.reset();
          setKind("");
          toastReport(result.report, "Provider connected");
          router.refresh();
        });
      }}
    >
      <FormField label="Provider" className="field-md">
        <select
          name="kind"
          value={kind}
          onChange={(event) => setKind(event.target.value as ProviderKind | "")}
        >
          <option value="">Choose a provider</option>
          {providers.map((option) => (
            <option key={option.kind} value={option.kind}>
              {option.label}
            </option>
          ))}
        </select>
      </FormField>
      {provider ? (
        <>
          <div className="callout">
            <ProviderNotice provider={provider} />
            <p className="muted">{residencyNotice}</p>
          </div>
          <fieldset className="ui-fieldset">
            <legend>Connection</legend>
            <div className="ui-form-grid">
              <FormField label="Name" required error={errors.name}>
                <input name="name" maxLength={64} defaultValue={provider.kind} />
              </FormField>
              {provider.fields.map((field) =>
                field.options?.length ? (
                  <FormField
                    key={field.name}
                    label={field.label}
                    hint={field.help}
                    required
                    error={errors[field.name]}
                  >
                    <select name={field.name}>
                      {field.options.map((option) => (
                        <option key={option} value={option}>
                          {option}
                        </option>
                      ))}
                    </select>
                  </FormField>
                ) : (
                  <FormField
                    key={field.name}
                    label={field.label}
                    hint={field.help}
                    required
                    error={errors[field.name]}
                  >
                    <input name={field.name} autoComplete="off" spellCheck={false} />
                  </FormField>
                ),
              )}
              <FormField
                label={provider.secret_label}
                hint="Write-only. Sealed at rest and never shown again."
                required
                error={errors.secret}
              >
                <input name="secret" type="password" minLength={8} autoComplete="new-password" />
              </FormField>
              <FormField
                label="Sync every"
                hint="Minutes, 5 to 1440."
                error={errors.interval_minutes}
              >
                <input name="interval_minutes" type="number" min={5} max={1440} defaultValue={15} />
              </FormField>
            </div>
            <label>
              <input type="checkbox" name="match_hostname" />
              Also match on hostname when no serial number or MAC address matches (weaker: users
              choose hostnames)
            </label>
          </fieldset>
          <div className={errors.privacy_acknowledged ? "ui-field has-error" : "ui-field"}>
            <label>
              <input
                type="checkbox"
                name="privacy_acknowledged"
                aria-invalid={errors.privacy_acknowledged ? true : undefined}
                aria-describedby={errors.privacy_acknowledged ? "privacy-ack-error" : undefined}
              />
              I have read what this integration collects and where the data comes from, and the
              organisation has approved it.
            </label>
            {errors.privacy_acknowledged ? (
              <p id="privacy-ack-error" className="ui-field-error">
                {errors.privacy_acknowledged}
              </p>
            ) : null}
          </div>
          <div className="ui-form-actions">
            <Button type="submit" loading={pending} loadingLabel="Connecting…">
              Connect and test
            </Button>
            <Button variant="secondary" disabled={pending} onClick={() => setKind("")}>
              Cancel
            </Button>
          </div>
        </>
      ) : null}
    </form>
  );
}

function IntegrationCard({
  integration,
  provider,
  canManage,
}: {
  integration: PostureIntegration;
  provider?: ProviderInfo;
  canManage: boolean;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState<string | null>(null);
  const [rotating, setRotating] = useState(false);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const run = (
    label: string,
    success: string,
    action: () => Promise<IntegrationActionResult>,
    after?: () => void,
  ) => {
    setBusy(label);
    startTransition(async () => {
      const result = await action();
      setBusy(null);
      after?.();
      if (!result.ok) {
        toastResult(result);
        return;
      }
      toastReport(result.report, success);
      router.refresh();
    });
  };
  const status: { label: string; tone: BadgeTone } = !integration.enabled
    ? { label: "Disabled", tone: "muted" }
    : integration.outage_since
      ? { label: `Outage since ${whenText(integration.outage_since)}`, tone: "danger" }
      : integration.last_success_at
        ? { label: "Healthy", tone: "success" }
        : { label: "Not yet synced", tone: "warning" };
  return (
    <li className="acl-rule">
      <div className="acl-rule-head">
        <h3 className="posture-name">
          {integration.name}
          <Badge dot={false}>{integration.provider}</Badge>
          <Badge tone={status.tone}>{status.label}</Badge>
        </h3>
        {canManage ? (
          <div className="cell-actions">
            <Button
              variant="secondary"
              size="sm"
              loading={busy === "sync"}
              loadingLabel="Testing…"
              disabled={pending}
              onClick={() =>
                run("sync", "Connection tested", () => syncIntegrationAction(integration.id))
              }
            >
              Test connection
            </Button>
            <Button
              variant="secondary"
              size="sm"
              loading={busy === "toggle"}
              disabled={pending}
              onClick={() =>
                run(
                  "toggle",
                  integration.enabled ? "Integration disabled" : "Integration enabled",
                  () => setIntegrationEnabledAction(integration.id, !integration.enabled),
                )
              }
            >
              {integration.enabled ? "Disable" : "Enable"}
            </Button>
            <Button
              variant="secondary"
              size="sm"
              disabled={pending}
              aria-expanded={rotating}
              onClick={() => setRotating(!rotating)}
            >
              {rotating ? "Cancel" : "Replace secret"}
            </Button>
            <Button
              variant="quiet-danger"
              size="sm"
              disabled={pending || integration.referenced_by.length > 0}
              title={
                integration.referenced_by.length
                  ? "Remove it from posture checks before deleting."
                  : undefined
              }
              onClick={() => setConfirmRemove(true)}
            >
              Remove
            </Button>
          </div>
        ) : null}
      </div>
      <dl className="details">
        <div>
          <dt>Last sync</dt>
          <dd>
            {when(integration.last_success_at)} (attempted {when(integration.last_attempt_at)}, next{" "}
            {when(integration.next_sync_at)}, every {Math.round(integration.interval_secs / 60)} min)
          </dd>
        </div>
        <div>
          <dt>Devices</dt>
          <dd>
            {integration.matched_devices} matched · {integration.ambiguous_devices} ambiguous ·{" "}
            {integration.contested_devices} held by an earlier device ·{" "}
            {integration.identity_changes_pending} awaiting hardware approval ·{" "}
            {integration.unmatched_devices} BlakTail devices not found · {integration.unmatched_records} of{" "}
            {integration.provider_devices} provider records unmatched
          </dd>
        </div>
        {integration.last_error ? (
          <div>
            <dt>Last error</dt>
            <dd>
              {integration.last_error} ({integration.consecutive_failures} consecutive failure
              {integration.consecutive_failures === 1 ? "" : "s"})
            </dd>
          </div>
        ) : null}
        {integration.secret_fingerprint ? (
          <div>
            <dt>Secret fingerprint</dt>
            <dd>
              <MonoValue value={integration.secret_fingerprint} />
            </dd>
          </div>
        ) : null}
        <div>
          <dt>Used by</dt>
          <dd>{integration.referenced_by.length ? integration.referenced_by.join(", ") : "No posture checks"}</dd>
        </div>
        <div>
          <dt>Privacy notice acknowledged</dt>
          <dd>
            {when(integration.privacy_acknowledged_at)}
            {integration.privacy_acknowledged_by ? ` by ${integration.privacy_acknowledged_by}` : ""}
          </dd>
        </div>
      </dl>
      {provider ? (
        <details>
          <summary>Data collected and residency</summary>
          <ProviderNotice provider={provider} />
        </details>
      ) : null}
      {rotating && canManage ? (
        <form
          className="device-name-editor"
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            const data = new FormData(event.currentTarget);
            if (String(data.get("secret") ?? "").length < 8) {
              toast.error("Enter the new secret. It's at least 8 characters.");
              return;
            }
            run("rotate", "Secret replaced", () => rotateIntegrationSecretAction(data), () =>
              setRotating(false),
            );
          }}
        >
          <input type="hidden" name="id" value={integration.id} />
          <FormField label={`New ${provider?.secret_label.toLowerCase() ?? "secret"}`} required>
            <input name="secret" type="password" minLength={8} autoComplete="new-password" />
          </FormField>
          <Button type="submit" loading={busy === "rotate"} loadingLabel="Testing…" disabled={pending}>
            Save and test
          </Button>
        </form>
      ) : null}
      <ConfirmDialog
        open={confirmRemove}
        title="Remove integration"
        description={`BlakTail stops polling ${integration.provider} and deletes the stored credential and device records for ${integration.name}. No posture check uses it, so access doesn't change.`}
        confirmText={integration.name}
        confirmLabel="Remove integration"
        pending={busy === "remove"}
        onCancel={() => setConfirmRemove(false)}
        onConfirm={() =>
          run("remove", "Integration removed", () => deleteIntegrationAction(integration.id), () =>
            setConfirmRemove(false),
          )
        }
      />
    </li>
  );
}

export function PostureIntegrations({
  providers,
  integrations,
  residencyNotice,
  canManage,
}: {
  providers: ProviderInfo[];
  integrations: PostureIntegration[];
  residencyNotice: string;
  canManage: boolean;
}) {
  return (
    <div className="stack">
      {integrations.length === 0 ? (
        <EmptyState
          compact
          headingLevel={3}
          title="No device-health providers connected"
          body={
            canManage
              ? "Connect an MDM or EDR below to require a healthy provider record in a posture check."
              : "An owner can connect an MDM or EDR your organisation already runs."
          }
        />
      ) : (
        <ul className="acl-rule-list">
          {integrations.map((integration) => (
            <IntegrationCard
              key={integration.id}
              integration={integration}
              provider={providers.find((provider) => provider.kind === integration.kind)}
              canManage={canManage}
            />
          ))}
        </ul>
      )}
      {canManage ? (
        <div className="stack">
          <h3>Connect a provider</h3>
          <AddIntegration providers={providers} residencyNotice={residencyNotice} />
        </div>
      ) : null}
    </div>
  );
}

/** Shown on a device whose reported identifiers await approval. */
export function ApproveHardwareButton({
  nodeId,
  deviceName,
  canManage,
  reason,
}: {
  nodeId: string;
  deviceName: string;
  canManage: boolean;
  reason: string | null;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [open, setOpen] = useState(false);
  return (
    <div className="stack">
      <Button
        variant="secondary"
        size="sm"
        disabled={!canManage || pending}
        title={canManage ? undefined : (reason ?? undefined)}
        aria-label={`Approve new hardware identifiers for ${deviceName}`}
        onClick={() => setOpen(true)}
      >
        Approve hardware change
      </Button>
      {!canManage && reason ? <span className="muted small">{reason}</span> : null}
      <ConfirmDialog
        open={open}
        tone="primary"
        title="Approve hardware change"
        description={`Approve ${deviceName}'s new serial number or MAC addresses? Only do this after a known hardware change. Another device that already holds an identifier keeps its provider match.`}
        confirmLabel="Approve change"
        pending={pending}
        onCancel={() => setOpen(false)}
        onConfirm={() =>
          startTransition(async () => {
            const result = await approveHardwareAction(nodeId);
            toastResult(result, {
              success: "Hardware change approved",
              successDescription: `${deviceName} can match its provider record again.`,
            });
            setOpen(false);
            if (result.ok) router.refresh();
          })
        }
      />
    </div>
  );
}
