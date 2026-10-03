"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
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

function when(seconds: number | null): string {
  if (!seconds) return "never";
  return new Date(seconds * 1000).toLocaleString("en-AU", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function reportText(report: SyncReport | undefined): string | null {
  if (!report) return null;
  return report.ok
    ? `Connected. ${report.devices} provider device${report.devices === 1 ? "" : "s"} synced.`
    : `Connection failed: ${report.error ?? report.error_code ?? "unknown error"}`;
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
  disabled,
}: {
  providers: ProviderInfo[];
  residencyNotice: string;
  disabled: boolean;
}) {
  const router = useRouter();
  const [kind, setKind] = useState<ProviderKind | "">("");
  const [pending, startTransition] = useTransition();
  const [message, setMessage] = useState<{ error: boolean; text: string } | null>(null);
  const provider = providers.find((candidate) => candidate.kind === kind);
  return (
    <form
      className="stack"
      onSubmit={(event) => {
        event.preventDefault();
        const form = event.currentTarget;
        const data = new FormData(form);
        setMessage(null);
        startTransition(async () => {
          const result: IntegrationActionResult = await createIntegrationAction(data);
          if (!result.ok) {
            setMessage({ error: true, text: result.error });
            return;
          }
          form.reset();
          setKind("");
          setMessage({ error: !result.report?.ok, text: reportText(result.report) ?? "Saved." });
          router.refresh();
        });
      }}
    >
      <label>
        Provider
        <select
          name="kind"
          required
          value={kind}
          onChange={(event) => setKind(event.target.value as ProviderKind | "")}
          disabled={disabled}
        >
          <option value="">Choose a provider</option>
          {providers.map((option) => (
            <option key={option.kind} value={option.kind}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
      {provider ? (
        <>
          <ProviderNotice provider={provider} />
          <p className="muted">{residencyNotice}</p>
          <div className="acl-rule-grid">
            <label className="acl-selector">
              <span>Name</span>
              <input name="name" required maxLength={64} defaultValue={provider.kind} disabled={disabled} />
            </label>
            {provider.fields.map((field) =>
              field.options?.length ? (
                <label key={field.name} className="acl-selector">
                  <span>{field.label}</span>
                  <select name={field.name} required disabled={disabled} aria-describedby={`help-${field.name}`}>
                    {field.options.map((option) => (
                      <option key={option} value={option}>
                        {option}
                      </option>
                    ))}
                  </select>
                  <small id={`help-${field.name}`} className="muted">
                    {field.help}
                  </small>
                </label>
              ) : (
                <label key={field.name} className="acl-selector">
                  <span>{field.label}</span>
                  <input
                    name={field.name}
                    required
                    autoComplete="off"
                    disabled={disabled}
                    aria-describedby={`help-${field.name}`}
                  />
                  <small id={`help-${field.name}`} className="muted">
                    {field.help}
                  </small>
                </label>
              ),
            )}
            <label className="acl-selector">
              <span>{provider.secret_label}</span>
              <input
                name="secret"
                type="password"
                required
                minLength={8}
                autoComplete="new-password"
                disabled={disabled}
                aria-describedby="help-secret"
              />
              <small id="help-secret" className="muted">
                Write-only. Sealed at rest and never shown again.
              </small>
            </label>
            <label className="acl-selector">
              <span>Sync every (minutes)</span>
              <input
                name="interval_minutes"
                type="number"
                min={5}
                max={1440}
                defaultValue={15}
                disabled={disabled}
              />
            </label>
          </div>
          <label>
            <input type="checkbox" name="match_hostname" disabled={disabled} /> Also match on hostname
            when no serial number or MAC address matches (weaker: users choose hostnames)
          </label>
          <label>
            <input type="checkbox" name="privacy_acknowledged" required disabled={disabled} /> I have read
            what this integration collects and where the data comes from, and the organisation has
            approved it.
          </label>
          <div className="actions">
            <button type="submit" disabled={disabled || pending}>
              {pending ? "Connecting…" : "Connect and test"}
            </button>
          </div>
        </>
      ) : null}
      {message ? (
        <p className={message.error ? "error" : "muted"} role={message.error ? "alert" : "status"}>
          {message.text}
        </p>
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
  const [message, setMessage] = useState<{ error: boolean; text: string } | null>(null);
  const [rotating, setRotating] = useState(false);
  const run = (action: () => Promise<IntegrationActionResult>) => {
    setMessage(null);
    startTransition(async () => {
      const result = await action();
      if (!result.ok) {
        setMessage({ error: true, text: result.error });
        return;
      }
      const text = reportText(result.report);
      if (text) setMessage({ error: !result.report?.ok, text });
      router.refresh();
    });
  };
  const status = !integration.enabled
    ? { label: "Disabled", className: "badge pending" }
    : integration.outage_since
      ? { label: `Outage since ${when(integration.outage_since)}`, className: "badge revoked" }
      : integration.last_success_at
        ? { label: "Healthy", className: "badge online" }
        : { label: "Not yet synced", className: "badge pending" };
  return (
    <li className="acl-rule">
      <div className="acl-rule-head">
        <h3>
          {integration.name} <span className="badge">{integration.provider}</span>{" "}
          <span className={status.className}>{status.label}</span>
        </h3>
        {canManage ? (
          <div className="row">
            <button type="button" className="secondary" disabled={pending} onClick={() => run(() => syncIntegrationAction(integration.id))}>
              {pending ? "Working…" : "Test connection"}
            </button>
            <button
              type="button"
              className="secondary"
              disabled={pending}
              onClick={() => run(() => setIntegrationEnabledAction(integration.id, !integration.enabled))}
            >
              {integration.enabled ? "Disable" : "Enable"}
            </button>
            <button type="button" className="secondary" disabled={pending} onClick={() => setRotating(!rotating)}>
              {rotating ? "Cancel" : "Replace secret"}
            </button>
            <button
              type="button"
              className="secondary"
              disabled={pending || integration.referenced_by.length > 0}
              title={
                integration.referenced_by.length
                  ? "Remove it from posture checks before deleting."
                  : undefined
              }
              onClick={() => run(() => deleteIntegrationAction(integration.id))}
            >
              Remove
            </button>
          </div>
        ) : null}
      </div>
      <dl className="audit-details">
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
        <div>
          <dt>Secret</dt>
          <dd className="mono">{integration.secret_fingerprint}</dd>
        </div>
        <div>
          <dt>Used by</dt>
          <dd>{integration.referenced_by.length ? integration.referenced_by.join(", ") : "No posture checks"}</dd>
        </div>
        <div>
          <dt>Privacy notice acknowledged</dt>
          <dd>
            {when(integration.privacy_acknowledged_at)} by {integration.privacy_acknowledged_by}
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
          className="row"
          onSubmit={(event) => {
            event.preventDefault();
            const data = new FormData(event.currentTarget);
            run(() => rotateIntegrationSecretAction(data));
            setRotating(false);
          }}
        >
          <input type="hidden" name="id" value={integration.id} />
          <label>
            New {provider?.secret_label.toLowerCase() ?? "secret"}
            <input name="secret" type="password" required minLength={8} autoComplete="new-password" />
          </label>
          <button type="submit" disabled={pending}>
            Save and test
          </button>
        </form>
      ) : null}
      {message ? (
        <p className={message.error ? "error" : "muted"} role={message.error ? "alert" : "status"}>
          {message.text}
        </p>
      ) : null}
    </li>
  );
}

export function PostureIntegrations({
  providers,
  integrations,
  residencyNotice,
  canManage,
  reason,
}: {
  providers: ProviderInfo[];
  integrations: PostureIntegration[];
  residencyNotice: string;
  canManage: boolean;
  reason: string | null;
}) {
  return (
    <div className="stack">
      {integrations.length === 0 ? (
        <p className="muted">No device-health providers connected.</p>
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
      <div>
        <h3>Connect a provider</h3>
        {reason ? <p className="muted">{reason}</p> : null}
        <AddIntegration providers={providers} residencyNotice={residencyNotice} disabled={!canManage} />
      </div>
    </div>
  );
}
