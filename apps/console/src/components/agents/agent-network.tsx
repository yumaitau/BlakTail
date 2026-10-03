"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  createKeyAction,
  createProviderAction,
  deleteProviderAction,
  readContentAction,
  revokeKeyAction,
  rotateProviderCredentialAction,
  setOffshoreAction,
  setProviderEnabledAction,
  updateKeyAction,
} from "@/app/agents/actions";
import type { AgentKey, AgentPolicy, AgentProvider } from "@/lib/coord-agents";

type Result = { ok: true } | { ok: false; error: string };

function useRunner() {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  function run(action: () => Promise<Result>, after?: () => void) {
    setError(null);
    startTransition(async () => {
      const result = await action();
      if (!result.ok) {
        setError(result.error);
        return;
      }
      after?.();
      router.refresh();
    });
  }
  return { pending, error, run, setError };
}

function when(seconds: number | null): string {
  if (!seconds) return "Never";
  return new Date(seconds * 1000).toLocaleString("en-AU", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function ErrorLine({ error }: { error: string | null }) {
  return error ? (
    <p className="error" role="alert">
      {error}
    </p>
  ) : null;
}

export function ResidencyBadge({ provider }: { provider: AgentProvider }) {
  if (provider.blocked_by_policy) {
    return <span className="badge revoked">Offshore — blocked by policy</span>;
  }
  return provider.residency === "onshore" ? (
    <span className="badge online">Onshore (declared)</span>
  ) : (
    <span className="badge warn">Offshore</span>
  );
}

export function OffshorePolicy({
  allowOffshore,
  isOwner,
  readOnlyReason,
}: {
  allowOffshore: boolean;
  isOwner: boolean;
  readOnlyReason: string | null;
}) {
  const { pending, error, run } = useRunner();
  const reason = readOnlyReason ?? (isOwner ? null : "Only an owner can decide whether data may go offshore.");
  return (
    <div className="stack">
      <p>
        Offshore providers are{" "}
        <strong>{allowOffshore ? "allowed" : "forbidden"}</strong> for this organisation.
        {allowOffshore
          ? " Prompts sent to an offshore provider leave Australia and are processed under that provider's terms."
          : " Requests that would reach an offshore provider are refused at the gateway."}
      </p>
      <div className="row">
        <button
          type="button"
          className={allowOffshore ? "secondary" : "quiet-danger"}
          disabled={pending || reason !== null}
          title={reason ?? undefined}
          onClick={() => {
            if (
              allowOffshore ||
              window.confirm(
                "Allow offshore model providers? Prompts, which may hold Indigenous Cultural and Intellectual Property, would leave Australia.",
              )
            ) {
              run(() => setOffshoreAction(!allowOffshore));
            }
          }}
        >
          {allowOffshore ? "Forbid offshore providers" : "Allow offshore providers"}
        </button>
      </div>
      {reason ? <p className="muted">{reason}</p> : null}
      <ErrorLine error={error} />
    </div>
  );
}

export function ProviderManager({
  providers,
  readOnlyReason,
}: {
  providers: AgentProvider[];
  readOnlyReason: string | null;
}) {
  const { pending, error, run } = useRunner();
  const disabled = pending || readOnlyReason !== null;
  const [formKey, setFormKey] = useState(0);
  return (
    <div className="stack">
      <ErrorLine error={error} />
      {providers.length === 0 ? (
        <p className="muted">No model providers yet. Add a self-hosted one first.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Provider</th>
                <th scope="col">Data location</th>
                <th scope="col">Models</th>
                <th scope="col">Credential</th>
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {providers.map((provider) => (
                <tr key={provider.id}>
                  <td>
                    <div className="device-primary">{provider.name}</div>
                    <div className="mono muted">{provider.base_url}</div>
                    {provider.enabled ? null : <span className="badge offline">Disabled</span>}
                  </td>
                  <td>
                    <div className="device-primary">{provider.data_location}</div>
                    <ResidencyBadge provider={provider} />
                  </td>
                  <td className="mono">{provider.models.join(", ")}</td>
                  <td>
                    {provider.has_credential ? "Stored, sealed" : "None"}
                    <form
                      className="inline-form"
                      onSubmit={(event) => {
                        event.preventDefault();
                        const form = new FormData(event.currentTarget);
                        run(() => rotateProviderCredentialAction(provider.id, provider.revision, form));
                      }}
                    >
                      <label>
                        <span className="visually-hidden">New credential for {provider.name}</span>
                        <input
                          name="credential"
                          type="password"
                          autoComplete="off"
                          placeholder="Replace credential"
                          disabled={disabled}
                        />
                      </label>
                      <button type="submit" className="secondary" disabled={disabled} title={readOnlyReason ?? undefined}>
                        Replace
                      </button>
                    </form>
                  </td>
                  <td>
                    <div className="row">
                      <button
                        type="button"
                        className="secondary"
                        disabled={disabled}
                        title={readOnlyReason ?? undefined}
                        onClick={() =>
                          run(() => setProviderEnabledAction(provider.id, provider.revision, !provider.enabled))
                        }
                      >
                        {provider.enabled ? "Disable" : "Enable"}
                      </button>
                      <button
                        type="button"
                        className="quiet-danger"
                        disabled={disabled}
                        title={readOnlyReason ?? undefined}
                        onClick={() => {
                          if (window.confirm(`Delete provider ${provider.name}? Its sealed credential is destroyed.`)) {
                            run(() => deleteProviderAction(provider.id));
                          }
                        }}
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <details>
        <summary>Add a provider</summary>
        <form
          key={formKey}
          className="stack"
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            run(() => createProviderAction(form), () => setFormKey((k) => k + 1));
          }}
        >
          <label>
            Name
            <input name="name" required maxLength={48} pattern="[a-z0-9][a-z0-9-]*" placeholder="local-ollama" disabled={disabled} />
          </label>
          <label>
            OpenAI-compatible base URL
            <input name="baseUrl" required placeholder="http://10.0.0.5:11434/v1" disabled={disabled} />
            <span className="muted">Ollama, vLLM and other OpenAI-compatible servers. Cloud metadata addresses are refused.</span>
          </label>
          <label>
            Data location
            <input name="dataLocation" required maxLength={80} placeholder="Australia (self-hosted, Mparntwe office)" disabled={disabled} />
            <span className="muted">Where prompts are processed. Shown wherever this provider appears.</span>
          </label>
          <fieldset disabled={disabled}>
            <legend>Residency</legend>
            <label className="route-option">
              <input type="radio" name="residency" value="onshore" required /> Onshore — processed in Australia
            </label>
            <label className="route-option">
              <input type="radio" name="residency" value="offshore" /> Offshore — processed outside Australia
            </label>
            <span className="muted">Declared by your administrators; BlakTail cannot verify where a provider processes data.</span>
          </fieldset>
          <label>
            Models served (one per line)
            <textarea name="models" required rows={3} placeholder="llama3.2:1b" disabled={disabled} />
          </label>
          <label>
            Credential (optional)
            <input name="credential" type="password" autoComplete="off" disabled={disabled} />
            <span className="muted">Sealed with the coordinator secret and never shown again.</span>
          </label>
          <button type="submit" disabled={disabled} title={readOnlyReason ?? undefined}>
            {pending ? "Adding…" : "Add provider"}
          </button>
        </form>
      </details>
    </div>
  );
}

function PolicyFields({
  policy,
  providers,
  devices,
  isOwner,
  icipWarning,
  disabled,
}: {
  policy: AgentPolicy | null;
  providers: AgentProvider[];
  devices: { id: string; label: string }[];
  isOwner: boolean;
  icipWarning: string;
  disabled: boolean;
}) {
  const [mode, setMode] = useState(policy?.logging_mode ?? "off");
  const fullLocked = !isOwner && policy?.logging_mode !== "full";
  return (
    <fieldset className="stack" disabled={disabled}>
      <legend>Policy</legend>
      <fieldset>
        <legend>Allowed providers</legend>
        {providers.length === 0 ? <p className="muted">Add a provider first.</p> : null}
        {providers.map((provider) => (
          <label key={provider.id} className="route-option">
            <input
              type="checkbox"
              name="providerIds"
              value={provider.id}
              defaultChecked={policy?.allowed_provider_ids.includes(provider.id) ?? false}
            />
            {provider.name} — {provider.data_location}
            {provider.blocked_by_policy ? " (blocked: offshore)" : ""}
          </label>
        ))}
      </fieldset>
      <label>
        Allowed models (one per line; empty allows every model of the allowed providers)
        <textarea name="allowedModels" rows={2} defaultValue={policy?.allowed_models.join("\n") ?? ""} />
      </label>
      <div className="row">
        <label>
          Requests per day
          <input name="dailyRequestQuota" type="number" min={1} max={1000000} required defaultValue={policy?.daily_request_quota ?? 1000} />
        </label>
        <label>
          Tokens per day
          <input name="dailyTokenQuota" type="number" min={1} max={1000000000} required defaultValue={policy?.daily_token_quota ?? 1000000} />
        </label>
        <label>
          Max request size (KiB)
          <input
            name="maxRequestKib"
            type="number"
            min={1}
            max={4096}
            required
            defaultValue={Math.max(1, Math.round((policy?.max_request_bytes ?? 262144) / 1024))}
          />
        </label>
      </div>
      <label>
        Bound device (optional)
        <select name="boundNodeId" defaultValue={policy?.bound_node_id ?? ""}>
          <option value="">Any device that holds the key</option>
          {devices.map((device) => (
            <option key={device.id} value={device.id}>
              {device.label}
            </option>
          ))}
        </select>
        <span className="muted">A bound key only works from that device&apos;s overlay address.</span>
      </label>
      <label>
        Redact before forwarding (one regular expression per line)
        <textarea name="redactPatterns" rows={2} className="mono" defaultValue={policy?.redact_patterns.join("\n") ?? ""} />
        <span className="muted">Matches in message text are replaced with [REDACTED] before the provider sees them.</span>
      </label>
      <label>
        Prompt logging
        <select name="loggingMode" value={mode} onChange={(event) => setMode(event.target.value as AgentPolicy["logging_mode"])}>
          <option value="off">Off — daily totals only</option>
          <option value="metadata">Metadata only — time, model, token counts</option>
          <option value="full" disabled={fullLocked}>
            Full — stores prompts and responses{fullLocked ? " (owner only)" : ""}
          </option>
        </select>
      </label>
      {mode === "full" ? (
        <div className="danger-zone stack" role="note">
          <strong>Indigenous Cultural and Intellectual Property warning</strong>
          <p>{icipWarning}</p>
          <label>
            Keep stored prompts for (days, at most 30)
            <input name="retentionDays" type="number" min={1} max={30} required defaultValue={policy?.log_retention_days || 7} />
          </label>
          <label className="route-option">
            <input type="checkbox" name="acknowledgeIcip" required={policy?.logging_mode !== "full"} /> I am an owner and the knowledge holders have consented to storing these prompts.
          </label>
        </div>
      ) : null}
      {fullLocked ? <p className="muted">Only an owner can turn on full prompt logging.</p> : null}
    </fieldset>
  );
}

export function KeyManager({
  keys,
  providers,
  devices,
  isOwner,
  icipWarning,
  organisationName,
  roleLabel,
  readOnlyReason,
}: {
  keys: AgentKey[];
  providers: AgentProvider[];
  devices: { id: string; label: string }[];
  isOwner: boolean;
  icipWarning: string;
  organisationName: string;
  roleLabel: string;
  readOnlyReason: string | null;
}) {
  const { pending, error, run } = useRunner();
  const [secret, setSecret] = useState<string | null>(null);
  const [formKey, setFormKey] = useState(0);
  const disabled = pending || readOnlyReason !== null;
  const deviceName = (id: string | null) =>
    id ? (devices.find((device) => device.id === id)?.label ?? "Removed device") : "Any device";
  return (
    <div className="stack">
      <p className="muted">
        Changing keys in <span className="badge network">{organisationName}</span> as {roleLabel}.
      </p>
      {readOnlyReason ? <p className="muted">{readOnlyReason}</p> : null}
      <ErrorLine error={error} />
      {secret ? (
        <div className="panel stack" role="status">
          <label>
            Agent key — shown once, copy it now
            <input className="mono" value={secret} readOnly onFocus={(event) => event.currentTarget.select()} />
          </label>
          <p className="muted">Only a hash is stored. Send it as <span className="mono">Authorization: Bearer</span> to the gateway over the overlay.</p>
          <button type="button" className="secondary" onClick={() => setSecret(null)}>
            I have saved it
          </button>
        </div>
      ) : null}
      {keys.length === 0 ? (
        <p className="muted">No agent keys yet.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Key</th>
                <th scope="col">Today (UTC)</th>
                <th scope="col">Policy</th>
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {keys.map((key) => (
                <tr key={key.id}>
                  <td>
                    <div className="device-primary">{key.name}</div>
                    <div className="mono muted">{key.key_prefix}…</div>
                    {key.revoked_at ? <span className="badge revoked">Revoked</span> : <span className="badge online">Active</span>}
                    <div className="muted">Last used {when(key.last_used_at)}</div>
                  </td>
                  <td>
                    {key.today.requests} / {key.policy.daily_request_quota} requests
                    <div className="muted">
                      {key.today.tokens.toLocaleString("en-AU")} / {key.policy.daily_token_quota.toLocaleString("en-AU")} tokens
                    </div>
                    {key.today.denied ? <div className="muted">{key.today.denied} denied</div> : null}
                  </td>
                  <td>
                    <div>
                      {key.policy.allowed_provider_ids
                        .map((id) => providers.find((p) => p.id === id)?.name ?? "removed")
                        .join(", ") || "No providers"}
                    </div>
                    <div className="muted">
                      {key.policy.allowed_models.length ? key.policy.allowed_models.join(", ") : "All declared models"} ·{" "}
                      {deviceName(key.policy.bound_node_id)}
                    </div>
                    <div>
                      Logging:{" "}
                      {key.policy.logging_mode === "full" ? (
                        <span className="badge warn">Full, {key.policy.log_retention_days} days</span>
                      ) : key.policy.logging_mode === "metadata" ? (
                        "metadata only"
                      ) : (
                        "off"
                      )}
                    </div>
                    {key.revoked_at ? null : (
                      <details>
                        <summary>Edit policy</summary>
                        <form
                          className="stack"
                          onSubmit={(event) => {
                            event.preventDefault();
                            const form = new FormData(event.currentTarget);
                            run(() => updateKeyAction(key.id, key.revision, form));
                          }}
                        >
                          <PolicyFields
                            policy={key.policy}
                            providers={providers}
                            devices={devices}
                            isOwner={isOwner}
                            icipWarning={icipWarning}
                            disabled={disabled}
                          />
                          <button type="submit" disabled={disabled} title={readOnlyReason ?? undefined}>
                            Save policy
                          </button>
                        </form>
                      </details>
                    )}
                  </td>
                  <td>
                    {key.revoked_at ? null : (
                      <button
                        type="button"
                        className="quiet-danger"
                        disabled={disabled}
                        title={readOnlyReason ?? undefined}
                        onClick={() => {
                          if (window.confirm(`Revoke ${key.name}? Agents using it stop working immediately.`)) {
                            run(() => revokeKeyAction(key.id));
                          }
                        }}
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <details>
        <summary>Create an agent key</summary>
        <form
          key={formKey}
          className="stack"
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            setSecret(null);
            run(async () => {
              const result = await createKeyAction(form);
              if (result.ok) {
                setSecret(result.data.secret);
                setFormKey((k) => k + 1);
              }
              return result;
            });
          }}
        >
          <label>
            Name
            <input name="name" required maxLength={48} pattern="[a-z0-9][a-z0-9-]*" placeholder="grants-writer" disabled={disabled} />
          </label>
          <PolicyFields
            policy={null}
            providers={providers}
            devices={devices}
            isOwner={isOwner}
            icipWarning={icipWarning}
            disabled={disabled}
          />
          <button type="submit" disabled={disabled} title={readOnlyReason ?? undefined}>
            {pending ? "Creating…" : "Create key"}
          </button>
        </form>
      </details>
    </div>
  );
}

export function StoredPromptButton({ requestId }: { requestId: string }) {
  const { pending, error, run } = useRunner();
  const [content, setContent] = useState<{ request: string; response: string } | null>(null);
  return (
    <div className="stack">
      <button
        type="button"
        className="secondary"
        disabled={pending}
        onClick={() =>
          run(async () => {
            const result = await readContentAction(requestId);
            if (result.ok) setContent(result.data);
            return result;
          })
        }
      >
        {content ? "Reload stored prompt" : "Read stored prompt (audited)"}
      </button>
      <ErrorLine error={error} />
      {content ? (
        <div className="stack">
          <pre className="dns-pre">{content.request}</pre>
          <pre className="dns-pre">{content.response}</pre>
        </div>
      ) : null}
    </div>
  );
}
