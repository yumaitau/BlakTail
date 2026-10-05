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
  setGatewayDesignationAction,
  setOffshoreAction,
  setProviderEnabledAction,
  updateKeyAction,
} from "@/app/agents/actions";
import type { AgentGateway, AgentKey, AgentPolicy, AgentProvider } from "@/lib/coord-agents";
import { formatDateTime } from "@/lib/format-time";
import { Alert } from "../ui/alert";
import { StatusPill } from "../ui/badge";
import { Button } from "../ui/button";
import { ConfirmDialog } from "../ui/confirm-dialog";
import { EmptyState } from "../empty-state";
import { FormField } from "../ui/form-field";
import { SecretPanel } from "../ui/secret-panel";
import { EmptyRow, Table, Td } from "../ui/table";
import { toast, toastResult } from "../ui/toast";

type Result = { ok: true } | { ok: false; error: string; ref?: string };

/** Runs a server action with a loading key, a toast for the outcome, and a refresh. */
function useRunner() {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState<string | null>(null);
  function run(key: string, action: () => Promise<Result>, success: string, after?: () => void) {
    setBusy(key);
    startTransition(async () => {
      const result = await action();
      setBusy(null);
      toastResult(result, { success });
      if (!result.ok) return;
      after?.();
      router.refresh();
    });
  }
  return { pending, busy, run };
}

function when(seconds: number | null): string {
  return formatDateTime(seconds, "Never");
}

export function ResidencyBadge({ provider }: { provider: AgentProvider }) {
  if (provider.blocked_by_policy) {
    return <StatusPill tone="danger">Offshore, blocked by policy</StatusPill>;
  }
  return provider.residency === "onshore" ? (
    <StatusPill tone="success">Onshore (declared)</StatusPill>
  ) : (
    <StatusPill tone="warning">Offshore</StatusPill>
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
  const { pending, busy, run } = useRunner();
  const [confirm, setConfirm] = useState(false);
  const reason = readOnlyReason ?? (isOwner ? null : "Only an owner can decide whether data may go offshore.");
  return (
    <>
      <p className="settings-inline-text">
          {allowOffshore
            ? "Prompts sent to an offshore provider leave Australia and are processed under that provider's terms."
            : "Requests that would reach an offshore provider are refused at the gateway."}
      </p>
      <div className="actions">
        <Button
          variant={allowOffshore ? "secondary" : "quiet-danger"}
          loading={busy === "offshore"}
          disabled={pending || reason !== null}
          title={reason ?? undefined}
          onClick={() => {
            if (allowOffshore) run("offshore", () => setOffshoreAction(false), "Offshore providers forbidden");
            else setConfirm(true);
          }}
        >
          {allowOffshore ? "Forbid offshore providers" : "Allow offshore providers"}
        </Button>
      </div>
      {reason && !readOnlyReason ? <p className="muted">{reason}</p> : null}
      <ConfirmDialog
        open={confirm}
        title="Allow offshore model providers?"
        description="Prompts, which may hold Indigenous Cultural and Intellectual Property, would leave Australia and be processed under the provider's terms. Each key still needs that provider allowed in its policy."
        confirmText="allow offshore"
        confirmLabel="Allow offshore"
        pending={pending}
        onCancel={() => setConfirm(false)}
        onConfirm={() =>
          run("offshore", () => setOffshoreAction(true), "Offshore providers allowed", () => setConfirm(false))
        }
      />
    </>
  );
}

export function GatewayDesignations({
  gateways,
  readOnlyReason,
}: {
  gateways: AgentGateway[];
  organisationName: string;
  roleLabel: string;
  readOnlyReason: string | null;
}) {
  const { pending, busy, run } = useRunner();
  const [designating, setDesignating] = useState<AgentGateway | null>(null);
  const disabled = pending || readOnlyReason !== null;
  if (gateways.length === 0) {
    return (
      <EmptyState
        compact
        headingLevel={3}
        title="No device can be a gateway yet"
        body={
          <>
            Run <code>blaktaild up --agent-gateway</code> on a device, start{" "}
            <code>blaktail-agentgw</code> there, then designate it here.
          </>
        }
      />
    );
  }
  return (
    <>
      <Table label="Gateway devices" mobile="stack">
        <thead>
          <tr>
            <th scope="col">Device</th>
            <th scope="col">Last seen</th>
            <th scope="col">Status</th>
            <th scope="col">
              <span className="visually-hidden">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {gateways.map((gateway) => (
            <tr key={gateway.id}>
              <Td label="Device">{gateway.name}</Td>
              <Td label="Last seen">{when(gateway.last_seen_at)}</Td>
              <Td label="Status">
                {gateway.designated && gateway.capable ? (
                  <StatusPill tone="success">Designated gateway</StatusPill>
                ) : gateway.designated ? (
                  <StatusPill tone="warning">Designated, not reporting the capability</StatusPill>
                ) : (
                  <StatusPill tone="muted">Not designated</StatusPill>
                )}
              </Td>
              <Td>
                <div className="cell-actions">
                  <Button
                    size="sm"
                    variant={gateway.designated ? "quiet-danger" : "secondary"}
                    loading={busy === gateway.id}
                    disabled={disabled}
                    title={readOnlyReason ?? undefined}
                    aria-label={`${gateway.designated ? "Release" : "Designate"} ${gateway.name} as an AI gateway`}
                    onClick={() => {
                      if (gateway.designated) {
                        run(
                          gateway.id,
                          () => setGatewayDesignationAction(gateway.id, false),
                          `${gateway.name} released`,
                        );
                      } else {
                        setDesignating(gateway);
                      }
                    }}
                  >
                    {gateway.designated ? "Release" : "Designate"}
                  </Button>
                </div>
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
      <ConfirmDialog
        open={designating !== null}
        title="Designate this gateway?"
        description={
          designating
            ? `${designating.name} will receive provider credentials for every request it forwards. Only designate a device you trust with them.`
            : null
        }
        confirmLabel="Designate"
        tone="primary"
        pending={pending}
        onCancel={() => setDesignating(null)}
        onConfirm={() => {
          if (!designating) return;
          const gateway = designating;
          run(
            gateway.id,
            () => setGatewayDesignationAction(gateway.id, true),
            `${gateway.name} is now a gateway`,
            () => setDesignating(null),
          );
        }}
      />
    </>
  );
}

export function ProviderManager({
  providers,
  readOnlyReason,
}: {
  providers: AgentProvider[];
  readOnlyReason: string | null;
}) {
  const { pending, busy, run } = useRunner();
  const disabled = pending || readOnlyReason !== null;
  const [formKey, setFormKey] = useState(0);
  const [deleting, setDeleting] = useState<AgentProvider | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  return (
    <>
      <Table label="Model providers" mobile="stack">
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
          {providers.length === 0 ? (
            <EmptyRow colSpan={5}>No model providers yet. Add a self-hosted one below.</EmptyRow>
          ) : (
            providers.map((provider) => (
              <tr key={provider.id}>
                <Td label="Provider">
                  {provider.name}
                  <span className="cell-sub mono cell-break">{provider.base_url}</span>
                  {provider.enabled ? null : <StatusPill tone="muted">Disabled</StatusPill>}
                </Td>
                <Td label="Data location">
                  {provider.data_location}
                  <span className="cell-sub">
                    <ResidencyBadge provider={provider} />
                  </span>
                </Td>
                <Td label="Models" className="mono">
                  {provider.models.join(", ")}
                </Td>
                <Td label="Credential">
                  <span>{provider.has_credential ? "Stored, sealed" : "None"}</span>
                  <form
                    className="form-row credential-form"
                    onSubmit={(event) => {
                      event.preventDefault();
                      const formEl = event.currentTarget;
                      const form = new FormData(formEl);
                      if (!String(form.get("credential") ?? "").trim()) {
                        setErrors({ [provider.id]: "Enter the new credential." });
                        return;
                      }
                      setErrors({});
                      run(
                        `cred-${provider.id}`,
                        () => rotateProviderCredentialAction(provider.id, provider.revision, form),
                        "Credential replaced",
                        () => formEl.reset(),
                      );
                    }}
                  >
                    <FormField label={<span className="visually-hidden">New credential for {provider.name}</span>} error={errors[provider.id]}>
                      <input
                        name="credential"
                        type="password"
                        autoComplete="off"
                        placeholder="Replace credential"
                        disabled={disabled}
                      />
                    </FormField>
                    <Button
                      type="submit"
                      size="sm"
                      variant="secondary"
                      loading={busy === `cred-${provider.id}`}
                      disabled={disabled}
                      title={readOnlyReason ?? undefined}
                    >
                      Replace
                    </Button>
                  </form>
                </Td>
                <Td>
                  <div className="cell-actions">
                    <Button
                      size="sm"
                      variant="secondary"
                      loading={busy === provider.id}
                      disabled={disabled}
                      title={readOnlyReason ?? undefined}
                      onClick={() =>
                        run(
                          provider.id,
                          () => setProviderEnabledAction(provider.id, provider.revision, !provider.enabled),
                          provider.enabled ? `${provider.name} disabled` : `${provider.name} enabled`,
                        )
                      }
                    >
                      {provider.enabled ? "Disable" : "Enable"}
                    </Button>
                    <Button
                      size="sm"
                      variant="quiet-danger"
                      disabled={disabled}
                      title={readOnlyReason ?? undefined}
                      onClick={() => setDeleting(provider)}
                    >
                      Delete
                    </Button>
                  </div>
                </Td>
              </tr>
            ))
          )}
        </tbody>
      </Table>
      <details className="form-disclosure" open={providers.length === 0 && readOnlyReason === null}>
        <summary>Add a provider</summary>
        <form
          key={formKey}
          className="ui-form"
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            run("create-provider", () => createProviderAction(form), "Provider added", () => setFormKey((k) => k + 1));
          }}
        >
          <div className="form-grid">
            <FormField label="Name" hint="Lower case letters, numbers and dashes." required>
              <input name="name" maxLength={48} pattern="[a-z0-9][a-z0-9-]*" placeholder="local-ollama" disabled={disabled} />
            </FormField>
            <FormField
              label="OpenAI-compatible base URL"
              hint="Ollama, vLLM and similar servers. Cloud metadata addresses are refused."
              required
            >
              <input name="baseUrl" placeholder="http://10.0.0.5:11434/v1" disabled={disabled} />
            </FormField>
          </div>
          <FormField label="Data location" hint="Where prompts are processed. Shown wherever this provider appears." required>
            <input name="dataLocation" maxLength={80} placeholder="Australia (self-hosted, Mparntwe office)" disabled={disabled} />
          </FormField>
          <fieldset className="form-fieldset" disabled={disabled}>
            <legend>Residency</legend>
            <label className="check-option">
              <input type="radio" name="residency" value="onshore" required />
              <span>Onshore, processed in Australia</span>
            </label>
            <label className="check-option">
              <input type="radio" name="residency" value="offshore" />
              <span>Offshore, processed outside Australia</span>
            </label>
            <p className="muted">Declared by your administrators; BlakTail can&apos;t verify where a provider processes data.</p>
          </fieldset>
          <FormField label="Models served" hint="One per line." required>
            <textarea name="models" rows={3} placeholder="llama3.2:1b" disabled={disabled} />
          </FormField>
          <FormField label="Credential" hint="Optional. Sealed with the coordinator secret and never shown again.">
            <input name="credential" type="password" autoComplete="off" disabled={disabled} />
          </FormField>
          <div className="actions">
            <Button type="submit" loading={busy === "create-provider"} loadingLabel="Adding…" disabled={disabled} title={readOnlyReason ?? undefined}>
              Add provider
            </Button>
          </div>
        </form>
      </details>
      <ConfirmDialog
        open={deleting !== null}
        title="Delete this provider?"
        description={
          deleting
            ? `${deleting.name} is removed and its sealed credential destroyed. Keys that allowed it can no longer use it.`
            : null
        }
        confirmText={deleting?.name}
        confirmLabel="Delete provider"
        pending={pending}
        onCancel={() => setDeleting(null)}
        onConfirm={() => {
          if (!deleting) return;
          const provider = deleting;
          run(provider.id, () => deleteProviderAction(provider.id), `${provider.name} deleted`, () => setDeleting(null));
        }}
      />
    </>
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
    <fieldset className="ui-form policy-fields" disabled={disabled}>
      <fieldset className="check-grid">
        <legend>Allowed providers</legend>
        {providers.length === 0 ? <p className="muted">Add a provider first.</p> : null}
        {providers.map((provider) => (
          <label key={provider.id} className="check-option">
            <input
              type="checkbox"
              name="providerIds"
              value={provider.id}
              defaultChecked={policy?.allowed_provider_ids.includes(provider.id) ?? false}
            />
            <span>
              {provider.name}
              <span className="muted">
                {provider.data_location}
                {provider.blocked_by_policy ? " (blocked: offshore)" : ""}
              </span>
            </span>
          </label>
        ))}
      </fieldset>
      <FormField label="Allowed models" hint="One per line. Leave empty to allow every model of the allowed providers.">
        <textarea name="allowedModels" rows={2} defaultValue={policy?.allowed_models.join("\n") ?? ""} />
      </FormField>
      <div className="form-grid">
        <FormField label="Requests per day" required>
          <input name="dailyRequestQuota" type="number" min={1} max={1000000} defaultValue={policy?.daily_request_quota ?? 1000} />
        </FormField>
        <FormField label="Tokens per day" required>
          <input name="dailyTokenQuota" type="number" min={1} max={1000000000} defaultValue={policy?.daily_token_quota ?? 1000000} />
        </FormField>
        <FormField label="Largest request (KiB)" required>
          <input
            name="maxRequestKib"
            type="number"
            min={1}
            max={4096}
            defaultValue={Math.max(1, Math.round((policy?.max_request_bytes ?? 262144) / 1024))}
          />
        </FormField>
      </div>
      <FormField label="Bound device" hint="Optional. A bound key only works from that device's overlay address.">
        <select name="boundNodeId" defaultValue={policy?.bound_node_id ?? ""}>
          <option value="">Any device that holds the key</option>
          {devices.map((device) => (
            <option key={device.id} value={device.id}>
              {device.label}
            </option>
          ))}
        </select>
      </FormField>
      <FormField
        label="Redact before forwarding"
        hint="One regular expression per line. Matches in message text become [REDACTED] before the provider sees them."
      >
        <textarea name="redactPatterns" rows={2} className="mono" defaultValue={policy?.redact_patterns.join("\n") ?? ""} />
      </FormField>
      <FormField
        label="Prompt logging"
        hint={fullLocked ? "Only an owner can turn on full prompt logging." : undefined}
      >
        <select name="loggingMode" value={mode} onChange={(event) => setMode(event.target.value as AgentPolicy["logging_mode"])}>
          <option value="off">Off: daily totals only</option>
          <option value="metadata">Metadata only: time, model, token counts</option>
          <option value="full" disabled={fullLocked}>
            Full: stores prompts and responses{fullLocked ? " (owner only)" : ""}
          </option>
        </select>
      </FormField>
      {mode === "full" ? (
        <Alert tone="warning" title="Indigenous Cultural and Intellectual Property">
          <div className="ui-form">
            <p>{icipWarning}</p>
            <FormField label="Keep stored prompts for (days, at most 30)" required className="field-narrow">
              <input name="retentionDays" type="number" min={1} max={30} defaultValue={policy?.log_retention_days || 7} />
            </FormField>
            <label className="check-option">
              <input type="checkbox" name="acknowledgeIcip" required={policy?.logging_mode !== "full"} />
              <span>I&apos;m an owner and the knowledge holders have agreed to storing these prompts.</span>
            </label>
          </div>
        </Alert>
      ) : null}
    </fieldset>
  );
}

export function KeyManager({
  keys,
  providers,
  devices,
  isOwner,
  icipWarning,
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
  const { pending, busy, run } = useRunner();
  const [secret, setSecret] = useState<{ name: string; value: string } | null>(null);
  const [formKey, setFormKey] = useState(0);
  const [revoking, setRevoking] = useState<AgentKey | null>(null);
  const disabled = pending || readOnlyReason !== null;
  const deviceName = (id: string | null) =>
    id ? (devices.find((device) => device.id === id)?.label ?? "Removed device") : "Any device";
  return (
    <>
      {secret ? (
        <SecretPanel
          title={`Copy the key for ${secret.name} now`}
          label="Agent key"
          secret={secret.value}
          description="Only a hash is stored, so this is the only time it's shown. The agent sends it as Authorization: Bearer to the gateway over the overlay."
          onDone={() => setSecret(null)}
        />
      ) : null}
      <Table label="Agent keys" mobile="stack">
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
          {keys.length === 0 ? (
            <EmptyRow colSpan={4}>No agent keys yet. Create one below for each agent.</EmptyRow>
          ) : (
            keys.map((key) => (
              <tr key={key.id}>
                <Td label="Key">
                  <span>{key.name}</span>{" "}
                  <StatusPill tone={key.revoked_at ? "muted" : "success"}>{key.revoked_at ? "Revoked" : "Active"}</StatusPill>
                  <span className="cell-sub mono">{key.key_prefix}…</span>
                  <span className="cell-sub">Last used {when(key.last_used_at)}</span>
                </Td>
                <Td label="Today">
                  {key.today.requests} of {key.policy.daily_request_quota} requests
                  <span className="cell-sub">
                    {key.today.tokens.toLocaleString("en-AU")} of {key.policy.daily_token_quota.toLocaleString("en-AU")} tokens
                  </span>
                  {key.today.denied ? <span className="cell-sub">{key.today.denied} refused</span> : null}
                </Td>
                <Td label="Policy">
                  <span>
                    {key.policy.allowed_provider_ids
                      .map((id) => providers.find((p) => p.id === id)?.name ?? "removed")
                      .join(", ") || "No providers"}
                  </span>
                  <span className="cell-sub">
                    {key.policy.allowed_models.length ? key.policy.allowed_models.join(", ") : "All declared models"} ·{" "}
                    {deviceName(key.policy.bound_node_id)}
                  </span>
                  <span className="cell-sub">
                    Logging:{" "}
                    {key.policy.logging_mode === "full"
                      ? `full, kept ${key.policy.log_retention_days} days`
                      : key.policy.logging_mode === "metadata"
                        ? "metadata only"
                        : "off"}
                  </span>
                  {key.revoked_at ? null : (
                    <details className="policy-edit">
                      <summary>Edit policy</summary>
                      <form
                        className="ui-form"
                        onSubmit={(event) => {
                          event.preventDefault();
                          const form = new FormData(event.currentTarget);
                          run(`policy-${key.id}`, () => updateKeyAction(key.id, key.revision, form), "Policy saved");
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
                        <div className="actions">
                          <Button
                            type="submit"
                            loading={busy === `policy-${key.id}`}
                            loadingLabel="Saving…"
                            disabled={disabled}
                            title={readOnlyReason ?? undefined}
                          >
                            Save policy
                          </Button>
                        </div>
                      </form>
                    </details>
                  )}
                </Td>
                <Td>
                  {key.revoked_at ? null : (
                    <div className="cell-actions">
                      <Button
                        size="sm"
                        variant="quiet-danger"
                        disabled={disabled}
                        title={readOnlyReason ?? undefined}
                        onClick={() => setRevoking(key)}
                      >
                        Revoke
                      </Button>
                    </div>
                  )}
                </Td>
              </tr>
            ))
          )}
        </tbody>
      </Table>
      <details className="form-disclosure" open={keys.length === 0 && readOnlyReason === null}>
        <summary>Create an agent key</summary>
        <form
          key={formKey}
          className="ui-form"
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            const name = String(form.get("name") ?? "");
            setSecret(null);
            run(
              "create-key",
              async () => {
                const result = await createKeyAction(form);
                if (result.ok) {
                  setSecret({ name, value: result.data.secret });
                  setFormKey((k) => k + 1);
                }
                return result;
              },
              "Agent key created",
            );
          }}
        >
          <FormField label="Name" hint="Lower case letters, numbers and dashes." required className="field-narrow">
            <input name="name" maxLength={48} pattern="[a-z0-9][a-z0-9-]*" placeholder="grants-writer" disabled={disabled} />
          </FormField>
          <PolicyFields
            policy={null}
            providers={providers}
            devices={devices}
            isOwner={isOwner}
            icipWarning={icipWarning}
            disabled={disabled}
          />
          <div className="actions">
            <Button type="submit" loading={busy === "create-key"} loadingLabel="Creating…" disabled={disabled} title={readOnlyReason ?? undefined}>
              Create key
            </Button>
          </div>
        </form>
      </details>
      <ConfirmDialog
        open={revoking !== null}
        title="Revoke this agent key?"
        description={revoking ? `Agents using ${revoking.name} stop working straight away. This can't be undone.` : null}
        confirmText={revoking?.name}
        confirmLabel="Revoke key"
        pending={pending}
        onCancel={() => setRevoking(null)}
        onConfirm={() => {
          if (!revoking) return;
          const key = revoking;
          run(key.id, () => revokeKeyAction(key.id), `${key.name} revoked`, () => setRevoking(null));
        }}
      />
    </>
  );
}

export function StoredPromptButton({ requestId }: { requestId: string }) {
  const [pending, startTransition] = useTransition();
  const [content, setContent] = useState<{ request: string; response: string } | null>(null);
  return (
    <div className="stack tight">
      <Button
        size="sm"
        variant="secondary"
        loading={pending}
        loadingLabel="Opening…"
        onClick={() =>
          startTransition(async () => {
            const result = await readContentAction(requestId);
            if (!result.ok) {
              toastResult(result);
              return;
            }
            setContent(result.data);
            toast.info("Stored prompt opened", { description: "Reading it was recorded in the audit log." });
          })
        }
      >
        {content ? "Reload stored prompt" : "Read stored prompt (audited)"}
      </Button>
      {content ? (
        <div className="stack tight">
          <pre className="dns-pre">{content.request}</pre>
          <pre className="dns-pre">{content.response}</pre>
        </div>
      ) : null}
    </div>
  );
}
