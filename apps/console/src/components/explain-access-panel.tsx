"use client";

import { useState, useTransition } from "react";
import { explainAccessAction, type ExplainForm } from "@/app/acls/actions";
import type { ExplainResult } from "@/lib/coord-policy";
import { ACL_ROLES, ACL_TAGS, personLabel, type AclPerson } from "@/lib/acl";
import { roleLabel } from "@/lib/roles";
import { EmptyState } from "./empty-state";
import { Alert } from "./ui/alert";
import { Badge, type BadgeTone } from "./ui/badge";
import { Button } from "./ui/button";
import { FormField } from "./ui/form-field";
import { Section } from "./ui/section";

export type ExplainDevice = { id: string; label: string; os: string | null };

const BASIS: Record<string, string> = {
  rule: "An allow rule matched.",
  deny_rule: "A deny rule matched. Deny always wins over allow.",
  default_same_tag: "No rule matched; the legacy same-tag default allowed it.",
  default_deny: "No rule matched, so the default denies it.",
  ssh_rules: "Decided by the SSH rules.",
  ssh_closed: "SSH rules govern TCP 22 here, and this source has no SSH grant the destination can enforce.",
  no_pairing: "Policy allows it, but the devices are not paired, so no tunnel exists.",
};

const ENFORCEMENT: Record<ExplainResult["enforcement"]["state"], string> = {
  device_enforced: "Enforced by the destination device",
  peer_map: "Enforced by the peer map (no tunnel)",
  not_enforced: "Not enforced on this device",
  unknown: "Enforcement not proven on this device",
};

function verdict(result: ExplainResult): { text: string; tone: BadgeTone } {
  const enforced =
    result.enforcement.state === "device_enforced" || result.enforcement.state === "peer_map";
  if (result.decision === "allow") {
    return enforced
      ? { text: "Allowed and enforced on the destination", tone: "success" }
      : { text: "Allowed by policy, but not enforced on this device", tone: "warning" };
  }
  return enforced
    ? { text: "Denied and enforced", tone: "danger" }
    : { text: "Denied by policy, but this device does not enforce it", tone: "warning" };
}

export function ExplainAccessPanel({
  devices,
  people,
  organisationName,
  role,
}: {
  devices: ExplainDevice[];
  people: AclPerson[];
  organisationName: string;
  role: string;
}) {
  const [form, setForm] = useState<ExplainForm>({
    sourceMode: "device",
    sourceNodeId: devices[0]?.id ?? "",
    sourceUser: people[0]?.userId ?? "",
    sourceRole: "member",
    sourceTags: [],
    destinationNodeId: devices[1]?.id ?? devices[0]?.id ?? "",
    protocol: "tcp",
    port: "",
    sshUser: "",
  });
  const [result, setResult] = useState<ExplainResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const update = (patch: Partial<ExplainForm>) => setForm((current) => ({ ...current, ...patch }));
  const sshMode = form.sshUser.trim() !== "";

  if (devices.length === 0) {
    return (
      <Section id="explain" title="Explain access">
        <EmptyState
          compact
          headingLevel={3}
          title="No devices to explain yet"
          body="Explanations need a destination device. Enrol one with a join key, then come back."
        />
      </Section>
    );
  }

  return (
    <Section
      id="explain"
      title="Explain access"
      description={`Check whether one device can reach another under the published policy for ${organisationName}. Nothing is sent over the network, unsaved edits above are not included, and your ${roleLabel(role as "owner" | "admin" | "member").toLowerCase()} role never changes policy here.`}
    >
      <form
        className="ui-form wide"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          setError(null);
          startTransition(async () => {
            const response = await explainAccessAction(form);
            if (response.ok) {
              setResult(response.data);
            } else {
              setResult(null);
              setError(response.error);
            }
          });
        }}
      >
        <fieldset className="ui-fieldset">
          <legend>Source</legend>
          <div className="ui-choices">
            <label>
              <input
                type="radio"
                name="explain-source-mode"
                checked={form.sourceMode === "device"}
                onChange={() => update({ sourceMode: "device" })}
              />
              A device
            </label>
            <label>
              <input
                type="radio"
                name="explain-source-mode"
                checked={form.sourceMode === "person"}
                onChange={() => update({ sourceMode: "person" })}
              />
              A person, role or tags
            </label>
          </div>
        {form.sourceMode === "device" ? (
          <FormField label="Source device" className="field-lg">
            <select
              value={form.sourceNodeId}
              onChange={(event) => update({ sourceNodeId: event.target.value })}
            >
              {devices.map((device) => (
                <option key={device.id} value={device.id}>
                  {device.label}
                </option>
              ))}
            </select>
          </FormField>
        ) : (
          <div className="ui-form-grid">
            <FormField label="Person">
              <select
                value={form.sourceUser}
                onChange={(event) => update({ sourceUser: event.target.value })}
              >
                <option value="">Nobody in particular</option>
                {people.map((person) => (
                  <option key={person.userId} value={person.userId}>
                    {personLabel(person)}
                  </option>
                ))}
              </select>
            </FormField>
            <FormField label="Role">
              <select
                value={form.sourceRole}
                onChange={(event) => update({ sourceRole: event.target.value })}
              >
                {ACL_ROLES.map((value) => (
                  <option key={value} value={value}>
                    {roleLabel(value)}
                  </option>
                ))}
              </select>
            </FormField>
            <fieldset className="acl-selector">
              <legend>Tags</legend>
              <div className="ui-choices">
                {ACL_TAGS.map((tag) => (
                  <label key={tag}>
                    <input
                      type="checkbox"
                      checked={form.sourceTags.includes(tag)}
                      onChange={() =>
                        update({
                          sourceTags: form.sourceTags.includes(tag)
                            ? form.sourceTags.filter((value) => value !== tag)
                            : [...form.sourceTags, tag],
                        })
                      }
                    />
                    {tag}
                  </label>
                ))}
              </div>
            </fieldset>
          </div>
        )}
        </fieldset>
        <fieldset className="ui-fieldset">
          <legend>Destination</legend>
          <FormField label="Destination device" className="field-lg">
            <select
              value={form.destinationNodeId}
              onChange={(event) => update({ destinationNodeId: event.target.value })}
            >
              {devices.map((device) => (
                <option key={device.id} value={device.id}>
                  {device.label}
                </option>
              ))}
            </select>
          </FormField>
          <div className="ui-form-grid">
          <FormField label="Protocol">
            <select
              value={form.protocol}
              disabled={sshMode}
              onChange={(event) => update({ protocol: event.target.value })}
            >
              <option value="">Any</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
            </select>
          </FormField>
          <FormField label="Port" hint="Leave blank for any port.">
            <input
              className="mono"
              inputMode="numeric"
              value={form.port}
              disabled={sshMode || form.protocol === "icmp"}
              placeholder="443"
              onChange={(event) => update({ port: event.target.value })}
            />
          </FormField>
          <FormField label="Or SSH login" hint="Checks SSH rules instead of a port.">
            <input
              className="mono"
              value={form.sshUser}
              placeholder="deploy"
              autoComplete="off"
              onChange={(event) => update({ sshUser: event.target.value })}
            />
          </FormField>
          </div>
        </fieldset>
        <div className="ui-form-actions">
          <Button
            type="submit"
            loading={pending}
            loadingLabel="Explaining…"
            data-testid="explain-access"
          >
            Explain access
          </Button>
        </div>
      </form>
      {error ? (
        <Alert tone="error" title="Couldn't explain this access">
          {error}
        </Alert>
      ) : null}
      {result ? <ExplainResultView result={result} /> : null}
    </Section>
  );
}

function ExplainResultView({ result }: { result: ExplainResult }) {
  const outcome = verdict(result);
  return (
    <div className="stack" aria-live="polite" data-testid="explain-result">
      <div className="row">
        <Badge tone={outcome.tone}>{outcome.text}</Badge>
      </div>
      <div className="row" aria-label="Result labels">
        <Badge>Simulated: no traffic sent</Badge>
        <Badge tone="brand">Published policy, revision {result.policy.revision}</Badge>
        <Badge
          tone={
            result.enforcement.state === "device_enforced" || result.enforcement.state === "peer_map"
              ? "success"
              : "warning"
          }
        >
          {result.dst_host
            ? `Routing peer: ${result.enforcement.state === "device_enforced" ? "forwarding enforced" : result.enforcement.state === "peer_map" ? "no route distributed" : "forwarding not enforced — upgrade agent"}`
            : `Device: ${ENFORCEMENT[result.enforcement.state]}`}
        </Badge>
      </div>
      <dl className="details">
        <div>
          <dt>Why</dt>
          <dd>{BASIS[result.basis] ?? result.basis}</dd>
        </div>
        <div>
          <dt>Enforcement</dt>
          <dd>{result.enforcement.detail}</dd>
        </div>
        <div>
          <dt>Source</dt>
          <dd>
            {result.source.name ?? result.source.user_id ?? "Selector"} · {result.source.role}
            {result.source.tags.length ? ` · tags ${result.source.tags.join(", ")}` : ""}
            {result.source.groups.length ? ` · groups ${result.source.groups.join(", ")}` : " · no groups"}
          </dd>
        </div>
        <div>
          <dt>Destination</dt>
          <dd>
            {result.destination.name ?? "Device"} · {result.destination.role}
            {result.destination.tags.length ? ` · tags ${result.destination.tags.join(", ")}` : ""}
            {result.destination.groups.length
              ? ` · groups ${result.destination.groups.join(", ")}`
              : " · no groups"}
            {result.destination.os ? ` · ${result.destination.os}` : " · OS not reported"}
          </dd>
        </div>
        {result.pairing ? (
          <div>
            <dt>Pairing</dt>
            <dd>
              Source lists destination:{" "}
              {result.pairing.source_map_includes_destination ? "yes" : "no"}. Destination
              lists source: {result.pairing.destination_map_includes_source ? "yes" : "no"}.
            </dd>
          </div>
        ) : null}
        {result.source.posture?.length ? (
          <div>
            <dt>Source posture</dt>
            <dd>
              <ul className="audit-details">
                {result.source.posture.map((entry) => (
                  <li key={entry.check}>
                    <Badge tone={entry.passed ? "success" : "danger"}>
                      {entry.check}: {entry.passed ? "passes" : "fails"}
                    </Badge>{" "}
                    {entry.reasons.join("; ")}
                  </li>
                ))}
              </ul>
            </dd>
          </div>
        ) : null}
      </dl>
      <div>
        <h3>Rules considered</h3>
        {result.rules.length === 0 ? (
          <p className="muted">No rule selects this source and destination.</p>
        ) : (
          <ol className="audit-details">
            {result.rules.map((rule) => (
              <li key={`${rule.section}-${rule.index}`}>
                <span className="mono">
                  {rule.section}[{rule.index}]
                </span>{" "}
                {rule.action} ·{" "}
                {rule.outcome === "matched"
                  ? "matched"
                  : rule.outcome === "skipped_posture"
                    ? "skipped: posture"
                    : "skipped: re-authentication lapsed"}{" "}
                · {rule.detail}
              </li>
            ))}
          </ol>
        )}
        {result.deny_precedence ? (
          <p className="muted">An allow also matched, but the deny takes precedence.</p>
        ) : null}
      </div>
      <ul className="audit-details">
        {result.reasons.map((reason) => (
          <li key={reason}>{reason}</li>
        ))}
      </ul>
      {result.compiled_ingress ? (
        <details className="acl-advanced">
          <summary>Compiled grant sent to the destination agent</summary>
          <pre className="mono">{JSON.stringify(result.compiled_ingress, null, 2)}</pre>
        </details>
      ) : null}
    </div>
  );
}
