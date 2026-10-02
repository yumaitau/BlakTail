"use client";

import { useState, useTransition } from "react";
import { explainAccessAction, type ExplainForm } from "@/app/acls/actions";
import type { ExplainResult } from "@/lib/coord-policy";
import { ACL_ROLES, ACL_TAGS, personLabel, type AclPerson } from "@/lib/acl";
import { roleLabel } from "@/lib/roles";

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

function verdict(result: ExplainResult): { text: string; badge: string } {
  const enforced =
    result.enforcement.state === "device_enforced" || result.enforcement.state === "peer_map";
  if (result.decision === "allow") {
    return enforced
      ? { text: "Allowed and enforced on the destination", badge: "badge online" }
      : { text: "Allowed by policy, but not enforced on this device", badge: "badge pending" };
  }
  return enforced
    ? { text: "Denied and enforced", badge: "badge revoked" }
    : { text: "Denied by policy, but this device does not enforce it", badge: "badge pending" };
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
      <section className="acl-section" aria-labelledby="explain-heading">
        <h2 id="explain-heading">Explain access</h2>
        <p className="muted">Enrol a device first. Explanations need a destination device.</p>
      </section>
    );
  }

  return (
    <section className="acl-section" aria-labelledby="explain-heading">
      <div>
        <h2 id="explain-heading">Explain access</h2>
        <p className="muted">
          The coordinator re-runs its evaluator and peer-map compiler against the
          published policy for {organisationName}. Nothing is sent over the
          network, and unsaved edits in the editor are not included. Your{" "}
          {roleLabel(role as "owner" | "admin" | "member").toLowerCase()} role
          can explain; it never changes policy.
        </p>
      </div>
      <form
        className="stack"
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
        <fieldset className="acl-selector">
          <legend>Source</legend>
          <div className="acl-options">
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
        </fieldset>
        {form.sourceMode === "device" ? (
          <label>
            Source device
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
          </label>
        ) : (
          <div className="acl-rule-grid">
            <label className="acl-selector">
              <span>Person</span>
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
            </label>
            <label className="acl-selector">
              <span>Role</span>
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
            </label>
            <fieldset className="acl-selector">
              <legend>Tags</legend>
              <div className="acl-options">
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
        <div className="acl-rule-grid">
          <label className="acl-selector">
            <span>Destination device</span>
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
          </label>
          <label className="acl-selector">
            <span>Protocol</span>
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
          </label>
          <label className="acl-selector">
            <span>Port</span>
            <input
              inputMode="numeric"
              value={form.port}
              disabled={sshMode || form.protocol === "icmp"}
              placeholder="443"
              onChange={(event) => update({ port: event.target.value })}
            />
          </label>
          <label className="acl-selector">
            <span>Or SSH login</span>
            <input
              value={form.sshUser}
              placeholder="deploy"
              autoComplete="off"
              onChange={(event) => update({ sshUser: event.target.value })}
            />
          </label>
        </div>
        <div className="actions">
          <button type="submit" disabled={pending} data-testid="explain-access">
            {pending ? "Explaining…" : "Explain access"}
          </button>
        </div>
      </form>
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
      {result ? <ExplainResultView result={result} /> : null}
    </section>
  );
}

function ExplainResultView({ result }: { result: ExplainResult }) {
  const outcome = verdict(result);
  return (
    <div className="stack" aria-live="polite" data-testid="explain-result">
      <div className="row">
        <span className={outcome.badge}>{outcome.text}</span>
      </div>
      <div className="row" aria-label="Result labels">
        <span className="badge">Simulated: no traffic sent</span>
        <span className="badge network">Published policy, revision {result.policy.revision}</span>
        <span
          className={
            result.enforcement.state === "device_enforced" || result.enforcement.state === "peer_map"
              ? "badge online"
              : "badge pending"
          }
        >
          Device: {ENFORCEMENT[result.enforcement.state]}
        </span>
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
                    <span className={entry.passed ? "badge online" : "badge revoked"}>
                      {entry.check}: {entry.passed ? "passes" : "fails"}
                    </span>{" "}
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
