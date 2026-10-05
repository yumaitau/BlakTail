"use client";

import { useState, useTransition } from "react";
import { previewDnsAction } from "@/app/dns/actions";
import type { DeviceTag } from "@/lib/coord";
import type { DnsAnswerKind, DnsPreview } from "@/lib/coord-dns";
import { Alert } from "../ui/alert";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { FormField } from "../ui/form-field";
import { MonoValue } from "../ui/mono-value";
import { Section } from "../ui/section";
import { Table, Td } from "../ui/table";

const TAGS: DeviceTag[] = ["office", "ranger", "store"];

const ANSWER_LABELS: Record<DnsAnswerKind, string> = {
  magic_dns: "MagicDNS (coordinator-authoritative)",
  zone: "Custom zone answers locally",
  zone_nxdomain: "Custom zone: NXDOMAIN",
  legacy_record: "Extra record answers locally",
  forward: "Forwarded to a private resolver",
  not_handled: "Not handled by BlakTail",
  unmanaged: "Organisation DNS is not managed",
};

const SOURCE_LABELS: Record<string, string> = {
  zone: "Custom zone",
  group: "Nameserver group",
  split: "Split route",
};

export function DnsPreviewPanel({
  devices,
}: {
  devices: { id: string; label: string }[];
}) {
  const [name, setName] = useState("");
  const [nodeId, setNodeId] = useState("");
  const [tags, setTags] = useState<DeviceTag[]>([]);
  const [result, setResult] = useState<DnsPreview | null>(null);
  const [error, setError] = useState<{ message: string; ref?: string } | null>(null);
  const [nameError, setNameError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  return (
    <Section
      id="preview"
      title="Split-match preview"
      description="Ask which answer a device gets for a name under the published revision. Longest suffix wins across zones, nameserver groups and split routes."
    >
      <form
        className="ui-form wide"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          setError(null);
          setNameError(null);
          if (!name.trim()) {
            setNameError("Enter a name to preview, such as wiki.kakadu.internal.");
            return;
          }
          startTransition(async () => {
            const response = await previewDnsAction({ name, nodeId, tags });
            if (!response.ok) {
              setResult(null);
              if (response.fieldErrors?.name) setNameError(response.fieldErrors.name);
              else setError({ message: response.error, ref: response.ref });
              return;
            }
            setResult(response.data);
          });
        }}
      >
        <div className="dns-grid">
          <FormField label="Name" required error={nameError}>
            <input
              className="mono"
              value={name}
              placeholder="db.corp.example"
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => setName(event.target.value)}
            />
          </FormField>
          <FormField label="Device">
            <select value={nodeId} onChange={(event) => setNodeId(event.target.value)}>
              <option value="">Choose by tags instead</option>
              {devices.map((device) => (
                <option key={device.id} value={device.id}>
                  {device.label}
                </option>
              ))}
            </select>
          </FormField>
        </div>
        {nodeId === "" ? (
          <fieldset className="ui-fieldset">
            <legend>Device tags</legend>
            <p className="ui-field-hint">None means an untagged device.</p>
            <div className="ui-choices">
              {TAGS.map((tag) => (
                <label key={tag}>
                  <input
                    type="checkbox"
                    checked={tags.includes(tag)}
                    onChange={(event) =>
                      setTags(
                        event.target.checked
                          ? [...tags, tag]
                          : tags.filter((value) => value !== tag),
                      )
                    }
                  />
                  {tag}
                </label>
              ))}
            </div>
          </fieldset>
        ) : null}
        <div className="ui-form-actions">
          <Button type="submit" variant="secondary" loading={pending} loadingLabel="Checking…">
            Preview
          </Button>
        </div>
      </form>
      {error ? (
        <Alert tone="error" title="Couldn't preview this name" reference={error.ref}>
          {error.message}
        </Alert>
      ) : null}
      {result ? (
        <div className="stack" role="status">
          <p>
            <Badge tone="brand">{ANSWER_LABELS[result.answer]}</Badge> {result.detail}
          </p>
          <dl className="details">
            <div>
              <dt>Name</dt>
              <dd>
                <MonoValue value={result.name} />
              </dd>
            </div>
            <div>
              <dt>Device</dt>
              <dd>
                {result.node_name ?? "Hypothetical device"} · tags{" "}
                {result.tags.length > 0 ? result.tags.join(", ") : "none"}
              </dd>
            </div>
            {result.matched_suffix ? (
              <div>
                <dt>Matched suffix</dt>
                <dd>
                  <MonoValue value={result.matched_suffix} />
                </dd>
              </div>
            ) : null}
            {result.nameserver_group ? (
              <div>
                <dt>Nameserver group</dt>
                <dd>{result.nameserver_group}</dd>
              </div>
            ) : null}
            {result.resolvers.length > 0 ? (
              <div>
                <dt>Resolvers (in order)</dt>
                <dd className="mono">{result.resolvers.join(", ")}</dd>
              </div>
            ) : null}
          </dl>
          {result.records.length > 0 ? (
            <ul className="audit-details">
              {result.records.map((record) => (
                <li key={`${record.type}-${record.name}-${record.value}`} className="mono">
                  {record.name} {record.ttl} {record.type} {record.value}
                </li>
              ))}
            </ul>
          ) : null}
          {result.candidates.length > 0 ? (
            <Table label="Matching suffixes considered" mobile="stack">
              <thead>
                <tr>
                  <th scope="col">Suffix</th>
                  <th scope="col">Source</th>
                  <th scope="col">Label</th>
                  <th scope="col">Applies</th>
                </tr>
              </thead>
              <tbody>
                {result.candidates.map((candidate) => (
                  <tr key={`${candidate.source}-${candidate.label}-${candidate.suffix}`}>
                    <Td label="Suffix" className="mono">
                      {candidate.suffix}
                    </Td>
                    <Td label="Source">{SOURCE_LABELS[candidate.source] ?? candidate.source}</Td>
                    <Td label="Label">{candidate.label}</Td>
                    <Td label="Applies">{candidate.applies ? "Yes" : "No"}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          ) : null}
        </div>
      ) : null}
    </Section>
  );
}
