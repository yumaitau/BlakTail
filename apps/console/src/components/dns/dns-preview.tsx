"use client";

import { useState, useTransition } from "react";
import { previewDnsAction } from "@/app/dns/actions";
import type { DeviceTag } from "@/lib/coord";
import type { DnsAnswerKind, DnsPreview } from "@/lib/coord-dns";

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

export function DnsPreviewPanel({
  devices,
}: {
  devices: { id: string; label: string }[];
}) {
  const [name, setName] = useState("");
  const [nodeId, setNodeId] = useState("");
  const [tags, setTags] = useState<DeviceTag[]>([]);
  const [result, setResult] = useState<DnsPreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  return (
    <div className="panel stack" id="preview">
      <div>
        <h2>Split-match preview</h2>
        <p className="muted">
          Ask which answer a device gets for a name under the published
          revision. Longest suffix wins across zones, nameserver groups and
          split routes.
        </p>
      </div>
      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          setError(null);
          startTransition(async () => {
            const response = await previewDnsAction({ name, nodeId, tags });
            if (!response.ok) {
              setResult(null);
              setError(response.error);
              return;
            }
            setResult(response.data);
          });
        }}
      >
        <div className="dns-grid">
          <label>
            Name
            <input
              className="mono"
              required
              value={name}
              placeholder="db.corp.example"
              onChange={(event) => setName(event.target.value)}
            />
          </label>
          <label>
            Device
            <select value={nodeId} onChange={(event) => setNodeId(event.target.value)}>
              <option value="">Choose by tags instead</option>
              {devices.map((device) => (
                <option key={device.id} value={device.id}>
                  {device.label}
                </option>
              ))}
            </select>
          </label>
        </div>
        {nodeId === "" ? (
          <fieldset className="dns-assign">
            <legend>Device tags (none means an untagged device)</legend>
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
          </fieldset>
        ) : null}
        <div>
          <button type="submit" className="secondary" disabled={pending}>
            {pending ? "Checking…" : "Preview"}
          </button>
        </div>
      </form>
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
      {result ? (
        <div className="stack" role="status">
          <p>
            <span className="badge network">{ANSWER_LABELS[result.answer]}</span>{" "}
            {result.detail}
          </p>
          <dl className="details">
            <div>
              <dt>Name</dt>
              <dd className="mono">{result.name}</dd>
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
                <dd className="mono">{result.matched_suffix}</dd>
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
            <ul>
              {result.records.map((record) => (
                <li key={`${record.type}-${record.name}-${record.value}`} className="mono">
                  {record.name} {record.ttl} {record.type} {record.value}
                </li>
              ))}
            </ul>
          ) : null}
          {result.candidates.length > 0 ? (
            <div className="table-wrap">
              <table className="table">
                <caption className="muted">Matching suffixes considered</caption>
                <thead>
                  <tr>
                    <th scope="col">Suffix</th>
                    <th scope="col">Source</th>
                    <th scope="col">Label</th>
                    <th scope="col">Applies to this device</th>
                  </tr>
                </thead>
                <tbody>
                  {result.candidates.map((candidate) => (
                    <tr key={`${candidate.source}-${candidate.label}-${candidate.suffix}`}>
                      <td className="mono">{candidate.suffix}</td>
                      <td>{candidate.source}</td>
                      <td>{candidate.label}</td>
                      <td>{candidate.applies ? "Yes" : "No"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
