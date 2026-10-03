"use client";

import { useMemo, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { publishDnsAction, validateDnsAction } from "@/app/dns/actions";
import type {
  DeviceTag,
  DnsZone,
  NameserverGroup,
  OrgDnsSettings,
  ZoneRecord,
  ZoneRecordType,
} from "@/lib/coord";
import { lineDiff } from "@/lib/text-diff";
import { DnsDiff } from "./dns-diff";

const TAGS: DeviceTag[] = ["office", "ranger", "store"];
const RECORD_TYPES: ZoneRecordType[] = ["A", "AAAA", "CNAME", "TXT"];
const DEFAULT_TTL = 300;

export function normaliseDns(dns: Partial<OrgDnsSettings>): OrgDnsSettings {
  return {
    managed: dns.managed !== false,
    global_resolvers: dns.global_resolvers ?? [],
    split: dns.split ?? [],
    search_domains: dns.search_domains ?? [],
    records: dns.records ?? [],
    nameserver_groups: (dns.nameserver_groups ?? []).map((group) => ({
      name: group.name ?? "",
      resolvers: group.resolvers ?? [],
      match_domains: group.match_domains ?? [],
      enabled: group.enabled !== false,
      all_devices: group.all_devices === true,
      tags: group.tags ?? [],
    })),
    zones: (dns.zones ?? []).map((zone) => ({
      name: zone.name ?? "",
      enabled: zone.enabled !== false,
      records: (zone.records ?? []).map((record) => ({
        ...record,
        ttl: record.ttl ?? DEFAULT_TTL,
      })),
    })),
  };
}

// Mirrors the coordinator: empty new arrays are omitted so a legacy-only
// document stays byte-compatible with older coordinators and agents.
export function serialiseDns(dns: OrgDnsSettings): string {
  const out: Partial<OrgDnsSettings> = {
    managed: dns.managed,
    global_resolvers: dns.global_resolvers,
    split: dns.split,
    search_domains: dns.search_domains,
    records: dns.records,
  };
  if (dns.nameserver_groups && dns.nameserver_groups.length > 0) {
    out.nameserver_groups = dns.nameserver_groups;
  }
  if (dns.zones && dns.zones.length > 0) {
    out.zones = dns.zones;
  }
  return JSON.stringify(out, null, 2);
}

function lines(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function ListField({
  label,
  hint,
  values,
  disabled,
  onChange,
}: {
  label: string;
  hint: string;
  values: string[];
  disabled: boolean;
  onChange: (values: string[]) => void;
}) {
  const [text, setText] = useState(values.join("\n"));
  return (
    <label>
      {label}
      <textarea
        className="mono"
        rows={Math.max(2, Math.min(6, values.length + 1))}
        value={text}
        disabled={disabled}
        onChange={(event) => {
          setText(event.target.value);
          onChange(lines(event.target.value));
        }}
      />
      <span className="muted dns-hint">{hint}</span>
    </label>
  );
}

function GroupEditor({
  group,
  index,
  disabled,
  onChange,
  onRemove,
  onMove,
  count,
}: {
  group: NameserverGroup;
  index: number;
  disabled: boolean;
  onChange: (group: NameserverGroup) => void;
  onRemove: () => void;
  onMove: (delta: number) => void;
  count: number;
}) {
  return (
    <fieldset className="dns-card stack">
      <legend>Group {index + 1}</legend>
      <div className="dns-grid">
        <label>
          Name
          <input
            value={group.name}
            maxLength={64}
            disabled={disabled}
            onChange={(event) => onChange({ ...group, name: event.target.value })}
          />
        </label>
        <label>
          <input
            type="checkbox"
            checked={group.enabled}
            disabled={disabled}
            onChange={(event) =>
              onChange({ ...group, enabled: event.target.checked })
            }
          />
          Enabled
        </label>
      </div>
      <div className="dns-grid">
        <ListField
          label="Resolvers"
          hint="One IP address per line, tried in this order (up to 4)."
          values={group.resolvers}
          disabled={disabled}
          onChange={(resolvers) => onChange({ ...group, resolvers })}
        />
        <ListField
          label="Match domains"
          hint="Names under these suffixes go to this group. Required: groups never replace a device's default resolver."
          values={group.match_domains}
          disabled={disabled}
          onChange={(match_domains) => onChange({ ...group, match_domains })}
        />
      </div>
      <fieldset className="dns-assign">
        <legend>Applies to</legend>
        <label>
          <input
            type="radio"
            name={`group-${index}-assign`}
            checked={group.all_devices}
            disabled={disabled}
            onChange={() => onChange({ ...group, all_devices: true, tags: [] })}
          />
          All devices
        </label>
        <label>
          <input
            type="radio"
            name={`group-${index}-assign`}
            checked={!group.all_devices}
            disabled={disabled}
            onChange={() => onChange({ ...group, all_devices: false })}
          />
          Devices with tags
        </label>
        {!group.all_devices
          ? TAGS.map((tag) => (
              <label key={tag}>
                <input
                  type="checkbox"
                  checked={group.tags.includes(tag)}
                  disabled={disabled}
                  onChange={(event) =>
                    onChange({
                      ...group,
                      tags: event.target.checked
                        ? [...group.tags, tag]
                        : group.tags.filter((value) => value !== tag),
                    })
                  }
                />
                {tag}
              </label>
            ))
          : null}
      </fieldset>
      <div className="row">
        <button
          type="button"
          className="secondary"
          disabled={disabled || index === 0}
          onClick={() => onMove(-1)}
        >
          Move up
        </button>
        <button
          type="button"
          className="secondary"
          disabled={disabled || index === count - 1}
          onClick={() => onMove(1)}
        >
          Move down
        </button>
        <button
          type="button"
          className="quiet-danger"
          disabled={disabled}
          onClick={onRemove}
        >
          Remove group
        </button>
      </div>
    </fieldset>
  );
}

function RecordRow({
  record,
  zoneIndex,
  index,
  disabled,
  onChange,
  onRemove,
}: {
  record: ZoneRecord;
  zoneIndex: number;
  index: number;
  disabled: boolean;
  onChange: (record: ZoneRecord) => void;
  onRemove: () => void;
}) {
  const id = `zone-${zoneIndex}-record-${index}`;
  return (
    <tr>
      <td>
        <label className="visually-hidden" htmlFor={`${id}-name`}>
          Record name
        </label>
        <input
          id={`${id}-name`}
          className="mono"
          value={record.name}
          disabled={disabled}
          onChange={(event) => onChange({ ...record, name: event.target.value })}
        />
      </td>
      <td>
        <label className="visually-hidden" htmlFor={`${id}-type`}>
          Record type
        </label>
        <select
          id={`${id}-type`}
          value={record.type}
          disabled={disabled}
          onChange={(event) =>
            onChange({ ...record, type: event.target.value as ZoneRecordType })
          }
        >
          {RECORD_TYPES.map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </select>
      </td>
      <td>
        <label className="visually-hidden" htmlFor={`${id}-value`}>
          Record value
        </label>
        <input
          id={`${id}-value`}
          className="mono"
          value={record.value}
          disabled={disabled}
          onChange={(event) => onChange({ ...record, value: event.target.value })}
        />
      </td>
      <td>
        <label className="visually-hidden" htmlFor={`${id}-ttl`}>
          TTL in seconds
        </label>
        <input
          id={`${id}-ttl`}
          type="number"
          min={30}
          max={86400}
          value={record.ttl ?? DEFAULT_TTL}
          disabled={disabled}
          onChange={(event) =>
            onChange({ ...record, ttl: Number(event.target.value) })
          }
        />
      </td>
      <td>
        <button
          type="button"
          className="quiet-danger"
          disabled={disabled}
          onClick={onRemove}
          aria-label={`Remove ${record.type} record ${record.name || index + 1}`}
        >
          Remove
        </button>
      </td>
    </tr>
  );
}

function ZoneEditor({
  zone,
  index,
  disabled,
  onChange,
  onRemove,
}: {
  zone: DnsZone;
  index: number;
  disabled: boolean;
  onChange: (zone: DnsZone) => void;
  onRemove: () => void;
}) {
  return (
    <fieldset className="dns-card stack">
      <legend>Zone {zone.name || index + 1}</legend>
      <div className="dns-grid">
        <label>
          Zone name
          <input
            className="mono"
            value={zone.name}
            disabled={disabled}
            onChange={(event) => onChange({ ...zone, name: event.target.value })}
          />
        </label>
        <label>
          <input
            type="checkbox"
            checked={zone.enabled}
            disabled={disabled}
            onChange={(event) => onChange({ ...zone, enabled: event.target.checked })}
          />
          Enabled
        </label>
      </div>
      <p className="muted dns-hint">
        Record names may be <span className="mono">@</span> for the zone
        apex, a relative label such as <span className="mono">wiki</span>, or
        a full name. The coordinator stores full names. A name with a CNAME
        cannot hold any other record.
      </p>
      {zone.records.length === 0 ? (
        <p className="muted">No records in this zone yet.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Type</th>
                <th scope="col">Value</th>
                <th scope="col">TTL (s)</th>
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {zone.records.map((record, recordIndex) => (
                <RecordRow
                  key={recordIndex}
                  record={record}
                  zoneIndex={index}
                  index={recordIndex}
                  disabled={disabled}
                  onChange={(next) =>
                    onChange({
                      ...zone,
                      records: zone.records.map((value, position) =>
                        position === recordIndex ? next : value,
                      ),
                    })
                  }
                  onRemove={() =>
                    onChange({
                      ...zone,
                      records: zone.records.filter(
                        (_, position) => position !== recordIndex,
                      ),
                    })
                  }
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="row">
        <button
          type="button"
          className="secondary"
          disabled={disabled}
          onClick={() =>
            onChange({
              ...zone,
              records: [
                ...zone.records,
                { name: "", type: "A", value: "", ttl: DEFAULT_TTL },
              ],
            })
          }
        >
          Add record
        </button>
        <button
          type="button"
          className="quiet-danger"
          disabled={disabled}
          onClick={onRemove}
        >
          Remove zone
        </button>
      </div>
    </fieldset>
  );
}

export function DnsEditor({
  initial,
  etag,
  organisationName,
  roleLabel,
  readOnlyReason,
}: {
  initial: OrgDnsSettings;
  etag: string;
  organisationName: string;
  roleLabel: string;
  readOnlyReason: string | null;
}) {
  const router = useRouter();
  const published = useMemo(() => normaliseDns(initial), [initial]);
  const publishedJson = useMemo(() => serialiseDns(published), [published]);
  const [draft, setDraft] = useState<OrgDnsSettings>(published);
  const [editorKey, setEditorKey] = useState(0);
  const [jsonText, setJsonText] = useState(publishedJson);
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [check, setCheck] = useState<{ warnings: string[]; canonical: string } | null>(
    null,
  );
  const disabled = readOnlyReason !== null || pending;
  const draftJson = serialiseDns(draft);
  const dirty = draftJson !== publishedJson;
  const groups = draft.nameserver_groups ?? [];
  const zones = draft.zones ?? [];

  function update(next: OrgDnsSettings) {
    setDraft(next);
    setJsonText(serialiseDns(next));
    setCheck(null);
    setNotice(null);
  }

  function setGroups(next: NameserverGroup[]) {
    update({ ...draft, nameserver_groups: next });
  }

  function setZones(next: DnsZone[]) {
    update({ ...draft, zones: next });
  }

  function replaceDraft(next: OrgDnsSettings) {
    update(next);
    setEditorKey((key) => key + 1);
  }

  return (
    <div className="stack">
      <div className="panel stack" id="editor">
        <div>
          <h2>Edit DNS</h2>
          <p className="muted">
            Editing <span className="badge network">{organisationName}</span>{" "}
            as {roleLabel}. Changes stay a draft until you publish; agents
            pick up each published revision on their next poll.
          </p>
          {readOnlyReason ? <p className="muted">{readOnlyReason}</p> : null}
        </div>
        <label>
          <input
            type="checkbox"
            checked={draft.managed}
            disabled={disabled}
            onChange={(event) => update({ ...draft, managed: event.target.checked })}
          />
          BlakTail manages device DNS for this organisation
        </label>
      </div>

      <div className="panel stack" id="nameserver-groups" key={`groups-${editorKey}`}>
        <div>
          <h2>Nameserver groups</h2>
          <p className="muted">
            Forward chosen domains to private resolvers for every device or
            for tagged devices. The longest matching suffix wins; for the
            same domain, the first group in this list wins.
          </p>
        </div>
        {groups.length === 0 ? (
          <p className="muted">No nameserver groups yet.</p>
        ) : (
          groups.map((group, index) => (
            <GroupEditor
              key={index}
              group={group}
              index={index}
              count={groups.length}
              disabled={disabled}
              onChange={(next) =>
                setGroups(groups.map((value, position) => (position === index ? next : value)))
              }
              onRemove={() => setGroups(groups.filter((_, position) => position !== index))}
              onMove={(delta) => {
                const next = [...groups];
                const [moved] = next.splice(index, 1);
                next.splice(index + delta, 0, moved!);
                setGroups(next);
                setEditorKey((key) => key + 1);
              }}
            />
          ))
        )}
        <div>
          <button
            type="button"
            className="secondary"
            disabled={disabled}
            onClick={() =>
              setGroups([
                ...groups,
                {
                  name: "",
                  resolvers: [],
                  match_domains: [],
                  enabled: true,
                  all_devices: true,
                  tags: [],
                },
              ])
            }
          >
            Add nameserver group
          </button>
        </div>
      </div>

      <div className="panel stack" id="zones" key={`zones-${editorKey}`}>
        <div>
          <h2>Custom zones</h2>
          <p className="muted">
            Agents answer these names themselves with A, AAAA, CNAME and TXT
            records. Unknown names inside a zone return NXDOMAIN rather than
            leaking to public DNS. Zones cannot use the protected{" "}
            <span className="mono">.blaktail</span> suffix. Agents older than
            this release answer only the A and AAAA records.
          </p>
        </div>
        {zones.length === 0 ? (
          <p className="muted">No custom zones yet.</p>
        ) : (
          zones.map((zone, index) => (
            <ZoneEditor
              key={index}
              zone={zone}
              index={index}
              disabled={disabled}
              onChange={(next) =>
                setZones(zones.map((value, position) => (position === index ? next : value)))
              }
              onRemove={() => setZones(zones.filter((_, position) => position !== index))}
            />
          ))
        )}
        <div>
          <button
            type="button"
            className="secondary"
            disabled={disabled}
            onClick={() => setZones([...zones, { name: "", enabled: true, records: [] }])}
          >
            Add zone
          </button>
        </div>
      </div>

      <div className="panel stack" id="legacy" key={`legacy-${editorKey}`}>
        <div>
          <h2>Split DNS, search domains and extra records</h2>
          <p className="muted">
            The original organisation DNS fields. They keep working for every
            agent version. Split suffixes here apply to every device.
          </p>
        </div>
        <ListField
          label="Search domains"
          hint="Appended after the MagicDNS domain (six suffixes total)."
          values={draft.search_domains}
          disabled={disabled}
          onChange={(search_domains) => update({ ...draft, search_domains })}
        />
        <ListField
          label="Global resolvers"
          hint="Stored and used only to probe new snapshots. BlakTail never becomes a public recursive resolver."
          values={draft.global_resolvers}
          disabled={disabled}
          onChange={(global_resolvers) => update({ ...draft, global_resolvers })}
        />
        <label>
          Split routes
          <textarea
            className="mono"
            rows={Math.max(2, draft.split.length + 1)}
            defaultValue={draft.split
              .map((route) => `${route.suffix} ${route.resolvers.join(" ")}`)
              .join("\n")}
            disabled={disabled}
            onChange={(event) =>
              update({
                ...draft,
                split: event.target.value
                  .split("\n")
                  .map((line) => line.trim().split(/[\s,]+/).filter(Boolean))
                  .filter((parts) => parts.length > 0)
                  .map(([suffix, ...resolvers]) => ({ suffix: suffix!, resolvers })),
              })
            }
          />
          <span className="muted dns-hint">
            One route per line: suffix followed by its resolvers, for example{" "}
            <span className="mono">internal.example 10.0.0.53</span>.
          </span>
        </label>
        <label>
          Extra A/AAAA records
          <textarea
            className="mono"
            rows={Math.max(2, draft.records.length + 1)}
            defaultValue={draft.records
              .map((record) => `${record.name} ${record.type} ${record.value}`)
              .join("\n")}
            disabled={disabled}
            onChange={(event) =>
              update({
                ...draft,
                records: event.target.value
                  .split("\n")
                  .map((line) => line.trim().split(/\s+/).filter(Boolean))
                  .filter((parts) => parts.length > 0)
                  .map(([name, type, value]) => ({
                    name: name ?? "",
                    type: (type ?? "").toUpperCase() === "AAAA" ? "AAAA" : "A",
                    value: value ?? "",
                  })),
              })
            }
          />
          <span className="muted dns-hint">
            One record per line: name, A or AAAA, address. Each must sit under
            a split suffix or search domain. New records belong in a custom
            zone.
          </span>
        </label>
      </div>

      <div className="panel stack" id="advanced">
        <details className="acl-advanced">
          <summary>Advanced JSON</summary>
          <div className="stack">
            <label>
              Settings JSON
              <textarea
                className="mono"
                rows={16}
                value={jsonText}
                disabled={disabled}
                onChange={(event) => {
                  setJsonText(event.target.value);
                  setJsonError(null);
                }}
              />
            </label>
            {jsonError ? <p className="error">{jsonError}</p> : null}
            <div>
              <button
                type="button"
                className="secondary"
                disabled={disabled}
                onClick={() => {
                  try {
                    const parsed = JSON.parse(jsonText) as Partial<OrgDnsSettings>;
                    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
                      throw new Error();
                    }
                    replaceDraft(normaliseDns(parsed));
                  } catch {
                    setJsonError("JSON is not a valid DNS settings object yet.");
                  }
                }}
              >
                Apply JSON to editor
              </button>
            </div>
          </div>
        </details>
      </div>

      <div className="panel stack" id="publish">
        <div>
          <h2>Check and publish</h2>
          <p className="muted">
            {dirty
              ? "You have unpublished changes."
              : "The draft matches the published revision."}
          </p>
        </div>
        {dirty ? <DnsDiff lines={lineDiff(publishedJson, draftJson)} label="Draft changes" /> : null}
        {check ? (
          <div className="stack">
            <p>
              Check passed.{" "}
              {check.warnings.length === 0
                ? "No warnings."
                : `${check.warnings.length} warning${check.warnings.length === 1 ? "" : "s"}:`}
            </p>
            {check.warnings.length > 0 ? (
              <ul>
                {check.warnings.map((warning) => (
                  <li key={warning}>
                    <span className="badge pending">Warning</span> {warning}
                  </li>
                ))}
              </ul>
            ) : null}
            <details>
              <summary>Canonical document</summary>
              <pre className="mono dns-pre">{check.canonical}</pre>
            </details>
          </div>
        ) : null}
        {error ? (
          <p className="error" role="alert">
            {error}
          </p>
        ) : null}
        {notice ? <p role="status">{notice}</p> : null}
        <div className="row">
          <button
            type="button"
            className="secondary"
            disabled={pending}
            onClick={() => {
              setError(null);
              startTransition(async () => {
                const result = await validateDnsAction(draftJson);
                if (!result.ok) {
                  setCheck(null);
                  setError(result.error);
                  return;
                }
                setCheck({
                  warnings: result.data.warnings,
                  canonical: JSON.stringify(result.data.dns, null, 2),
                });
              });
            }}
          >
            {pending ? "Working…" : "Check"}
          </button>
          <button
            type="button"
            disabled={disabled || !dirty}
            title={readOnlyReason ?? (dirty ? undefined : "No changes to publish")}
            onClick={() => {
              setError(null);
              startTransition(async () => {
                const result = await publishDnsAction(draftJson, etag);
                if (!result.ok) {
                  setError(result.error);
                  return;
                }
                setNotice("Published. Agents apply it on their next poll.");
                router.refresh();
              });
            }}
          >
            {pending ? "Publishing…" : "Publish DNS"}
          </button>
          <button
            type="button"
            className="secondary"
            disabled={disabled || !dirty}
            onClick={() => replaceDraft(published)}
          >
            Discard changes
          </button>
        </div>
      </div>
    </div>
  );
}
