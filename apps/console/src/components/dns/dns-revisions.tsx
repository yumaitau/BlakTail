"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { loadDnsRevisionAction, rollbackDnsAction } from "@/app/dns/actions";
import type { OrgDnsSettings } from "@/lib/coord";
import type { DnsRevision } from "@/lib/coord-dns";
import { lineDiff } from "@/lib/text-diff";
import { DnsDiff } from "./dns-diff";
import { normaliseDns, serialiseDns } from "./dns-editor";

function when(seconds: number): string {
  return new Date(seconds * 1000).toLocaleString("en-AU", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export function DnsRevisions({
  revisions,
  loadError,
  current,
  etag,
  hasPrevious,
  readOnlyReason,
}: {
  revisions: DnsRevision[];
  loadError: string | null;
  current: OrgDnsSettings;
  etag: string;
  hasPrevious: boolean;
  readOnlyReason: string | null;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [compare, setCompare] = useState<{ revision: number; text: string } | null>(
    null,
  );
  const currentText = serialiseDns(normaliseDns(current));
  const disabled = readOnlyReason !== null || pending;

  function restore(revision: number | null) {
    const label = revision === null ? "the previous revision" : `revision ${revision}`;
    if (!window.confirm(`Publish ${label} as a new revision?`)) {
      return;
    }
    setError(null);
    startTransition(async () => {
      const result = await rollbackDnsAction(etag, revision);
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setCompare(null);
      router.refresh();
    });
  }

  return (
    <div className="panel stack" id="revisions">
      <div>
        <h2>Revision history</h2>
        <p className="muted">
          Restoring publishes the older document as a new revision; nothing is
          deleted. Revisions published before this workspace existed are not
          listed, but one-step rollback still covers the latest of them.
        </p>
        {readOnlyReason ? <p className="muted">{readOnlyReason}</p> : null}
      </div>
      {loadError ? <p className="error">{loadError}</p> : null}
      {!loadError && revisions.length === 0 ? (
        <p className="muted">No recorded revisions yet.</p>
      ) : null}
      {revisions.length > 0 ? (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Revision</th>
                <th scope="col">Published</th>
                <th scope="col">Contents</th>
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {revisions.map((revision) => (
                <tr key={revision.revision}>
                  <td>
                    {revision.revision}{" "}
                    {revision.current ? <span className="badge online">Current</span> : null}
                  </td>
                  <td>{when(revision.created_at)}</td>
                  <td className="muted">
                    {revision.summary.nameserver_groups} groups ·{" "}
                    {revision.summary.zones} zones ({revision.summary.zone_records}{" "}
                    records) · {revision.summary.split} split ·{" "}
                    {revision.summary.records} extra records
                  </td>
                  <td>
                    {revision.current ? null : (
                      <div className="row">
                        <button
                          type="button"
                          className="secondary"
                          disabled={pending}
                          onClick={() => {
                            setError(null);
                            startTransition(async () => {
                              const result = await loadDnsRevisionAction(revision.revision);
                              if (!result.ok) {
                                setError(result.error);
                                return;
                              }
                              setCompare({
                                revision: revision.revision,
                                text: serialiseDns(normaliseDns(result.data.dns)),
                              });
                            });
                          }}
                        >
                          Compare
                        </button>
                        <button
                          type="button"
                          className="secondary"
                          disabled={disabled}
                          title={readOnlyReason ?? undefined}
                          onClick={() => restore(revision.revision)}
                        >
                          Restore
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {compare ? (
        <DnsDiff
          lines={lineDiff(compare.text, currentText)}
          label={`Changes from revision ${compare.revision} to the current revision`}
        />
      ) : null}
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
      {hasPrevious ? (
        <div>
          <button
            type="button"
            className="secondary"
            disabled={disabled}
            title={readOnlyReason ?? undefined}
            onClick={() => restore(null)}
          >
            {pending ? "Working…" : "Roll back to previous revision"}
          </button>
        </div>
      ) : null}
    </div>
  );
}
