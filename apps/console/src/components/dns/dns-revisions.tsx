"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { loadDnsRevisionAction, rollbackDnsAction } from "@/app/dns/actions";
import type { OrgDnsSettings } from "@/lib/coord";
import type { DnsRevision } from "@/lib/coord-dns";
import { lineDiff } from "@/lib/text-diff";
import { EmptyState } from "../empty-state";
import { Alert } from "../ui/alert";
import { StatusPill } from "../ui/badge";
import { Button } from "../ui/button";
import { ConfirmDialog } from "../ui/confirm-dialog";
import { Section } from "../ui/section";
import { Table, Td } from "../ui/table";
import { toastResult } from "../ui/toast";
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
  const [comparing, setComparing] = useState<number | null>(null);
  const [compare, setCompare] = useState<{ revision: number; text: string } | null>(
    null,
  );
  // undefined: closed; null: one-step rollback; number: restore that revision.
  const [restoring, setRestoring] = useState<number | null | undefined>(undefined);
  const currentText = serialiseDns(normaliseDns(current));
  const canRestore = readOnlyReason === null;

  return (
    <Section
      id="revisions"
      title="Revision history"
      description="Restoring publishes the older document as a new revision; nothing is deleted. Revisions published before this workspace existed aren't listed, but one-step rollback still covers the latest of them."
      actions={
        hasPrevious && canRestore ? (
          <Button
            variant="secondary"
            size="sm"
            disabled={pending}
            onClick={() => setRestoring(null)}
          >
            Roll back to previous revision
          </Button>
        ) : null
      }
    >
      {loadError ? (
        <Alert tone="error" title="Revision history couldn't be loaded">
          {loadError}
        </Alert>
      ) : null}
      {!loadError && revisions.length === 0 ? (
        <EmptyState
          compact
          headingLevel={3}
          title="No recorded revisions yet"
          body="Each time DNS is published, the revision shows here so you can compare or restore it."
        />
      ) : null}
      {revisions.length > 0 ? (
        <Table label="DNS revisions" mobile="stack">
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
                <Td label="Revision">
                  <div className="row">
                    <span className="mono">{revision.revision}</span>
                    {revision.current ? <StatusPill tone="success">Current</StatusPill> : null}
                  </div>
                </Td>
                <Td label="Published">
                  {/* Server and browser format dates differently; the browser wins. */}
                  <time
                    dateTime={new Date(revision.created_at * 1000).toISOString()}
                    suppressHydrationWarning
                  >
                    {when(revision.created_at)}
                  </time>
                </Td>
                <Td label="Contents" className="muted">
                  {revision.summary.nameserver_groups} groups · {revision.summary.zones} zones (
                  {revision.summary.zone_records} records) · {revision.summary.split} split ·{" "}
                  {revision.summary.records} extra records
                </Td>
                <Td>
                  {revision.current ? null : (
                    <div className="cell-actions">
                      <Button
                        variant="secondary"
                        size="sm"
                        loading={comparing === revision.revision}
                        disabled={pending}
                        onClick={() => {
                          setComparing(revision.revision);
                          startTransition(async () => {
                            const result = await loadDnsRevisionAction(revision.revision);
                            setComparing(null);
                            if (!result.ok) {
                              toastResult(result);
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
                      </Button>
                      {canRestore ? (
                        <Button
                          variant="secondary"
                          size="sm"
                          disabled={pending}
                          onClick={() => setRestoring(revision.revision)}
                        >
                          Restore
                        </Button>
                      ) : null}
                    </div>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : null}
      {compare ? (
        <DnsDiff
          lines={lineDiff(compare.text, currentText)}
          label={`Changes from revision ${compare.revision} to the current revision`}
        />
      ) : null}
      <ConfirmDialog
        open={restoring !== undefined}
        title={restoring === null ? "Roll back DNS" : `Restore revision ${restoring ?? ""}`}
        description={`${
          restoring === null ? "The previous revision" : `Revision ${restoring ?? ""}`
        } is published again as a new revision. Every device picks it up on its next poll, and any unpublished edits on this page are lost.`}
        confirmLabel={restoring === null ? "Roll back DNS" : "Restore revision"}
        pending={pending}
        onCancel={() => setRestoring(undefined)}
        onConfirm={() => {
          const revision = restoring ?? null;
          startTransition(async () => {
            const result = await rollbackDnsAction(etag, revision);
            toastResult(result, {
              success: revision === null ? "DNS rolled back" : `Revision ${revision} restored`,
              successDescription: "Agents apply it on their next poll.",
            });
            setRestoring(undefined);
            if (result.ok) {
              setCompare(null);
              router.refresh();
            }
          });
        }}
      />
    </Section>
  );
}
