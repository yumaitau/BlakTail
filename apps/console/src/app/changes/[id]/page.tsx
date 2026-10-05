import { Suspense } from "react";
import Link from "next/link";
import { errorText } from "@/lib/server-errors";
import { ConsoleShell } from "@/components/console-shell";
import { DnsDiff } from "@/components/dns/dns-diff";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/ui/alert";
import { StatusPill } from "@/components/ui/badge";
import { MonoValue } from "@/components/ui/mono-value";
import { PermissionNotice } from "@/components/ui/permission-notice";
import { Section } from "@/components/ui/section";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, Td } from "@/components/ui/table";
import {
  getDraft,
  previewDraft,
  type ChangeDraft,
  type DraftPreview,
  type PreviewPair,
} from "@/lib/coord-changes";
import { editHref, getTopology, type TopologyNode } from "@/lib/coord-topology";
import { requireConsoleContext, type ConsoleContext } from "@/lib/session";
import { lineDiff } from "@/lib/text-diff";
import {
  DiscardButton,
  DraftEditor,
  PreviewForm,
  PublishForm,
  RebaseButton,
} from "../draft-forms";
import { LocalTime } from "@/components/ui/local-time";
import { draftStatus, surfaceLabel, surfaceNoun } from "../format";

type Search = {
  preview?: string;
  src?: string;
  dst?: string;
  protocol?: string;
  port?: string;
};

const UUID = /^[0-9a-f-]{36}$/i;

function pretty(value: unknown): string {
  return JSON.stringify(value ?? null, null, 2);
}

function previewPair(search: Search): PreviewPair[] {
  if (!UUID.test(search.src ?? "") || !UUID.test(search.dst ?? "")) return [];
  const protocol = ["tcp", "udp", "icmp"].includes(search.protocol ?? "")
    ? (search.protocol as PreviewPair["protocol"])
    : undefined;
  const port = Number(search.port);
  return [
    {
      source_node_id: search.src!,
      destination_node_id: search.dst!,
      ...(protocol ? { protocol } : {}),
      ...(protocol !== "icmp" && Number.isInteger(port) && port >= 1 && port <= 65535
        ? { port }
        : {}),
    },
  ];
}

function decision(value: { decision: "allow" | "deny"; basis: string }) {
  return (
    <>
      <StatusPill tone={value.decision === "allow" ? "success" : "muted"}>
        {value.decision === "allow" ? "Allowed" : "Denied"}
      </StatusPill>
      <div className="cell-sub">{value.basis.replaceAll("_", " ")}</div>
    </>
  );
}

async function PreviewResults({
  ctx,
  draft,
  search,
  nodes,
}: {
  ctx: ConsoleContext;
  draft: ChangeDraft;
  search: Search;
  nodes: TopologyNode[];
}) {
  let preview: DraftPreview | null = null;
  let previewError: string | null = null;
  try {
    preview = await previewDraft(ctx, draft.id, previewPair(search));
  } catch (err) {
    previewError = errorText(err, "Could not preview this draft.");
  }
  if (!preview) {
    return (
      <Alert tone="error" title="Couldn't run the preview">
        {previewError}
      </Alert>
    );
  }
  const nodeName = (nodeId: string) => nodes.find((node) => node.id === nodeId)?.label ?? nodeId;
  const ref = {
    organisationId: ctx.organisationId,
    id: draft.id,
    version: draft.version,
    surfaces: draft.surfaces,
  };
  const changedPaths = preview.reachability.added.length + preview.reachability.removed.length;

  return (
    <div className="stack" aria-live="polite">
      {preview.stale_surfaces.length ? (
        <Alert
          tone="warning"
          title="Rebase needed before publishing"
          action={<RebaseButton draft={ref} />}
        >
          {preview.stale_surfaces.map(surfaceLabel).join(", ")} changed since this draft was
          based. Rebase to compare your proposal with the latest live state.
        </Alert>
      ) : null}
      {preview.valid ? (
        <Alert tone="success" title="The draft validates">
          Every change passes the coordinator&apos;s own checks.
        </Alert>
      ) : (
        <Alert tone="error" title="The draft doesn't validate">
          <ul>
            {preview.errors.map((message) => (
              <li key={message}>{message}</li>
            ))}
          </ul>
        </Alert>
      )}
      {preview.policy ? (
        <DnsDiff
          lines={lineDiff(pretty(preview.policy.before), pretty(preview.policy.after))}
          label="Access policy: live → draft"
        />
      ) : null}
      {preview.dns ? (
        <DnsDiff
          lines={lineDiff(pretty(preview.dns.before), pretty(preview.dns.after))}
          label="DNS: live → draft"
        />
      ) : null}
      {preview.resources.length ? (
        <div className="stack">
          <h3>Network resource changes</h3>
          <ul className="audit-details">
            {preview.resources.map((change) => (
              <li key={`${change.op}-${change.id}`}>
                <StatusPill
                  tone={change.op === "create" ? "success" : change.op === "update" ? "info" : "danger"}
                >
                  {change.op === "create" ? "Create" : change.op === "update" ? "Update" : "Delete"}
                </StatusPill>{" "}
                {change.name}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {preview.valid ? (
        <div className="stack">
          <h3>Who gains or loses a path</h3>
          {changedPaths === 0 ? (
            <p className="muted">No device gains or loses a path.</p>
          ) : (
            <ul className="audit-details">
              {preview.reachability.added.map((edge) => (
                <li
                  key={`a-${edge.kind}-${edge.source_node_id}-${edge.target_node_id}-${edge.destination}`}
                >
                  <StatusPill tone="warning">Opens</StatusPill> {edge.explanation}{" "}
                  <Link href={editHref(edge)}>Where it&apos;s set</Link>
                </li>
              ))}
              {preview.reachability.removed.map((edge) => (
                <li
                  key={`r-${edge.kind}-${edge.source_node_id}-${edge.target_node_id}-${edge.destination}`}
                >
                  <StatusPill tone="muted">Closes</StatusPill> {edge.explanation}
                </li>
              ))}
            </ul>
          )}
          {preview.reachability.truncated ? (
            <p className="muted">Only the first paths are listed.</p>
          ) : null}
        </div>
      ) : null}
      {preview.pairs.length ? (
        <div className="stack">
          <h3>Named test</h3>
          <Table label="Named test result" mobile="stack">
            <thead>
              <tr>
                <th scope="col">Source → destination</th>
                <th scope="col">Live</th>
                <th scope="col">After publish</th>
              </tr>
            </thead>
            <tbody>
              {preview.pairs.map((pair) => (
                <tr key={`${pair.source_node_id}-${pair.destination_node_id}`}>
                  <Td label="Path">
                    {nodeName(pair.source_node_id)} → {nodeName(pair.destination_node_id)}
                    <div className="cell-sub">
                      {pair.protocol ? pair.protocol.toUpperCase() : "Any protocol"}
                      {pair.port ? ` port ${pair.port}` : ""}
                    </div>
                  </Td>
                  <Td label="Live">{decision(pair.before)}</Td>
                  <Td label="After publish">
                    {pair.after ? decision(pair.after) : <span className="muted">Not evaluated</span>}
                    {pair.changed ? <div className="cell-sub">Changes on publish</div> : null}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
      ) : null}
      {preview.dns_warnings.length ? (
        <Alert tone="warning" title="DNS warnings">
          <ul>
            {preview.dns_warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        </Alert>
      ) : null}
      {preview.notes.length ? (
        <ul className="muted">
          {preview.notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      ) : null}

      {preview.valid && preview.stale_surfaces.length === 0 ? (
        <div className="stack">
          <h3>Publish</h3>
          <PublishForm
            draft={ref}
            organisationName={ctx.organisationName}
            surfaceLabels={draft.surfaces.map(surfaceNoun).join(" and ")}
            risks={preview.risks}
          />
        </div>
      ) : null}
    </div>
  );
}

export default async function ChangeDraftPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<Search>;
}) {
  const ctx = await requireConsoleContext();
  const { id } = await params;
  const search = await searchParams;

  let draft: ChangeDraft | null = null;
  let error: string | null = null;
  try {
    draft = UUID.test(id) ? await getDraft(ctx, id) : null;
  } catch (err) {
    error = errorText(err, "Could not load this draft.");
  }

  if (!draft) {
    return (
      <ConsoleShell ctx={ctx} current="/changes">
        <div className="stack">
          <Link className="back-link" href="/changes">
            ← All drafts
          </Link>
          <PageHeader
            eyebrow={ctx.organisationName}
            title={error ? "Draft unavailable" : "Draft not found"}
          />
          {error ? (
            <Alert tone="error" title="Couldn't load this draft">
              {error}
            </Alert>
          ) : (
            <Section title="Nothing here">
              <EmptyState
                compact
                headingLevel={3}
                title={`No such draft in ${ctx.organisationName}`}
                body="Drafts belong to one organisation. If you switched organisation, switch back to open it."
                action={
                  <Link className="button secondary" href="/changes">
                    All drafts
                  </Link>
                }
              />
            </Section>
          )}
        </div>
      </ConsoleShell>
    );
  }

  const open = draft.status === "open";
  const editable = open && draft.can_edit && Boolean(draft.payload);
  const wantPreview = editable && (search.preview === "1" || Boolean(search.src));
  let nodes: TopologyNode[] = [];
  if (editable) {
    try {
      nodes = (await getTopology(ctx)).nodes;
    } catch {
      nodes = [];
    }
  }
  const status = draftStatus[draft.status];
  const ref = {
    organisationId: ctx.organisationId,
    id: draft.id,
    version: draft.version,
    surfaces: draft.surfaces,
  };
  const based = [
    draft.base.policy_revision !== undefined ? `Policy revision ${draft.base.policy_revision}` : null,
    draft.base.dns_revision !== undefined ? `DNS revision ${draft.base.dns_revision}` : null,
    draft.base.resources_etag ? "Network resources as they were at creation" : null,
  ].filter(Boolean);
  const documents = draft.payload
    ? [
        draft.payload.policy !== undefined
          ? {
              field: "policy" as const,
              label: "Access policy (JSON)",
              hint: "Replaces the live policy when published.",
              href: "/acls",
              link: "Access policy",
              value: pretty(draft.payload.policy),
            }
          : null,
        draft.payload.resources !== undefined
          ? {
              field: "resources" as const,
              label: "Network resources (JSON array)",
              hint: "The full desired list: items with an id update that resource, items without one are created, and live resources left out are deleted.",
              href: "/networks",
              link: "Networks",
              value: pretty(draft.payload.resources),
            }
          : null,
        draft.payload.dns !== undefined
          ? {
              field: "dns" as const,
              label: "DNS (JSON)",
              hint: "Replaces the live DNS settings when published.",
              href: "/dns",
              link: "DNS",
              value: pretty(draft.payload.dns),
            }
          : null,
      ].filter((doc) => doc !== null)
    : [];

  return (
    <ConsoleShell ctx={ctx} current="/changes">
      <div className="stack">
        <Link className="back-link" href="/changes">
          ← All drafts
        </Link>
        <PageHeader
          eyebrow={ctx.organisationName}
          title={draft.title}
          description={
            <>
              Changes {draft.surfaces.map(surfaceNoun).join(" and ")}. Created by{" "}
              {draft.created_by_name || draft.created_by} on <LocalTime value={draft.created_at} fallback="—" />.
            </>
          }
          actions={editable ? <DiscardButton draft={ref} title={draft.title} /> : null}
        />
        {!draft.payload ? (
          <PermissionNotice reason="You can see this summary only. Viewing or changing the proposed documents needs permission to manage every area this draft touches." />
        ) : null}

        <Section id="summary" title="Summary" actions={<StatusPill tone={status.tone}>{status.label}</StatusPill>}>
          <dl className="details">
            <div>
              <dt>Draft</dt>
              <dd>
                <MonoValue value={draft.id} copy copyLabel="Copy draft ID" />
              </dd>
            </div>
            <div>
              <dt>Version</dt>
              <dd>{draft.version}</dd>
            </div>
            <div>
              <dt>Based on</dt>
              <dd>{based.length ? based.join(" · ") : "—"}</dd>
            </div>
            <div>
              <dt>{open ? "Expires" : "Closed"}</dt>
              <dd>
                {open ? (
                  <LocalTime value={draft.expires_at} fallback="—" />
                ) : (
                  <>
                    <LocalTime value={draft.closed_at} fallback="—" />
                    {draft.closed_by && draft.closed_by === draft.created_by && draft.created_by_name
                      ? ` by ${draft.created_by_name}`
                      : ""}
                  </>
                )}
              </dd>
            </div>
            <div>
              <dt>Last edited by</dt>
              <dd>
                {draft.updated_by === draft.created_by && draft.created_by_name ? (
                  draft.created_by_name
                ) : (
                  <MonoValue value={draft.updated_by} />
                )}{" "}
                · <LocalTime value={draft.updated_at} fallback="—" />
              </dd>
            </div>
          </dl>
          {draft.status === "published" && draft.result ? (
            <p className="muted">
              Published in one transaction. The <Link href="/audit">audit log</Link> entry
              “change_draft.published” has the before and after revisions.
            </p>
          ) : null}
        </Section>

        {editable && documents.length ? (
          <Section
            id="documents"
            title="Proposed documents"
            description="Edit the JSON directly. Never paste credentials; the coordinator refuses them."
          >
            <DraftEditor draft={ref} title={draft.title} documents={documents} />
          </Section>
        ) : null}

        {editable ? (
          <Section
            id="preview"
            title="Preview"
            description="Validate the draft, compare it with live state and see who gains or loses access. Publishing needs a fresh preview."
          >
            <PreviewForm
              draftId={draft.id}
              nodes={nodes.map((node) => ({ id: node.id, label: node.label }))}
              initial={search}
            />
            {wantPreview ? (
              <Suspense
                key={JSON.stringify(search)}
                fallback={<Skeleton lines={5} label="Running preview" />}
              >
                <PreviewResults ctx={ctx} draft={draft} search={search} nodes={nodes} />
              </Suspense>
            ) : null}
          </Section>
        ) : null}
      </div>
    </ConsoleShell>
  );
}
