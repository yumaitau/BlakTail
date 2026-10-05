import { errorText } from "@/lib/server-errors";
import Link from "next/link";
import { ConsoleShell } from "@/components/console-shell";
import { DnsDiff } from "@/components/dns/dns-diff";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import {
  getDraft,
  previewDraft,
  type ChangeDraft,
  type DraftPreview,
  type PreviewPair,
} from "@/lib/coord-changes";
import { editHref, getTopology, type TopologyNode } from "@/lib/coord-topology";
import { roleLabel } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";
import { lineDiff } from "@/lib/text-diff";
import {
  discardDraftAction,
  publishDraftAction,
  rebaseDraftAction,
  saveDraftAction,
} from "../actions";
import { statusBadge, surfaceLabel, when } from "../format";

type Search = {
  error?: string;
  notice?: string;
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

function Hidden({ ctxOrg, draft }: { ctxOrg: string; draft: ChangeDraft }) {
  return (
    <>
      <input type="hidden" name="organisationId" value={ctxOrg} />
      <input type="hidden" name="draftId" value={draft.id} />
      <input type="hidden" name="version" value={draft.version} />
      {draft.surfaces.map((surface) => (
        <input key={surface} type="hidden" name="surfaces" value={surface} />
      ))}
    </>
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
          <PageHeader eyebrow={ctx.organisationName} title="Draft not found" />
          <div className="panel">
            {error ? (
              <p className="error" role="alert">
                {error}
              </p>
            ) : (
              <EmptyState
                title={`No such draft in ${ctx.organisationName}`}
                body="Drafts belong to one organisation. If you switched organisation, switch back to open it."
                action={<Link href="/changes">All drafts</Link>}
              />
            )}
          </div>
        </div>
      </ConsoleShell>
    );
  }

  const open = draft.status === "open";
  const editable = open && draft.can_edit && Boolean(draft.payload);
  const wantPreview = editable && (search.preview === "1" || Boolean(search.src));
  let preview: DraftPreview | null = null;
  let previewError: string | null = null;
  let nodes: TopologyNode[] = [];
  if (editable) {
    try {
      nodes = (await getTopology(ctx)).nodes;
    } catch {
      nodes = [];
    }
  }
  if (wantPreview) {
    try {
      preview = await previewDraft(ctx, draft.id, previewPair(search));
    } catch (err) {
      previewError = errorText(err, "Could not preview this draft.");
    }
  }
  const nodeName = (nodeId: string) => nodes.find((node) => node.id === nodeId)?.label ?? nodeId;

  return (
    <ConsoleShell ctx={ctx} current="/changes">
      <div className="stack">
        <p>
          <Link href="/changes">← All drafts</Link>
        </p>
        <PageHeader
          eyebrow={ctx.organisationName}
          title={draft.title}
          description={`Changes ${draft.surfaces.map(surfaceLabel).join(", ")}. Created by ${draft.created_by_name || draft.created_by} ${when(draft.created_at)}.`}
        />
        {search.error ? (
          <p className="error" role="alert">
            {search.error}
          </p>
        ) : null}
        {search.notice ? (
          <p className="muted" role="status">
            {search.notice}
          </p>
        ) : null}

        <section className="panel stack" aria-labelledby="summary-title">
          <div className="row">
            <h2 id="summary-title">Summary</h2>
            <span className={`badge ${statusBadge[draft.status]}`}>{draft.status}</span>
            <span className="badge network">{ctx.organisationName}</span>
            <span className="muted">{roleLabel(ctx.role)}</span>
          </div>
          <dl className="details">
            <div>
              <dt>Version</dt>
              <dd>{draft.version}</dd>
            </div>
            <div>
              <dt>Based on</dt>
              <dd>
                {draft.base.policy_revision !== undefined
                  ? `policy revision ${draft.base.policy_revision}. `
                  : ""}
                {draft.base.dns_revision !== undefined ? `DNS revision ${draft.base.dns_revision}. ` : ""}
                {draft.base.resources_etag ? "Network resources as they were at creation." : ""}
              </dd>
            </div>
            <div>
              <dt>{open ? "Expires" : "Closed"}</dt>
              <dd>
                {open ? when(draft.expires_at) : `${when(draft.closed_at)} by ${draft.closed_by ?? "—"}`}
              </dd>
            </div>
            <div>
              <dt>Last edited by</dt>
              <dd>
                {draft.updated_by} · {when(draft.updated_at)}
              </dd>
            </div>
          </dl>
          {!draft.payload ? (
            <p className="muted">
              You can see this summary only. Viewing or changing the proposed documents needs
              permission to manage every surface this draft touches.
            </p>
          ) : null}
          {draft.status === "published" && draft.result ? (
            <p className="muted">
              Published in one transaction. See the <Link href="/audit">audit log</Link> entry
              change_draft.published for before and after revisions.
            </p>
          ) : null}
        </section>

        {editable && draft.payload ? (
          <section className="panel stack" aria-labelledby="edit-title">
            <h2 id="edit-title">Proposed documents</h2>
            <p className="muted">
              Each document replaces the live one when published. Network resources are the full
              desired list: items with an id update that resource, items without an id are
              created, and live resources left out are deleted. Never paste credentials; the
              coordinator refuses them.
            </p>
            <form action={saveDraftAction} className="stack">
              <Hidden ctxOrg={ctx.organisationId} draft={draft} />
              <label>
                Title
                <input name="title" required maxLength={120} defaultValue={draft.title} />
              </label>
              {draft.payload.policy !== undefined ? (
                <label>
                  Access policy (JSON) — also editable on <Link href="/acls">Access policy</Link>
                  <textarea name="policy" className="mono" rows={16} spellCheck={false} defaultValue={pretty(draft.payload.policy)} />
                </label>
              ) : null}
              {draft.payload.resources !== undefined ? (
                <label>
                  Network resources (JSON array) — see <Link href="/networks">Networks</Link>
                  <textarea name="resources" className="mono" rows={14} spellCheck={false} defaultValue={pretty(draft.payload.resources)} />
                </label>
              ) : null}
              {draft.payload.dns !== undefined ? (
                <label>
                  DNS (JSON) — see <Link href="/dns">DNS</Link>
                  <textarea name="dns" className="mono" rows={14} spellCheck={false} defaultValue={pretty(draft.payload.dns)} />
                </label>
              ) : null}
              <div className="row">
                <button className="button" type="submit">
                  Save draft (version {draft.version})
                </button>
              </div>
            </form>
          </section>
        ) : null}

        {editable ? (
          <section className="panel stack" aria-labelledby="preview-title">
            <h2 id="preview-title">Preview</h2>
            <form method="get" className="filter-row" aria-label="Preview options">
              <input type="hidden" name="preview" value="1" />
              <label>
                Test source
                <select name="src" defaultValue={search.src ?? ""}>
                  <option value="">None</option>
                  {nodes.map((node) => (
                    <option key={node.id} value={node.id}>
                      {node.label}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Test destination
                <select name="dst" defaultValue={search.dst ?? ""}>
                  <option value="">None</option>
                  {nodes.map((node) => (
                    <option key={node.id} value={node.id}>
                      {node.label}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Protocol
                <select name="protocol" defaultValue={search.protocol ?? ""}>
                  <option value="">Any</option>
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                  <option value="icmp">ICMP</option>
                </select>
              </label>
              <label>
                Port
                <input name="port" inputMode="numeric" pattern="[0-9]*" maxLength={5} defaultValue={search.port ?? ""} />
              </label>
              <button className="button" type="submit">
                Run preview
              </button>
            </form>
            {previewError ? (
              <p className="error" role="alert">
                {previewError}
              </p>
            ) : null}
            {preview ? (
              <div className="stack" aria-live="polite">
                {preview.stale_surfaces.length ? (
                  <div className="stack">
                    <p className="error" role="alert">
                      Rebase required: {preview.stale_surfaces.map(surfaceLabel).join(", ")} changed
                      since this draft was based. Publishing is blocked until you rebase.
                    </p>
                    <form action={rebaseDraftAction}>
                      <Hidden ctxOrg={ctx.organisationId} draft={draft} />
                      <button className="button" type="submit">
                        Rebase on live state
                      </button>
                    </form>
                  </div>
                ) : null}
                {preview.valid ? (
                  <p role="status">Every surface validates with the coordinator&apos;s own validators.</p>
                ) : (
                  <ul className="error" role="alert">
                    {preview.errors.map((message) => (
                      <li key={message}>{message}</li>
                    ))}
                  </ul>
                )}
                {preview.policy ? (
                  <DnsDiff lines={lineDiff(pretty(preview.policy.before), pretty(preview.policy.after))} label="Access policy: live → draft" />
                ) : null}
                {preview.dns ? (
                  <DnsDiff lines={lineDiff(pretty(preview.dns.before), pretty(preview.dns.after))} label="DNS: live → draft" />
                ) : null}
                {preview.resources.length ? (
                  <div>
                    <h3>Network resource changes</h3>
                    <ul className="audit-details">
                      {preview.resources.map((change) => (
                        <li key={`${change.op}-${change.id}`}>
                          {change.op === "create" ? "Create" : change.op === "update" ? "Update" : "Delete"}{" "}
                          {change.name}
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : null}
                {preview.valid ? (
                  <div>
                    <h3>Reachability change</h3>
                    {preview.reachability.added.length + preview.reachability.removed.length === 0 ? (
                      <p className="muted">No device gains or loses a path.</p>
                    ) : (
                      <ul className="audit-details">
                        {preview.reachability.added.map((edge) => (
                          <li key={`a-${edge.kind}-${edge.source_node_id}-${edge.target_node_id}-${edge.destination}`}>
                            <span className="badge pending">Opens</span> {edge.explanation}{" "}
                            <Link href={editHref(edge)}>Owner page</Link>
                          </li>
                        ))}
                        {preview.reachability.removed.map((edge) => (
                          <li key={`r-${edge.kind}-${edge.source_node_id}-${edge.target_node_id}-${edge.destination}`}>
                            <span className="badge offline">Closes</span> {edge.explanation}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                ) : null}
                {preview.pairs.length ? (
                  <div className="table-wrap">
                    <table className="table">
                      <caption className="muted">Named test</caption>
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
                            <td>
                              {nodeName(pair.source_node_id)} → {nodeName(pair.destination_node_id)}
                              <div className="muted">
                                {pair.protocol ?? "any protocol"}
                                {pair.port ? ` port ${pair.port}` : ""}
                              </div>
                            </td>
                            <td>
                              {pair.before.decision} ({pair.before.basis.replaceAll("_", " ")})
                            </td>
                            <td>
                              {pair.after
                                ? `${pair.after.decision} (${pair.after.basis.replaceAll("_", " ")})`
                                : "not evaluated"}
                              {pair.changed ? <strong> · changes</strong> : null}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : null}
                {preview.dns_warnings.length ? (
                  <ul className="muted">
                    {preview.dns_warnings.map((warning) => (
                      <li key={warning}>{warning}</li>
                    ))}
                  </ul>
                ) : null}
                <ul className="muted">
                  {preview.notes.map((note) => (
                    <li key={note}>{note}</li>
                  ))}
                </ul>

                {preview.valid && preview.stale_surfaces.length === 0 ? (
                  <form action={publishDraftAction} className="stack">
                    <Hidden ctxOrg={ctx.organisationId} draft={draft} />
                    <fieldset>
                      <legend>Risks to confirm</legend>
                      {preview.risks.length === 0 ? (
                        <p className="muted">No risk flags.</p>
                      ) : (
                        preview.risks.map((risk) => (
                          <label key={risk.code} className="route-option">
                            <input type="checkbox" name="risk" value={risk.code} required />
                            <span className={`badge ${risk.severity === "high" ? "revoked" : "pending"}`}>
                              {risk.severity}
                            </span>{" "}
                            {risk.message}
                          </label>
                        ))
                      )}
                    </fieldset>
                    <label className="route-option">
                      <input type="checkbox" name="confirm" required />
                      Publish version {draft.version} to {ctx.organisationName} now. Every surface
                      changes in one transaction; devices pick it up on their next poll.
                    </label>
                    <div>
                      <button className="button" type="submit">
                        Publish
                      </button>
                    </div>
                  </form>
                ) : null}
              </div>
            ) : (
              <p className="muted">
                Run a preview to validate the draft, see the diff against live state and who gains
                or loses access. Publishing needs a fresh preview.
              </p>
            )}
          </section>
        ) : null}

        {editable ? (
          <section className="panel stack danger-zone" aria-labelledby="discard-title">
            <h2 id="discard-title">Discard</h2>
            <form action={discardDraftAction}>
              <Hidden ctxOrg={ctx.organisationId} draft={draft} />
              <button className="button" type="submit">
                Discard this draft
              </button>
            </form>
          </section>
        ) : null}
      </div>
    </ConsoleShell>
  );
}
