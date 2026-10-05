import { errorText } from "@/lib/server-errors";
import Link from "next/link";
import { ConsoleShell } from "@/components/console-shell";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { listDrafts, type ChangeDraft } from "@/lib/coord-changes";
import { can, permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";
import { createDraftAction } from "./actions";
import { SURFACES, statusBadge, surfaceLabel, when } from "./format";

export default async function ChangesPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const ctx = await requireConsoleContext();
  const { error: actionError } = await searchParams;
  let drafts: ChangeDraft[] = [];
  let error: string | null = null;
  try {
    drafts = await listDrafts(ctx);
  } catch (err) {
    error = errorText(err, "Could not load change drafts.");
  }
  const allowed = SURFACES.filter((surface) => can(ctx.role, surface.permission));

  return (
    <ConsoleShell ctx={ctx} current="/changes">
      <div className="stack">
        <PageHeader
          eyebrow={ctx.organisationName}
          title="Change drafts"
          description="Stage policy, network resource and DNS changes together, preview who gains or loses access, then publish them in one database transaction. Drafts live on the coordinator, belong to one organisation and expire after seven days."
        />
        {actionError ? (
          <p className="error" role="alert">
            {actionError}
          </p>
        ) : null}

        <section className="panel stack" aria-labelledby="new-title">
          <div className="row">
            <h2 id="new-title">New draft</h2>
            <span className="badge network">{ctx.organisationName}</span>
            <span className="muted">{roleLabel(ctx.role)}</span>
          </div>
          {allowed.length === 0 ? (
            <p className="muted">
              {permissionReason(ctx.role, "manage_policy")} You can still read draft summaries
              below.
            </p>
          ) : (
            <form action={createDraftAction} className="stack">
              <input type="hidden" name="organisationId" value={ctx.organisationId} />
              <label>
                Title
                <input name="title" required maxLength={120} placeholder="Open the office NAS to rangers" />
              </label>
              <fieldset>
                <legend>Start from the live state of</legend>
                {SURFACES.map((surface) => {
                  const permitted = can(ctx.role, surface.permission);
                  return (
                    <label key={surface.value} className="route-option">
                      <input
                        type="checkbox"
                        name="surfaces"
                        value={surface.value}
                        disabled={!permitted}
                        defaultChecked={permitted && surface.value === "policy"}
                      />
                      {surface.label}
                      {permitted ? null : (
                        <span className="muted"> — {permissionReason(ctx.role, surface.permission)}</span>
                      )}
                    </label>
                  );
                })}
              </fieldset>
              <div>
                <button className="button" type="submit">
                  Create draft in {ctx.organisationName}
                </button>
              </div>
            </form>
          )}
        </section>

        <section className="panel stack" aria-labelledby="drafts-title">
          <h2 id="drafts-title">Drafts</h2>
          {error ? (
            <p className="error" role="alert">
              {error}
            </p>
          ) : drafts.length === 0 ? (
            <EmptyState
              title="No drafts yet"
              body="A draft copies the live documents you choose. Nothing changes for devices until it is published."
            />
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Title</th>
                    <th scope="col">Status</th>
                    <th scope="col">Changes</th>
                    <th scope="col">Created by</th>
                    <th scope="col">Updated</th>
                    <th scope="col">Expires</th>
                  </tr>
                </thead>
                <tbody>
                  {drafts.map((draft) => (
                    <tr key={draft.id}>
                      <td>
                        <Link href={`/changes/${draft.id}`}>{draft.title}</Link>
                      </td>
                      <td>
                        <span className={`badge ${statusBadge[draft.status]}`}>{draft.status}</span>
                      </td>
                      <td>
                        {draft.surfaces.map(surfaceLabel).join(", ")}
                      </td>
                      <td>{draft.created_by_name || draft.created_by}</td>
                      <td>{when(draft.updated_at)}</td>
                      <td>{draft.status === "open" ? when(draft.expires_at) : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </ConsoleShell>
  );
}
