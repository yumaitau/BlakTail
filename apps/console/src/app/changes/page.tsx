import { Suspense } from "react";
import Link from "next/link";
import { errorText } from "@/lib/server-errors";
import { ConsoleShell } from "@/components/console-shell";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/ui/alert";
import { StatusPill } from "@/components/ui/badge";
import { PermissionNotice } from "@/components/ui/permission-notice";
import { Section } from "@/components/ui/section";
import { SkeletonTable } from "@/components/ui/skeleton";
import { Table, Td } from "@/components/ui/table";
import { listDrafts, type ChangeDraft } from "@/lib/coord-changes";
import { can, permissionReason } from "@/lib/roles";
import { requireConsoleContext, type ConsoleContext } from "@/lib/session";
import { NewDraftForm } from "./draft-forms";
import { SURFACES, draftStatus, surfaceLabel, when } from "./format";

async function DraftList({ ctx }: { ctx: ConsoleContext }) {
  let drafts: ChangeDraft[] = [];
  let error: string | null = null;
  try {
    drafts = await listDrafts(ctx);
  } catch (err) {
    error = errorText(err, "Could not load change drafts.");
  }
  if (error) {
    return (
      <Alert tone="error" title="Couldn't load drafts">
        {error}
      </Alert>
    );
  }
  if (drafts.length === 0) {
    return (
      <EmptyState
        compact
        headingLevel={3}
        title="No drafts yet"
        body="A draft copies the live documents you choose. Nothing changes for devices until it is published."
      />
    );
  }
  return (
    <Table label="Change drafts" mobile="stack">
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
        {drafts.map((draft) => {
          const status = draftStatus[draft.status];
          return (
            <tr key={draft.id}>
              <Td label="Title">
                <Link href={`/changes/${draft.id}`}>{draft.title}</Link>
              </Td>
              <Td label="Status">
                <StatusPill tone={status.tone}>{status.label}</StatusPill>
              </Td>
              <Td label="Changes">{draft.surfaces.map(surfaceLabel).join(", ")}</Td>
              <Td label="Created by">{draft.created_by_name || draft.created_by}</Td>
              <Td label="Updated">{when(draft.updated_at)}</Td>
              <Td label="Expires">{draft.status === "open" ? when(draft.expires_at) : "—"}</Td>
            </tr>
          );
        })}
      </tbody>
    </Table>
  );
}

export default async function ChangesPage() {
  const ctx = await requireConsoleContext();
  const surfaces = SURFACES.map((surface) => ({
    value: surface.value,
    label: surface.label,
    permitted: can(ctx.role, surface.permission),
    reason: permissionReason(ctx.role, surface.permission),
  }));
  const canCreate = surfaces.some((surface) => surface.permitted);

  return (
    <ConsoleShell ctx={ctx} current="/changes">
      <div className="stack">
        <PageHeader
          eyebrow={ctx.organisationName}
          title="Change drafts"
          description="Stage access policy, network resource and DNS changes together, preview who gains or loses access, then publish them in one step. Drafts belong to one organisation and expire after seven days."
          actions={
            canCreate ? (
              <a className="button" href="#new-draft">
                New draft
              </a>
            ) : null
          }
        />
        {canCreate ? null : (
          <PermissionNotice reason={permissionReason(ctx.role, "manage_policy") ?? ""}>
            You can still read draft summaries below.
          </PermissionNotice>
        )}

        <Section id="drafts" title="Drafts">
          <Suspense fallback={<SkeletonTable rows={4} label="Loading drafts" />}>
            <DraftList ctx={ctx} />
          </Suspense>
        </Section>

        {canCreate ? (
          <Section
            id="new-draft"
            title="New draft"
            description={`Starts from what is live in ${ctx.organisationName} now. You edit and preview it before anything changes.`}
          >
            <NewDraftForm
              organisationId={ctx.organisationId}
              organisationName={ctx.organisationName}
              surfaces={surfaces}
            />
          </Section>
        ) : null}
      </div>
    </ConsoleShell>
  );
}
