import { Suspense } from "react";
import Link from "next/link";
import { errorText } from "@/lib/server-errors";
import { AclEditor } from "@/components/acl-editor";
import { ConsoleShell } from "@/components/console-shell";
import { ExplainAccessPanel } from "@/components/explain-access-panel";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/ui/alert";
import { PermissionNotice } from "@/components/ui/permission-notice";
import { Section } from "@/components/ui/section";
import { Skeleton, SkeletonTable } from "@/components/ui/skeleton";
import { getAcl, listNodes } from "@/lib/coord";
import { listPostureChecks } from "@/lib/coord-policy";
import { listMemberships } from "@/lib/oidc";
import { permissionReason } from "@/lib/roles";
import { requireConsoleContext, type ConsoleContext } from "@/lib/session";

export default async function AclsPage() {
  const ctx = await requireConsoleContext();
  const readOnlyReason = permissionReason(ctx.role, "manage_policy");

  return (
    <ConsoleShell ctx={ctx} current="/acls">
      <div className="stack">
        <PageHeader
          eyebrow={ctx.organisationName}
          title="Access"
          description="Who can reach what. New organisations start deny-all; existing documents keep the visible same-tag default until you switch them to deny."
          actions={
            <>
              <Link className="button secondary" href="/topology">
                View topology
              </Link>
              <Link className="button secondary" href="/changes">
                Stage in a change draft
              </Link>
            </>
          }
        />
        {readOnlyReason ? (
          <PermissionNotice reason={readOnlyReason}>
            You can still read the policy and explain access below.
          </PermissionNotice>
        ) : null}
        <Suspense fallback={<AclSkeleton />}>
          <AclWorkspace ctx={ctx} />
        </Suspense>
      </div>
    </ConsoleShell>
  );
}

function AclSkeleton() {
  return (
    <>
      <Section title="Default">
        <Skeleton lines={2} label="Loading access policy" />
      </Section>
      <Section title="Rules">
        <SkeletonTable rows={4} label="Loading rules" />
      </Section>
    </>
  );
}

async function AclWorkspace({ ctx }: { ctx: ConsoleContext }) {
  let initialAcl = '{\n  "groups": {},\n  "rules": []\n}';
  let error: string | null = null;
  try {
    const acl = await getAcl(ctx);
    initialAcl = JSON.stringify(acl, null, 2);
  } catch (err) {
    error = errorText(err, "Could not load access policy.");
  }
  const [memberships, nodes, postureChecks] = await Promise.all([
    listMemberships(ctx.organisationId).catch(() => []),
    listNodes(ctx).catch(() => null),
    listPostureChecks(ctx).catch(() => null),
  ]);
  const people = memberships
    .filter((row) => row.status === "active")
    .map((row) => ({
      userId: row.userId,
      email: row.email,
      name: row.name,
    }));
  const devices = (nodes ?? [])
    .filter((node) => !node.revoked && !node.deleted)
    .map((node) => ({
      id: node.id,
      label: `${node.display_name || node.name} (${node.os ?? "OS not reported"})`,
      os: node.os ?? null,
    }));

  return (
    <>
      {error ? (
        <Alert tone="error" title="Access policy couldn't be loaded">
          {error} Editing is turned off so nothing overwrites the published policy.
        </Alert>
      ) : (
        <AclEditor
          initialAcl={initialAcl}
          role={ctx.role}
          people={people}
          postureChecks={postureChecks?.map((check) => check.name) ?? []}
        />
      )}
      {nodes === null ? (
        <Section id="explain" title="Explain access">
          <Alert tone="error" title="Devices couldn't be loaded">
            Access can&apos;t be explained until the device list loads. Reload the page in a moment.
          </Alert>
        </Section>
      ) : (
        <ExplainAccessPanel
          devices={devices}
          people={people}
          organisationName={ctx.organisationName}
          role={ctx.role}
        />
      )}
    </>
  );
}
