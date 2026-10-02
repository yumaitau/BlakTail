import { AclEditor } from "@/components/acl-editor";
import { ConsoleShell } from "@/components/console-shell";
import { ExplainAccessPanel } from "@/components/explain-access-panel";
import { PageHeader } from "@/components/page-header";
import { getAcl, listNodes } from "@/lib/coord";
import { listPostureChecks } from "@/lib/coord-policy";
import { listMemberships } from "@/lib/oidc";
import { requireConsoleContext } from "@/lib/session";

export default async function AclsPage() {
  const ctx = await requireConsoleContext();
  let initialAcl = '{\n  "groups": {},\n  "rules": []\n}';
  let error: string | null = null;
  try {
    const acl = await getAcl(ctx);
    initialAcl = JSON.stringify(acl, null, 2);
  } catch (err) {
    error = err instanceof Error ? err.message : "Could not load access policy.";
  }
  const memberships = (await listMemberships(ctx.organisationId).catch(() => []))
    .filter((row) => row.status === "active");
  const people = memberships.map((row) => ({
    userId: row.userId,
    email: row.email,
    name: row.name,
  }));
  const [nodes, postureChecks] = await Promise.all([
    listNodes(ctx).catch(() => null),
    listPostureChecks(ctx).catch(() => null),
  ]);
  const devices = (nodes ?? [])
    .filter((node) => !node.revoked && !node.deleted)
    .map((node) => ({
      id: node.id,
      label: `${node.display_name || node.name} (${node.os ?? "OS not reported"})`,
      os: node.os ?? null,
    }));

  return (
    <ConsoleShell ctx={ctx} current="/acls">
      <div className="stack">
        <PageHeader
          title="Access"
          description="New organisations start deny-all. Existing documents keep the visible same-tag legacy default until you switch them to deny."
        />
        <div className="panel stack">
          {error ? <p className="error">{error}</p> : null}
          <AclEditor
            initialAcl={initialAcl}
            role={ctx.role}
            people={people}
            postureChecks={postureChecks?.map((check) => check.name) ?? []}
          />
        </div>
        <div className="panel stack">
          {nodes === null ? (
            <p className="error" role="alert">
              Could not load devices, so access cannot be explained right now.
            </p>
          ) : (
            <ExplainAccessPanel
              devices={devices}
              people={people}
              organisationName={ctx.organisationName}
              role={ctx.role}
            />
          )}
        </div>
      </div>
    </ConsoleShell>
  );
}
