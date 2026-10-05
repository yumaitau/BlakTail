import { errorText } from "@/lib/server-errors";
import { ConsoleShell } from "@/components/console-shell";
import { IngressManager } from "@/components/ingress/ingress-manager";
import { PageHeader } from "@/components/page-header";
import { listNodes } from "@/lib/coord";
import { getIngressWorkspace, type IngressWorkspace } from "@/lib/coord-ingress";
import { listServices } from "@/lib/coord-services";
import { can, permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

export default async function IngressPage() {
  const ctx = await requireConsoleContext();
  let workspace: IngressWorkspace | null = null;
  let error: string | null = null;
  try {
    workspace = await getIngressWorkspace(ctx);
  } catch (err) {
    error = errorText(err, "Could not load public ingress.");
  }
  const canManage = can(ctx.role, "manage_public_ingress");
  const [nodes, services] = canManage
    ? await Promise.all([
        listNodes(ctx).catch(() => []),
        listServices(ctx)
          .then((workspace) => workspace.services)
          .catch(() => []),
      ])
    : [[], []];
  const devices = nodes
    .filter((node) => !node.revoked && !node.deleted && !node.expired)
    .map((node) => ({ id: node.id, label: node.display_name || node.name }));
  const httpServices = services
    .filter((service) => service.enabled && service.protocol === "http")
    .map((service) => ({ id: service.id, label: `${service.name} (${service.fqdn})` }));

  return (
    <ConsoleShell ctx={ctx} current="/ingress">
      <div className="stack">
        <PageHeader
          eyebrow="Services"
          title="Public ingress"
          description="PUBLIC: routes here put a service on the Internet through an ingress host your organisation runs onshore. Anyone who can reach the ingress can reach the route, subject to its sign-in and limits. Private services stay on the Private services page."
        />
        {workspace ? (
          <IngressManager
            workspace={workspace}
            devices={devices}
            services={httpServices}
            organisationName={ctx.organisationName}
            roleLabel={roleLabel(ctx.role).toLowerCase()}
            ownerReason={permissionReason(ctx.role, "manage_public_ingress")}
            canEmergencyDisable={
              can(ctx.role, "manage_services") || can(ctx.role, "manage_public_ingress")
            }
          />
        ) : (
          <div className="panel stack">
            <h2>Public ingress unavailable</h2>
            <p className="error">{error}</p>
            <p className="muted">Check that the coordinator is reachable, then reload this page.</p>
          </div>
        )}
      </div>
    </ConsoleShell>
  );
}
