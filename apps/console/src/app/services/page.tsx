import { ConsoleShell } from "@/components/console-shell";
import { PageHeader } from "@/components/page-header";
import { ServiceCaPanel } from "@/components/services/service-ca";
import { ServiceManager } from "@/components/services/service-manager";
import { listNodes } from "@/lib/coord";
import { listServices, type ServiceWorkspace } from "@/lib/coord-services";
import { permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

export default async function ServicesPage() {
  const ctx = await requireConsoleContext();
  let workspace: ServiceWorkspace | null = null;
  let error: string | null = null;
  try {
    workspace = await listServices(ctx);
  } catch (err) {
    error = err instanceof Error ? err.message : "Could not load private services.";
  }
  const nodes = await listNodes(ctx).catch(() => []);
  const devices = nodes
    .filter((node) => !node.revoked && !node.deleted && !node.expired)
    .map((node) => ({ id: node.id, label: node.display_name || node.name }));

  return (
    <ConsoleShell ctx={ctx} current="/services">
      <div className="stack">
        <PageHeader
          eyebrow="Services"
          title="Private services"
          description="Organisation-owned private HTTPS names for services running on your devices. Private only: nothing here is published to the Internet."
        />
        {workspace ? (
          <>
            <ServiceManager
              services={workspace.services}
              devices={devices}
              namespace={workspace.namespace}
              organisationName={ctx.organisationName}
              roleLabel={roleLabel(ctx.role).toLowerCase()}
              readOnlyReason={permissionReason(ctx.role, "manage_services")}
            />
            <ServiceCaPanel ca={workspace.ca} />
          </>
        ) : (
          <div className="panel stack">
            <h2>Private services unavailable</h2>
            <p className="error">{error}</p>
            <p className="muted">
              Check that the coordinator is reachable, then reload this page.
            </p>
          </div>
        )}
      </div>
    </ConsoleShell>
  );
}
