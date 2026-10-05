import { Suspense } from "react";
import Link from "next/link";
import { errorText } from "@/lib/server-errors";
import { ConsoleShell } from "@/components/console-shell";
import { PageHeader } from "@/components/page-header";
import { ServiceCaPanel } from "@/components/services/service-ca";
import { ServiceManager } from "@/components/services/service-manager";
import { Alert } from "@/components/ui/alert";
import { PermissionNotice } from "@/components/ui/permission-notice";
import { Section } from "@/components/ui/section";
import { SkeletonTable } from "@/components/ui/skeleton";
import { listNodes } from "@/lib/coord";
import { listServices, type ServiceWorkspace } from "@/lib/coord-services";
import { permissionReason } from "@/lib/roles";
import { requireConsoleContext, type ConsoleContext } from "@/lib/session";

async function ServicesBody({ ctx }: { ctx: ConsoleContext }) {
  let workspace: ServiceWorkspace | null = null;
  let error: string | null = null;
  try {
    workspace = await listServices(ctx);
  } catch (err) {
    error = errorText(err, "Could not load private services.");
  }
  if (!workspace) {
    return (
      <Alert tone="error" title="Couldn't load private services">
        {error}
      </Alert>
    );
  }
  const nodes = await listNodes(ctx).catch(() => []);
  const devices = nodes
    .filter((node) => !node.revoked && !node.deleted && !node.expired)
    .map((node) => ({ id: node.id, label: node.display_name || node.name }));

  return (
    <>
      <ServiceManager
        services={workspace.services}
        devices={devices}
        namespace={workspace.namespace}
        readOnlyReason={permissionReason(ctx.role, "manage_services")}
      />
      <ServiceCaPanel ca={workspace.ca} />
    </>
  );
}

export default async function ServicesPage() {
  const ctx = await requireConsoleContext();
  const readOnlyReason = permissionReason(ctx.role, "manage_services");

  return (
    <ConsoleShell ctx={ctx} current="/services">
      <div className="stack">
        <PageHeader
          eyebrow="Services"
          title="Private services"
          description="Organisation-owned private HTTPS names for services running on your devices. Private only: nothing here is published to the Internet."
          actions={
            readOnlyReason ? null : (
              <Link className="button" href="#create">
                New service
              </Link>
            )
          }
        />
        {readOnlyReason ? <PermissionNotice reason={readOnlyReason} /> : null}
        <Suspense
          fallback={
            <Section title="Services">
              <SkeletonTable rows={3} label="Loading private services" />
            </Section>
          }
        >
          <ServicesBody ctx={ctx} />
        </Suspense>
      </div>
    </ConsoleShell>
  );
}
