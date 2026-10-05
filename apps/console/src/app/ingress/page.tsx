import { Suspense } from "react";
import { errorText } from "@/lib/server-errors";
import { ConsoleShell } from "@/components/console-shell";
import { IngressManager } from "@/components/ingress/ingress-manager";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/ui/alert";
import { Section } from "@/components/ui/section";
import { Skeleton } from "@/components/ui/skeleton";
import { listNodes } from "@/lib/coord";
import { getIngressWorkspace, type IngressWorkspace } from "@/lib/coord-ingress";
import { listServices } from "@/lib/coord-services";
import { unixNow } from "@/lib/format-time";
import { can, permissionReason } from "@/lib/roles";
import { requireConsoleContext, type ConsoleContext } from "@/lib/session";

async function IngressBody({ ctx }: { ctx: ConsoleContext }) {
  let workspace: IngressWorkspace | null = null;
  let error: string | null = null;
  try {
    workspace = await getIngressWorkspace(ctx);
  } catch (err) {
    error = errorText(err, "Could not load public ingress.");
  }
  if (!workspace) {
    return (
      <Alert tone="error" title="Couldn't load public ingress">
        {error}
      </Alert>
    );
  }
  const canManage = can(ctx.role, "manage_public_ingress");
  const [nodes, services] = canManage
    ? await Promise.all([
        listNodes(ctx).catch(() => []),
        listServices(ctx)
          .then((result) => result.services)
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
    <IngressManager
      workspace={workspace}
      devices={devices}
      services={httpServices}
      ownerReason={permissionReason(ctx.role, "manage_public_ingress")}
      canEmergencyDisable={can(ctx.role, "manage_services") || canManage}
      now={unixNow()}
    />
  );
}

export default async function IngressPage() {
  const ctx = await requireConsoleContext();

  return (
    <ConsoleShell ctx={ctx} current="/ingress">
      <div className="stack">
        <PageHeader
          eyebrow="Services"
          title="Public ingress"
          description="Routes here put a service on the Internet through an ingress host your organisation runs onshore. Anyone who can reach the ingress can reach the route, subject to its sign-in and limits. Private services stay on the Private services page."
        />
        <Suspense
          fallback={
            <Section title="Organisation setting">
              <Skeleton lines={4} label="Loading public ingress" />
            </Section>
          }
        >
          <IngressBody ctx={ctx} />
        </Suspense>
      </div>
    </ConsoleShell>
  );
}
