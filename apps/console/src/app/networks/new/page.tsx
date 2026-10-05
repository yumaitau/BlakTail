import { Suspense } from "react";
import Link from "next/link";
import { errorText } from "@/lib/server-errors";
import { ConsoleShell } from "@/components/console-shell";
import { NetworkResourceForm } from "@/components/network-resource-form";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/ui/alert";
import { PermissionNotice } from "@/components/ui/permission-notice";
import { Section } from "@/components/ui/section";
import { Skeleton } from "@/components/ui/skeleton";
import { can, permissionReason } from "@/lib/roles";
import { requireConsoleContext, type ConsoleContext } from "@/lib/session";
import { resourceFormChoices } from "../choices";

async function NewResourceForm({ ctx }: { ctx: ConsoleContext }) {
  let choices: Awaited<ReturnType<typeof resourceFormChoices>> = { peers: [], groups: [] };
  try {
    choices = await resourceFormChoices(ctx);
  } catch (err) {
    return (
      <Alert tone="error" title="Couldn't load devices and policy groups">
        {errorText(err, "Could not load devices and policy groups.")}
      </Alert>
    );
  }
  return (
    <Section title="Resource" description="Four short steps. Nothing is saved until you create it.">
      <NetworkResourceForm
        organisationId={ctx.organisationId}
        role={ctx.role}
        peers={choices.peers}
        groups={choices.groups}
      />
    </Section>
  );
}

export default async function NewNetworkResourcePage() {
  const ctx = await requireConsoleContext();
  const denied = permissionReason(ctx.role, "manage_networks");

  return (
    <ConsoleShell ctx={ctx} current="/networks">
      <div className="stack">
        <Link className="back-link" href="/networks">
          ← Networks
        </Link>
        <PageHeader
          eyebrow={ctx.organisationName}
          title="New network resource"
          description="Name the destination, pick the routing peers that carry it, choose who receives it, then check for overlaps before saving."
        />
        {!can(ctx.role, "manage_networks") && denied ? (
          <PermissionNotice reason={denied} />
        ) : (
          <Suspense
            fallback={
              <Section title="Resource">
                <Skeleton lines={6} label="Loading devices and policy groups" />
              </Section>
            }
          >
            <NewResourceForm ctx={ctx} />
          </Suspense>
        )}
      </div>
    </ConsoleShell>
  );
}
