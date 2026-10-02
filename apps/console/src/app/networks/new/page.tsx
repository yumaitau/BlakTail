import Link from "next/link";
import { ConsoleShell } from "@/components/console-shell";
import { NetworkResourceForm } from "@/components/network-resource-form";
import { PageHeader } from "@/components/page-header";
import { requireConsoleContext } from "@/lib/session";
import { resourceFormChoices } from "../choices";

export default async function NewNetworkResourcePage() {
  const ctx = await requireConsoleContext();
  let choices: Awaited<ReturnType<typeof resourceFormChoices>> = { peers: [], groups: [] };
  let error: string | null = null;
  try {
    choices = await resourceFormChoices(ctx);
  } catch (err) {
    error = err instanceof Error ? err.message : "Could not load devices and policy groups.";
  }

  return (
    <ConsoleShell ctx={ctx} current="/networks">
      <div className="stack">
        <p>
          <Link href="/networks">← Networks</Link>
        </p>
        <PageHeader
          eyebrow={ctx.organisationName}
          title="New network resource"
          description="Name the destination, pick the routing peers that carry it, choose who receives it, then check for overlaps before saving."
        />
        {error ? (
          <p className="error" role="alert">
            {error}
          </p>
        ) : (
          <NetworkResourceForm
            organisationId={ctx.organisationId}
            organisationName={ctx.organisationName}
            role={ctx.role}
            peers={choices.peers}
            groups={choices.groups}
          />
        )}
      </div>
    </ConsoleShell>
  );
}
