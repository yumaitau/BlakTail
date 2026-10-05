import { errorText } from "@/lib/server-errors";
import Link from "next/link";
import { ConsoleShell } from "@/components/console-shell";
import { ControlCenter } from "@/components/control-center/control-center";
import { getTopology, type Topology } from "@/lib/coord-topology";
import { requireConsoleContext, requireOrganisationContext } from "@/lib/session";

function one(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export default async function ControlCenterPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const organisation = one(params.organisation);
  // Deep links may name an organisation; membership is checked.
  const ctx = organisation
    ? await requireOrganisationContext(organisation)
    : await requireConsoleContext();

  let topology: Topology | null = null;
  let error: string | null = null;
  try {
    topology = await getTopology(ctx);
  } catch (err) {
    error = errorText(err, "Could not load the topology.");
  }

  return (
    <ConsoleShell ctx={ctx} current="/control-center" bleed>
      <h1 className="visually-hidden">Control Center</h1>
      {topology ? (
        <ControlCenter
          topology={topology}
          initial={{
            tab: one(params.tab),
            device: one(params.device),
            selector: one(params.selector),
            network: one(params.network),
            view: one(params.view),
          }}
        />
      ) : (
        <div className="cc-error panel" role="alert">
          <h2>Coordinator unavailable</h2>
          <p className="error">{error}</p>
          <p className="muted">
            This says nothing about whether devices can still reach each other; existing tunnels
            keep working without the coordinator. See <Link href="/status">Status</Link>.
          </p>
        </div>
      )}
    </ConsoleShell>
  );
}
