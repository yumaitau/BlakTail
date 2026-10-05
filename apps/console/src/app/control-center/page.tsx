import { Suspense } from "react";
import Link from "next/link";
import { errorText } from "@/lib/server-errors";
import { ConsoleShell } from "@/components/console-shell";
import { ControlCenter } from "@/components/control-center/control-center";
import { Alert } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import { getTopology, type Topology } from "@/lib/coord-topology";
import {
  requireConsoleContext,
  requireOrganisationContext,
  type ConsoleContext,
} from "@/lib/session";

function one(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

type Initial = {
  tab?: string;
  device?: string;
  selector?: string;
  network?: string;
  view?: string;
};

async function Graph({ ctx, initial }: { ctx: ConsoleContext; initial: Initial }) {
  let topology: Topology | null = null;
  let error: string | null = null;
  try {
    topology = await getTopology(ctx);
  } catch (err) {
    error = errorText(err, "Could not load the topology.");
  }
  if (!topology) {
    return (
      <div className="cc-error">
        <Alert
          tone="error"
          title="The Control Center couldn't reach the coordinator"
          action={
            <Link className="button secondary" href="/status">
              Check status
            </Link>
          }
        >
          <p>{error}</p>
          <p>
            Devices that are already connected keep working without the coordinator. Reload this
            page in a moment.
          </p>
        </Alert>
      </div>
    );
  }
  return <ControlCenter topology={topology} initial={initial} />;
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
  const initial: Initial = {
    tab: one(params.tab),
    device: one(params.device),
    selector: one(params.selector),
    network: one(params.network),
    view: one(params.view),
  };

  return (
    <ConsoleShell ctx={ctx} current="/control-center" bleed>
      <h1 className="visually-hidden">Control Center</h1>
      <Suspense
        fallback={
          <div className="cc-loading">
            <Skeleton lines={4} label="Loading the Control Center" />
          </div>
        }
      >
        <Graph ctx={ctx} initial={initial} />
      </Suspense>
    </ConsoleShell>
  );
}
