import { Suspense } from "react";
import { errorText } from "@/lib/server-errors";
import { ConsoleShell } from "@/components/console-shell";
import { EnrolmentWorkspace } from "@/components/enrolment-workspace";
import { PageHeader } from "@/components/page-header";
import { Section } from "@/components/ui/section";
import { Skeleton, SkeletonTable } from "@/components/ui/skeleton";
import { agentCoordinatorUrl, listJoinKeys, type JoinKeySummary } from "@/lib/coord-peers";
import { can } from "@/lib/roles";
import { requireConsoleContext, type ConsoleContext } from "@/lib/session";

async function JoinKeys({ ctx }: { ctx: ConsoleContext }) {
  let keys: JoinKeySummary[] = [];
  let loadError: string | null = null;
  if (can(ctx.role, "manage_join_keys")) {
    try {
      keys = await listJoinKeys(ctx);
    } catch (error) {
      loadError = errorText(error, "Could not load join keys.");
    }
  }
  return (
    <EnrolmentWorkspace
      keys={keys}
      loadError={loadError}
      organisationId={ctx.organisationId}
      organisationName={ctx.organisationName}
      role={ctx.role}
      coordinatorUrl={agentCoordinatorUrl()}
    />
  );
}

function JoinKeysSkeleton() {
  return (
    <div className="stack">
      <Section id="mint" title="Mint a join key">
        <Skeleton lines={4} label="Loading" />
      </Section>
      <Section id="keys" title="Keys">
        <SkeletonTable rows={4} label="Loading join keys" />
      </Section>
    </div>
  );
}

export default async function JoinKeysPage() {
  const ctx = await requireConsoleContext();

  return (
    <ConsoleShell ctx={ctx} current="/join-keys">
      <div className="stack">
        <PageHeader
          eyebrow="Enrolment"
          title="Join keys"
          description={`Enrol devices into ${ctx.organisationName} without a browser. Browser approval (blaktaild up with no key) remains the default for people enrolling their own machine.`}
        />
        {can(ctx.role, "manage_join_keys") ? (
          <ol className="ceremony" aria-label="Join-key steps">
            <li>Network</li>
            <li aria-current="step">Mint key</li>
            <li>Show once</li>
            <li>Enrol device</li>
          </ol>
        ) : null}
        <Suspense fallback={<JoinKeysSkeleton />}>
          <JoinKeys ctx={ctx} />
        </Suspense>
      </div>
    </ConsoleShell>
  );
}
