import { ConsoleShell } from "@/components/console-shell";
import { EnrolmentWorkspace } from "@/components/enrolment-workspace";
import { PageHeader } from "@/components/page-header";
import { agentCoordinatorUrl, listJoinKeys, type JoinKeySummary } from "@/lib/coord-peers";
import { can } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

export default async function JoinKeysPage() {
  const ctx = await requireConsoleContext();
  let keys: JoinKeySummary[] = [];
  let loadError: string | null = null;
  if (can(ctx.role, "manage_join_keys")) {
    try {
      keys = await listJoinKeys(ctx);
    } catch (error) {
      loadError = error instanceof Error ? error.message : "Could not load join keys.";
    }
  }

  return (
    <ConsoleShell ctx={ctx} current="/join-keys">
      <div className="stack">
        <PageHeader
          eyebrow="Enrolment"
          title="Join keys"
          description={`Enrol devices into ${ctx.organisationName} without a browser. Browser approval (blaktaild up with no key) remains the default for people enrolling their own machine.`}
        />
        <ol className="ceremony" aria-label="Join-key ceremony">
          <li>Network</li>
          <li aria-current="step">Mint key</li>
          <li>Show once</li>
          <li>Enrol device</li>
        </ol>
        <EnrolmentWorkspace
          keys={keys}
          loadError={loadError}
          organisationId={ctx.organisationId}
          organisationName={ctx.organisationName}
          role={ctx.role}
          coordinatorUrl={agentCoordinatorUrl()}
        />
      </div>
    </ConsoleShell>
  );
}
