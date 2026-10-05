import { Suspense } from "react";
import { errorText } from "@/lib/server-errors";
import { ConsoleShell } from "@/components/console-shell";
import { Alert, Card, PageHeader, Section, Skeleton, StatusPill } from "@/components/ui";
import { getCoordHealth } from "@/lib/coord";
import { requireConsoleContext } from "@/lib/session";

export default async function StatusPage() {
  const ctx = await requireConsoleContext();
  return (
    <ConsoleShell ctx={ctx} current="/status">
      <div className="stack">
        <PageHeader
          title="Status"
          description="Whether the onshore coordinator that holds your network's state is answering."
        />
        <Suspense
          fallback={
            <Card>
              <Skeleton lines={3} label="Checking the coordinator" />
            </Card>
          }
        >
          <CoordinatorStatus />
        </Suspense>
      </div>
    </ConsoleShell>
  );
}

async function CoordinatorStatus() {
  let health: Awaited<ReturnType<typeof getCoordHealth>> | null = null;
  let error: string | null = null;
  try {
    health = await getCoordHealth();
  } catch (err) {
    error = errorText(err, "Could not reach the coordinator.");
  }

  return (
    <Section
      title="Coordinator"
      description="Device reachability is on Devices. Component versions and relay checks are on Operator health."
      actions={
        <StatusPill tone={health ? "success" : "danger"}>{health ? "Available" : "Unreachable"}</StatusPill>
      }
    >
      {health ? (
        <dl className="detail-list">
          <dt>Health check</dt>
          <dd>{health.status}</dd>
          <dt>Data location</dt>
          <dd>
            <span className="region-mark">
              <span className="region-dot" aria-hidden="true" />
              <strong>Onshore</strong>
              <span>Sydney, Australia · ap-southeast-2</span>
            </span>
          </dd>
        </dl>
      ) : (
        <Alert tone="error" title="The coordinator isn't answering">
          <p>{error}</p>
          <p>
            Devices keep their last approved configuration until it answers again. Check that the
            coordinator is running and that its TLS certificate is the one this console trusts, then
            reload this page.
          </p>
        </Alert>
      )}
    </Section>
  );
}
