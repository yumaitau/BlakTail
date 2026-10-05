import { Suspense } from "react";
import { errorText } from "@/lib/server-errors";
import { ConsoleShell } from "@/components/console-shell";
import {
  Alert,
  Card,
  EmptyState,
  PageHeader,
  Section,
  SkeletonTable,
  StatusPill,
  Table,
  Td,
} from "@/components/ui";
import {
  getConsoleOperations,
  getOperationsHealth,
  type ConsoleOperations,
  type OperationsHealth,
} from "@/lib/coord-operations";
import { formatDateTime } from "@/lib/format-time";
import { permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext, type ConsoleContext } from "@/lib/session";

const RELAY_LABEL: Record<string, { label: string; tone: "success" | "danger" | "warning" | "muted" }> = {
  reachable: { label: "Reachable", tone: "success" },
  unreachable: { label: "No answer", tone: "danger" },
  unresolved: { label: "Name didn't resolve", tone: "danger" },
  not_probed: { label: "Not checked", tone: "muted" },
};

function Stat({ label, value, warn = false }: { label: string; value: number; warn?: boolean }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>
        {value.toLocaleString("en-AU")}
        {warn && value > 0 ? <StatusPill tone="warning">Check</StatusPill> : null}
      </dd>
    </div>
  );
}

export default async function OperationsPage() {
  const ctx = await requireConsoleContext();
  const denied = permissionReason(ctx.role, "view_operations");
  return (
    <ConsoleShell ctx={ctx} current="/operations">
      <div className="stack">
        <PageHeader
          title="Operator health"
          description="Versions, schema, relays, the webhook queue, expiring credentials and backup proof for this deployment. Read-only, and never shows keys, tokens or webhook addresses."
        />
        <p className="page-context">
          {ctx.organisationName} · {roleLabel(ctx.role)}
        </p>
        {denied ? (
          <Alert tone="info" title="Operator health isn't available to your role">
            {denied}
          </Alert>
        ) : (
          <Suspense
            fallback={
              <Card>
                <SkeletonTable rows={5} label="Loading operator health" />
              </Card>
            }
          >
            <OperationsContent ctx={ctx} />
          </Suspense>
        )}
      </div>
    </ConsoleShell>
  );
}

async function OperationsContent({ ctx }: { ctx: ConsoleContext }) {
  let health: OperationsHealth | null = null;
  let consoleOps: ConsoleOperations | null = null;
  let error: string | null = null;
  try {
    [health, consoleOps] = await Promise.all([getOperationsHealth(ctx), getConsoleOperations(ctx)]);
  } catch (err) {
    error = errorText(err, "Could not load operator health.");
  }
  if (!health || !consoleOps) {
    return (
      <Alert tone="error" title="Operator health couldn't be loaded">
        <p>{error}</p>
        <p>Check that the coordinator is running and trusts this console, then reload.</p>
      </Alert>
    );
  }
  const schemaCurrent = health.schema.status === "current";

  return (
    <>
      <Section
        id="components"
        title="Components"
        description="Relay and agent versions aren't reported to the coordinator. Check relays on their private metrics endpoint and agents on Devices."
      >
        <Table label="Components" mobile="stack">
          <thead>
            <tr>
              <th scope="col">Component</th>
              <th scope="col">Version</th>
              <th scope="col">State</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <Td label="Component">Console</Td>
              <Td label="Version" className="mono">
                {consoleOps.version}
              </Td>
              <Td label="State">
                Database migrations applied: {consoleOps.migrations.applied ?? "unknown"}
                {consoleOps.migrations.packaged !== null
                  ? ` of ${consoleOps.migrations.packaged}`
                  : " (migration list not packaged)"}
              </Td>
            </tr>
            <tr>
              <Td label="Component">Coordinator</Td>
              <Td label="Version" className="mono">
                {health.coordinator.version}
              </Td>
              <Td label="State">
                {health.coordinator.region} · {health.coordinator.database_backend}
              </Td>
            </tr>
            <tr>
              <Td label="Component">Coordinator schema</Td>
              <Td label="Version" className="mono">
                {health.schema.applied_version} of {health.schema.supported_version}
              </Td>
              <Td label="State">
                <StatusPill tone={schemaCurrent ? "success" : "danger"}>
                  {schemaCurrent
                    ? "Current"
                    : health.schema.status === "behind"
                      ? "Behind: run blaktail-coord migrate"
                      : "Ahead of this binary: roll forward"}
                </StatusPill>
                <span className="cell-sub mono">{health.schema.latest_migration}</span>
              </Td>
            </tr>
          </tbody>
        </Table>
      </Section>

      <Section
        id="relays"
        title="Relays"
        description="Checked just now from the coordinator with a short-lived credential. This proves the relay answers the coordinator, not that every device can reach it. Agents use the first healthy relay in this order."
      >
        {health.relays.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No relays configured"
            body="Devices connect directly over UDP only. Add relays in the coordinator configuration for networks that block direct connections."
          />
        ) : (
          <Table label="Relays" mobile="stack">
            <thead>
              <tr>
                <th scope="col">Relay</th>
                <th scope="col">Region</th>
                <th scope="col">State</th>
                <th scope="col">Round trip</th>
              </tr>
            </thead>
            <tbody>
              {health.relays.map((relay) => {
                const state = RELAY_LABEL[relay.status] ?? { label: relay.status, tone: "muted" as const };
                return (
                  <tr key={relay.endpoint}>
                    <Td label="Relay" className="mono">
                      {relay.endpoint}
                    </Td>
                    <Td label="Region">{relay.region}</Td>
                    <Td label="State">
                      <StatusPill tone={state.tone}>{state.label}</StatusPill>
                      {relay.status === "not_probed" ? (
                        <span className="cell-sub">No relay secret, or over the check limit</span>
                      ) : null}
                    </Td>
                    <Td label="Round trip">{relay.round_trip_ms !== null ? `${relay.round_trip_ms} ms` : "—"}</Td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        )}
      </Section>

      <Section
        id="queues"
        title="Webhook queue and expiry"
        description="The coordinator's own TLS certificate is managed by your proxy or load balancer and isn't shown here."
      >
        <dl className="stat-list">
          <Stat label="Webhook deliveries waiting" value={health.webhooks.pending} />
          <Stat label="Due now" value={health.webhooks.due_now} />
          <Stat label="Gave up after retries" value={health.webhooks.dead_letters} warn />
          <Stat label="Device credentials expired" value={health.expiry.node_credentials_expired} warn />
          <Stat label="Device credentials expiring in 14 days" value={health.expiry.node_credentials_expiring_14_days} warn />
          <Stat label="Service certificates expiring in 30 days" value={health.expiry.service_certificates_expiring_30_days} warn />
          <Stat label="Service CA expiring in 30 days" value={health.expiry.service_ca_expiring_30_days} warn />
          <Stat label="API clients expiring in 14 days" value={health.expiry.api_clients_expiring_14_days} warn />
        </dl>
        <p className="muted">
          {health.webhooks.oldest_pending_age_seconds !== null
            ? `Oldest waiting delivery: ${Math.round(health.webhooks.oldest_pending_age_seconds / 60)} minutes. `
            : ""}
          Single sign-on providers: {consoleOps.sso.enabled} enabled of {consoleOps.sso.configured} configured.
        </p>
      </Section>

      <Section
        id="backup"
        title="Last backup proof"
        description="What your backup job wrote to BLAKTAIL_BACKUP_PROOF_FILE. BlakTail doesn't check the backup itself; see the backup and restore runbook in docs/upgrades.md."
        actions={
          <StatusPill tone={health.backup.status === "recorded" ? "success" : "warning"}>
            {health.backup.status === "recorded"
              ? "Recorded"
              : health.backup.status === "unreadable"
                ? "Proof file unreadable"
                : "Not recorded"}
          </StatusPill>
        }
      >
        {health.backup.status === "recorded" ? (
          <dl className="detail-list">
            <dt>Backup completed</dt>
            <dd>{formatDateTime(health.backup.completed_at, "Not recorded")}</dd>
            <dt>Restore last checked</dt>
            <dd>{formatDateTime(health.backup.restore_verified_at, "Not recorded")}</dd>
            {health.backup.label ? (
              <>
                <dt>Label</dt>
                <dd>{health.backup.label}</dd>
              </>
            ) : null}
          </dl>
        ) : (
          <Alert tone="warning">The operator hasn&apos;t recorded a backup on this coordinator.</Alert>
        )}
        <p className="muted">Generated {formatDateTime(health.generated_at)}.</p>
      </Section>
    </>
  );
}
