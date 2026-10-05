import { errorText } from "@/lib/server-errors";
import { ConsoleShell } from "@/components/console-shell";
import { PageHeader } from "@/components/page-header";
import {
  getConsoleOperations,
  getOperationsHealth,
  type ConsoleOperations,
  type OperationsHealth,
} from "@/lib/coord-operations";
import { permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

function when(seconds: number | null): string {
  if (!seconds) return "not recorded";
  return new Date(seconds * 1000).toLocaleString("en-AU", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function Count({ value, warn }: { value: number; warn?: boolean }) {
  return (
    <span className={value > 0 && warn ? "badge pending" : "badge"}>
      {value}
    </span>
  );
}

const RELAY_LABEL: Record<string, string> = {
  reachable: "Reachable from the coordinator",
  unreachable: "No answer to an authenticated probe",
  unresolved: "Name did not resolve",
  not_probed: "Not probed (no relay secret, or over the probe limit)",
};

export default async function OperationsPage() {
  const ctx = await requireConsoleContext();
  const denied = permissionReason(ctx.role, "view_operations");
  let health: OperationsHealth | null = null;
  let consoleOps: ConsoleOperations | null = null;
  let error: string | null = null;
  if (!denied) {
    try {
      [health, consoleOps] = await Promise.all([
        getOperationsHealth(ctx),
        getConsoleOperations(ctx),
      ]);
    } catch (err) {
      error = errorText(err, "Could not load operator health.");
    }
  }

  return (
    <ConsoleShell ctx={ctx} current="/operations">
      <div className="stack">
        <PageHeader
          title="Operator health"
          description="Versions, schema, relays, outbox, expiry and backup proof for this deployment. Read-only and never shows keys, tokens or webhook addresses."
        />
        <p className="muted">
          {ctx.organisationName} · {roleLabel(ctx.role)}
        </p>
        {denied ? (
          <div className="panel stack">
            <p role="note">{denied}</p>
          </div>
        ) : null}
        {error ? (
          <div className="panel stack">
            <p className="error" role="alert">
              {error}
            </p>
            <p className="muted">
              Check that the coordinator is running and trusts this console, then reload.
            </p>
          </div>
        ) : null}
        {health && consoleOps ? (
          <>
            <section className="panel stack" aria-labelledby="ops-components">
              <h2 id="ops-components">Components</h2>
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th scope="col">Component</th>
                      <th scope="col">Version</th>
                      <th scope="col">State</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>Console</td>
                      <td className="mono">{consoleOps.version}</td>
                      <td>
                        Drizzle migrations applied:{" "}
                        {consoleOps.migrations.applied ?? "unknown"}
                        {consoleOps.migrations.packaged !== null
                          ? ` of ${consoleOps.migrations.packaged} packaged`
                          : " (journal not packaged)"}
                      </td>
                    </tr>
                    <tr>
                      <td>Coordinator</td>
                      <td className="mono">{health.coordinator.version}</td>
                      <td>
                        {health.coordinator.region} · {health.coordinator.database_backend}
                      </td>
                    </tr>
                    <tr>
                      <td>Coordinator schema</td>
                      <td className="mono">
                        {health.schema.applied_version} / {health.schema.supported_version}
                      </td>
                      <td>
                        <span
                          className={
                            health.schema.status === "current" ? "badge online" : "badge revoked"
                          }
                        >
                          {health.schema.status === "current"
                            ? "Current"
                            : health.schema.status === "behind"
                              ? "Behind: run blaktail-coord migrate"
                              : "Ahead of this binary: roll forward"}
                        </span>{" "}
                        {health.schema.latest_migration}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <p className="muted">
                Relay and agent versions are not reported to the coordinator. Check
                relays with their private metrics endpoint and agents on Devices.
              </p>
            </section>

            <section className="panel stack" aria-labelledby="ops-relays">
              <h2 id="ops-relays">Relays</h2>
              <p className="muted">
                Probed now from the coordinator with an authenticated, short-lived
                capability. This proves the relay answers the coordinator, not that
                every device can reach it. Agents use the first healthy relay in
                this order.
              </p>
              {health.relays.length === 0 ? (
                <p className="muted">No relays are configured. Devices use direct UDP only.</p>
              ) : (
                <ol className="stack">
                  {health.relays.map((relay) => (
                    <li key={relay.endpoint}>
                      <span className="mono">{relay.endpoint}</span> · {relay.region} ·{" "}
                      <span
                        className={
                          relay.status === "reachable" ? "badge online" : "badge revoked"
                        }
                      >
                        {RELAY_LABEL[relay.status] ?? relay.status}
                      </span>
                      {relay.round_trip_ms !== null ? ` · ${relay.round_trip_ms} ms` : ""}
                    </li>
                  ))}
                </ol>
              )}
            </section>

            <section className="panel stack" aria-labelledby="ops-queues">
              <h2 id="ops-queues">Webhook outbox and expiry</h2>
              <ul className="stack">
                <li>
                  Webhook deliveries pending <Count value={health.webhooks.pending} />, due now{" "}
                  <Count value={health.webhooks.due_now} />, dead letters{" "}
                  <Count value={health.webhooks.dead_letters} warn />
                  {health.webhooks.oldest_pending_age_seconds !== null
                    ? ` · oldest pending ${Math.round(health.webhooks.oldest_pending_age_seconds / 60)} min`
                    : ""}
                </li>
                <li>
                  Device credentials expired{" "}
                  <Count value={health.expiry.node_credentials_expired} warn />, expiring within
                  14 days <Count value={health.expiry.node_credentials_expiring_14_days} warn />
                </li>
                <li>
                  Private service certificates expiring within 30 days{" "}
                  <Count value={health.expiry.service_certificates_expiring_30_days} warn />,
                  service CA <Count value={health.expiry.service_ca_expiring_30_days} warn />
                </li>
                <li>
                  Automation credentials expiring within 14 days{" "}
                  <Count value={health.expiry.api_clients_expiring_14_days} warn />
                </li>
                <li>
                  Single sign-on providers: {consoleOps.sso.enabled} enabled of{" "}
                  {consoleOps.sso.configured} configured
                </li>
              </ul>
              <p className="muted">
                The coordinator&apos;s own TLS certificate is managed by your proxy or
                load balancer and is not shown here.
              </p>
            </section>

            <section className="panel stack" aria-labelledby="ops-backup">
              <h2 id="ops-backup">Last backup proof</h2>
              {health.backup.status === "recorded" ? (
                <p>
                  Backup completed {when(health.backup.completed_at)}; restore last
                  verified {when(health.backup.restore_verified_at)}
                  {health.backup.label ? ` (${health.backup.label})` : ""}.
                </p>
              ) : (
                <p>
                  <span className="badge pending">
                    {health.backup.status === "unreadable" ? "Marker unreadable" : "Not recorded"}
                  </span>{" "}
                  The operator has not recorded a backup on this coordinator.
                </p>
              )}
              <p className="muted">
                This is what your backup job wrote to{" "}
                <span className="mono">BLAKTAIL_BACKUP_PROOF_FILE</span>; BlakTail does not
                verify the backup itself. See the backup and restore runbook in
                docs/upgrades.md.
              </p>
              <p className="muted">Generated {when(health.generated_at)}.</p>
            </section>
          </>
        ) : null}
      </div>
    </ConsoleShell>
  );
}
