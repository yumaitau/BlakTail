import { ConsoleShell } from "@/components/console-shell";
import { PageHeader } from "@/components/page-header";
import { ApproveHardwareButton, PostureIntegrations } from "@/components/posture-integrations";
import { PostureManager } from "@/components/posture-manager";
import {
  listPostureAssessments,
  listPostureChecks,
  type AssessmentReport,
  type PostureCheck,
} from "@/lib/coord-policy";
import {
  listPostureIntegrations,
  type IntegrationFact,
  type IntegrationList,
} from "@/lib/coord-posture-integrations";
import { can, permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

function when(seconds: number): string {
  return new Date(seconds * 1000).toLocaleString("en-AU", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

const SOURCE_LABEL: Record<string, string> = {
  agent_reported: "self-reported",
  coordinator_observed: "coordinator",
  provider_reported: "provider",
};

const MATCHED_BY: Record<string, string> = {
  serial_number: "serial number",
  mac_address: "MAC address",
  hostname: "hostname",
};

function signalText(fact: IntegrationFact): string {
  const match = fact.match;
  if (!fact.enabled) return "integration disabled";
  if (match.state === "unmatched") return "no matching provider record";
  if (match.state === "ambiguous") return `ambiguous match (${match.candidates} candidates)`;
  if (match.state === "identity_changed") {
    return "hardware identifiers changed or already held by another device; awaiting approval";
  }
  if (match.state === "contested") return "provider record held by a device that reported it first";
  const seen = match.last_seen_at ? `, provider last saw it ${when(match.last_seen_at)}` : "";
  return `${match.status} (matched by ${MATCHED_BY[match.matched_by] ?? match.matched_by}, synced ${when(match.synced_at)}${seen})`;
}

const FILTER_LABEL: Record<string, string> = {
  enforced: "Filters inbound traffic",
  unknown: "Filter support not reported",
  not_enforced: "No inbound filter",
};

export default async function PosturePage() {
  const ctx = await requireConsoleContext();
  let checks: PostureCheck[] = [];
  let report: AssessmentReport | null = null;
  let error: string | null = null;
  let integrations: IntegrationList | null = null;
  let integrationsError: string | null = null;
  try {
    [checks, report] = await Promise.all([listPostureChecks(ctx), listPostureAssessments(ctx)]);
  } catch (err) {
    error = err instanceof Error ? err.message : "Could not load posture checks.";
  }
  try {
    integrations = await listPostureIntegrations(ctx);
  } catch (err) {
    integrationsError = err instanceof Error ? err.message : "Could not load integrations.";
  }
  const canManage = can(ctx.role, "manage_policy");
  const canManageIntegrations = can(ctx.role, "manage_security");

  return (
    <ConsoleShell ctx={ctx} current="/posture">
      <div className="stack">
        <PageHeader
          title="Posture checks"
          description="Named, versioned device requirements. An allow rule or SSH rule that names a check only grants access to source devices that pass it; failing devices keep every other grant."
        />
        <div className="panel stack">
          <p className="muted" role="note">
            Operating system, OS version, agent version and capabilities are
            reported by each device. They are hygiene signals, not attestation,
            and are not evidence of compliance. Credential renewal and device
            state are observed by the coordinator. Results are re-evaluated
            whenever peer maps compile, and agents are told to recompile when
            a passing result reaches its time limit.
          </p>
          <p className="muted">
            {ctx.organisationName} · {roleLabel(ctx.role)}
          </p>
          {error ? (
            <p className="error" role="alert">
              {error}
            </p>
          ) : (
            <PostureManager
              checks={checks}
              canManage={canManage}
              reason={permissionReason(ctx.role, "manage_policy")}
              integrations={(integrations?.integrations ?? []).map((integration) => ({
                id: integration.id,
                name: integration.name,
                provider: integration.provider,
              }))}
            />
          )}
        </div>
        <div className="panel stack" aria-labelledby="integrations-heading">
          <div>
            <h2 id="integrations-heading">Integrations</h2>
            <p className="muted">
              Optional device-health signals from an MDM or EDR your organisation already runs.
              BlakTail polls the provider with a read-only credential and matches its records to
              devices in this organisation by serial number or MAC address (hostname only if you
              opt in). Serial numbers and MAC addresses are reported by each device; a record that
              matches more than one device fails for all of them.
            </p>
            <p className="muted">
              {ctx.organisationName} · {roleLabel(ctx.role)}
            </p>
          </div>
          {integrationsError ? (
            <p className="error" role="alert">
              {integrationsError}
            </p>
          ) : integrations ? (
            <>
              <p className="muted" role="note">
                {integrations.residency_notice}
              </p>
              <PostureIntegrations
                providers={integrations.providers}
                integrations={integrations.integrations}
                residencyNotice={integrations.residency_notice}
                canManage={canManageIntegrations}
                reason={permissionReason(ctx.role, "manage_security")}
              />
            </>
          ) : (
            <p className="muted">Loading integrations…</p>
          )}
        </div>
        {report ? (
          <div className="panel stack">
            <div>
              <h2>Device assessments</h2>
              <p className="muted">Evaluated {when(report.evaluated_at)}.</p>
            </div>
            {report.devices.length === 0 ? (
              <p className="muted">No active devices yet.</p>
            ) : (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th scope="col">Device</th>
                      <th scope="col">Reported</th>
                      <th scope="col">Enforcement</th>
                      <th scope="col">Checks</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.devices.map((device) => (
                      <tr key={device.node_id}>
                        <td>
                          {device.display_name || device.name}
                          <div className="muted mono">{device.name}</div>
                        </td>
                        <td>
                          {device.os ?? "OS not reported"} {device.os_version ?? ""}
                          <div className="muted">
                            Agent {device.agent_version ?? "not reported"} · inventory{" "}
                            {when(device.inventory_reported_at)}
                          </div>
                        </td>
                        <td>
                          <span
                            className={
                              device.enforcement.packet_filter === "enforced"
                                ? "badge online"
                                : "badge pending"
                            }
                          >
                            {FILTER_LABEL[device.enforcement.packet_filter] ??
                              device.enforcement.packet_filter}
                          </span>
                          {device.enforcement.ssh_users ? (
                            <div className="muted">SSH user limits verified</div>
                          ) : null}
                          {(device.integrations ?? []).map((fact) => (
                            <div key={fact.integration_id} className="muted">
                              {fact.provider}: {signalText(fact)} — source: provider
                              {fact.outage_since ? `, outage since ${when(fact.outage_since)}` : ""}
                            </div>
                          ))}
                          {(device.integrations ?? []).some(
                            (fact) => fact.match.state === "identity_changed",
                          ) ? (
                            <ApproveHardwareButton
                              nodeId={device.node_id}
                              deviceName={device.display_name || device.name}
                              canManage={canManageIntegrations}
                              reason={permissionReason(ctx.role, "manage_security")}
                            />
                          ) : null}
                        </td>
                        <td>
                          {device.assessments.length === 0 ? (
                            <span className="muted">No checks defined</span>
                          ) : (
                            <ul className="audit-details">
                              {device.assessments.map((assessment) => (
                                <li key={assessment.check}>
                                  <span className={assessment.passed ? "badge online" : "badge revoked"}>
                                    {assessment.check}: {assessment.passed ? "passes" : "fails"}
                                  </span>{" "}
                                  {assessment.reasons
                                    .map(
                                      (reason) =>
                                        `${reason.text} (${SOURCE_LABEL[reason.source] ?? reason.source})`,
                                    )
                                    .join("; ")}
                                  {!assessment.passed && assessment.affected_rules.length ? (
                                    <div className="muted">
                                      Loses {assessment.affected_rules.join(", ")}. Remediate by
                                      upgrading the agent or OS, or renewing the device credential.
                                    </div>
                                  ) : null}
                                  {assessment.passed && assessment.expires_at ? (
                                    <div className="muted">Lapses {when(assessment.expires_at)}</div>
                                  ) : null}
                                </li>
                              ))}
                            </ul>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        ) : null}
      </div>
    </ConsoleShell>
  );
}
