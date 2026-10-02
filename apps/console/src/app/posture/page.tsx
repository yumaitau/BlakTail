import { ConsoleShell } from "@/components/console-shell";
import { PageHeader } from "@/components/page-header";
import { PostureManager } from "@/components/posture-manager";
import {
  listPostureAssessments,
  listPostureChecks,
  type AssessmentReport,
  type PostureCheck,
} from "@/lib/coord-policy";
import { can, permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

function when(seconds: number): string {
  return new Date(seconds * 1000).toLocaleString("en-AU", {
    dateStyle: "medium",
    timeStyle: "short",
  });
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
  try {
    [checks, report] = await Promise.all([listPostureChecks(ctx), listPostureAssessments(ctx)]);
  } catch (err) {
    error = err instanceof Error ? err.message : "Could not load posture checks.";
  }
  const canManage = can(ctx.role, "manage_policy");

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
            />
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
                                        `${reason.text} (${reason.source === "agent_reported" ? "self-reported" : "coordinator"})`,
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
