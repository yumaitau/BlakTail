import { Suspense } from "react";
import Link from "next/link";
import { errorText } from "@/lib/server-errors";
import { ConsoleShell } from "@/components/console-shell";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { PermissionNotice } from "@/components/ui/permission-notice";
import { Section } from "@/components/ui/section";
import { Skeleton, SkeletonTable } from "@/components/ui/skeleton";
import { Table, Td } from "@/components/ui/table";
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
import { can, permissionReason } from "@/lib/roles";
import { requireConsoleContext, type ConsoleContext } from "@/lib/session";

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
  const policyReason = permissionReason(ctx.role, "manage_policy");

  return (
    <ConsoleShell ctx={ctx} current="/posture">
      <div className="stack">
        <PageHeader
          eyebrow={ctx.organisationName}
          title="Posture checks"
          description="Named, versioned device requirements. An allow or SSH rule that names a check only grants access to source devices that pass it; failing devices keep every other grant."
          actions={
            <Link className="button secondary" href="/acls">
              Use in access rules
            </Link>
          }
        />
        <Alert tone="info" title="What these signals mean">
          Operating system, OS version, agent version and capabilities are reported by each
          device. They are hygiene signals, not attestation or evidence of compliance. Credential
          renewal and device state are observed by the coordinator. Results are re-evaluated
          whenever peer maps compile.
        </Alert>
        {policyReason ? <PermissionNotice reason={policyReason} /> : null}
        <Suspense
          fallback={
            <>
              <Section title="Checks">
                <Skeleton lines={4} label="Loading posture checks" />
              </Section>
              <Section title="Device assessments">
                <SkeletonTable rows={4} label="Loading device assessments" />
              </Section>
            </>
          }
        >
          <PostureWorkspace ctx={ctx} />
        </Suspense>
      </div>
    </ConsoleShell>
  );
}

async function PostureWorkspace({ ctx }: { ctx: ConsoleContext }) {
  let checks: PostureCheck[] = [];
  let report: AssessmentReport | null = null;
  let error: string | null = null;
  let integrations: IntegrationList | null = null;
  let integrationsError: string | null = null;
  try {
    [checks, report] = await Promise.all([listPostureChecks(ctx), listPostureAssessments(ctx)]);
  } catch (err) {
    error = errorText(err, "Could not load posture checks.");
  }
  try {
    integrations = await listPostureIntegrations(ctx);
  } catch (err) {
    integrationsError = errorText(err, "Could not load integrations.");
  }
  const canManage = can(ctx.role, "manage_policy");
  const canManageIntegrations = can(ctx.role, "manage_security");
  const securityReason = permissionReason(ctx.role, "manage_security");

  return (
    <>
      {error ? (
        <Alert tone="error" title="Posture checks couldn't be loaded">
          {error}
        </Alert>
      ) : (
        <PostureManager
          checks={checks}
          canManage={canManage}
          integrations={(integrations?.integrations ?? []).map((integration) => ({
            id: integration.id,
            name: integration.name,
            provider: integration.provider,
          }))}
        />
      )}
      <Section
        id="integrations"
        title="Integrations"
        description="Optional device-health signals from an MDM or EDR your organisation already runs. BlakTail polls the provider with a read-only credential and matches its records to devices by serial number or MAC address (hostname only if you opt in). A record that matches more than one device fails for all of them."
      >
        {integrationsError ? (
          <Alert tone="error" title="Integrations couldn't be loaded">
            {integrationsError}
          </Alert>
        ) : integrations ? (
          <>
            <p className="muted small" role="note">
              {integrations.residency_notice}
            </p>
            {securityReason ? <PermissionNotice reason={securityReason} /> : null}
            <PostureIntegrations
              providers={integrations.providers}
              integrations={integrations.integrations}
              residencyNotice={integrations.residency_notice}
              canManage={canManageIntegrations}
            />
          </>
        ) : null}
      </Section>
      {report ? (
        <Section
          id="assessments"
          title="Device assessments"
          description={`Evaluated ${when(report.evaluated_at)}.`}
        >
          {report.devices.length === 0 ? (
            <EmptyState
              compact
              headingLevel={3}
              title="No active devices yet"
              body="Each device's results show here once it enrols."
            />
          ) : (
            <Table label="Device assessments" mobile="stack">
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
                    <Td label="Device">
                      <div>
                        <div className="device-primary">{device.display_name || device.name}</div>
                        {device.display_name ? (
                          <div className="cell-sub mono">{device.name}</div>
                        ) : null}
                      </div>
                    </Td>
                    <Td label="Reported">
                      <div>
                        {device.os ?? "OS not reported"} {device.os_version ?? ""}
                        <div className="cell-sub">
                          Agent {device.agent_version ?? "not reported"} · inventory{" "}
                          {when(device.inventory_reported_at)}
                        </div>
                      </div>
                    </Td>
                    <Td label="Enforcement">
                      <div className="stack-tight">
                      <Badge
                        tone={device.enforcement.packet_filter === "enforced" ? "success" : "warning"}
                      >
                        {FILTER_LABEL[device.enforcement.packet_filter] ??
                          device.enforcement.packet_filter}
                      </Badge>
                      {device.enforcement.ssh_users ? (
                        <div className="cell-sub">SSH user limits verified</div>
                      ) : null}
                      {(device.integrations ?? []).map((fact) => (
                        <div key={fact.integration_id} className="cell-sub">
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
                          reason={securityReason}
                        />
                      ) : null}
                      </div>
                    </Td>
                    <Td label="Checks">
                      {device.assessments.length === 0 ? (
                        <span className="muted">No checks defined</span>
                      ) : (
                        <ul className="posture-results">
                          {device.assessments.map((assessment) => (
                            <li key={assessment.check}>
                              <Badge tone={assessment.passed ? "success" : "danger"}>
                                {assessment.check}: {assessment.passed ? "passes" : "fails"}
                              </Badge>{" "}
                                  {assessment.reasons
                                    .map(
                                      (reason) =>
                                        `${reason.text} (${SOURCE_LABEL[reason.source] ?? reason.source})`,
                                    )
                                    .join("; ")}
                              {!assessment.passed && assessment.affected_rules.length ? (
                                <div className="cell-sub">
                                  Loses {assessment.affected_rules.join(", ")}. Remediate by
                                  upgrading the agent or OS, or renewing the device credential.
                                </div>
                              ) : null}
                              {assessment.passed && assessment.expires_at ? (
                                <div className="cell-sub">Lapses {when(assessment.expires_at)}</div>
                              ) : null}
                            </li>
                          ))}
                        </ul>
                      )}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Section>
      ) : null}
    </>
  );
}
