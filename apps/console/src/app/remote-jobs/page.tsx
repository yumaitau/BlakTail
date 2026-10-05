import { Suspense } from "react";
import { errorText } from "@/lib/server-errors";
import Link from "next/link";
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
  type BadgeTone,
} from "@/components/ui";
import {
  DisableTemplateButton,
  JobTemplateForm,
  RequestRunForm,
  RunDecision,
} from "@/components/remote-jobs-manager";
import { listNodes, type CoordNode } from "@/lib/coord";
import { listJobRuns, listJobTemplates, type JobRun, type JobTemplate } from "@/lib/coord-remote";
import { formatDateTime } from "@/lib/format-time";
import { listMemberships } from "@/lib/oidc";
import { can, permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext, type ConsoleContext } from "@/lib/session";

const STATUS: Record<JobRun["status"], { label: string; tone: BadgeTone }> = {
  pending_approval: { label: "Waiting for approval", tone: "warning" },
  approved: { label: "Approved", tone: "info" },
  running: { label: "Running", tone: "info" },
  succeeded: { label: "Succeeded", tone: "success" },
  failed: { label: "Failed", tone: "danger" },
  timed_out: { label: "Timed out", tone: "danger" },
  output_capped: { label: "Output cut off", tone: "warning" },
  cancelled: { label: "Cancelled", tone: "muted" },
  rejected: { label: "Rejected", tone: "muted" },
  expired: { label: "Expired", tone: "muted" },
  error: { label: "Error", tone: "danger" },
};

function decisions(run: JobRun, canApprove: boolean, canCancel: boolean) {
  const out: ("approve" | "reject" | "cancel")[] = [];
  if (run.status === "pending_approval" && canApprove) out.push("approve", "reject");
  if (
    canCancel &&
    (run.status === "pending_approval" ||
      run.status === "approved" ||
      (run.status === "running" && !run.cancel_requested_at))
  ) {
    out.push("cancel");
  }
  return out;
}

export default async function RemoteJobsPage() {
  const ctx = await requireConsoleContext();
  const denied = permissionReason(ctx.role, "use_remote_sessions");
  return (
    <ConsoleShell ctx={ctx} current="/remote-jobs">
      <div className="stack">
        <PageHeader
          eyebrow="Remote"
          title="Remote jobs"
          description="Owner-defined programs with fixed arguments that opted-in devices run on request. Every run needs an owner's approval, runs without a shell as an unprivileged account, and is limited in time and output."
        />
        <p className="page-context">
          {ctx.organisationName} · {roleLabel(ctx.role)}
        </p>
        {denied ? (
          <Alert tone="info" title="Remote jobs aren't available to your role">
            {denied}
          </Alert>
        ) : (
          <Suspense
            fallback={
              <Card>
                <SkeletonTable rows={5} label="Loading remote jobs" />
              </Card>
            }
          >
            <RemoteJobsContent ctx={ctx} />
          </Suspense>
        )}
      </div>
    </ConsoleShell>
  );
}

async function RemoteJobsContent({ ctx }: { ctx: ConsoleContext }) {
  const ownerDenied = permissionReason(ctx.role, "manage_remote_jobs");
  let templates: JobTemplate[] = [];
  let runs: JobRun[] = [];
  let nodes: CoordNode[] = [];
  let people = new Map<string, string>();
  let error: string | null = null;
  try {
    let members: Awaited<ReturnType<typeof listMemberships>>;
    [templates, runs, nodes, members] = await Promise.all([
      listJobTemplates(ctx),
      listJobRuns(ctx),
      listNodes(ctx),
      listMemberships(ctx.organisationId),
    ]);
    people = new Map(members.map((member) => [member.userId, member.name || member.email]));
  } catch (err) {
    error = errorText(err, "Could not load remote jobs.");
  }
  if (error) {
    return (
      <Alert tone="error" title="Remote jobs couldn't be loaded">
        {error}
      </Alert>
    );
  }
  const names = new Map(nodes.map((node) => [node.id, node.display_name || node.name]));
  const devices = nodes
    .filter((node) => !node.revoked && !node.deleted)
    .map((node) => ({ id: node.id, label: node.display_name || node.name }));
  const optedIn = nodes.filter((node) => node.capabilities?.includes("remote-jobs"));
  const canManage = can(ctx.role, "manage_remote_jobs");

  return (
    <>
      <Section
        id="templates"
        title="Templates"
        description={`${optedIn.length} device${optedIn.length === 1 ? "" : "s"} accept remote jobs (agents started with --allow-remote-jobs).`}
      >
        {templates.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No job templates"
            body={canManage ? "Define the first program devices may run below." : "An owner defines the programs devices may run."}
          />
        ) : (
          <Table label="Job templates" mobile="stack">
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Program and arguments</th>
                <th scope="col">Limits</th>
                <th scope="col">Targets</th>
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {templates.map((template) => (
                <tr key={template.id}>
                  <Td label="Name">{template.name}</Td>
                  <Td label="Program" className="mono cell-break">
                    {template.argv.join(" ")}
                  </Td>
                  <Td label="Limits">
                    {template.timeout_secs} s
                    <span className="cell-sub">{template.output_cap_bytes.toLocaleString("en-AU")} bytes of output</span>
                  </Td>
                  <Td label="Targets">
                    {[
                      ...(template.target.tags ?? []).map((tag) => `Tag ${tag}`),
                      ...(template.target.node_ids ?? []).map((id) => names.get(id) ?? id),
                    ].join(", ")}
                  </Td>
                  <Td>
                    {canManage ? (
                      <div className="cell-actions">
                        <DisableTemplateButton templateId={template.id} name={template.name} />
                      </div>
                    ) : null}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
        <details className="form-disclosure" open={templates.length === 0 && canManage}>
          <summary>New template</summary>
          <JobTemplateForm devices={devices} disabledReason={ownerDenied} />
        </details>
      </Section>

      <Section id="request" title="Request a run" description="An owner approves each run before the device runs it.">
        <RequestRunForm
          templates={templates.map((template) => ({ id: template.id, label: template.name }))}
          devices={devices}
          disabledReason={null}
        />
      </Section>

      <Section id="runs" title="Runs" description="Newest first. Output is kept up to each template's limit.">
        {runs.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No runs yet"
            body="Requested runs wait here for an owner's approval."
          />
        ) : (
          <ul className="run-list">
            {runs.map((run) => (
              <li key={run.id} className="run-card">
                <div className="audit-event-head">
                  <StatusPill tone={STATUS[run.status].tone}>{STATUS[run.status].label}</StatusPill>
                  <strong>{run.template_name}</strong>
                  <span>
                    on <Link href={`/devices/${run.node_id}`}>{names.get(run.node_id) ?? run.node_id}</Link>
                  </span>
                  {run.exit_code !== null ? <span className="muted">exit code {run.exit_code}</span> : null}
                </div>
                <p className="muted">
                  Requested by {people.get(run.requested_by) ?? run.requested_by}, {formatDateTime(run.requested_at)}: “{run.reason}”
                  {run.decided_by ? ` · decided by ${people.get(run.decided_by) ?? run.decided_by}, ${formatDateTime(run.decided_at)}` : ""}
                  {run.finished_at ? ` · finished ${formatDateTime(run.finished_at)}` : ""}
                </p>
                <p className="mono cell-break">{run.argv.join(" ")}</p>
                {run.output !== null ? (
                  <pre className="dns-pre" aria-label={`Output of ${run.template_name}`}>
                    {run.output || "(no output)"}
                    {run.output_truncated ? "\n[output cut off at the template's limit]" : ""}
                  </pre>
                ) : null}
                <RunDecision
                  runId={run.id}
                  name={run.template_name}
                  decisions={decisions(run, canManage, can(ctx.role, "use_remote_sessions"))}
                />
              </li>
            ))}
          </ul>
        )}
      </Section>
    </>
  );
}
