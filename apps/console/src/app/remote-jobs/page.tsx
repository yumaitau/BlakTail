import Link from "next/link";
import { ConsoleShell } from "@/components/console-shell";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import {
  DisableTemplateButton,
  JobTemplateForm,
  RequestRunForm,
  RunDecision,
} from "@/components/remote-jobs-manager";
import { listNodes, type CoordNode } from "@/lib/coord";
import { listJobRuns, listJobTemplates, type JobRun, type JobTemplate } from "@/lib/coord-remote";
import { can, permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

function when(seconds: number | null): string {
  if (!seconds) return "—";
  return new Date(seconds * 1000).toLocaleString("en-AU", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

const STATUS_BADGE: Record<JobRun["status"], string> = {
  pending_approval: "badge pending",
  approved: "badge pending",
  running: "badge online",
  succeeded: "badge online",
  failed: "badge warn",
  timed_out: "badge warn",
  output_capped: "badge warn",
  cancelled: "badge",
  rejected: "badge revoked",
  expired: "badge",
  error: "badge revoked",
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
  const ownerDenied = permissionReason(ctx.role, "manage_remote_jobs");
  let templates: JobTemplate[] = [];
  let runs: JobRun[] = [];
  let nodes: CoordNode[] = [];
  let error: string | null = null;
  if (!denied) {
    try {
      [templates, runs, nodes] = await Promise.all([
        listJobTemplates(ctx),
        listJobRuns(ctx),
        listNodes(ctx),
      ]);
    } catch (err) {
      error = err instanceof Error ? err.message : "Could not load remote jobs.";
    }
  }
  const names = new Map(nodes.map((node) => [node.id, node.display_name || node.name]));
  const devices = nodes
    .filter((node) => !node.revoked && !node.deleted)
    .map((node) => ({ id: node.id, label: node.display_name || node.name }));
  const optedIn = nodes.filter((node) => node.capabilities?.includes("remote-jobs"));

  return (
    <ConsoleShell ctx={ctx} current="/remote-jobs">
      <div className="stack">
        <PageHeader
          eyebrow="Remote"
          title="Remote jobs"
          description="Owner-defined programs with fixed arguments that opted-in devices run on request. Every run needs an owner's approval, runs with no shell as an unprivileged account, and is capped in time and output."
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
          </div>
        ) : null}
        {!denied && !error ? (
          <>
            <section className="panel stack" aria-labelledby="templates-title">
              <h2 id="templates-title">Templates</h2>
              <p className="muted">
                {optedIn.length} device{optedIn.length === 1 ? "" : "s"} accept remote jobs
                (agents started with <span className="mono">--allow-remote-jobs</span>).
              </p>
              {templates.length === 0 ? (
                <EmptyState title="No job templates" body="An owner defines the programs devices may run." />
              ) : (
                <div className="table-wrap">
                  <table className="table">
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
                          <td>{template.name}</td>
                          <td className="mono">
                            {template.argv.map((arg, index) => (
                              <span key={index} className="badge">
                                {arg}
                              </span>
                            ))}
                          </td>
                          <td>
                            {template.timeout_secs} s · {template.output_cap_bytes.toLocaleString("en-AU")} bytes
                          </td>
                          <td>
                            {[
                              ...(template.target.tags ?? []).map((tag) => `tag ${tag}`),
                              ...(template.target.node_ids ?? []).map((id) => names.get(id) ?? id),
                            ].join(", ")}
                          </td>
                          <td>
                            {can(ctx.role, "manage_remote_jobs") ? (
                              <DisableTemplateButton templateId={template.id} name={template.name} />
                            ) : null}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <details>
                <summary>New template</summary>
                <JobTemplateForm devices={devices} disabledReason={ownerDenied} />
              </details>
            </section>

            <section className="panel stack" aria-labelledby="request-title">
              <h2 id="request-title">Request a run</h2>
              <RequestRunForm
                templates={templates.map((template) => ({ id: template.id, label: template.name }))}
                devices={devices}
                disabledReason={null}
              />
            </section>

            <section className="panel stack" aria-labelledby="runs-title">
              <h2 id="runs-title">Runs</h2>
              {runs.length === 0 ? (
                <EmptyState title="No runs yet" body="Requested runs wait here for an owner's approval." />
              ) : (
                <ul className="stack">
                  {runs.map((run) => (
                    <li key={run.id} className="panel stack">
                      <div className="row">
                        <span className={STATUS_BADGE[run.status]}>{run.status.replace("_", " ")}</span>
                        <strong>{run.template_name}</strong>
                        <span>
                          on <Link href={`/devices/${run.node_id}`}>{names.get(run.node_id) ?? run.node_id}</Link>
                        </span>
                        {run.exit_code !== null ? <span className="muted">exit {run.exit_code}</span> : null}
                      </div>
                      <p className="muted">
                        Requested by {run.requested_by} {when(run.requested_at)} · {run.reason}
                        {run.decided_by ? ` · decided by ${run.decided_by} ${when(run.decided_at)}` : ""}
                        {run.finished_at ? ` · finished ${when(run.finished_at)}` : ""}
                      </p>
                      <p className="mono">{run.argv.join(" · ")}</p>
                      {run.output !== null ? (
                        <pre className="dns-pre" aria-label={`Output of ${run.template_name}`}>
                          {run.output || "(no output)"}
                          {run.output_truncated ? "\n[output truncated at the template's cap]" : ""}
                        </pre>
                      ) : null}
                      <RunDecision
                        runId={run.id}
                        decisions={decisions(
                          run,
                          can(ctx.role, "manage_remote_jobs"),
                          can(ctx.role, "use_remote_sessions"),
                        )}
                      />
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </>
        ) : null}
      </div>
    </ConsoleShell>
  );
}
