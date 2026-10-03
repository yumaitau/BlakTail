import { ConsoleShell } from "@/components/console-shell";
import { PageHeader } from "@/components/page-header";
import {
  GatewayDesignations,
  KeyManager,
  OffshorePolicy,
  ProviderManager,
  ResidencyBadge,
  StoredPromptButton,
} from "@/components/agents/agent-network";
import { listNodes } from "@/lib/coord";
import {
  getAgentOverview,
  getAgentUsage,
  type AgentOverview,
  type AgentUsage,
} from "@/lib/coord-agents";
import { can, permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

function when(seconds: number | null): string {
  if (!seconds) return "never";
  return new Date(seconds * 1000).toLocaleString("en-AU", { dateStyle: "medium", timeStyle: "short" });
}

function UsageChart({ usage }: { usage: AgentUsage }) {
  const byDay = new Map<string, number>();
  for (const row of usage.days) {
    byDay.set(row.day, (byDay.get(row.day) ?? 0) + row.prompt_tokens + row.completion_tokens);
  }
  const days = [...byDay.entries()].sort(([a], [b]) => a.localeCompare(b));
  const max = Math.max(1, ...days.map(([, tokens]) => tokens));
  if (days.length === 0) return null;
  return (
    <figure className="stack" aria-label="Tokens per day">
      <figcaption className="muted">Tokens per day (UTC), all keys and models</figcaption>
      {days.map(([day, tokens]) => (
        <div key={day} className="agent-bar-row">
          <span className="mono">{day}</span>
          <span className="agent-bar" style={{ width: `${Math.max(1, (tokens / max) * 100)}%` }} />
          <span className="mono">{tokens.toLocaleString("en-AU")}</span>
        </div>
      ))}
    </figure>
  );
}

export default async function AgentsPage() {
  const ctx = await requireConsoleContext();
  const viewReason = permissionReason(ctx.role, "view_agent_usage");
  let overview: AgentOverview | null = null;
  let usage: AgentUsage | null = null;
  let error: string | null = null;
  if (!viewReason) {
    try {
      [overview, usage] = await Promise.all([getAgentOverview(ctx), getAgentUsage(ctx)]);
    } catch (err) {
      error = err instanceof Error ? err.message : "Could not load the agent network.";
    }
  }
  const nodes = viewReason ? [] : await listNodes(ctx).catch(() => []);
  const devices = nodes
    .filter((node) => !node.revoked && !node.deleted && !node.expired)
    .map((node) => ({ id: node.id, label: node.display_name || node.name }));
  const deviceLabel = (id: string | null) =>
    id ? (devices.find((device) => device.id === id)?.label ?? "Unknown device") : "—";
  const manageReason = permissionReason(ctx.role, "manage_agent_gateway");
  const isOwner = ctx.role === "owner";

  return (
    <ConsoleShell ctx={ctx} current="/agents">
      <div className="stack">
        <PageHeader
          eyebrow="Agents"
          title="Agent network"
          description="An organisation-run AI model gateway. Agents reach it only over the BlakTail overlay with a per-agent key; every request is checked against provider location, model, quota and logging policy."
        />
        {viewReason ? (
          <div className="panel stack">
            <h2>Not available to your role</h2>
            <p className="muted">{viewReason}</p>
          </div>
        ) : !overview || !usage ? (
          <div className="panel stack">
            <h2>Agent network unavailable</h2>
            <p className="error">{error}</p>
            <p className="muted">Check that the coordinator is reachable, then reload this page.</p>
          </div>
        ) : (
          <>
            <section className="panel stack" aria-labelledby="agents-sovereignty">
              <h2 id="agents-sovereignty">Data sovereignty</h2>
              <OffshorePolicy
                allowOffshore={overview.settings.allow_offshore}
                isOwner={isOwner}
                readOnlyReason={manageReason}
              />
            </section>

            <section className="panel stack" aria-labelledby="agents-gateways">
              <h2 id="agents-gateways">Gateways</h2>
              <GatewayDesignations
                gateways={overview.gateways}
                organisationName={ctx.organisationName}
                roleLabel={roleLabel(ctx.role).toLowerCase()}
                readOnlyReason={manageReason}
              />
            </section>

            <section className="panel stack" aria-labelledby="agents-providers">
              <h2 id="agents-providers">Model providers</h2>
              <p className="muted">
                Each provider declares where prompts are processed. Credentials are sealed at rest and never shown again.
              </p>
              <ProviderManager providers={overview.providers} readOnlyReason={manageReason} />
            </section>

            <section className="panel stack" aria-labelledby="agents-keys">
              <h2 id="agents-keys">Agent keys and policies</h2>
              <KeyManager
                keys={overview.keys}
                providers={overview.providers}
                devices={devices}
                isOwner={isOwner}
                icipWarning={overview.icip_warning}
                organisationName={ctx.organisationName}
                roleLabel={roleLabel(ctx.role).toLowerCase()}
                readOnlyReason={manageReason}
              />
            </section>

            <section className="panel stack" aria-labelledby="agents-usage">
              <h2 id="agents-usage">Usage</h2>
              <UsageChart usage={usage} />
              {usage.days.length === 0 ? (
                <p className="muted">No model requests in the last 14 days.</p>
              ) : (
                <div className="table-wrap">
                  <table className="table">
                    <thead>
                      <tr>
                        <th scope="col">Day (UTC)</th>
                        <th scope="col">Key</th>
                        <th scope="col">Model</th>
                        <th scope="col">Requests</th>
                        <th scope="col">Errors</th>
                        <th scope="col">Prompt tokens</th>
                        <th scope="col">Completion tokens</th>
                      </tr>
                    </thead>
                    <tbody>
                      {usage.days.map((row) => (
                        <tr key={`${row.day}-${row.key_id}-${row.model}`}>
                          <td className="mono">{row.day}</td>
                          <td>{row.key_name ?? "Deleted key"}</td>
                          <td className="mono">{row.model}</td>
                          <td>{row.requests}</td>
                          <td>{row.errors}</td>
                          <td>{row.prompt_tokens.toLocaleString("en-AU")}</td>
                          <td>{row.completion_tokens.toLocaleString("en-AU")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <h3>Recent requests</h3>
              <p className="muted">
                Only keys with metadata or full logging keep per-request records (90 days). Estimated token counts are marked.
              </p>
              {usage.recent.length === 0 ? (
                <p className="muted">No per-request records.</p>
              ) : (
                <div className="table-wrap">
                  <table className="table">
                    <thead>
                      <tr>
                        <th scope="col">When</th>
                        <th scope="col">Key</th>
                        <th scope="col">Model and provider</th>
                        <th scope="col">Caller</th>
                        <th scope="col">Result</th>
                        <th scope="col">Tokens</th>
                      </tr>
                    </thead>
                    <tbody>
                      {usage.recent.map((request) => {
                        const provider = overview.providers.find((p) => p.id === request.provider_id);
                        const key = overview.keys.find((k) => k.id === request.key_id);
                        return (
                          <tr key={request.id}>
                            <td>{when(request.started_at)}</td>
                            <td>{key?.name ?? "Deleted key"}</td>
                            <td>
                              <span className="mono">{request.model}</span>
                              {provider ? (
                                <div className="muted">
                                  {provider.name}, {provider.data_location} <ResidencyBadge provider={provider} />
                                </div>
                              ) : null}
                            </td>
                            <td>{deviceLabel(request.caller_node_id)}</td>
                            <td>
                              {request.status}
                              {request.http_status ? ` (${request.http_status})` : ""}
                              {request.latency_ms !== null ? <div className="muted">{request.latency_ms} ms</div> : null}
                            </td>
                            <td>
                              {request.prompt_tokens} + {request.completion_tokens}
                              {request.usage_estimated ? <div className="muted">estimated</div> : null}
                              {request.has_content && isOwner && can(ctx.role, "manage_agent_gateway") ? (
                                <StoredPromptButton requestId={request.id} />
                              ) : request.has_content ? (
                                <div className="muted">Prompt stored; owners can read it</div>
                              ) : null}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          </>
        )}
      </div>
    </ConsoleShell>
  );
}
