import { Suspense } from "react";
import { errorText } from "@/lib/server-errors";
import { ConsoleShell } from "@/components/console-shell";
import {
  Alert,
  Card,
  EmptyRow,
  EmptyState,
  PageHeader,
  Section,
  SkeletonTable,
  StatusPill,
  Table,
  Td,
} from "@/components/ui";
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
import { formatDateTime } from "@/lib/format-time";
import { can, permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext, type ConsoleContext } from "@/lib/session";

const REQUEST_TONE = { ok: "success", pending: "info", error: "danger", abandoned: "warning" } as const;

function UsageChart({ usage }: { usage: AgentUsage }) {
  const byDay = new Map<string, number>();
  for (const row of usage.days) {
    byDay.set(row.day, (byDay.get(row.day) ?? 0) + row.prompt_tokens + row.completion_tokens);
  }
  const days = [...byDay.entries()].sort(([a], [b]) => a.localeCompare(b));
  const max = Math.max(1, ...days.map(([, tokens]) => tokens));
  if (days.length === 0) return null;
  return (
    <figure className="stack tight" aria-label="Tokens per day">
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
  return (
    <ConsoleShell ctx={ctx} current="/agents">
      <div className="stack">
        <PageHeader
          eyebrow="Agents"
          title="Agent network"
          description="An organisation-run AI model gateway. Agents reach it only over the BlakTail overlay with their own key; every request is checked against provider location, model, quota and logging policy."
        />
        <p className="page-context">
          {ctx.organisationName} · {roleLabel(ctx.role)}
        </p>
        {viewReason ? (
          <Alert tone="info" title="The agent network isn't available to your role">
            {viewReason}
          </Alert>
        ) : (
          <Suspense
            fallback={
              <Card>
                <SkeletonTable rows={6} label="Loading the agent network" />
              </Card>
            }
          >
            <AgentsContent ctx={ctx} />
          </Suspense>
        )}
      </div>
    </ConsoleShell>
  );
}

async function AgentsContent({ ctx }: { ctx: ConsoleContext }) {
  let overview: AgentOverview | null = null;
  let usage: AgentUsage | null = null;
  let error: string | null = null;
  try {
    [overview, usage] = await Promise.all([getAgentOverview(ctx), getAgentUsage(ctx)]);
  } catch (err) {
    error = errorText(err, "Could not load the agent network.");
  }
  if (!overview || !usage) {
    return (
      <Alert tone="error" title="The agent network couldn't be loaded">
        <p>{error}</p>
        <p>Check that the coordinator is reachable, then reload this page.</p>
      </Alert>
    );
  }
  const nodes = await listNodes(ctx).catch(() => []);
  const devices = nodes
    .filter((node) => !node.revoked && !node.deleted && !node.expired)
    .map((node) => ({ id: node.id, label: node.display_name || node.name }));
  const deviceLabel = (id: string | null) =>
    id ? (devices.find((device) => device.id === id)?.label ?? "Unknown device") : "—";
  const manageReason = permissionReason(ctx.role, "manage_agent_gateway");
  const isOwner = ctx.role === "owner";
  const providers = overview.providers;
  const keys = overview.keys;

  return (
    <>
      {manageReason ? <Alert tone="info">View only. {manageReason}</Alert> : null}
      <Section
        id="agents-sovereignty"
        title="Data sovereignty"
        description="Whether prompts may be sent to model providers outside Australia. Only an owner can change this."
        actions={
          <StatusPill tone={overview.settings.allow_offshore ? "warning" : "success"}>
            {overview.settings.allow_offshore ? "Offshore allowed" : "Onshore only"}
          </StatusPill>
        }
      >
        <OffshorePolicy
          allowOffshore={overview.settings.allow_offshore}
          isOwner={isOwner}
          readOnlyReason={manageReason}
        />
      </Section>

      <Section
        id="agents-gateways"
        title="Gateways"
        description="A device only acts as a gateway once designated. It then receives provider credentials and vouches for the calling device's address. Changes are audited."
      >
        <GatewayDesignations
          gateways={overview.gateways}
          organisationName={ctx.organisationName}
          roleLabel={roleLabel(ctx.role).toLowerCase()}
          readOnlyReason={manageReason}
        />
      </Section>

      <Section
        id="agents-providers"
        title="Model providers"
        description="Each provider declares where prompts are processed. Credentials are sealed at rest and never shown again."
      >
        <ProviderManager providers={providers} readOnlyReason={manageReason} />
      </Section>

      <Section
        id="agents-keys"
        title="Agent keys and policies"
        description="Each agent gets its own key, limited to the providers, models, daily quota and device you choose."
      >
        <KeyManager
          keys={keys}
          providers={providers}
          devices={devices}
          isOwner={isOwner}
          icipWarning={overview.icip_warning}
          organisationName={ctx.organisationName}
          roleLabel={roleLabel(ctx.role).toLowerCase()}
          readOnlyReason={manageReason}
        />
      </Section>

      <Section id="agents-usage" title="Usage" description="The last 14 days across all keys and models. Days are UTC.">
        {usage.days.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No model requests yet"
            body="Requests from agents appear here shortly after they're made."
          />
        ) : (
          <>
            <UsageChart usage={usage} />
            <Table label="Usage by day" mobile="stack">
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
                    <Td label="Day" className="mono">
                      {row.day}
                    </Td>
                    <Td label="Key">{row.key_name ?? "Deleted key"}</Td>
                    <Td label="Model" className="mono">
                      {row.model}
                    </Td>
                    <Td label="Requests">{row.requests}</Td>
                    <Td label="Errors">{row.errors}</Td>
                    <Td label="Prompt tokens">{row.prompt_tokens.toLocaleString("en-AU")}</Td>
                    <Td label="Completion tokens">{row.completion_tokens.toLocaleString("en-AU")}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </>
        )}
        <div className="ui-subsection">
          <div className="ui-subsection-head">
            <h3 className="card-heading">Recent requests</h3>
            <p className="muted">
              Only keys with metadata or full logging keep per-request records (90 days). Estimated
              token counts are marked.
            </p>
          </div>
          <Table label="Recent requests" mobile="stack">
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
              {usage.recent.length === 0 ? (
                <EmptyRow colSpan={6}>No per-request records.</EmptyRow>
              ) : (
                usage.recent.map((request) => {
                  const provider = providers.find((p) => p.id === request.provider_id);
                  const key = keys.find((k) => k.id === request.key_id);
                  return (
                    <tr key={request.id}>
                      <Td label="When">{formatDateTime(request.started_at)}</Td>
                      <Td label="Key">{key?.name ?? "Deleted key"}</Td>
                      <Td label="Model">
                        <span className="mono">{request.model}</span>
                        {provider ? (
                          <span className="cell-sub">
                            {provider.name}, {provider.data_location} <ResidencyBadge provider={provider} />
                          </span>
                        ) : null}
                      </Td>
                      <Td label="Caller">{deviceLabel(request.caller_node_id)}</Td>
                      <Td label="Result">
                        <StatusPill tone={REQUEST_TONE[request.status] ?? "neutral"}>
                          {request.status}
                          {request.http_status ? ` (${request.http_status})` : ""}
                        </StatusPill>
                        {request.latency_ms !== null ? <span className="cell-sub">{request.latency_ms} ms</span> : null}
                      </Td>
                      <Td label="Tokens">
                        {request.prompt_tokens} + {request.completion_tokens}
                        {request.usage_estimated ? <span className="cell-sub">Estimated</span> : null}
                        {request.has_content && isOwner && can(ctx.role, "manage_agent_gateway") ? (
                          <StoredPromptButton requestId={request.id} />
                        ) : request.has_content ? (
                          <span className="cell-sub">Prompt stored; owners can read it</span>
                        ) : null}
                      </Td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </Table>
        </div>
      </Section>
    </>
  );
}
