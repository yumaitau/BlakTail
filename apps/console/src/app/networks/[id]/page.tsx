import Link from "next/link";
import { notFound } from "next/navigation";
import { errorText } from "@/lib/server-errors";
import { ConsoleShell } from "@/components/console-shell";
import { EmptyState } from "@/components/empty-state";
import { NetworkResourceActions } from "@/components/network-resource-actions";
import { NetworkResourceForm } from "@/components/network-resource-form";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/ui/alert";
import { StatusPill } from "@/components/ui/badge";
import { LocalTime } from "@/components/ui/local-time";
import { MonoValue } from "@/components/ui/mono-value";
import { PermissionNotice } from "@/components/ui/permission-notice";
import { Section } from "@/components/ui/section";
import { Table, Td } from "@/components/ui/table";
import { getNetworkResource, type NetworkResource } from "@/lib/coord-networks";
import { can, permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";
import { resourceFormChoices } from "../choices";
import { lastSeen, peerStateLabel, resourceStateLabel } from "../format";

function accessSummary(resource: NetworkResource): string {
  const parts = [
    ...resource.access.roles.map((role) => `${roleLabel(role)} devices`),
    ...resource.access.tags.map((tag) => `tag:${tag}`),
    ...resource.access.groups.map((group) => `group:${group}`),
  ];
  return parts.join(", ") || "Nobody yet";
}

export default async function NetworkResourcePage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const ctx = await requireConsoleContext();
  let resource: NetworkResource | null = null;
  let error: string | null = null;
  try {
    resource = await getNetworkResource(ctx, id);
  } catch (err) {
    error = errorText(err, "Could not load this resource.");
  }
  if (!resource && !error) notFound();
  const canManage = can(ctx.role, "manage_networks");
  const denied = permissionReason(ctx.role, "manage_networks");
  const choices =
    canManage && resource ? await resourceFormChoices(ctx).catch(() => null) : null;
  const state = resource ? resourceStateLabel[resource.status.state] : null;
  const receiving = resource?.status.clients.filter((client) => client.receives) ?? [];

  return (
    <ConsoleShell ctx={ctx} current="/networks">
      <div className="stack">
        <Link className="back-link" href="/networks">
          ← Networks
        </Link>
        {error || !resource || !state ? (
          <>
            <PageHeader eyebrow={ctx.organisationName} title="Network resource" />
            <Alert tone="error" title="Couldn't load this resource">
              {error}
            </Alert>
          </>
        ) : (
          <>
            <PageHeader
              eyebrow={ctx.organisationName}
              title={resource.name}
              description={resource.description || undefined}
              actions={
                <NetworkResourceActions
                  organisationId={ctx.organisationId}
                  role={ctx.role}
                  resourceId={resource.id}
                  resourceName={resource.name}
                  etag={resource.etag}
                  enabled={resource.enabled}
                />
              }
            />
            {denied ? <PermissionNotice reason={denied} /> : null}

            <Section id="overview" title="Overview">
              <dl className="details">
                <div>
                  <dt>State</dt>
                  <dd>
                    <StatusPill tone={state.tone}>{state.label}</StatusPill>
                  </dd>
                </div>
                <div>
                  <dt>Destination</dt>
                  <dd>
                    <MonoValue
                      value={resource.cidr ?? resource.dns_target ?? ""}
                      copy
                      copyLabel="Copy destination"
                    />
                    {resource.family ? (
                      <span className="muted">
                        {" "}
                        {resource.family === "ipv6" ? "IPv6" : "IPv4"}
                      </span>
                    ) : null}
                  </dd>
                </div>
                {resource.kind === "dns" ? (
                  <div>
                    <dt>DNS resolution</dt>
                    <dd>
                      {resource.dns_resolution === "resolved"
                        ? "Resolved by the selected app connector"
                        : resource.dns_resolution === "blocked"
                          ? `Blocked: ${resource.connector?.blocked_reason ?? "unsafe answer"}`
                          : "Not resolved yet"}
                      <div className="cell-sub">
                        Only exact host addresses (/32, /128) are routed. Anyone allowed this
                        resource can reach every port at those addresses until router-side port
                        filtering ships.
                      </div>
                    </dd>
                  </div>
                ) : null}
                <div>
                  <dt>Who may receive it</dt>
                  <dd>{accessSummary(resource)}</dd>
                </div>
                <div>
                  <dt>Ports and protocols</dt>
                  <dd>
                    {[...resource.protocols.map((p) => p.toUpperCase()), ...resource.ports].join(
                      ", ",
                    ) || "Any"}
                    <div className="cell-sub">
                      {resource.port_enforcement === "enforced"
                        ? "Enforced by the routing peer for each authorised device."
                        : "Not enforced: the routing peer forwards the whole subnet."}
                    </div>
                  </dd>
                </div>
                <div>
                  <dt>Router forwarding</dt>
                  <dd>
                    <StatusPill
                      tone={resource.status.forwarding === "enforced" ? "success" : "muted"}
                    >
                      {resource.status.forwarding === "enforced"
                        ? "Enforced"
                        : resource.status.forwarding === "not_enforced"
                          ? "Not enforced: upgrade agent"
                          : "No routing peer"}
                    </StatusPill>
                    <div className="cell-sub">{resource.status.forwarding_detail}</div>
                  </dd>
                </div>
                <div>
                  <dt>Masquerade (NAT)</dt>
                  <dd>
                    Always on
                    <div className="cell-sub">
                      Forwarding without NAT isn&apos;t supported by the Linux agent yet.
                    </div>
                  </dd>
                </div>
                {resource.public_route_confirmed_by ? (
                  <div>
                    <dt>Public route confirmed by</dt>
                    <dd>
                      <MonoValue value={resource.public_route_confirmed_by} />
                    </dd>
                  </div>
                ) : null}
                <div>
                  <dt>Revision</dt>
                  <dd>{resource.revision}</dd>
                </div>
              </dl>
            </Section>

            {resource.kind === "dns" ? (
              <Section
                id="connector"
                title="App connector answers"
                description={`The selected connector resolves ${resource.dns_target} from its own resolver every 30 seconds. Each answer is leased for its DNS TTL (30 seconds to 5 minutes); expired or changed answers are withdrawn from clients on their next sync. An answer pointing at loopback, link-local, cloud metadata, multicast or BlakTail's own addresses blocks the resource.`}
              >
                {resource.connector?.blocked_reason ? (
                  <Alert tone="error" title="Blocked">
                    {resource.connector.blocked_reason}. Nothing is routed until the connector
                    reports a safe answer.
                  </Alert>
                ) : null}
                {resource.connector && resource.connector.answers.length > 0 ? (
                  <Table label="App connector answers" mobile="stack">
                    <thead>
                      <tr>
                        <th>Host route</th>
                        <th>DNS TTL</th>
                        <th>Lease expires</th>
                      </tr>
                    </thead>
                    <tbody>
                      {resource.connector.answers.map((lease) => (
                        <tr key={lease.route}>
                          <Td label="Host route">
                            <MonoValue value={lease.route} />
                          </Td>
                          <Td label="DNS TTL">
                            <div>
  {lease.ttl} s
                            </div>
                          </Td>
                          <Td label="Lease expires">
                            <LocalTime value={lease.expires_at} />
                          </Td>
                        </tr>
                      ))}
                    </tbody>
                  </Table>
                ) : resource.connector?.blocked_reason ? null : (
                  <EmptyState
                    compact
                    headingLevel={3}
                    title="Not resolved yet"
                    body={
                      <>
                        Add a Linux routing peer started with{" "}
                        <span className="mono">blaktaild up --app-connector</span>.
                      </>
                    }
                  />
                )}
                {resource.connector && resource.connector.reports.length > 0 ? (
                  <dl className="details">
                    {resource.connector.reports.map((report) => {
                      const peer = resource.status.routing_peers.find(
                        (candidate) => candidate.node_id === report.node_id,
                      );
                      return (
                        <div key={report.node_id}>
                          <dt>{peer?.name ?? report.node_id}</dt>
                          <dd>
                            Last report: {report.state}
                            {report.reason ? `: ${report.reason}` : ""}
                            <div className="cell-sub">{lastSeen(report.reported_at)}</div>
                          </dd>
                        </div>
                      );
                    })}
                  </dl>
                ) : null}
              </Section>
            ) : null}

            <Section
              id="routing-peers"
              title="Routing peers and failover"
              description="Ordered by metric. Clients use the online primary; when it hasn't checked in for 90 seconds the next standby takes over on the following sync."
            >
              {resource.status.routing_peers.length === 0 ? (
                <EmptyState
                  compact
                  headingLevel={3}
                  title="No routing peers selected"
                  body="Nothing is distributed until a routing peer carries this destination. Edit the resource to choose one."
                />
              ) : (
                <Table label="Routing peers" mobile="stack">
                  <thead>
                    <tr>
                      <th>Metric</th>
                      <th>Device</th>
                      <th>Role</th>
                      <th>Health</th>
                      <th>Covering advertisement</th>
                      <th>Forwarding</th>
                    </tr>
                  </thead>
                  <tbody>
                    {resource.status.routing_peers.map((peer) => (
                      <tr key={peer.node_id}>
                        <Td label="Metric">{peer.metric}</Td>
                        <Td label="Device">{peer.name ?? <MonoValue value={peer.node_id} />}</Td>
                        <Td label="Role">{peerStateLabel[peer.state]}</Td>
                        <Td label="Health">
                          <div>
                            <StatusPill tone={peer.online ? "success" : "muted"}>
                              {peer.online ? "Online" : "Offline"}
                            </StatusPill>
                            <div className="cell-sub">{lastSeen(peer.last_seen_at)}</div>
                          </div>
                        </Td>
                        <Td label="Covering route">
                          {peer.covering_route ? (
                            <MonoValue value={peer.covering_route} />
                          ) : (
                            <span className="muted">None</span>
                          )}
                        </Td>
                        <Td label="Forwarding">
                          {peer.forwarding === "enforced" ? (
                            <StatusPill tone="success">Enforced</StatusPill>
                          ) : (
                            <StatusPill tone="muted">Not enforced: upgrade agent</StatusPill>
                          )}
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </Section>

            <Section
              id="distribution"
              title="Effective distribution"
              description={`${receiving.length} of ${resource.status.clients.length} other devices receive exactly ${resource.cidr ?? "this destination"}.`}
            >
              {resource.status.clients.length ? (
                <Table label="Effective distribution" mobile="stack">
                  <thead>
                    <tr>
                      <th>Device</th>
                      <th>Receives route</th>
                      <th>Why</th>
                    </tr>
                  </thead>
                  <tbody>
                    {resource.status.clients.map((client) => (
                      <tr key={client.node_id}>
                        <Td label="Device">{client.name}</Td>
                        <Td label="Receives">
                          <StatusPill tone={client.receives ? "success" : "muted"}>
                            {client.receives ? "Yes" : "No"}
                          </StatusPill>
                        </Td>
                        <Td label="Why">{client.reason}</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              ) : (
                <EmptyState
                  compact
                  headingLevel={3}
                  title="No other devices"
                  body="No other active devices in this organisation could receive this route yet."
                />
              )}
            </Section>

            {choices ? (
              <Section
                id="edit"
                title="Edit this resource"
                description="Change the destination, routing peers or who receives it. Check overlaps before saving."
              >
                <details className="network-editor">
                  <summary>Show the editor</summary>
                  <NetworkResourceForm
                    organisationId={ctx.organisationId}
                    role={ctx.role}
                    peers={choices.peers}
                    groups={choices.groups}
                    existing={resource}
                  />
                </details>
              </Section>
            ) : canManage ? (
              <Alert tone="warning" title="The editor couldn't load">
                Devices and policy groups didn&apos;t load, so this resource can&apos;t be edited
                right now. Reload the page in a moment.
              </Alert>
            ) : null}
          </>
        )}
      </div>
    </ConsoleShell>
  );
}
