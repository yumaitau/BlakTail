import { errorText } from "@/lib/server-errors";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ConsoleShell } from "@/components/console-shell";
import { NetworkResourceActions } from "@/components/network-resource-actions";
import { NetworkResourceForm } from "@/components/network-resource-form";
import { PageHeader } from "@/components/page-header";
import { getNetworkResource, type NetworkResource } from "@/lib/coord-networks";
import { can, roleLabel } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";
import { resourceFormChoices } from "../choices";
import { lastSeen, peerStateLabel, resourceStateLabel } from "../format";

function accessSummary(resource: NetworkResource): string {
  const parts = [
    ...resource.access.roles.map((role) => `${roleLabel(role)} devices`),
    ...resource.access.tags.map((tag) => `tag:${tag}`),
    ...resource.access.groups.map((group) => `group:${group}`),
  ];
  return parts.join(", ");
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
  const choices = canManage && resource
    ? await resourceFormChoices(ctx).catch(() => null)
    : null;
  const state = resource ? resourceStateLabel[resource.status.state] : null;
  const receiving = resource?.status.clients.filter((client) => client.receives) ?? [];

  return (
    <ConsoleShell ctx={ctx} current="/networks">
      <div className="stack">
        <p>
          <Link href="/networks">← Networks</Link>
        </p>
        {error || !resource || !state ? (
          <p className="error" role="alert">
            {error}
          </p>
        ) : (
          <>
            <PageHeader
              eyebrow={ctx.organisationName}
              title={resource.name}
              description={resource.description || undefined}
            />
            <div className="panel stack">
              <dl className="details">
                <div>
                  <dt>State</dt>
                  <dd>
                    <span className={`badge ${state.badge}`}>{state.label}</span>
                  </dd>
                </div>
                <div>
                  <dt>Destination</dt>
                  <dd className="mono">
                    {resource.cidr ?? resource.dns_target}
                    {resource.family ? ` (${resource.family === "ipv6" ? "IPv6" : "IPv4"})` : ""}
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
                      <div className="muted">
                        Only exact host addresses (/32, /128) are routed. Anyone
                        allowed this resource can reach every port at those
                        addresses until router-side port filtering ships.
                      </div>
                    </dd>
                  </div>
                ) : null}
                <div>
                  <dt>Owning network</dt>
                  <dd>
                    <span className="badge network">{ctx.organisationName}</span>
                  </dd>
                </div>
                <div>
                  <dt>Who may receive it</dt>
                  <dd>{accessSummary(resource)}</dd>
                </div>
                <div>
                  <dt>Ports and protocols</dt>
                  <dd>
                    {[...resource.protocols.map((p) => p.toUpperCase()), ...resource.ports].join(", ") ||
                      "Any"}
                    <div className="muted">
                      {resource.port_enforcement === "enforced"
                        ? "Enforced by the routing peer for each authorised device."
                        : "Not enforced: the routing peer forwards the whole subnet."}
                    </div>
                  </dd>
                </div>
                <div>
                  <dt>Router forwarding</dt>
                  <dd>
                    <span
                      className={`badge ${resource.status.forwarding === "enforced" ? "online" : "offline"}`}
                    >
                      {resource.status.forwarding === "enforced"
                        ? "Enforced"
                        : resource.status.forwarding === "not_enforced"
                          ? "Forwarding not enforced — upgrade agent"
                          : "No routing peer"}
                    </span>
                    <div className="muted">{resource.status.forwarding_detail}</div>
                  </dd>
                </div>
                <div>
                  <dt>Masquerade (NAT)</dt>
                  <dd>
                    Always on <span className="muted">(no-NAT forwarding is not supported by the Linux agent yet)</span>
                  </dd>
                </div>
                {resource.public_route_confirmed_by ? (
                  <div>
                    <dt>Public route confirmed by</dt>
                    <dd className="mono">{resource.public_route_confirmed_by}</dd>
                  </div>
                ) : null}
                <div>
                  <dt>Revision</dt>
                  <dd>{resource.revision}</dd>
                </div>
              </dl>
              <NetworkResourceActions
                organisationId={ctx.organisationId}
                organisationName={ctx.organisationName}
                role={ctx.role}
                resourceId={resource.id}
                resourceName={resource.name}
                etag={resource.etag}
                enabled={resource.enabled}
              />
            </div>

            {resource.kind === "dns" ? (
              <div className="panel stack">
                <div>
                  <h2>App connector answers</h2>
                  <p className="muted">
                    The selected connector resolves {resource.dns_target} from its
                    own resolver every 30 seconds. Each answer is leased for its
                    DNS TTL (at least 30 seconds, at most 5 minutes); expired or
                    changed answers are withdrawn from clients on their next sync.
                    An answer pointing at loopback, link-local, cloud metadata,
                    multicast or BlakTail&apos;s own addresses blocks the resource.
                  </p>
                </div>
                {resource.connector?.blocked_reason ? (
                  <p className="error" role="alert">
                    Blocked: {resource.connector.blocked_reason}. Nothing is routed
                    until the connector reports a safe answer.
                  </p>
                ) : null}
                {resource.connector && resource.connector.answers.length > 0 ? (
                  <div className="table-wrap">
                    <table className="table">
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
                            <td className="mono">{lease.route}</td>
                            <td>{lease.ttl} s</td>
                            <td>
                              {new Date(lease.expires_at * 1000).toLocaleTimeString("en-AU", {
                                timeZone: "Australia/Sydney",
                              })}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : resource.connector?.blocked_reason ? null : (
                  <p className="muted">
                    Not resolved yet. Add a Linux routing peer started with{" "}
                    <code>blaktaild up --app-connector</code>.
                  </p>
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
                            {report.reason ? ` — ${report.reason}` : ""}
                            <div className="muted">{lastSeen(report.reported_at)}</div>
                          </dd>
                        </div>
                      );
                    })}
                  </dl>
                ) : null}
              </div>
            ) : null}

            <div className="panel stack">
              <div>
                <h2>Routing peers and failover</h2>
                <p className="muted">
                  Ordered by metric. Clients use the online primary; when it has
                  not checked in for 90 seconds the next standby takes over on
                  the following sync.
                </p>
              </div>
              {resource.status.routing_peers.length === 0 ? (
                <p className="muted">No routing peers selected, so nothing is distributed.</p>
              ) : (
                <div className="table-wrap">
                  <table className="table">
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
                          <td>{peer.metric}</td>
                          <td>{peer.name ?? <span className="mono">{peer.node_id}</span>}</td>
                          <td>{peerStateLabel[peer.state]}</td>
                          <td>
                            <span className={peer.online ? "badge online" : "badge offline"}>
                              {peer.online ? "Online" : "Offline"}
                            </span>
                            <div className="muted">{lastSeen(peer.last_seen_at)}</div>
                          </td>
                          <td className="mono">{peer.covering_route ?? "None"}</td>
                          <td>
                            {peer.forwarding === "enforced" ? (
                              <span className="badge online">Enforced</span>
                            ) : (
                              <span className="badge offline">Not enforced — upgrade agent</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="panel stack">
              <div>
                <h2>Effective distribution</h2>
                <p className="muted">
                  {receiving.length} of {resource.status.clients.length} other
                  devices receive exactly {resource.cidr ?? "this destination"}.
                </p>
              </div>
              {resource.status.clients.length ? (
                <div className="table-wrap">
                  <table className="table">
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
                          <td>{client.name}</td>
                          <td>
                            <span className={client.receives ? "badge online" : "badge offline"}>
                              {client.receives ? "Yes" : "No"}
                            </span>
                          </td>
                          <td>{client.reason}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="muted">No other active devices in this organisation.</p>
              )}
            </div>

            {choices ? (
              <details className="panel">
                <summary>Edit this resource</summary>
                <NetworkResourceForm
                  organisationId={ctx.organisationId}
                  organisationName={ctx.organisationName}
                  role={ctx.role}
                  peers={choices.peers}
                  groups={choices.groups}
                  existing={resource}
                />
              </details>
            ) : null}
          </>
        )}
      </div>
    </ConsoleShell>
  );
}
