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
    error = err instanceof Error ? err.message : "Could not load this resource.";
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
                      Not resolved. BlakTail records the name but does not resolve
                      or route DNS targets yet.
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
                      Recorded only: the routing peer forwards the whole subnet today.
                    </div>
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
