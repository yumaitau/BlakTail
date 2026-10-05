import { errorText } from "@/lib/server-errors";
import Link from "next/link";
import { ConsoleShell } from "@/components/console-shell";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { listNetworks, type NetworksOverview } from "@/lib/coord-networks";
import { can, permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";
import { lastSeen, resourceStateLabel } from "./format";

/** IPv6 routes (including the ::/0 exit route) are labelled so they are not mistaken for IPv4. */
function Routes({ routes }: { routes: string[] }) {
  if (routes.length === 0) return <>None</>;
  return (
    <>
      {routes.map((route, index) => (
        <span key={route}>
          {index ? ", " : null}
          {route}
          {route.includes(":") ? (
            <span className="muted"> ({route === "::/0" ? "IPv6 exit" : "IPv6"})</span>
          ) : null}
        </span>
      ))}
    </>
  );
}

export default async function NetworksPage() {
  const ctx = await requireConsoleContext();
  let overview: NetworksOverview = { resources: [], device_routes: [] };
  let error: string | null = null;
  try {
    overview = await listNetworks(ctx);
  } catch (err) {
    error = errorText(err, "Could not load networks.");
  }
  const canManage = can(ctx.role, "manage_networks");
  const peerName = (id: string | null) =>
    overview.resources
      .flatMap((resource) => resource.status.routing_peers)
      .find((peer) => peer.node_id === id)?.name ?? "None";

  return (
    <ConsoleShell ctx={ctx} current="/networks">
      <div className="stack">
        <PageHeader
          eyebrow={ctx.organisationName}
          title="Networks"
          description="Named private subnets your devices can reach through routing peers. Creating a resource is the approval: a device advertising a subnet never shares it on its own."
        />
        <div className="panel stack">
          <div className="row">
            <h2>Resources</h2>
            <span className="badge network">{ctx.organisationName}</span>
            <span className="muted">{roleLabel(ctx.role)}</span>
            <Link className="button secondary" href="/networks/addresses">
              Addresses
            </Link>
            {canManage ? (
              <Link className="button" href="/networks/new">
                New resource
              </Link>
            ) : (
              <span className="muted">{permissionReason(ctx.role, "manage_networks")}</span>
            )}
          </div>
          {error ? (
            <p className="error" role="alert">
              {error}
            </p>
          ) : null}
          {!error && overview.resources.length === 0 ? (
            <EmptyState
              title="No network resources yet"
              body="Add a subnet such as an office LAN, choose which Linux routing peers carry it, and choose who receives it."
            />
          ) : null}
          {overview.resources.length ? (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Destination</th>
                    <th>State</th>
                    <th>Routing peer</th>
                    <th>Receiving devices</th>
                  </tr>
                </thead>
                <tbody>
                  {overview.resources.map((resource) => {
                    const state = resourceStateLabel[resource.status.state];
                    return (
                      <tr key={resource.id}>
                        <td>
                          <Link href={`/networks/${resource.id}`}>{resource.name}</Link>
                          {resource.description ? (
                            <div className="muted">{resource.description}</div>
                          ) : null}
                        </td>
                        <td className="mono">
                          {resource.cidr ?? resource.dns_target}
                          {resource.family ? (
                            <div className="muted">{resource.family === "ipv6" ? "IPv6" : "IPv4"}</div>
                          ) : null}
                        </td>
                        <td>
                          <span className={`badge ${state.badge}`}>{state.label}</span>
                        </td>
                        <td>
                          {peerName(resource.status.selected_routing_peer)}
                          {resource.status.forwarding === "not_enforced" ? (
                            <div>
                              <span className="badge offline">Forwarding not enforced — upgrade agent</span>
                            </div>
                          ) : null}
                        </td>
                        <td>
                          {resource.status.clients.filter((client) => client.receives).length}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : null}
        </div>

        <div className="panel stack" id="routes">
          <div>
            <h2>Advertised routes on devices</h2>
            <p className="muted">
              What each routing peer offers. Unapproved routes are never sent to
              clients. Device-level approvals (on Devices) keep working and go to
              every device policy lets reach the router. IPv6 subnets (unique
              local or global) are routed like IPv4 ones; exit routes (0.0.0.0/0
              and ::/0) are only used by clients that choose that exit node.
            </p>
          </div>
          {overview.device_routes.length === 0 ? (
            <p className="muted">No device advertises a subnet or exit route.</p>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Device</th>
                    <th>Health</th>
                    <th>Advertised</th>
                    <th>Approved on device</th>
                    <th>Not approved</th>
                    <th>Forwarding</th>
                  </tr>
                </thead>
                <tbody>
                  {overview.device_routes.map((device) => (
                    <tr key={device.node_id}>
                      <td>{device.display_name || device.name}</td>
                      <td>
                        <span className={device.online ? "badge online" : "badge offline"}>
                          {device.online ? "Online" : "Offline"}
                        </span>
                        <div className="muted">
                          {device.credential_expired ? "Credential expired" : lastSeen(device.last_seen_at)}
                        </div>
                      </td>
                      <td className="mono">
                        <Routes routes={device.advertised_routes} />
                      </td>
                      <td className="mono">
                        <Routes routes={device.approved_routes} />
                      </td>
                      <td className="mono">
                        <Routes routes={device.unapproved_routes} />
                      </td>
                      <td>
                        {device.forwarding === "enforced" ? (
                          <span className="badge online">Enforced</span>
                        ) : (
                          <span className="badge offline" title={device.forwarding_detail}>
                            Not enforced — upgrade agent
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </ConsoleShell>
  );
}
