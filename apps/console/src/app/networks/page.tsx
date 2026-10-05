import { Suspense } from "react";
import Link from "next/link";
import { errorText } from "@/lib/server-errors";
import { ConsoleShell } from "@/components/console-shell";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/ui/alert";
import { StatusPill } from "@/components/ui/badge";
import { MonoValue } from "@/components/ui/mono-value";
import { PermissionNotice } from "@/components/ui/permission-notice";
import { Section } from "@/components/ui/section";
import { SkeletonTable } from "@/components/ui/skeleton";
import { Table, Td } from "@/components/ui/table";
import { listNetworks, type NetworksOverview } from "@/lib/coord-networks";
import { can, permissionReason } from "@/lib/roles";
import { requireConsoleContext, type ConsoleContext } from "@/lib/session";
import { lastSeen, resourceStateLabel } from "./format";

/** IPv6 routes (including the ::/0 exit route) are labelled so they are not mistaken for IPv4. */
function Routes({ routes }: { routes: string[] }) {
  if (routes.length === 0) return <span className="muted">None</span>;
  return (
    <span className="route-list">
      {routes.map((route) => (
        <span key={route}>
          <MonoValue value={route} />
          {route.includes(":") ? (
            <span className="muted"> ({route === "::/0" ? "IPv6 exit" : "IPv6"})</span>
          ) : route === "0.0.0.0/0" ? (
            <span className="muted"> (exit)</span>
          ) : null}
        </span>
      ))}
    </span>
  );
}

const ROUTES_INTRO =
  "What each routing peer offers. Unapproved routes are never sent to clients. Device-level approvals (on Devices) keep working and go to every device policy lets reach the router. Exit routes (0.0.0.0/0 and ::/0) are only used by clients that choose that exit node.";

async function NetworksBody({ ctx, canManage }: { ctx: ConsoleContext; canManage: boolean }) {
  let overview: NetworksOverview = { resources: [], device_routes: [] };
  let error: string | null = null;
  try {
    overview = await listNetworks(ctx);
  } catch (err) {
    error = errorText(err, "Could not load networks.");
  }
  if (error) {
    return (
      <Alert tone="error" title="Couldn't load networks">
        {error}
      </Alert>
    );
  }
  const peerName = (id: string | null) =>
    overview.resources
      .flatMap((resource) => resource.status.routing_peers)
      .find((peer) => peer.node_id === id)?.name ?? null;

  return (
    <>
      <Section
        id="resources"
        title="Resources"
        description="Each resource is one subnet or DNS name, carried by a routing peer to the devices you choose."
      >
        {overview.resources.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No network resources yet"
            body="Add a subnet such as an office LAN, choose which Linux routing peers carry it, and choose who receives it."
            action={
              canManage ? (
                <Link className="button" href="/networks/new">
                  New resource
                </Link>
              ) : undefined
            }
          />
        ) : (
          <Table label="Network resources" mobile="stack">
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
                const peer = peerName(resource.status.selected_routing_peer);
                return (
                  <tr key={resource.id}>
                    <Td label="Name">
                      <div>
                        <Link href={`/networks/${resource.id}`}>{resource.name}</Link>
                        {resource.description ? (
                          <div className="cell-sub">{resource.description}</div>
                        ) : null}
                      </div>
                    </Td>
                    <Td label="Destination">
                      <div>
                        <MonoValue value={resource.cidr ?? resource.dns_target ?? ""} />
                        {resource.family ? (
                          <div className="cell-sub">{resource.family === "ipv6" ? "IPv6" : "IPv4"}</div>
                        ) : null}
                      </div>
                    </Td>
                    <Td label="State">
                      <StatusPill tone={state.tone}>{state.label}</StatusPill>
                    </Td>
                    <Td label="Routing peer">
                      <div>
                        {peer ?? <span className="muted">None</span>}
                        {resource.status.forwarding === "not_enforced" ? (
                          <div className="cell-sub">Forwarding not enforced: upgrade the agent</div>
                        ) : null}
                      </div>
                    </Td>
                    <Td label="Receiving devices">
                      {resource.status.clients.filter((client) => client.receives).length}
                    </Td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        )}
      </Section>

      <Section id="routes" title="Advertised routes on devices" description={ROUTES_INTRO}>
        {overview.device_routes.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No device advertises a route"
            body={
              <>
                Start a Linux agent with <span className="mono">--advertise-routes</span> to
                offer a subnet or exit route. It shows here for approval.
              </>
            }
          />
        ) : (
          <Table label="Advertised routes on devices" mobile="stack">
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
                  <Td label="Device">{device.display_name || device.name}</Td>
                  <Td label="Health">
                    <div>
                      <StatusPill tone={device.online ? "success" : "muted"}>
                        {device.online ? "Online" : "Offline"}
                      </StatusPill>
                      <div className="cell-sub">
                        {device.credential_expired ? "Credential expired" : lastSeen(device.last_seen_at)}
                      </div>
                    </div>
                  </Td>
                  <Td label="Advertised">
                    <Routes routes={device.advertised_routes} />
                  </Td>
                  <Td label="Approved">
                    <Routes routes={device.approved_routes} />
                  </Td>
                  <Td label="Not approved">
                    <Routes routes={device.unapproved_routes} />
                  </Td>
                  <Td label="Forwarding">
                    {device.forwarding === "enforced" ? (
                      <StatusPill tone="success">Enforced</StatusPill>
                    ) : (
                      <StatusPill tone="muted" title={device.forwarding_detail}>
                        Not enforced: upgrade agent
                      </StatusPill>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>
    </>
  );
}

export default async function NetworksPage() {
  const ctx = await requireConsoleContext();
  const canManage = can(ctx.role, "manage_networks");
  const denied = permissionReason(ctx.role, "manage_networks");

  return (
    <ConsoleShell ctx={ctx} current="/networks">
      <div className="stack">
        <PageHeader
          eyebrow={ctx.organisationName}
          title="Networks"
          description="Named private subnets your devices can reach through routing peers. Creating a resource is the approval: a device advertising a subnet never shares it on its own."
          actions={
            <>
              <Link className="button secondary" href="/networks/addresses">
                Addresses
              </Link>
              {canManage ? (
                <Link className="button" href="/networks/new">
                  New resource
                </Link>
              ) : null}
            </>
          }
        />
        {denied ? <PermissionNotice reason={denied} /> : null}
        <Suspense
          fallback={
            <Section title="Resources">
              <SkeletonTable rows={3} label="Loading network resources" />
            </Section>
          }
        >
          <NetworksBody ctx={ctx} canManage={canManage} />
        </Suspense>
      </div>
    </ConsoleShell>
  );
}
