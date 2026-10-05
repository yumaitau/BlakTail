import { Suspense } from "react";
import Link from "next/link";
import { errorText } from "@/lib/server-errors";
import { ConsoleShell } from "@/components/console-shell";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/ui/alert";
import { StatusPill, type BadgeTone } from "@/components/ui/badge";
import { LocalTime } from "@/components/ui/local-time";
import { Section } from "@/components/ui/section";
import { SkeletonTable } from "@/components/ui/skeleton";
import { Table, Td } from "@/components/ui/table";
import {
  editHref,
  getTopology,
  type Topology,
  type TopologyEdge,
  type TopologyNode,
} from "@/lib/coord-topology";
import {
  requireConsoleContext,
  requireOrganisationContext,
  type ConsoleContext,
} from "@/lib/session";

const KINDS = ["device", "resource", "route", "exit"] as const;
const PATHS = ["direct", "relay", "mixed", "unknown", "peer_offline"] as const;

const kindLabel: Record<TopologyEdge["kind"], string> = {
  device: "Device to device",
  resource: "Network resource",
  route: "Subnet route",
  exit: "Exit node",
};

const pathLabel: Record<TopologyEdge["path"], { label: string; tone: BadgeTone }> = {
  direct: { label: "Direct", tone: "success" },
  relay: { label: "Relayed", tone: "warning" },
  mixed: { label: "Mixed", tone: "warning" },
  unknown: { label: "Not measured", tone: "neutral" },
  peer_offline: { label: "Endpoint offline", tone: "muted" },
};

const stateLabel: Record<TopologyNode["state"], { label: string; tone: BadgeTone }> = {
  online: { label: "Online", tone: "success" },
  stale: { label: "Stale heartbeat", tone: "warning" },
  never: { label: "Never seen", tone: "muted" },
  suspended: { label: "Suspended", tone: "danger" },
  expired: { label: "Credential expired", tone: "danger" },
};

const transportLabel: Record<TopologyNode["transport"]["state"], string> = {
  direct: "Direct UDP",
  relay: "Australian relay",
  mixed: "Mixed",
  not_measured: "Not measured",
};

const filterLabel: Record<TopologyNode["packet_filter"], string> = {
  enforced: "Enforced",
  unknown: "Unknown",
  not_enforced: "Not enforced",
};

function when(seconds: number | null) {
  return <LocalTime value={seconds} fallback="never" />;
}

function pick<T extends string>(value: string | undefined, allowed: readonly T[]): T | "" {
  return allowed.includes(value as T) ? (value as T) : "";
}

type Params = {
  q?: string;
  kind?: string;
  path?: string;
  node?: string;
  organisation?: string;
};

async function TopologyBody({ ctx, params }: { ctx: ConsoleContext; params: Params }) {
  const q = (params.q ?? "").trim().toLowerCase().slice(0, 100);
  const kind = pick(params.kind, KINDS);
  const path = pick(params.path, PATHS);
  const focus = /^[0-9a-f-]{36}$/i.test(params.node ?? "") ? params.node! : "";

  let topology: Topology | null = null;
  let error: string | null = null;
  try {
    topology = await getTopology(ctx);
  } catch (err) {
    error = errorText(err, "Could not load the topology.");
  }
  if (!topology) {
    return (
      <Alert
        tone="error"
        title="Couldn't reach the coordinator"
        action={
          <Link className="button secondary" href="/status">
            Check status
          </Link>
        }
      >
        <p>{error}</p>
        <p>Devices that are already connected keep working without the coordinator.</p>
      </Alert>
    );
  }

  const nodes = new Map(topology.nodes.map((node) => [node.id, node]));
  const focused = focus ? nodes.get(focus) : undefined;
  const edges = topology.edges.filter(
    (edge) =>
      (!kind || edge.kind === kind) &&
      (!path || edge.path === path) &&
      (!focus || edge.source_node_id === focus || edge.target_node_id === focus) &&
      (!q ||
        edge.explanation.toLowerCase().includes(q) ||
        edge.destination.toLowerCase().includes(q)),
  );
  const bySource = new Map<string, TopologyEdge[]>();
  for (const edge of edges) {
    bySource.set(edge.source_node_id, [...(bySource.get(edge.source_node_id) ?? []), edge]);
  }
  const filtered = Boolean(q || kind || path || focus);
  const online = topology.nodes.filter((node) => node.state === "online").length;

  return (
    <>
      <Section
        id="planes"
        title="Control plane and data plane"
        description={
          <>
            Coordinator answered {when(topology.generated_at)}. Path types come from what each agent last
            reported; reports older than ten minutes show as not measured.
          </>
        }
      >
        <dl className="stat-grid">
          <div>
            <dt>Devices online</dt>
            <dd>
              {online} of {topology.nodes.length}
            </dd>
          </div>
          <div>
            <dt>Paths</dt>
            <dd>{topology.edges.length}</dd>
          </div>
          <div>
            <dt>Policy revision</dt>
            <dd>{topology.policy.revision}</dd>
          </div>
          <div>
            <dt>Default for unmatched traffic</dt>
            <dd>{topology.policy.defaults === "deny" ? "Deny" : "Same tag"}</dd>
          </div>
        </dl>
        {topology.notes.length ? (
          <ul className="muted">
            {topology.notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        ) : null}
      </Section>

      <Section
        id="reach"
        title="Who can reach what"
        description={
          <>
            Change access on <Link href="/acls">Access policy</Link>, routes on{" "}
            <Link href="/networks">Networks</Link>, or stage several changes together on{" "}
            <Link href="/changes">Change drafts</Link>.
          </>
        }
      >
        <form className="ui-toolbar" method="get" role="search" aria-label="Filter paths">
          <div className="ui-form-grid topology-filters">
            <div className="ui-field">
              <label className="ui-field-label" htmlFor="topology-q">
                Search
              </label>
              <input id="topology-q" name="q" type="search" defaultValue={params.q ?? ""} maxLength={100} placeholder="Device, route or resource" />
            </div>
            <div className="ui-field">
              <label className="ui-field-label" htmlFor="topology-kind">
                Kind
              </label>
              <select id="topology-kind" name="kind" defaultValue={kind}>
                <option value="">All kinds</option>
                {KINDS.map((value) => (
                  <option key={value} value={value}>
                    {kindLabel[value]}
                  </option>
                ))}
              </select>
            </div>
            <div className="ui-field">
              <label className="ui-field-label" htmlFor="topology-path">
                Path
              </label>
              <select id="topology-path" name="path" defaultValue={path}>
                <option value="">All paths</option>
                {PATHS.map((value) => (
                  <option key={value} value={value}>
                    {pathLabel[value].label}
                  </option>
                ))}
              </select>
            </div>
          </div>
          {focus ? <input type="hidden" name="node" value={focus} /> : null}
          {params.organisation ? (
            <input type="hidden" name="organisation" value={ctx.organisationId} />
          ) : null}
          <div className="ui-form-actions">
            <button className="button ui-button" type="submit">
              Apply filters
            </button>
            {filtered ? (
              <Link className="button secondary ui-button" href="/topology">
                Clear
              </Link>
            ) : null}
          </div>
        </form>
        {focus && !focused ? (
          <Alert tone="warning">That device is not an active device in {ctx.organisationName}.</Alert>
        ) : null}
        {focused ? (
          <p>
            Showing paths to and from <strong>{focused.label}</strong>.{" "}
            <Link href={`/devices/${focused.id}?organisation=${ctx.organisationId}`}>
              Device detail
            </Link>
          </p>
        ) : null}
        <p className="muted" role="status">
          {edges.length} of {topology.edges.length} paths
          {topology.truncated ? " (only the first pairs are evaluated for a large estate)" : ""}.
        </p>
        {topology.nodes.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No devices yet"
            body="Enrol devices with a join key; their effective paths appear here."
            action={
              <Link className="button" href="/join-keys">
                Create a join key
              </Link>
            }
          />
        ) : edges.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title={filtered ? "No paths match these filters" : "No paths yet"}
            body={
              filtered
                ? "Try a broader search or clear the filters."
                : "Policy currently lets no device reach another device, route or resource."
            }
          />
        ) : (
          <div className="topology-groups">
            {[...bySource.entries()].map(([source, list]) => {
              const node = nodes.get(source);
              return (
                <div key={source} className="topology-group">
                  <h3>
                    From {node?.label ?? source}{" "}
                    {node ? (
                      <StatusPill tone={stateLabel[node.state].tone}>
                        {stateLabel[node.state].label}
                      </StatusPill>
                    ) : null}
                  </h3>
                  <ul className="topology-edges">
                    {list.map((edge) => (
                      <li
                        key={`${edge.kind}-${edge.target_node_id}-${edge.resource_id}-${edge.destination}`}
                      >
                        <StatusPill tone={pathLabel[edge.path].tone}>
                          {pathLabel[edge.path].label}
                        </StatusPill>
                        <span>
                          {edge.explanation}{" "}
                          <Link href={editHref(edge)}>
                            {edge.edit.surface === "policy"
                              ? "Policy"
                              : edge.edit.surface === "network_resource"
                                ? "Resource"
                                : "Router"}
                            <span className="visually-hidden"> for {edge.destination}</span>
                          </Link>
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              );
            })}
          </div>
        )}
      </Section>

      <Section id="devices" title="Devices">
        {topology.nodes.length === 0 ? (
          <p className="muted">No devices.</p>
        ) : (
          <Table label="Devices in the topology" mobile="stack">
            <thead>
              <tr>
                <th scope="col">Device</th>
                <th scope="col">State</th>
                <th scope="col">Transport</th>
                <th scope="col">Inbound filter</th>
                <th scope="col">Approved routes</th>
              </tr>
            </thead>
            <tbody>
              {topology.nodes.map((node) => (
                <tr key={node.id}>
                  <Td label="Device">
                    <Link href={`/topology?node=${node.id}&organisation=${ctx.organisationId}`}>
                      {node.label}
                    </Link>
                    <div className="cell-sub">
                      {node.tags.length ? node.tags.join(", ") : "Untagged"} ·{" "}
                      <Link href={`/devices/${node.id}?organisation=${ctx.organisationId}`}>
                        Details<span className="visually-hidden"> for {node.label}</span>
                      </Link>
                    </div>
                  </Td>
                  <Td label="State">
                    <StatusPill tone={stateLabel[node.state].tone}>
                      {stateLabel[node.state].label}
                    </StatusPill>
                    <div className="cell-sub">Last seen {when(node.last_seen_at)}</div>
                  </Td>
                  <Td label="Transport">
                    {transportLabel[node.transport.state]}
                    <div className="cell-sub">
                      {node.transport.reported_at
                        ? <>{node.transport.stale ? "Stale report" : "Reported"} {when(node.transport.reported_at)}</>
                        : "No report"}
                    </div>
                  </Td>
                  <Td label="Inbound filter">{filterLabel[node.packet_filter]}</Td>
                  <Td label="Approved routes">
                    {node.approved_routes.length ? (
                      <span className="mono">{node.approved_routes.join(", ")}</span>
                    ) : (
                      <span className="muted">None</span>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>

      <Section id="resources" title="Network resources and routing peers">
        {topology.resources.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No network resources yet"
            body="Resources share a private subnet through a routing peer."
            action={
              <Link className="button secondary" href="/networks/new">
                New resource
              </Link>
            }
          />
        ) : (
          <Table label="Network resources" mobile="stack">
            <thead>
              <tr>
                <th scope="col">Resource</th>
                <th scope="col">State</th>
                <th scope="col">Receiving devices</th>
                <th scope="col">Routing peers</th>
              </tr>
            </thead>
            <tbody>
              {topology.resources.map((resource) => (
                <tr key={resource.id}>
                  <Td label="Resource">
                    <Link href={`/networks/${resource.id}`}>{resource.name}</Link>
                    <div className="cell-sub mono">{resource.destination}</div>
                  </Td>
                  <Td label="State">{resource.state.replaceAll("_", " ")}</Td>
                  <Td label="Receiving devices">{resource.receiving}</Td>
                  <Td label="Routing peers">
                    {resource.routing_peers.length ? (
                      resource.routing_peers.map((peer) => (
                        <div key={peer.node_id}>
                          {peer.name ?? peer.node_id}{" "}
                          <span className="muted">({peer.state.replaceAll("_", " ")})</span>
                        </div>
                      ))
                    ) : (
                      <span className="muted">None</span>
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

export default async function TopologyPage({
  searchParams,
}: {
  searchParams: Promise<Params>;
}) {
  const params = await searchParams;
  // Deep links from a device name its organisation; membership is checked.
  const ctx = params.organisation
    ? await requireOrganisationContext(params.organisation)
    : await requireConsoleContext();

  return (
    <ConsoleShell ctx={ctx} current="/control-center">
      <div className="stack">
        <PageHeader
          eyebrow={ctx.organisationName}
          title="Topology"
          description="Who can reach what in this organisation, through which router, and whether the path is direct, relayed or not yet measured. Built from the published policy by the same compiler that sends devices their peer lists."
          actions={
            <Link className="button secondary" href="/control-center">
              Open the graph
            </Link>
          }
        />
        <Suspense
          fallback={
            <Section title="Who can reach what">
              <SkeletonTable rows={6} label="Loading the topology" />
            </Section>
          }
        >
          <TopologyBody ctx={ctx} params={params} />
        </Suspense>
      </div>
    </ConsoleShell>
  );
}
