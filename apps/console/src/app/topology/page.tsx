import { errorText } from "@/lib/server-errors";
import Link from "next/link";
import { ConsoleShell } from "@/components/console-shell";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import {
  editHref,
  getTopology,
  type Topology,
  type TopologyEdge,
  type TopologyNode,
} from "@/lib/coord-topology";
import { roleLabel } from "@/lib/roles";
import { requireConsoleContext, requireOrganisationContext } from "@/lib/session";

const KINDS = ["device", "resource", "route", "exit"] as const;
const PATHS = ["direct", "relay", "mixed", "unknown", "peer_offline"] as const;

const kindLabel: Record<TopologyEdge["kind"], string> = {
  device: "Device to device",
  resource: "Network resource",
  route: "Subnet route",
  exit: "Exit node",
};

const pathLabel: Record<TopologyEdge["path"], { label: string; badge: string }> = {
  direct: { label: "Direct", badge: "online" },
  relay: { label: "Relayed", badge: "pending" },
  mixed: { label: "Mixed", badge: "pending" },
  unknown: { label: "Not measured", badge: "" },
  peer_offline: { label: "Endpoint offline", badge: "offline" },
};

const stateLabel: Record<TopologyNode["state"], { label: string; badge: string }> = {
  online: { label: "Online", badge: "online" },
  stale: { label: "Stale heartbeat", badge: "pending" },
  never: { label: "Never seen", badge: "offline" },
  suspended: { label: "Suspended", badge: "revoked" },
  expired: { label: "Credential expired", badge: "revoked" },
};

const transportLabel: Record<TopologyNode["transport"]["state"], string> = {
  direct: "Direct UDP",
  relay: "Australian relay",
  mixed: "Mixed",
  not_measured: "Not measured",
};

function when(seconds: number | null): string {
  if (!seconds) return "never";
  return new Date(seconds * 1000).toLocaleString("en-AU", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function pick<T extends string>(value: string | undefined, allowed: readonly T[]): T | "" {
  return allowed.includes(value as T) ? (value as T) : "";
}

export default async function TopologyPage({
  searchParams,
}: {
  searchParams: Promise<{
    q?: string;
    kind?: string;
    path?: string;
    node?: string;
    organisation?: string;
  }>;
}) {
  const params = await searchParams;
  // Deep links from a device name its organisation; membership is checked.
  const ctx = params.organisation
    ? await requireOrganisationContext(params.organisation)
    : await requireConsoleContext();
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

  const nodes = new Map((topology?.nodes ?? []).map((node) => [node.id, node]));
  const focused = focus ? nodes.get(focus) : undefined;
  const edges = (topology?.edges ?? []).filter(
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

  return (
    <ConsoleShell ctx={ctx} current="/control-center">
      <div className="stack">
        <PageHeader
          eyebrow={ctx.organisationName}
          title="Topology"
          description="Who can reach what in this organisation, through which router, and whether the path is direct, relayed or unknown. Computed from the published policy by the same compiler that builds device peer maps."
        />
        <p>
          <Link className="button secondary" href="/control-center">
            Open the Control Center graph
          </Link>
        </p>
        <p className="muted">
          <span className="badge network">{ctx.organisationName}</span> {roleLabel(ctx.role)} ·
          Only this organisation&apos;s devices are shown. Change access on{" "}
          <Link href="/acls">Access policy</Link>, routes on <Link href="/networks">Networks</Link>,
          or stage several changes together on <Link href="/changes">Change drafts</Link>.
        </p>
        {error ? (
          <div className="panel">
            <p className="error" role="alert">
              Coordinator unavailable: {error}. This says nothing about whether devices can still
              reach each other; existing tunnels keep working without the coordinator.
            </p>
          </div>
        ) : null}
        {topology ? (
          <>
            <section className="panel stack" aria-labelledby="planes-title">
              <h2 id="planes-title">Control plane and data plane</h2>
              <dl className="details">
                <div>
                  <dt>Control plane</dt>
                  <dd>
                    Coordinator answered {when(topology.generated_at)} · policy revision{" "}
                    {topology.policy.revision} · control revision {topology.control_revision} ·
                    defaults {topology.policy.defaults === "deny" ? "deny" : "legacy same-tag"}
                  </dd>
                </div>
                <div>
                  <dt>Data plane</dt>
                  <dd>
                    {topology.nodes.filter((node) => node.state === "online").length} of{" "}
                    {topology.nodes.length} devices online. Path types come from what each agent last
                    reported; unreported or older-than-ten-minute reports show as not measured.
                  </dd>
                </div>
              </dl>
              <ul className="muted">
                {topology.notes.map((note) => (
                  <li key={note}>{note}</li>
                ))}
              </ul>
            </section>

            <section className="panel stack" aria-labelledby="reach-title">
              <h2 id="reach-title">Who can reach what</h2>
              <form className="filter-row" method="get" role="search" aria-label="Filter paths">
                <label>
                  Search
                  <input name="q" type="search" defaultValue={params.q ?? ""} maxLength={100} />
                </label>
                <label>
                  Kind
                  <select name="kind" defaultValue={kind}>
                    <option value="">All</option>
                    {KINDS.map((value) => (
                      <option key={value} value={value}>
                        {kindLabel[value]}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Path
                  <select name="path" defaultValue={path}>
                    <option value="">All</option>
                    {PATHS.map((value) => (
                      <option key={value} value={value}>
                        {pathLabel[value].label}
                      </option>
                    ))}
                  </select>
                </label>
                {focus ? <input type="hidden" name="node" value={focus} /> : null}
                {params.organisation ? (
                  <input type="hidden" name="organisation" value={ctx.organisationId} />
                ) : null}
                <button className="button" type="submit">
                  Apply
                </button>
                {filtered ? <Link href="/topology">Clear filters</Link> : null}
              </form>
              {focus && !focused ? (
                <p className="muted" role="status">
                  That device is not an active device in {ctx.organisationName}.
                </p>
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
                {topology.truncated ? " (pairwise evaluation truncated for a large estate)" : ""}.
              </p>
              {topology.nodes.length === 0 ? (
                <EmptyState
                  title="No devices yet"
                  body="Enrol devices with a join key; their effective paths appear here."
                  action={<Link href="/join-keys">Join keys</Link>}
                />
              ) : edges.length === 0 ? (
                <p className="muted">
                  {filtered
                    ? "No paths match these filters."
                    : "Policy currently lets no device reach another device, route or resource."}
                </p>
              ) : (
                [...bySource.entries()].map(([source, list]) => {
                  const node = nodes.get(source);
                  return (
                    <div key={source} className="stack">
                      <h3>
                        From {node?.label ?? source}{" "}
                        {node ? (
                          <span className={`badge ${stateLabel[node.state].badge}`}>
                            {stateLabel[node.state].label}
                          </span>
                        ) : null}
                      </h3>
                      <ul className="audit-details">
                        {list.map((edge) => (
                          <li key={`${edge.kind}-${edge.target_node_id}-${edge.resource_id}-${edge.destination}`}>
                            <span className={`badge ${pathLabel[edge.path].badge}`}>
                              {pathLabel[edge.path].label}
                            </span>{" "}
                            {edge.explanation}{" "}
                            <Link href={editHref(edge)}>
                              {edge.edit.surface === "policy"
                                ? "Policy"
                                : edge.edit.surface === "network_resource"
                                  ? "Resource"
                                  : "Router"}
                              <span className="visually-hidden"> for {edge.destination}</span>
                            </Link>
                          </li>
                        ))}
                      </ul>
                    </div>
                  );
                })
              )}
            </section>

            <section className="panel stack" aria-labelledby="devices-title">
              <h2 id="devices-title">Devices</h2>
              {topology.nodes.length === 0 ? (
                <p className="muted">No devices.</p>
              ) : (
                <div className="table-wrap">
                  <table className="table">
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
                          <td>
                            <Link href={`/topology?node=${node.id}&organisation=${ctx.organisationId}`}>
                              {node.label}
                            </Link>
                            <div className="muted">
                              {node.tags.length ? node.tags.join(", ") : "untagged"} ·{" "}
                              <Link href={`/devices/${node.id}?organisation=${ctx.organisationId}`}>
                                detail
                              </Link>
                            </div>
                          </td>
                          <td>
                            <span className={`badge ${stateLabel[node.state].badge}`}>
                              {stateLabel[node.state].label}
                            </span>
                            <div className="muted">Last seen {when(node.last_seen_at)}</div>
                          </td>
                          <td>
                            {transportLabel[node.transport.state]}
                            <div className="muted">
                              {node.transport.reported_at
                                ? `${node.transport.stale ? "Stale report" : "Reported"} ${when(node.transport.reported_at)}`
                                : "No report"}
                            </div>
                          </td>
                          <td>{node.packet_filter.replace("_", " ")}</td>
                          <td className="mono">{node.approved_routes.join(", ") || "None"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>

            <section className="panel stack" aria-labelledby="resources-title">
              <h2 id="resources-title">Network resources and routing peers</h2>
              {topology.resources.length === 0 ? (
                <p className="muted">
                  No network resources. <Link href="/networks">Add one on Networks</Link>.
                </p>
              ) : (
                <ul className="audit-details">
                  {topology.resources.map((resource) => (
                    <li key={resource.id}>
                      <Link href={`/networks/${resource.id}`}>{resource.name}</Link>{" "}
                      <span className="mono">{resource.destination}</span> · {resource.state.replaceAll("_", " ")} ·{" "}
                      {resource.receiving} receiving device(s) · routing peers:{" "}
                      {resource.routing_peers.length
                        ? resource.routing_peers
                            .map((peer) => `${peer.name ?? peer.node_id} (${peer.state.replace("_", " ")})`)
                            .join(", ")
                        : "none"}
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
