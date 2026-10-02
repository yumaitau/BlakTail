import type { Topology } from "@/lib/coord-topology";

const MAX_GRAPH_NODES = 60;
const COLUMN = 210;
const ROW = 54;

type Placed = { id: string; label: string; x: number; y: number; href: string; title: string };

/**
 * Static SVG of devices grouped by tag, with resources in the last column.
 * Every shape is a link, so Tab moves through it; the list beside it is the
 * full text equivalent. Nothing animates.
 */
export function TopologyGraph({ topology }: { topology: Topology }) {
  const groups = new Map<string, Topology["nodes"]>();
  for (const node of topology.nodes) {
    const key = node.tags[0] ?? "untagged";
    groups.set(key, [...(groups.get(key) ?? []), node]);
  }
  if (topology.nodes.length + topology.resources.length > MAX_GRAPH_NODES) {
    return (
      <p className="muted">
        Too many devices to draw clearly. Use the list, search and filters instead.
      </p>
    );
  }
  const columns = [...groups.entries()].sort(([a], [b]) => a.localeCompare(b));
  const placed = new Map<string, Placed>();
  columns.forEach(([, nodes], column) => {
    nodes.forEach((node, row) => {
      placed.set(node.id, {
        id: node.id,
        label: node.label,
        x: 90 + column * COLUMN,
        y: 70 + row * ROW,
        href: `/topology?node=${node.id}`,
        title: `${node.label}: ${node.state}, transport ${node.transport.state.replace("_", " ")}`,
      });
    });
  });
  const resourceColumn = columns.length;
  topology.resources.forEach((resource, row) => {
    placed.set(resource.id, {
      id: resource.id,
      label: resource.name,
      x: 90 + resourceColumn * COLUMN,
      y: 70 + row * ROW,
      href: `/networks/${resource.id}`,
      title: `Network resource ${resource.name} (${resource.destination}), ${resource.state}`,
    });
  });
  const lines = new Map<string, { from: Placed; to: Placed; kind: string }>();
  for (const edge of topology.edges) {
    const from = placed.get(edge.source_node_id);
    const toId = edge.kind === "resource" ? edge.resource_id : edge.target_node_id;
    const to = toId ? placed.get(toId) : undefined;
    if (!from || !to || edge.kind === "route" || edge.kind === "exit") continue;
    // Resource edges are drawn once, from the routing peer.
    const start = edge.kind === "resource" && edge.target_node_id ? placed.get(edge.target_node_id) : from;
    if (!start) continue;
    const key = [start.id, to.id].sort().join("|");
    lines.set(key, { from: start, to, kind: edge.kind });
  }
  const rows = Math.max(
    1,
    ...columns.map(([, nodes]) => nodes.length),
    topology.resources.length,
  );
  const width = 90 + (resourceColumn + 1) * COLUMN;
  const height = 100 + rows * ROW;
  const headings = [...columns.map(([tag]) => tag), ...(topology.resources.length ? ["resources"] : [])];

  return (
    <svg
      className="topology-graph"
      viewBox={`0 0 ${width} ${height}`}
      role="group"
      aria-label="Graph of devices grouped by tag, with network resources. The list on this page has the same information as text."
    >
      {headings.map((heading, column) => (
        <text key={heading} x={90 + column * COLUMN} y={30} textAnchor="middle" className="topology-heading">
          {heading}
        </text>
      ))}
      {[...lines.values()].map(({ from, to, kind }) => (
        <line
          key={`${from.id}-${to.id}`}
          x1={from.x}
          y1={from.y}
          x2={to.x}
          y2={to.y}
          className={`topology-line topology-line-${kind}`}
          aria-hidden="true"
        />
      ))}
      {[...placed.values()].map((node) => (
        <a key={node.id} href={node.href} aria-label={node.title}>
          <title>{node.title}</title>
          <circle cx={node.x} cy={node.y} r={9} className="topology-dot" />
          <text x={node.x} y={node.y + 24} textAnchor="middle" className="topology-label">
            {node.label.length > 22 ? `${node.label.slice(0, 21)}…` : node.label}
          </text>
        </a>
      ))}
    </svg>
  );
}
