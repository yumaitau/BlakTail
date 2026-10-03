"use client";

import "@xyflow/react/dist/style.css";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  type Edge,
  MarkerType,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
} from "@xyflow/react";
import { Graph as DagreGraph, layout as dagreLayout } from "@dagrejs/dagre";
import { ArrowLeft, LayoutGrid, List, Monitor, Network, Users, Waypoints, X } from "lucide-react";
import type { Topology } from "@/lib/coord-topology";
import {
  allSelectors,
  deviceGraph,
  devicesFor,
  type EdgeState,
  type Graph,
  type GraphNode,
  groupGraph,
  networkDetailGraph,
  networksGraph,
  networksOf,
  type SelectorKey,
  selectorLabel,
} from "@/lib/control-center";
import { type FlowNode, nodeSize, nodeType, nodeTypes } from "./graph-nodes";
import { Picker, type PickerOption } from "./picker";

type Tab = "devices" | "groups" | "networks";

const TABS: { id: Tab; label: string; icon: typeof Monitor }[] = [
  { id: "devices", label: "Devices", icon: Monitor },
  { id: "groups", label: "Groups", icon: Users },
  { id: "networks", label: "Networks", icon: Network },
];

const EDGE_STYLE: Record<EdgeState, { stroke: string; dash: string; animated: boolean }> = {
  allowed: { stroke: "var(--cc-allowed)", dash: "6 5", animated: true },
  unenforced: { stroke: "var(--cc-unenforced)", dash: "2 5", animated: false },
  denied: { stroke: "var(--cc-denied)", dash: "10 5", animated: false },
  inactive: { stroke: "var(--cc-inactive)", dash: "2 6", animated: false },
};

const STATE_LABEL: Record<EdgeState, string> = {
  allowed: "Allowed, enforced",
  unenforced: "Allowed, ports not enforced",
  denied: "Denied",
  inactive: "In policy, unused",
};

function subscribeMotion(callback: () => void) {
  const query = window.matchMedia("(prefers-reduced-motion: reduce)");
  query.addEventListener("change", callback);
  return () => query.removeEventListener("change", callback);
}

function useReducedMotion() {
  return useSyncExternalStore(
    subscribeMotion,
    () => window.matchMedia("(prefers-reduced-motion: reduce)").matches,
    () => true,
  );
}

function layoutGraph(graph: Graph): Map<string, { x: number; y: number; width: number; height: number }> {
  const g = new DagreGraph();
  g.setGraph({ rankdir: "LR", ranksep: 170, nodesep: 22, marginx: 20, marginy: 20 });
  g.setDefaultEdgeLabel(() => ({}));
  const sorted = [...graph.nodes].sort((a, b) => a.rank - b.rank || a.label.localeCompare(b.label));
  for (const node of sorted) g.setNode(node.id, { ...nodeSize(node), rank: node.rank });
  for (const edge of graph.edges) g.setEdge(edge.source, edge.target);
  dagreLayout(g);
  const placed = new Map<string, { x: number; y: number; width: number; height: number }>();
  for (const node of sorted) {
    const box = g.node(node.id) as { x: number; y: number; width: number; height: number };
    placed.set(node.id, { x: box.x - box.width / 2, y: box.y - box.height / 2, width: box.width, height: box.height });
  }
  return placed;
}

/** Keeps the chosen view in the address bar so it can be shared and reloaded. */
function writeQuery(patch: Record<string, string | null>) {
  const params = new URLSearchParams(window.location.search);
  for (const [key, value] of Object.entries(patch)) {
    if (value === null || value === "") params.delete(key);
    else params.set(key, value);
  }
  const query = params.toString();
  window.history.replaceState(null, "", `${window.location.pathname}${query ? `?${query}` : ""}`);
}

export function ControlCenter(props: {
  topology: Topology;
  initial: { tab?: string; device?: string; selector?: string; network?: string; view?: string };
}) {
  return (
    <ReactFlowProvider>
      <ControlCenterInner {...props} />
    </ReactFlowProvider>
  );
}

function ControlCenterInner({
  topology,
  initial,
}: {
  topology: Topology;
  initial: { tab?: string; device?: string; selector?: string; network?: string; view?: string };
}) {
  const reduced = useReducedMotion();
  const flow = useReactFlow();
  const panelHeading = useRef<HTMLHeadingElement>(null);

  const devicesWithPaths = useMemo(() => {
    const counts = new Map<string, number>();
    for (const edge of topology.edges) counts.set(edge.source_node_id, (counts.get(edge.source_node_id) ?? 0) + 1);
    return counts;
  }, [topology]);
  const defaultDevice = useMemo(() => {
    const ranked = [...topology.nodes].sort(
      (a, b) =>
        Number(b.state === "online") - Number(a.state === "online") ||
        (devicesWithPaths.get(b.id) ?? 0) - (devicesWithPaths.get(a.id) ?? 0) ||
        a.label.localeCompare(b.label),
    );
    return ranked[0]?.id ?? "";
  }, [topology, devicesWithPaths]);
  const selectors = useMemo(() => allSelectors(topology), [topology]);
  const networks = useMemo(() => networksOf(topology), [topology]);

  const [tab, setTab] = useState<Tab>(
    initial.tab === "groups" || initial.tab === "networks" ? initial.tab : "devices",
  );
  const [device, setDevice] = useState(
    topology.nodes.some((node) => node.id === initial.device) ? initial.device! : defaultDevice,
  );
  const [selector, setSelector] = useState<SelectorKey | "">(
    selectors.includes(initial.selector as SelectorKey) ? (initial.selector as SelectorKey) : (selectors[0] ?? ""),
  );
  const [network, setNetwork] = useState(
    networks.some((n) => n.key === initial.network) ? initial.network! : "all",
  );
  const [listView, setListView] = useState(initial.view === "list");
  const [openId, setOpenId] = useState<string | null>(null);

  const graph = useMemo<Graph>(() => {
    if (tab === "devices") return device ? deviceGraph(topology, device) : { nodes: [], edges: [] };
    if (tab === "groups") return selector ? groupGraph(topology, selector) : { nodes: [], edges: [] };
    return network === "all" ? networksGraph(topology) : networkDetailGraph(topology, network);
  }, [tab, device, selector, network, topology]);

  const open = openId ? graph.nodes.find((node) => node.id === openId) : undefined;

  const drillable = tab === "networks" && network === "all";
  const onOpen = useCallback(
    (id: string) => {
      // In the networks overview a network card drills in, as its picker does.
      const drill = drillable ? graph.nodes.find((node) => node.id === id)?.drill : undefined;
      if (drill) {
        setNetwork(drill);
        setOpenId(null);
        writeQuery({ network: drill });
        return;
      }
      setOpenId(id);
    },
    [drillable, graph],
  );

  const nodes = useMemo<FlowNode[]>(() => {
    const placed = layoutGraph(graph);
    return graph.nodes.map((node) => {
      const box = placed.get(node.id)!;
      return {
        id: node.id,
        type: nodeType(node),
        position: { x: box.x, y: box.y },
        width: box.width,
        height: box.height,
        data: { ...node, onOpen, selected: node.id === openId },
        draggable: false,
        selectable: false,
        focusable: false,
        ariaLabel: node.title,
      } satisfies FlowNode;
    });
  }, [graph, onOpen, openId]);

  const edges = useMemo<Edge[]>(
    () =>
      graph.edges.map((edge) => {
        const style = EDGE_STYLE[edge.state];
        return {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          type: "default",
          animated: style.animated && !reduced,
          className: `cc-edge cc-edge-${edge.state}`,
          style: { stroke: style.stroke, strokeWidth: 1.4, strokeDasharray: style.dash },
          label: edge.label,
          labelStyle: { fill: "var(--foreground)", fontSize: 10, fontFamily: "var(--font-mono)" },
          labelBgStyle: { fill: "var(--surface)" },
          labelBgPadding: [4, 2] as [number, number],
          labelBgBorderRadius: 4,
          markerEnd: edge.state === "denied" ? { type: MarkerType.Arrow, color: "var(--cc-denied)" } : undefined,
          focusable: false,
          selectable: false,
          ariaLabel: edge.text,
        };
      }),
    [graph, reduced],
  );

  // Re-fit whenever the question changes.
  useEffect(() => {
    // On a phone, keep labels legible and let people pan rather than shrinking everything.
    const narrow = window.matchMedia("(max-width: 800px)").matches;
    const frame = requestAnimationFrame(() =>
      flow.fitView({ padding: 0.15, maxZoom: 1.1, minZoom: narrow ? 0.55 : 0.2, duration: reduced ? 0 : 250 }),
    );
    return () => cancelAnimationFrame(frame);
  }, [graph, flow, reduced, listView]);

  useEffect(() => {
    if (open) panelHeading.current?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpenId(null);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open]);

  function switchTab(next: Tab) {
    setTab(next);
    setOpenId(null);
    writeQuery({ tab: next === "devices" ? null : next });
  }

  const deviceOptions: PickerOption[] = topology.nodes.map((node) => ({
    value: node.id,
    label: node.label,
    sub: node.tags.length ? node.tags.map((tag) => `tag:${tag}`).join(" ") : "untagged",
    status: node.state === "online" ? "ok" : node.state === "suspended" || node.state === "expired" ? "bad" : "idle",
  }));
  const selectorOptions: PickerOption[] = selectors.map((key) => ({
    value: key,
    label: selectorLabel(key),
    sub: `${devicesFor(topology, key).length} device(s)`,
  }));
  const networkOptions: PickerOption[] = [
    { value: "all", label: "All networks", sub: `${networks.length} network(s)` },
    ...networks.map((n) => ({ value: n.key, label: n.name, sub: `${n.resources.length} resource(s)` })),
  ];
  const drilled = tab === "networks" && network !== "all" ? networks.find((n) => n.key === network) : undefined;

  function onTabKey(event: React.KeyboardEvent<HTMLButtonElement>, index: number) {
    const delta = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
    if (!delta) return;
    event.preventDefault();
    const next = TABS[(index + delta + TABS.length) % TABS.length]!;
    switchTab(next.id);
    document.getElementById(`cc-tab-${next.id}`)?.focus();
  }

  const emptyMessage =
    topology.nodes.length === 0
      ? "No devices yet. Enrol devices with a join key and their effective paths appear here."
      : graph.nodes.length === 0
        ? tab === "networks"
          ? "No network resources yet. Add one on Networks to see who can reach it."
          : tab === "groups"
            ? "No tags, groups or roles are used in policy yet."
            : "Choose a device."
        : graph.edges.length === 0
          ? tab === "devices"
            ? "Policy currently lets this device reach no other device, route or resource."
            : "Nothing in policy starts from this selection."
          : null;

  return (
    <div className="cc">
      <div className="cc-toolbar">
        {drilled ? (
          <>
            <button
              type="button"
              className="icon-button cc-back"
              aria-label="Back to all networks"
              onClick={() => {
                setNetwork("all");
                setOpenId(null);
                writeQuery({ network: null });
              }}
            >
              <ArrowLeft aria-hidden="true" size={18} />
            </button>
            <Picker
              label="Network"
              value={network}
              options={networkOptions}
              icon={<Network aria-hidden="true" size={16} />}
              onChange={(value) => {
                setNetwork(value);
                setOpenId(null);
                writeQuery({ network: value === "all" ? null : value });
              }}
            />
            <span className="cc-chip">
              <span className={`dot dot-${drilled.routingPeers.some((p) => p.online) ? "ok" : "idle"}`} aria-hidden="true" />
              {drilled.routingPeers.length} routing peer{drilled.routingPeers.length === 1 ? "" : "s"}
              <span className="muted">
                {" "}
                · {drilled.routingPeers.filter((p) => p.online).length} online
              </span>
            </span>
          </>
        ) : (
          <>
            <div className="cc-tabs" role="tablist" aria-label="Control Center view">
              {TABS.map((item, index) => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    id={`cc-tab-${item.id}`}
                    type="button"
                    role="tab"
                    aria-selected={tab === item.id}
                    aria-controls="cc-panel"
                    tabIndex={tab === item.id ? 0 : -1}
                    className="cc-tab"
                    onClick={() => switchTab(item.id)}
                    onKeyDown={(event) => onTabKey(event, index)}
                  >
                    <Icon aria-hidden="true" size={15} />
                    {item.label}
                  </button>
                );
              })}
            </div>
            {tab === "devices" && deviceOptions.length ? (
              <Picker
                label="Device"
                value={device}
                options={deviceOptions}
                icon={<Monitor aria-hidden="true" size={16} />}
                onChange={(value) => {
                  setDevice(value);
                  setOpenId(null);
                  writeQuery({ device: value });
                }}
              />
            ) : null}
            {tab === "groups" && selectorOptions.length ? (
              <Picker
                label="Group, tag or role"
                value={selector}
                options={selectorOptions}
                icon={<Users aria-hidden="true" size={16} />}
                onChange={(value) => {
                  setSelector(value as SelectorKey);
                  setOpenId(null);
                  writeQuery({ selector: value });
                }}
              />
            ) : null}
            {tab === "networks" ? (
              <Picker
                label="Network"
                value={network}
                options={networkOptions}
                icon={<LayoutGrid aria-hidden="true" size={16} />}
                onChange={(value) => {
                  setNetwork(value);
                  setOpenId(null);
                  writeQuery({ network: value === "all" ? null : value });
                }}
              />
            ) : null}
          </>
        )}
        <div className="cc-toolbar-end">
          <span className="cc-meta" title="When the coordinator computed this view">
            Policy rev {topology.policy.revision} ·{" "}
            {new Date(topology.generated_at * 1000).toLocaleTimeString("en-AU", { timeStyle: "short" })}
          </span>
          <button
            type="button"
            className="cc-toggle"
            aria-pressed={listView}
            onClick={() => {
              setListView(!listView);
              writeQuery({ view: listView ? null : "list" });
            }}
          >
            {listView ? <Waypoints aria-hidden="true" size={15} /> : <List aria-hidden="true" size={15} />}
            {listView ? "Graph view" : "List view"}
          </button>
        </div>
      </div>

      <div
        id="cc-panel"
        role="tabpanel"
        aria-labelledby={drilled ? undefined : `cc-tab-${tab}`}
        aria-label={drilled ? `Network ${drilled.name}` : undefined}
        className="cc-body"
      >
        {listView ? (
          <GraphList graph={graph} onOpen={onOpen} />
        ) : (
          <div
            className="cc-canvas"
            role="group"
            aria-label="Policy graph. Each node is a button that opens its details; the List view has the same paths as text."
          >
            <ReactFlow
              nodes={nodes}
              edges={edges}
              nodeTypes={nodeTypes}
              nodesDraggable={false}
              nodesConnectable={false}
              nodesFocusable={false}
              edgesFocusable={false}
              elementsSelectable={false}
              minZoom={0.2}
              maxZoom={2}
              fitView
              proOptions={{ hideAttribution: true }}
              colorMode="dark"
            >
              <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="var(--cc-dot)" />
              <Controls showInteractive={false} position="bottom-right" />
              {graph.nodes.length > 24 ? (
                <MiniMap
                  pannable
                  zoomable
                  position="bottom-left"
                  maskColor="rgba(0,0,0,0.55)"
                  nodeColor="var(--surface-hover)"
                  ariaLabel="Minimap"
                />
              ) : null}
            </ReactFlow>
            <Legend />
            {emptyMessage ? (
              <div className="cc-empty" role="status">
                <p>{emptyMessage}</p>
                {topology.nodes.length === 0 ? <Link href="/join-keys">Create a join key</Link> : null}
                {tab === "networks" && topology.resources.length === 0 ? <Link href="/networks/new">New resource</Link> : null}
              </div>
            ) : null}
          </div>
        )}
        {open ? (
          <aside className="cc-panel" aria-labelledby="cc-panel-title">
            <div className="cc-panel-head">
              <h2 id="cc-panel-title" ref={panelHeading} tabIndex={-1}>
                {open.label}
              </h2>
              <button type="button" className="icon-button" aria-label="Close details" onClick={() => setOpenId(null)}>
                <X aria-hidden="true" size={18} />
              </button>
            </div>
            <p className="muted cc-panel-kind">{kindLabel(open)}</p>
            <dl className="cc-details">
              {open.details.map((detail) => (
                <div key={detail.label}>
                  <dt>{detail.label}</dt>
                  <dd>{detail.value}</dd>
                </div>
              ))}
            </dl>
            <h3 className="cc-panel-sub">Paths</h3>
            <ul className="cc-panel-paths">
              {graph.edges
                .filter((edge) => edge.source === open.id || edge.target === open.id)
                .map((edge) => (
                  <li key={edge.id}>
                    <span className={`cc-line cc-line-${edge.state}`} aria-hidden="true" />
                    {edge.text}
                  </li>
                ))}
            </ul>
            <div className="actions">
              {open.link ? (
                <Link className="button" href={open.link.href}>
                  {open.link.label}
                </Link>
              ) : null}
              {open.drill && network !== open.drill ? (
                <button
                  type="button"
                  className="secondary"
                  onClick={() => {
                    setTab("networks");
                    setNetwork(open.drill!);
                    setOpenId(null);
                    writeQuery({ tab: "networks", network: open.drill! });
                  }}
                >
                  Show this network
                </button>
              ) : null}
            </div>
          </aside>
        ) : null}
      </div>
    </div>
  );
}

function kindLabel(node: GraphNode) {
  switch (node.kind) {
    case "device":
      return "Device";
    case "rule":
      return node.id.startsWith("rule:") ? "Access rule" : node.id.startsWith("access:") ? "Resource access" : node.id === "default" ? "Default policy" : "Approved routes";
    case "selector":
      return "Destination or source selector";
    case "network":
      return "Network (resources sharing routing peers)";
    case "resource":
      return "Network resource";
    default:
      return "Route";
  }
}

function Legend() {
  return (
    <ul className="cc-legend" aria-label="Line styles">
      {(Object.keys(STATE_LABEL) as EdgeState[]).map((state) => (
        <li key={state}>
          <span className={`cc-line cc-line-${state}`} aria-hidden="true" />
          {STATE_LABEL[state]}
        </li>
      ))}
    </ul>
  );
}

/** Text equivalent of the graph: every node and every path, in column order. */
function GraphList({ graph, onOpen }: { graph: Graph; onOpen: (id: string) => void }) {
  const ordered = [...graph.nodes].sort((a, b) => a.rank - b.rank || a.label.localeCompare(b.label));
  if (ordered.length === 0) return <p className="muted cc-list-empty">Nothing to show for this selection.</p>;
  return (
    <div className="cc-list">
      <ul>
        {ordered.map((node) => {
          const out = graph.edges.filter((edge) => edge.source === node.id);
          return (
            <li key={node.id}>
              <button type="button" className="link-button" onClick={() => onOpen(node.id)}>
                {node.label}
              </button>{" "}
              <span className="muted">
                {kindLabel(node)}
                {node.badge ? ` · ${node.badge}` : ""}
                {node.sub ? ` · ${node.sub}` : ""}
              </span>
              {out.length ? (
                <ul>
                  {out.map((edge) => (
                    <li key={edge.id}>
                      <span className={`cc-line cc-line-${edge.state}`} aria-hidden="true" /> {edge.text}
                    </li>
                  ))}
                </ul>
              ) : null}
            </li>
          );
        })}
      </ul>
      <p className="muted">
        Every device-to-device path with its explanation is on the <Link href="/topology">topology list</Link>.
      </p>
    </div>
  );
}
