"use client";

import { Handle, type Node, type NodeProps, Position } from "@xyflow/react";
import {
  Boxes,
  Globe,
  Laptop,
  Layers,
  Network,
  Route,
  Server,
  Tag,
  UserCog,
  Users,
  Waypoints,
} from "lucide-react";
import type { GraphNode } from "@/lib/control-center";

export type FlowData = GraphNode & { onOpen: (id: string) => void; selected?: boolean };
export type FlowNode = Node<FlowData>;

const ICONS = {
  device: Laptop,
  tag: Tag,
  group: Users,
  role: UserCog,
  any: Boxes,
  host: Server,
  cidr: Waypoints,
  dns: Globe,
  network: Network,
  route: Route,
} as const;

function Icon({ name, size = 16 }: { name?: GraphNode["icon"]; size?: number }) {
  const Component = name ? ICONS[name] : Layers;
  return <Component aria-hidden="true" size={size} strokeWidth={1.75} />;
}

function Handles() {
  return (
    <>
      <Handle type="target" position={Position.Left} isConnectable={false} className="cc-handle" />
      <Handle type="source" position={Position.Right} isConnectable={false} className="cc-handle" />
    </>
  );
}

const STATUS_TEXT = { ok: "active", idle: "inactive", bad: "denied or blocked" } as const;

export function RuleNode({ data }: NodeProps<FlowNode>) {
  return (
    <>
      <Handles />
      <button
        type="button"
        className="cc-pill nodrag"
        aria-pressed={data.selected}
        title={data.title}
        onClick={() => data.onOpen(data.id)}
      >
        <span className={`dot dot-${data.status ?? "idle"}`} aria-hidden="true" />
        <span className="cc-pill-label">{data.label}</span>
        {data.badge ? <span className="cc-pill-badge">{data.badge}</span> : null}
        <span className="visually-hidden">, {STATUS_TEXT[data.status ?? "idle"]}. Show details</span>
      </button>
    </>
  );
}

export function CardNode({ data }: NodeProps<FlowNode>) {
  return (
    <>
      <Handles />
      <button
        type="button"
        className={`cc-card nodrag cc-card-${data.kind}`}
        aria-pressed={data.selected}
        title={data.title}
        onClick={() => data.onOpen(data.id)}
      >
        <span className="cc-card-icon">
          <Icon name={data.icon} />
          {data.kind === "device" ? (
            <span className={`cc-card-status dot dot-${data.status ?? "idle"}`} aria-hidden="true" />
          ) : null}
        </span>
        <span className="cc-card-text">
          <span className="cc-card-label">{data.label}</span>
          {data.sub ? <span className="cc-card-sub">{data.sub}</span> : null}
        </span>
        <span className="visually-hidden">. Show details</span>
      </button>
    </>
  );
}

export function PlainNode({ data }: NodeProps<FlowNode>) {
  return (
    <>
      <Handles />
      <button
        type="button"
        className="cc-plain nodrag"
        aria-pressed={data.selected}
        title={data.title}
        onClick={() => data.onOpen(data.id)}
      >
        <span className="cc-card-icon small">
          <Icon name={data.icon} size={14} />
        </span>
        <span className="cc-card-text">
          <span className="cc-card-label">{data.label}</span>
          {data.sub ? <span className="cc-card-sub mono">{data.sub}</span> : null}
        </span>
        <span className="visually-hidden">. Show details</span>
      </button>
    </>
  );
}

export function NetworkNode({ data }: NodeProps<FlowNode>) {
  const peers = data.peers ?? { online: 0, total: 0 };
  return (
    <>
      <Handles />
      <div className={`cc-network${data.selected ? " selected" : ""}`}>
        <button
          type="button"
          className="cc-network-head nodrag"
          title={data.title}
          onClick={() => data.onOpen(data.id)}
        >
          <span className="cc-network-title">
            <Network aria-hidden="true" size={14} strokeWidth={1.75} />
            <span>{data.label}</span>
          </span>
          <span className="cc-network-sub">{data.sub}</span>
          <span className="cc-network-peers">
            <span className={`dot dot-${peers.online ? "ok" : "idle"}`} aria-hidden="true" />
            {peers.online}/{peers.total} routing peer{peers.total === 1 ? "" : "s"} online
          </span>
          <span className="visually-hidden">. Show details</span>
        </button>
        {data.items?.length ? (
          <ul className="cc-network-items">
            {data.items.map((item) => (
              <li key={`${item.label}-${item.sub}`}>
                <span className="cc-card-icon small">
                  <Icon name={item.icon} size={14} />
                </span>
                <span className="cc-card-text">
                  <span className="cc-card-label">{item.label}</span>
                  <span className="cc-card-sub mono">{item.sub}</span>
                </span>
              </li>
            ))}
          </ul>
        ) : null}
      </div>
    </>
  );
}

export const nodeTypes = {
  rule: RuleNode,
  card: CardNode,
  plain: PlainNode,
  network: NetworkNode,
};

/** Approximate rendered sizes so dagre can lay out before measuring. */
export function nodeSize(node: GraphNode): { width: number; height: number } {
  switch (node.kind) {
    case "rule":
      return { width: Math.max(150, 52 + node.label.length * 7 + (node.badge ? 18 + node.badge.length * 7 : 0)), height: 30 };
    case "network": {
      const rows = Math.ceil((node.items?.length ?? 0) / 2);
      return { width: 340, height: 66 + rows * 46 };
    }
    case "resource":
    case "route":
      return { width: 210, height: 44 };
    default:
      return { width: 210, height: 50 };
  }
}

export function nodeType(node: GraphNode): keyof typeof nodeTypes {
  if (node.kind === "rule") return "rule";
  if (node.kind === "network") return "network";
  if (node.kind === "resource" || node.kind === "route") return "plain";
  return "card";
}
