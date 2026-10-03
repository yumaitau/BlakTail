"use client";

import Link from "next/link";
import { useState } from "react";
import {
  Activity,
  Bot,
  ChevronDown,
  Gauge,
  Globe,
  HeartPulse,
  KeyRound,
  type LucideIcon,
  Monitor,
  MonitorSmartphone,
  Network,
  Server,
  Settings,
  ShieldCheck,
  Users,
  Waypoints,
} from "lucide-react";
import {
  isCurrent,
  type NavEntry,
  type NavIcon,
  PRIMARY_NAV,
  SECONDARY_NAV,
} from "./nav-items";

const ICONS: Record<NavIcon, LucideIcon> = {
  "control-center": Waypoints,
  devices: Monitor,
  "join-keys": KeyRound,
  access: ShieldCheck,
  networks: Network,
  dns: Globe,
  services: Server,
  agents: Bot,
  remote: MonitorSmartphone,
  team: Users,
  activity: Activity,
  settings: Settings,
  operations: HeartPulse,
  status: Gauge,
};

function testId(href: string) {
  return `nav-${href.slice(1).replace("#", "-")}`;
}

function Entry({
  entry,
  current,
  collapsed,
  open,
  onToggle,
  onNavigate,
}: {
  entry: NavEntry;
  current: string;
  collapsed: boolean;
  open: boolean;
  onToggle: () => void;
  onNavigate?: () => void;
}) {
  const Icon = ICONS[entry.icon];
  if (entry.href) {
    const active = isCurrent(current, entry.href);
    return (
      <li>
        <Link
          href={entry.href}
          className="side-link"
          data-testid={testId(entry.href)}
          aria-current={active ? "page" : undefined}
          title={collapsed ? entry.label : undefined}
          onClick={onNavigate}
        >
          <Icon className="side-icon" aria-hidden="true" size={18} strokeWidth={1.75} />
          <span className="side-label">{entry.label}</span>
        </Link>
      </li>
    );
  }
  const children = entry.children ?? [];
  const containsCurrent = children.some((child) => isCurrent(current, child.href));
  const panelId = `side-group-${entry.id}`;
  if (collapsed) {
    // Icon rail: the group icon goes to its first page; the label is the tooltip.
    const first = children[0]!;
    return (
      <li>
        <Link
          href={first.href}
          className="side-link"
          aria-current={containsCurrent ? "true" : undefined}
          title={`${entry.label}: ${children.map((child) => child.label).join(", ")}`}
          aria-label={entry.label}
          onClick={onNavigate}
        >
          <Icon className="side-icon" aria-hidden="true" size={18} strokeWidth={1.75} />
          <span className="side-label">{entry.label}</span>
        </Link>
      </li>
    );
  }
  return (
    <li>
      <button
        type="button"
        className="side-link side-group-toggle"
        aria-expanded={open}
        aria-controls={panelId}
        data-active={containsCurrent ? "true" : undefined}
        onClick={onToggle}
      >
        <Icon className="side-icon" aria-hidden="true" size={18} strokeWidth={1.75} />
        <span className="side-label">{entry.label}</span>
        <ChevronDown className="side-chevron" aria-hidden="true" size={16} />
      </button>
      <ul id={panelId} className="side-children" hidden={!open}>
        {children.map((child) => (
          <li key={child.href}>
            <Link
              href={child.href}
              className="side-child"
              data-testid={testId(child.href)}
              aria-current={isCurrent(current, child.href) ? "page" : undefined}
              onClick={onNavigate}
            >
              {child.label}
            </Link>
          </li>
        ))}
      </ul>
    </li>
  );
}

export function SidebarNav({
  current,
  collapsed,
  onNavigate,
}: {
  current: string;
  collapsed: boolean;
  onNavigate?: () => void;
}) {
  const initial = Object.fromEntries(
    [...PRIMARY_NAV, ...SECONDARY_NAV]
      .filter((entry) => entry.children?.some((child) => isCurrent(current, child.href)))
      .map((entry) => [entry.id, true]),
  );
  const [open, setOpen] = useState<Record<string, boolean>>(initial);
  const render = (entries: NavEntry[]) =>
    entries.map((entry) => (
      <Entry
        key={entry.id}
        entry={entry}
        current={current}
        collapsed={collapsed}
        open={Boolean(open[entry.id])}
        onToggle={() => setOpen((state) => ({ ...state, [entry.id]: !state[entry.id] }))}
        onNavigate={onNavigate}
      />
    ));
  return (
    <nav aria-label="Console" className="side-nav">
      <ul className="side-list">{render(PRIMARY_NAV)}</ul>
      <ul className="side-list side-list-secondary">{render(SECONDARY_NAV)}</ul>
    </nav>
  );
}
