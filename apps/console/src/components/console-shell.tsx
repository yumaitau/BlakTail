import type { ReactNode } from "react";
import Link from "next/link";
import { roleLabel } from "@/lib/roles";
import type { ConsoleContext, PersonSessionContext } from "@/lib/session";
import { OrganisationSwitcher } from "./organisation-switcher";
import { PathMotif } from "./path-motif";
import { Wordmark } from "./wordmark";

// Task-based homes. Each link must be backed by a real page and API; add a
// link here only when its page ships.
const groups: { label: string; links: { href: string; label: string }[] }[] = [
  {
    label: "Devices",
    links: [
      { href: "/devices", label: "Devices" },
      { href: "/join-keys", label: "Join keys" },
    ],
  },
  {
    label: "Networks",
    links: [
      { href: "/networks", label: "Networks" },
      { href: "/networks/addresses", label: "Addresses" },
      { href: "/topology", label: "Topology" },
      { href: "/changes", label: "Change drafts" },
    ],
  },
  {
    label: "Access",
    links: [
      { href: "/acls", label: "Access policy" },
      { href: "/posture", label: "Posture checks" },
      { href: "/tunnel-protection", label: "Tunnel protection" },
    ],
  },
  { label: "DNS", links: [{ href: "/dns", label: "DNS" }] },
  { label: "Services", links: [{ href: "/services", label: "Private services" }] },
  { label: "Agents", links: [{ href: "/agents", label: "Agent network" }] },
  {
    label: "Events",
    links: [
      { href: "/audit", label: "Audit log" },
      { href: "/traffic", label: "Traffic" },
    ],
  },
  {
    label: "Settings",
    links: [
      { href: "/status", label: "Status" },
      { href: "/operations", label: "Operator health" },
      { href: "/settings", label: "Settings" },
    ],
  },
];

function isCurrent(current: string, href: string) {
  return current === href || current.startsWith(`${href}/`);
}

export function ConsoleShell({
  ctx,
  current,
  children,
}: {
  ctx: ConsoleContext | PersonSessionContext;
  current: string;
  children: ReactNode;
}) {
  const selectedId =
    "organisationId" in ctx
      ? ctx.organisationId
      : ctx.organisations[0]?.organisationId;
  const selected = ctx.organisations.find(
    (organisation) => organisation.organisationId === selectedId,
  );

  return (
    <div className="shell">
      <aside className="nav">
        <div className="nav-head">
          <Wordmark />
          <input
            id="console-nav"
            className="nav-toggle"
            type="checkbox"
          />
          <label className="nav-toggle-label" htmlFor="console-nav">
            Menu
          </label>
          <div className="nav-body">
            <PathMotif className="path-motif nav-motif" />
            <OrganisationSwitcher
              organisations={ctx.organisations}
              activeOrganisationId={
                selectedId ?? ctx.organisations[0]!.organisationId
              }
            />
            <nav aria-label="Console">
              {groups
                .filter((group) => group.links.length > 0)
                .map((group) => (
                  <div className="nav-group" key={group.label}>
                    <p className="nav-group-label">{group.label}</p>
                    {group.links.map((link) => (
                      <Link
                        key={link.href}
                        href={link.href}
                        data-testid={`nav-${link.href.slice(1)}`}
                        aria-current={isCurrent(current, link.href) ? "page" : undefined}
                      >
                        {link.label}
                      </Link>
                    ))}
                  </div>
                ))}
            </nav>
            <div className="account-block">
              <div>
                {ctx.name}
                {selected ? ` · ${roleLabel(selected.role)}` : ""}
              </div>
              {selected ? (
                <div>
                  <span className="badge network">{selected.organisationName}</span>
                </div>
              ) : null}
              <div>
                <Link href="/privacy">Privacy and data handling</Link>
              </div>
            </div>
            <p className="region-mark">
              <span className="region-dot" aria-hidden="true" />
              <strong>Onshore</strong>
              <span>Sydney, Australia · AU · ap-southeast-2</span>
            </p>
          </div>
        </div>
      </aside>
      <main className="main">
        <div className="main-motif" aria-hidden="true">
          <PathMotif />
        </div>
        {children}
      </main>
    </div>
  );
}
