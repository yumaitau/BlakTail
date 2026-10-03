"use client";

import Link from "next/link";
import { type ReactNode, useEffect, useRef, useState } from "react";
import { Menu, PanelLeftClose, PanelLeftOpen, X } from "lucide-react";
import { Wordmark } from "../wordmark";
import { OrgSwitcher, type ShellOrganisation } from "./org-switcher";
import { SidebarNav } from "./sidebar-nav";
import { UserMenu } from "./user-menu";

const COLLAPSE_KEY = "blaktail.sidebar.collapsed";

export function ShellFrame({
  current,
  bleed,
  organisations,
  activeOrganisationId,
  user,
  children,
}: {
  current: string;
  bleed?: boolean;
  organisations: ShellOrganisation[];
  activeOrganisationId: string;
  user: { name: string; email: string; role: string };
  children: ReactNode;
}) {
  const [collapsed, setCollapsed] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const menuButton = useRef<HTMLButtonElement>(null);
  const sidebar = useRef<HTMLElement>(null);

  useEffect(() => {
    try {
      // Restored after hydration so server and client markup agree.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setCollapsed(window.localStorage.getItem(COLLAPSE_KEY) === "1");
    } catch {
      /* storage unavailable: stay expanded */
    }
  }, []);

  useEffect(() => {
    if (!drawer) return;
    sidebar.current?.querySelector<HTMLElement>("a, button")?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setDrawer(false);
        menuButton.current?.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [drawer]);

  function toggleCollapsed() {
    const next = !collapsed;
    setCollapsed(next);
    try {
      window.localStorage.setItem(COLLAPSE_KEY, next ? "1" : "0");
    } catch {
      /* not remembered */
    }
  }

  return (
    <div className="shell" data-collapsed={collapsed ? "true" : undefined} data-drawer={drawer ? "open" : undefined}>
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="topbar">
        <button
          ref={menuButton}
          type="button"
          className="icon-button topbar-menu"
          aria-label={drawer ? "Close navigation" : "Open navigation"}
          aria-expanded={drawer}
          aria-controls="console-sidebar"
          onClick={() => setDrawer(!drawer)}
        >
          {drawer ? <X aria-hidden="true" size={20} /> : <Menu aria-hidden="true" size={20} />}
        </button>
        <Wordmark />
        <button
          type="button"
          className="icon-button topbar-collapse"
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          aria-pressed={collapsed}
          aria-controls="console-sidebar"
          onClick={toggleCollapsed}
        >
          {collapsed ? (
            <PanelLeftOpen aria-hidden="true" size={18} />
          ) : (
            <PanelLeftClose aria-hidden="true" size={18} />
          )}
        </button>
        <div className="topbar-spacer" />
        <OrgSwitcher organisations={organisations} activeId={activeOrganisationId} />
        <UserMenu name={user.name} email={user.email} role={user.role} />
      </header>
      <div className="drawer-backdrop" aria-hidden="true" onClick={() => setDrawer(false)} />
      <aside className="sidebar" id="console-sidebar" ref={sidebar} aria-label="Console navigation">
        <SidebarNav
          current={current}
          collapsed={collapsed && !drawer}
          onNavigate={() => setDrawer(false)}
        />
        <div className="sidebar-foot">
          <p className="region-mark" title="Onshore: Sydney, Australia · AU · ap-southeast-2">
            <span className="region-dot" aria-hidden="true" />
            <span className="region-text">
              <strong>Onshore</strong>
              <span>Sydney, Australia · ap-southeast-2</span>
            </span>
          </p>
          <Link className="sidebar-privacy" href="/privacy">
            Privacy and data handling
          </Link>
        </div>
      </aside>
      <main className={bleed ? "main main-bleed" : "main"} id="main" tabIndex={-1}>
        {children}
      </main>
    </div>
  );
}
