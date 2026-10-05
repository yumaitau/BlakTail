"use client";

import { useEffect, useState } from "react";

export type SettingsNavGroup = {
  label: string;
  items: { id: string; label: string }[];
};

function jumpTo(id: string) {
  const target = document.getElementById(id);
  if (!target) return;
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  target.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
  history.replaceState(null, "", `#${id}`);
  // Move focus to the section heading so keyboard and screen reader users land there.
  const heading = target.querySelector<HTMLElement>("h2, h3");
  if (heading) {
    heading.setAttribute("tabindex", "-1");
    heading.focus({ preventScroll: true });
  }
}

/**
 * Settings page navigation: a sticky index beside the content on desktop and
 * a "Jump to" menu on phones and tablets. Highlights the section in view.
 */
export function SettingsNav({ groups }: { groups: SettingsNavGroup[] }) {
  const ids = groups.flatMap((group) => group.items.map((item) => item.id));
  const [active, setActive] = useState<string>(ids[0] ?? "");
  const key = ids.join(",");

  useEffect(() => {
    const sections = key
      .split(",")
      .map((id) => document.getElementById(id))
      .filter((element): element is HTMLElement => element !== null);
    if (sections.length === 0 || typeof IntersectionObserver === "undefined") return;
    const visible = new Map<string, number>();
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) visible.set(entry.target.id, entry.boundingClientRect.top);
          else visible.delete(entry.target.id);
        }
        const first = sections.find((section) => visible.has(section.id));
        if (first) setActive(first.id);
      },
      { rootMargin: "-80px 0px -55% 0px" },
    );
    for (const section of sections) observer.observe(section);
    return () => observer.disconnect();
  }, [key]);

  return (
    <>
      <nav className="settings-index" aria-label="Settings sections">
        {groups.map((group) => (
          <div key={group.label} className="settings-index-group">
            <p className="settings-index-label">{group.label}</p>
            <ul>
              {group.items.map((item) => (
                <li key={item.id}>
                  <a
                    href={`#${item.id}`}
                    aria-current={active === item.id ? "true" : undefined}
                    onClick={(event) => {
                      event.preventDefault();
                      setActive(item.id);
                      jumpTo(item.id);
                    }}
                  >
                    {item.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>
      <div className="settings-jump">
        <label className="settings-jump-label" htmlFor="settings-jump">
          Jump to
        </label>
        <select
          id="settings-jump"
          value={active}
          onChange={(event) => {
            const id = event.currentTarget.value;
            setActive(id);
            jumpTo(id);
          }}
        >
          {groups.map((group) => (
            <optgroup key={group.label} label={group.label}>
              {group.items.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.label}
                </option>
              ))}
            </optgroup>
          ))}
        </select>
      </div>
    </>
  );
}
