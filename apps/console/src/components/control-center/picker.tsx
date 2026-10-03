"use client";

import { useId, useMemo, useRef, useState } from "react";
import { Check, ChevronsUpDown, Search } from "lucide-react";
import { usePopover } from "../shell/use-popover";

export type PickerOption = { value: string; label: string; sub?: string; status?: "ok" | "idle" | "bad" };

/** Searchable single-choice picker. The trigger names what is chosen. */
export function Picker({
  label,
  value,
  options,
  onChange,
  icon,
}: {
  label: string;
  value: string;
  options: PickerOption[];
  onChange: (value: string) => void;
  icon?: React.ReactNode;
}) {
  const { open, setOpen, root, trigger } = usePopover();
  const [query, setQuery] = useState("");
  const listId = useId();
  const search = useRef<HTMLInputElement>(null);
  const current = options.find((option) => option.value === value);
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q
      ? options.filter((option) => `${option.label} ${option.sub ?? ""}`.toLowerCase().includes(q))
      : options;
  }, [options, query]);

  function choose(next: string) {
    setOpen(false);
    setQuery("");
    trigger.current?.focus();
    onChange(next);
  }

  return (
    <div className="picker" ref={root}>
      <button
        ref={trigger}
        type="button"
        className="picker-trigger"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={listId}
        aria-label={`${label}: ${current?.label ?? "none"}`}
        onClick={() => {
          setOpen(!open);
          requestAnimationFrame(() => search.current?.focus());
        }}
      >
        {icon}
        {current?.status ? <span className={`dot dot-${current.status}`} aria-hidden="true" /> : null}
        <span className="picker-value">{current?.label ?? "Choose…"}</span>
        {current?.sub ? <span className="picker-sub">{current.sub}</span> : null}
        <ChevronsUpDown aria-hidden="true" size={16} className="picker-chevron" />
      </button>
      {open ? (
        <div className="popover picker-menu">
          <label className="picker-search">
            <Search aria-hidden="true" size={16} />
            <span className="visually-hidden">Search {label.toLowerCase()}</span>
            <input
              ref={search}
              type="search"
              placeholder="Search…"
              value={query}
              onChange={(event) => setQuery(event.currentTarget.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && shown[0]) {
                  event.preventDefault();
                  choose(shown[0].value);
                }
                if (event.key === "ArrowDown") {
                  event.preventDefault();
                  root.current?.querySelector<HTMLButtonElement>(".picker-option")?.focus();
                }
              }}
            />
          </label>
          <ul id={listId} role="listbox" aria-label={label}>
            {shown.length === 0 ? <li className="picker-empty">No matches</li> : null}
            {shown.map((option) => (
              <li key={option.value} role="option" aria-selected={option.value === value}>
                <button
                  type="button"
                  className="popover-item picker-option"
                  onClick={() => choose(option.value)}
                  onKeyDown={(event) => {
                    const item = event.currentTarget.parentElement;
                    if (event.key === "ArrowDown") {
                      event.preventDefault();
                      item?.nextElementSibling?.querySelector<HTMLButtonElement>("button")?.focus();
                    }
                    if (event.key === "ArrowUp") {
                      event.preventDefault();
                      const previous = item?.previousElementSibling?.querySelector<HTMLButtonElement>("button");
                      if (previous) previous.focus();
                      else search.current?.focus();
                    }
                  }}
                >
                  {option.status ? <span className={`dot dot-${option.status}`} aria-hidden="true" /> : null}
                  <span className="picker-option-text">
                    <span>{option.label}</span>
                    {option.sub ? <span className="picker-sub">{option.sub}</span> : null}
                  </span>
                  {option.value === value ? <Check aria-hidden="true" size={16} className="popover-check" /> : null}
                </button>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
