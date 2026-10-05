"use client";

import { useRouter } from "next/navigation";
import { useTransition } from "react";
import { Check, ChevronsUpDown } from "lucide-react";
import { Spinner } from "../ui/button";
import { toast } from "../ui/toast";
import { usePopover } from "./use-popover";

export type ShellOrganisation = { id: string; name: string; subtitle: string };

function initial(name: string) {
  return (name.trim()[0] ?? "?").toUpperCase();
}

export function OrgSwitcher({
  organisations,
  activeId,
}: {
  organisations: ShellOrganisation[];
  activeId: string;
}) {
  const router = useRouter();
  const { open, setOpen, root, trigger } = usePopover();
  const [pending, startTransition] = useTransition();
  const active = organisations.find((org) => org.id === activeId) ?? organisations[0];
  if (!active) return null;

  const summary = (
    <>
      <span className="org-initial" aria-hidden="true">
        {initial(active.name)}
      </span>
      <span className="org-text">
        <span className="org-name">{active.name}</span>
        <span className="org-sub">{active.subtitle}</span>
      </span>
    </>
  );

  if (organisations.length < 2) {
    return (
      <div className="org-switcher" aria-label={`Organisation: ${active.name}`}>
        <div className="org-trigger static">{summary}</div>
      </div>
    );
  }

  function choose(id: string) {
    setOpen(false);
    if (id === active!.id) return;
    const name = organisations.find((org) => org.id === id)?.name ?? "the organisation";
    startTransition(async () => {
      let response: Response;
      try {
        response = await fetch("/api/organisations/active", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ organisationId: id }),
        });
      } catch {
        toast.error(`Couldn't switch to ${name}. Check your connection and try again.`);
        return;
      }
      if (!response.ok) {
        const result = (await response.json().catch(() => ({}))) as { error?: string; ref?: string };
        toast.error(result.error ?? `Couldn't switch to ${name}.`, { reference: result.ref });
        return;
      }
      toast.success(`Switched to ${name}`);
      router.refresh();
    });
  }

  return (
    <div className="org-switcher" ref={root}>
      <button
        ref={trigger}
        type="button"
        className="org-trigger"
        aria-haspopup="true"
        aria-expanded={open}
        aria-controls="org-menu"
        aria-label={`Organisation: ${active.name}. Switch organisation`}
        aria-busy={pending || undefined}
        disabled={pending}
        onClick={() => setOpen(!open)}
      >
        {summary}
        {pending ? <Spinner /> : <ChevronsUpDown aria-hidden="true" size={16} className="org-chevron" />}
      </button>
      {open ? (
        <div className="popover org-menu" id="org-menu">
          <p className="popover-heading">Organisations</p>
          <ul>
            {organisations.map((org) => (
              <li key={org.id}>
                <button
                  type="button"
                  className="popover-item"
                  aria-current={org.id === active.id ? "true" : undefined}
                  onClick={() => choose(org.id)}
                >
                  <span className="org-initial small" aria-hidden="true">
                    {initial(org.name)}
                  </span>
                  <span className="org-text">
                    <span className="org-name">{org.name}</span>
                    <span className="org-sub">{org.subtitle}</span>
                  </span>
                  {org.id === active.id ? (
                    <Check aria-label="Active" size={16} className="popover-check" />
                  ) : null}
                </button>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
