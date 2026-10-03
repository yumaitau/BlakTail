import type { ReactNode } from "react";
import { roleLabel } from "@/lib/roles";
import type { ConsoleContext, PersonSessionContext } from "@/lib/session";
import { ShellFrame } from "./shell/shell-frame";

export function ConsoleShell({
  ctx,
  current,
  bleed = false,
  children,
}: {
  ctx: ConsoleContext | PersonSessionContext;
  current: string;
  /** Full-bleed canvas pages (Control Center) skip the content padding. */
  bleed?: boolean;
  children: ReactNode;
}) {
  const selectedId =
    "organisationId" in ctx
      ? ctx.organisationId
      : ctx.organisations[0]?.organisationId;
  const selected = ctx.organisations.find(
    (organisation) => organisation.organisationId === selectedId,
  );
  const organisations = ctx.organisations.map((organisation) => ({
    id: organisation.organisationId,
    name: organisation.organisationName,
    subtitle: `${roleLabel(organisation.role)} · Onshore AU`,
  }));

  return (
    <ShellFrame
      current={current}
      bleed={bleed}
      organisations={organisations}
      activeOrganisationId={selectedId ?? ""}
      user={{
        name: ctx.name,
        email: ctx.email,
        role: selected ? `${roleLabel(selected.role)} in ${selected.organisationName}` : "",
      }}
    >
      {children}
    </ShellFrame>
  );
}
