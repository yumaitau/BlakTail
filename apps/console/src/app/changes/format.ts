import type { ChangeDraft, ChangeSurface } from "@/lib/coord-changes";
import type { BadgeTone } from "@/components/ui/badge";
import type { Permission } from "@/lib/roles";

export const SURFACES: { value: ChangeSurface; label: string; permission: Permission }[] = [
  { value: "policy", label: "Access policy", permission: "manage_policy" },
  { value: "resources", label: "Network resources", permission: "manage_networks" },
  { value: "dns", label: "DNS", permission: "manage_dns" },
];

/** Lower-case noun for sentences: "Changes the access policy and DNS." */
export function surfaceNoun(value: ChangeSurface): string {
  return value === "policy" ? "the access policy" : value === "dns" ? "DNS" : "network resources";
}

export function surfaceLabel(value: ChangeSurface): string {
  return SURFACES.find((surface) => surface.value === value)?.label ?? value;
}

export const draftStatus: Record<ChangeDraft["status"], { label: string; tone: BadgeTone }> = {
  open: { label: "Open", tone: "warning" },
  published: { label: "Published", tone: "success" },
  discarded: { label: "Discarded", tone: "muted" },
  expired: { label: "Expired", tone: "muted" },
};
