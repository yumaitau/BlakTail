import type { ChangeDraft, ChangeSurface } from "@/lib/coord-changes";
import type { Permission } from "@/lib/roles";

export const SURFACES: { value: ChangeSurface; label: string; permission: Permission }[] = [
  { value: "policy", label: "Access policy", permission: "manage_policy" },
  { value: "resources", label: "Network resources", permission: "manage_networks" },
  { value: "dns", label: "DNS", permission: "manage_dns" },
];

export function surfaceLabel(value: ChangeSurface): string {
  return SURFACES.find((surface) => surface.value === value)?.label ?? value;
}

export const statusBadge: Record<ChangeDraft["status"], string> = {
  open: "pending",
  published: "online",
  discarded: "offline",
  expired: "offline",
};

export function when(seconds: number | null | undefined): string {
  if (!seconds) return "—";
  return new Date(seconds * 1000).toLocaleString("en-AU", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}
