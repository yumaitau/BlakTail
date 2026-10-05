import type { BadgeTone } from "@/components/ui/badge";
import type { ResourceState, RoutingPeerState } from "@/lib/coord-networks";

export function lastSeen(at: number | null | undefined): string {
  if (!at) return "Never seen";
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - at);
  if (seconds < 90) return "Seen just now";
  if (seconds < 3600) return `Seen ${Math.round(seconds / 60)} min ago`;
  if (seconds < 86400) return `Seen ${Math.round(seconds / 3600)} h ago`;
  return `Seen ${Math.round(seconds / 86400)} days ago`;
}

export const resourceStateLabel: Record<ResourceState, { label: string; tone: BadgeTone }> = {
  distributing: { label: "Distributing", tone: "success" },
  stale: { label: "Routing peer offline", tone: "warning" },
  no_routing_peer: { label: "No routing peer", tone: "danger" },
  dns_not_resolved: { label: "DNS not resolved", tone: "warning" },
  dns_blocked: { label: "Blocked: unsafe DNS answer", tone: "danger" },
  disabled: { label: "Disabled", tone: "muted" },
};

export const peerStateLabel: Record<RoutingPeerState, string> = {
  primary: "Primary",
  standby: "Standby",
  offline: "Offline",
  not_advertising: "Does not advertise this subnet",
  not_connector: "Not running an app connector",
  expired: "Credential expired",
  missing: "Removed from the organisation",
};
