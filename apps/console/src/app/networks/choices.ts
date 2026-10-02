import "server-only";

import type { RoutingPeerChoice } from "@/components/network-resource-form";
import { parseAclPolicy } from "@/lib/acl";
import { getAcl, listNodes } from "@/lib/coord";
import type { ConsoleContext } from "@/lib/session";

/** Active devices that could carry a route, and the policy groups to grant. */
export async function resourceFormChoices(ctx: ConsoleContext): Promise<{
  peers: RoutingPeerChoice[];
  groups: string[];
}> {
  const [nodes, acl] = await Promise.all([listNodes(ctx), getAcl(ctx)]);
  return {
    peers: nodes
      .filter((node) => !node.revoked && !node.deleted && !node.expired)
      .sort((a, b) => b.advertised_routes.length - a.advertised_routes.length)
      .map((node) => ({
        id: node.id,
        label: node.display_name || node.name,
        advertisedRoutes: node.advertised_routes,
        online: Boolean(node.online),
      })),
    groups: parseAclPolicy(acl).groups.map((group) => group.name),
  };
}
