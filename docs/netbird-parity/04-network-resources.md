# First-class private network resources and a scoped Networks workspace

**Priority:** P1. **Depends on:** draft 01 navigation; policy and route integration. **Area:** coordinator schema/API, agent map, console.

## Gap and outcome

NetBird Networks groups named private CIDR/IP/domain resources with routing peers and access control. BlakTail already distributes peer routes and separate policy documents, but no named resource object or Networks page connects ownership, reachability and lifecycle. Do not confuse organisation workspaces with routed private networks.

## Scope

- Define organisation-scoped resource with stable ID, display name, IPv4/IPv6 CIDR or exact DNS target, destination port/protocol constraints, routing-peer set, selected access groups, state and audit revision. Separate static subnet resources from domain connectors (draft 06).
- Console create/edit/disable/delete and details: route overlap preview, effective access, per-router health, DNS resolution context, priority/failover and explicit owner network. Keep approval distinct from node self-advertisement; do not silently accept 0/0.
- Enforce isolation, deterministic policy evaluation, stale lease withdrawal, route conflict detection across selected clients and idempotent API writes. Plan migration for existing approved routes without changing access on upgrade.

## Acceptance / proof

Create overlapping and non-overlapping dual-stack resources with two routers; only authorised clients install exact routes and reach allowed ports. Delete/revoke removes routes, policy references and DNS state safely; two organisations with same private CIDR remain isolated. UI reflects effective state after failover/restart; source-of-truth API and migration tests pass.

**Evidence:** `docs/project-status.md`, `docs/policy.md`, `blaktail-coord/src/ipam.rs`, `apps/console/src/components/device-actions.tsx`; https://docs.netbird.io/manage/networks.
