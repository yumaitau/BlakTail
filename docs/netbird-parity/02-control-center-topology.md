# Control Center: live connectivity and policy topology for an authorised network

**Priority:** P1. **Depends on:** draft 01 navigation and existing device/route/policy APIs. **Area:** console plus coordinator read models.

## Gap and outcome

NetBird Control Center joins peers, resources, routes and access policy in a live network view. BlakTail's `/devices` summary and `/status` health page cannot answer “why can this person reach this service?” or “is path direct or relayed?” Build an accessible, network-scoped operational map, not decorative animation or a replacement for All networks.

## Scope

- Model graph edges from effective, revisioned coordinator snapshots: nodes, network resources, approved subnet/exit routes, policy decisions and actual transport state where agents report it. Label unknown/stale telemetry rather than inventing a live link.
- Start with searchable/filterable lists and a text equivalent; optional graph must support keyboard, screen reader, reduced motion, large estates and grouping by organisation. Explain source/destination selector, service/port, route and deny reason without revealing another network's inventory.
- Display last update and split control-plane health from data-plane reachability. Link each edge to the owner-scoped edit page; only permitted actors see mutation controls. Avoid sending private addresses, metadata or topology to external analytics.

## Acceptance / proof

Two-network fixture with allow, deny, offline, stale and relayed peers shows correct effective paths; denied resource stays unavailable from another organisation even via direct URL/API. Contract tests prove graph reflects publish/revoke; accessibility test proves an equivalent non-visual explanation. A live two-node drill confirms displayed connection type against agent status, or explicitly reports unsupported.

**Evidence:** `apps/console/src/app/devices/page.tsx`, `apps/console/src/app/status/page.tsx`, `docs/project-status.md`; https://docs.netbird.io/manage/control-center, https://github.com/netbirdio/dashboard/tree/main/src/app/%28dashboard%29/control-center.
