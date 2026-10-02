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

## Status (2 October 2026)

**Done:** `blaktail-coord/src/topology.rs` serves `GET /v1/orgs/{org}/topology` (`ViewNetwork`): one organisation's devices (online/stale/never/suspended/expired, agent-reported transport with timestamp or `not_measured`, stale-report flag, inbound-filter capability), network resources with routing-peer health, approved subnet/exit routes, and effective edges, with policy revision/etag, control revision and `generated_at`. Device edges reuse the explain evaluator and peer-map compiler through the new shared `policy_explain::device_flow` (the explain handler now calls it too); resource edges reuse `resources::overview_conn`. Each edge carries a plain-text explanation, path (`direct`/`relay`/`mixed`/`unknown`/`peer_offline`), enforcement and an owner-scoped edit target. Console `/topology` (Networks group): control-plane vs data-plane summary, searchable/filterable "who can reach what" list grouped by source, device and resource tables, per-device deep links (`?node=…&organisation=…`), and an optional static SVG graph grouped by tag inside `<details>` (focusable links with `<title>` text, no motion). Docs: `docs/console.md`.
**Proven by tests:** `change_drafts::tests::topology_reflects_publish_and_revoke_and_never_leaks_other_orgs` — another organisation's nodes never appear and its owner gets 401 on the URL; same-tag defaults give both directed edges; no path type is claimed when nothing was measured; a published draft removes the edges and bumps control revision exactly once; a revoked device disappears; a preview pair naming another organisation's device is 404.
**Still needs live/field proof or a decision:** a live two-node drill comparing the displayed path type with `blaktaild` status (agents report one summary per device, not per pair, so per-pair truth is unsupported today); a browser accessibility audit with a screen reader and keyboard; behaviour above 400 active devices (edges are truncated and labelled); per-pair deny reasons beyond what `/acls` Explain access already shows.
