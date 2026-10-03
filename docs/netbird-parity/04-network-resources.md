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

## Status (2 October 2026)

**Done:** `blaktail-coord/src/resources.rs` (new module) plus migration slot 19 (`network_resources`, SQLite and Postgres). Organisation-scoped resources with stable UUID, name, description, IPv4/IPv6 CIDR *or* exact DNS target (validated, stored with `dns_resolution: not_resolved`; resolution left to draft 06), port/protocol constraints, routing-peer set with metric, access selection (roles, device tags, policy groups; any-match, unknown groups rejected at write and fail closed later), enabled state, revision and etag. Console routes `/v1/orgs/:org_id/networks[/:id]` (list/detail/create/replace/delete, `dry_run` preview) and `/api/v1/network-resources[/:id]` with `Idempotency-Key`, body `etag` on PUT (412 when stale), `If-Match` on DELETE, OpenAPI in `docs/openapi/admin-v1.yaml`. `ManageNetworks` for writes, `ViewNetwork` for reads, every mutation audited and bumps the control revision. Overlap detection against the overlay pools (`100.64.0.0/10`, org ULA `/64`), other resources (nested only with explicit `allow_nested_overlap`, exact duplicates never) and device-approved routes in the same organisation only; device route approval (console and `/api/v1/devices/:id/routes`) now also refuses overlap with a resource. `0.0.0.0/0`, `::/0` and public prefixes need owner `confirm_public_route`. Distribution reuses `list_peers`: the selected routing peer's `allowed_ips` gain exactly the resource prefix for clients that match access and that policy lets reach the router; the routing peer only carries it if it advertises a covering subnet. Console: `/networks` list, `/networks/new` four-step wizard with server-side overlap check, `/networks/[id]` detail with per-router health, effective distribution per device, enable/disable, delete and edit. Docs: `docs/network-resources.md`.
**Proven by tests:** `resources::tests` (7 integration tests): dual-stack overlapping vs non-overlapping, overlay/reserved/host-bit rejection, public/default routes needing owner confirmation, DNS target validation, overlap with device approvals both ways, dry run not persisted; only group-authorised clients receive exactly the resource prefix (not the wider advertisement), unapproved advertisement never distributed, member writes rejected (403), stale etag 412, disable and delete withdraw distribution, audit rows written; two organisations with the same CIDR isolated (cross-org routing peer refused, cross-org read/delete 404, cross-org assertion 401); API idempotency replay/conflict and etag guard; migration leaves existing approved routes and exit-node distribution unchanged.
**Still needs live/field proof or a decision:** routing peers do not enforce resource ports/protocols or per-client authorisation on the forward path (the existing Linux `FORWARD` rule accepts the whole advertised subnet), so distribution restriction is not a security boundary against a modified client; agent work is needed. IPv6 resources cannot be carried until agents and the coordinator accept IPv6 advertisements. DNS targets are never resolved. No two-router dual-stack lab, packet captures, or post-delete DNS-state check have been run. PostgreSQL concurrent-writer serialisation relies on the org-row lock taken by the control-revision bump and is untested against a live Postgres.

### Router forwarding enforcement (2 October 2026, security follow-up)

- **Done:** `blaktail-coord/src/forwarding.rs` compiles, for a routing peer reporting `forward-filter`, a `forward_filter` field in its peer map/update response: per authorised client, overlay source addresses x each prefix it receives through that router (device-approved routes, resource routes via `resources::Distribution::grants_via`) x resource ports/protocols, plus policy `hosts` rules inside those prefixes (deny carve-outs win, allow rules add ports). `0.0.0.0/0` only for clients currently selecting that exit node (selection persisted in `nodes.exit_node_id`, migration slot 28; a change bumps the control revision), with the router's other ungranted prefixes denied to them. `blaktaild` (`blaktaild/src/forward_filter.rs`) enforces it in `BLAKTAIL-FWD` (iptables/ip6tables, default reject, atomic staging-chain swap, cleaned on `down`/`pause`/route withdrawal) and reports `forward-filter`. Routers without the capability keep distributing, but resources, device routes and routing peers show `forwarding: not_enforced` ("Forwarding not enforced — upgrade agent" in `/networks`), and policy explain returns `not_enforced` for hosts behind them.
- **Proven by tests:** `blaktail-coord/src/tests/forwarding.rs` (authorised client present with exact ports, unauthorised client and other organisation absent, host deny/allow entries, disabled resource removes entries, exit node only for selecting clients and withdrawn on deselect, capability-driven status and explain enforcement); `blaktaild/src/forward_filter.rs` tests (deterministic rules, IPv4/IPv6 split, default reject, malformed entries never widen access, atomic swap order, failed install keeps previous chain, idempotent cleanup) with a fake command runner.
- **Still needs live/field proof or a decision:** no packet test on a real Linux router (iptables-legacy and iptables-nft `-E` rename with a live jump is relied on, not proven here). A router joining for the first time, with no stored list, forwards legacy-style until its first peer map (seconds).

### IPv6 resources carried (3 October 2026)

- **Done:** IPv6 resources now have routing peers: Linux agents advertise IPv6 subnets (see draft 05 status), so an IPv6 CIDR resource is distributed and forward-filtered like an IPv4 one. `docs/network-resources.md` updated.
- **Proven by tests:** `ipv6_subnet_routes_are_approved_distributed_and_forward_filtered` (coordinator) and the IPv6 subnet step of `deploy/homelab/prove-ipv6-renumber.sh` (device-approved route, one Docker host, 3 October 2026).
- **Still needs live/field proof or a decision:** the live lab used a device approval, not a named IPv6 resource; a two-router dual-stack resource lab is still outstanding.

### Live lab: two-site routing (3 October 2026)

`deploy/homelab/prove-routing.sh` on Docker context `m3-max` (about 5 minutes;
everything `labs-routing-*`, removed on exit; results table in
`docs/network-resources.md#live-lab-3-october-2026`). Two sites (site A: `ra1`
metric 10 on iptables-nft, `ra2` metric 20 on iptables-legacy; site B: `rb` on
iptables-legacy), an exit node on iptables-nft, an authorised client and a
guest, all on internal Docker networks.

- **Passed:** allowed port behind each router reachable 1 s after resource
  creation; adjacent ports refused with the `BLAKTAIL-FWD` default reject
  counting them on nft and legacy (3 → 4 packets each); a guest that forced
  the site prefix into WireGuard was refused by `BLAKTAIL-FWD` (4 → 5);
  router-to-router traffic both ways. Six resource edits rebuilt and renamed
  `BLAKTAIL-FWD-NEW` over the live, jumped-to chain on all four routers while
  the client connected 150 times: 0 failures, one jump and no staging chain
  left on both backends.
- **Exit node:** only the selecting client reached the Internet host; the
  guest's forced exit traffic was rejected (0 → 2); captures showed 0 packets
  on the exit's Internet uplink from non-exit attempts and 0 non-WireGuard
  packets on the exit client's uplink while it used DNS and HTTP through the
  exit (no DNS or default-route leak).
- **Router loss:** `docker kill` of the primary; the client reached site A
  through the standby after **82 s** (89 s in an earlier run; bound now about 92 s).
- **Bugs found and fixed:** (1) `/updates` ignored a changed `exit_node` when
  the revision was unchanged, so an agent resumed with `--exit-node` never got
  its default route; the long-poll now records the selection and bumps the
  revision (`exit_selection_on_a_long_poll_returns_a_fresh_snapshot`).
  (2) Routing-peer liveness never bumped the revision, so idle clients kept a
  dead router's routes indefinitely; long-polls now re-check online
  route-advertising devices every 2 s per organisation
  (`resources::bump_on_router_liveness_change`,
  `routing_peer_failover_reaches_idle_long_polls`). The long-poll
  `last_seen_at` refresh from the app-connector lab is also required.
- **Still unproven:** IPv6 routing, host-to-host site-to-site without NAT
  (unsupported), physical routers and real WAN links, other Linux
  distributions' iptables builds.
