# Route management: site-to-site, exit-node, overlap and failover UX

**Priority:** P1. **Depends on:** draft 04 for named resources; existing subnet router and exit-node work #29. **Area:** agent routing, coordinator, console.

## Gap and outcome

BlakTail's Linux routers and opt-in IPv4 exit nodes exist, with route approval embedded in device rows. NetBird documents separate Network Routes, routing-peer sizing, masquerade, site-to-site and overlapping-route controls. Give operators explicit route lifecycle and failure behaviour rather than another boolean in device inventory.

## Scope

- Dedicated route list/detail/wizard with advertiser, network owner, CIDR, IPv4/IPv6 capability, routing peer groups, enabled/approved state, NAT/masquerade choice, metric/failover order and intended consumer groups. Distinguish client route from router forwarding and exit-node Internet routing.
- Detect overlap with local LAN, overlay pools and other routed networks; document deterministic client selection and explicit exceptions for intentional overlaps. Reject public/default routes without separate owner confirmation and policy checks.
- Show health, last seen, effective route distribution and withdrawal; make revocation/failover bounded and observable. Preserve existing routes on migration and avoid breaking remote administrators.

## Acceptance / proof

Two-site lab tests bidirectional traffic, no NAT and opt-in NAT, dual-stack where supported, router loss and failover; packet captures confirm no default-route or DNS leak. UI/API rejects unauthorized approval and collisions. Rollback restores previous route distribution; no advertised route becomes implicitly approved.

**Evidence:** `docs/project-status.md`, `apps/console/src/components/device-actions.tsx`; https://docs.netbird.io/manage/network-routes, https://docs.netbird.io/manage/network-routes/overlapping-routes, https://docs.netbird.io/manage/networks/masquerade.

## Status (2 October 2026)

**Done:** console Networks group with `/networks` (resources plus an "Advertised routes on devices" table showing advertisers, online/last seen, advertised, approved and never-distributed unapproved routes), `/networks/new` wizard (destination, routing peers with metric, access, review with coordinator-side overlap/distribution check and owner-only public-route confirmation; disabled controls explain why) and `/networks/[id]` (state, owning organisation, routing peers in failover order with primary/standby/offline/not-advertising state and last seen, covering advertisement, effective distribution per device with reasons, enable/disable, delete with confirmation, edit). Deterministic failover: online lowest-metric advertising peer, ties on node ID, fall back to the lowest-metric advertising peer when none is online; a routing peer never receives its own resource via another peer. Client route vs exit-node routing kept distinct: `0.0.0.0/0` resources only reach clients that select that exit node. Masquerade is shown as always on because `blaktaild` (`LinuxNetwork::configure_router`) unconditionally masquerades; the API rejects `masquerade: false` with an explanation instead of offering a dead toggle. Approval stays separate from advertisement, and migration slot 19 leaves device-approved routes untouched.
**Proven by tests:** `failover_prefers_online_lowest_metric_routing_peer` (primary chosen by metric, standby takes over when primary's last-seen is stale, detail reports offline/primary), `unadvertised_prefixes_and_default_routes_stay_opt_in`, `upgrade_keeps_existing_approved_routes_distributing`, plus the draft 04 tests for unauthorised approval, collisions and isolation.
**Still needs live/field proof or a decision:** two-site lab with bidirectional traffic, router loss/failover timing and packet captures for default-route or DNS leaks; no-NAT (site-to-site without masquerade) needs agent support and a decision on return routing; detection of overlap with clients' local LANs needs agent-reported interface data; IPv6 routing peers need IPv6 advertisement support; failover is bounded by the 90-second online window plus the agent's ~25-second resync and has not been measured on devices.
