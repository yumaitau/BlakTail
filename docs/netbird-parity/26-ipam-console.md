# IPAM operator UI for address pools, reservations and safe renumbering

**Priority:** P1. **Depends on:** existing closed #51 engine and draft 01 network navigation. **Area:** coordinator IPAM API, console, agent migration.

## Gap and outcome

Closed #51 added address-pool math and reservation concepts; BlakTail's Devices UI exposes assigned addresses but no clear pool/reservation or renumber workflow. NetBird Settings > Networks exposes address management. Offer safe, per-organisation control without destabilising working WireGuard peers or claiming IPv6-only proof prematurely.

## Scope

- Show CGNAT IPv4 and organisation ULA IPv6 pools, available/used/reserved counts, proposed allocations, conflicts, lease/owner and audit history. Network page can reserve/release address and preview impact of pool expansion or renumber.
- Define immutable identity versus mutable address, staged dual-address transition, peer map/DNS/route/ACL propagation and rollback. Reject overlap with other pools/host networks where client collision is known; explain isolation when CIDRs overlap across organisations.
- Keep allocator concurrency safe under two coordinators; API enforces owner/admin role and etag/idempotency. Do not expose raw keys or silently recycle tombstoned address before safe grace period.

## Acceptance / proof

Concurrent enrollment never allocates same address; reservation survives restart/failover; renumber preserves allowed traffic during documented window and later withdraws old DNS/address. DNS, route and policy references update or block with explicit conflict. Independent IPv6-only drill passes before claiming IPv6-only operation.

**Evidence:** `blaktail-coord/src/ipam.rs`, closed #51/#32, `docs/project-status.md`; https://docs.netbird.io/manage/settings/networks, https://docs.netbird.io/manage/settings/ipv6.

## Status (2 October 2026)

**Done:** `blaktail-coord/src/address_pool.rs` (routes `GET /v1/orgs/:org/ipam`,
`POST /v1/orgs/:org/ipam/reservations`, `DELETE …/reservations/:id` with
`If-Match`; `ViewNetwork` reads, `ManageNetworks` writes, audited) and slot 20
(`ipam_leases` with `(org_id,address)` primary key plus backfill,
`ipam_address_reservations`). `register_node` now allocates through
`address_pool::allocate`: insert-or-skip on the lease key so concurrent
enrolment on PostgreSQL moves to the next host; reservations are never
auto-allocated; a reservation bound to a device name or WireGuard key is handed
to that device (taking over a revoked/deleted holder, refusing an active one);
released addresses wait out a 7-day grace period (`ADDRESS_REUSE_GRACE_SECS`).
Console `/networks/addresses` (nav link under Networks, link from `/networks`):
pools with used/reserved/grace/available counts, per-address owner and reuse
time, reservations with reserve/release, conflicts. Renumbering and pool
expansion are a design-only section in `docs/ipam.md`; no renumber button.

**Proven by tests:** `address_pool::tests` — 24 concurrent enrolments get unique
IPv4/IPv6 addresses and skip a lease held by another coordinator; reservations
honoured (held skipped, bound name gets its address), replay idempotent,
release etag/412/idempotent, member and other-org writes rejected, audit rows;
tombstoned and purged addresses not reused inside the grace period and reused
after it; bound reservation reclaims a tombstoned address and refuses one held
by an active device. `postgres_concurrent_enrolment_allocates_unique_addresses`
ran 40 parallel enrolments through two coordinator pools on PostgreSQL 16
(throwaway container) with 40 distinct leases.

**Still needs live/field proof or a decision:** reservation survival across a
real HA failover drill; staged dual-address renumber implementation; pool
expansion beyond 254 devices (needs IPv6 derivation change); independent
IPv6-only drill before any IPv6-only claim; whether `/api/v1` automation
routes for IPAM are wanted (not added).

### Pool growth and staged renumbering (3 October 2026)

**Done:** migration slot 39 (`orgs.ipv4_pool_cidr`, default `100.64.0.0/24`;
`ipam_renumber_plans` with one staged plan per organisation). Pools are `/24`
to `/20` inside `100.64.0.0/10`; the IPv6 interface ID is now the IPv4
address's offset in `100.64.0.0/10`, so every existing `100.64.0.x` device keeps
its IPv6 address. `blaktail-coord/src/renumber.rs`: preview, stage, complete,
roll back (`/v1/orgs/:org/ipam/renumber[/preview|/:id/complete|/:id/rollback]`,
`ManageNetworks`, `If-Match` etags, audited, control revision bumped); a
dual-address window (10 minutes to 30 days, default 24 hours) in which moved
devices carry old and new AllowedIPs, policy and forward allow-lists include
both, peer maps list `retiring_ips` so MagicDNS answers only new addresses, and
the window ends automatically on the next check-in. Literal policy/DNS
references to an old address block the plan; reservations outside a target
pool block a pool change; rollback is refused if a device enrolled from the
new pool. `blaktaild` adopts the coordinator's address list (new IPv4 becomes
primary, old addresses removed at completion). Console `/networks/addresses`:
plan form (pool change or chosen devices, optional exact address, window,
reason), **Preview impact** (moves, peer maps, allow lists, MagicDNS names,
blockers) before **Start**, staged plan with window progress, **Complete now**
and **Roll back**, and plan history. Docs: `docs/ipam.md`.
**Proven by tests:** `blaktail-coord/src/tests/ipv6_renumber.rs`
(`renumber_stage_then_complete_keeps_both_addresses_during_the_window`,
`renumber_rollback_restores_the_old_address_and_window_end_completes`,
`renumber_is_blocked_by_literal_policy_references_and_pool_moves_follow_the_window`,
`pool_growth_beyond_254_keeps_addresses_and_allocates_uniquely`,
`schema_38_upgrade_keeps_every_device_address`); `blaktaild`
`renumbered_addresses_become_primary_and_retiring_ones_are_tracked` and
`dns::tests::renumber_window_answers_only_the_new_addresses`. Live lab
`deploy/homelab/prove-ipv6-renumber.sh` on `m3-max` (3 October 2026, passed):
pool move `100.64.0.0/24` → `100.64.8.0/24` with 0/74 pings lost to the old
address during staging, old and new IPv4/IPv6 both answering in the window,
only new after completion; single-device stage and rollback; and an IPv6-only
*underlay* (Docker network with no IPv4) where enrolment and an overlay ping
worked.
**Still needs live/field proof or a decision:** IPv6-only operation on real
networks (ISP, NAT64/DNS64, mobile) — the overlay still assigns IPv4, so no
IPv6-only claim; renumbering with agents older than this release (untested);
a PostgreSQL/HA renumber drill; macOS/Windows/iOS/Android agents adopting a
new address (only Linux proven); `/api/v1` automation routes for IPAM (not
added, needs a decision).
