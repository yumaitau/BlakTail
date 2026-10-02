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
