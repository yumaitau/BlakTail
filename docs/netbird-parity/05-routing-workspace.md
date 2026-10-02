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
