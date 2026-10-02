# Complete and prove domain-scoped application connectors end to end

**Priority:** P2. **Depends on:** draft 04 resource model, draft 09 DNS and draft 07 policy. **Area:** DNS/route leases, connector agent, console.

## Gap and outcome

Closed #49 proposed application connectors; `blaktail-coord/src/connectors.rs` contains validation helpers, not evidence of an enrolled connector resolving domains, leasing host routes, updating clients and enforcing service ports. NetBird Networks supports named resources; complete BlakTail's existing design without re-opening a duplicate tracker blindly.

## Scope

- Exact FQDN first, with explicit resolver perspective and connector group, TTL-bound A/AAAA/CNAME resolution, safe host-route leases, policy scoped by app and port, and atomic withdrawal when answers expire/change. Reject loopback, metadata, rebinding, broad prefixes and cross-org DNS leakage.
- Add lifecycle API and UI for create, preview current answers/lease/connector health, pause, transfer and delete. Expose split-horizon and shared-IP limitations; an authorised app must not grant all services at its resolved IP.
- Record minimal auditable changes; secrets, full browsing history and unmanaged wildcard domains are out of scope. Document interaction with existing static routes and offline DNS.

## Acceptance / proof

Two organisations resolving same name differently stay isolated; TTL rotation withdraws old address without broad exposure. DNS rebinding to forbidden addresses fails closed. End-to-end agent test proves allowed port works and adjacent port fails, including connector outage/restart. Console and API show actual effective state, not helper validation alone.

**Evidence:** closed #49, `blaktail-coord/src/connectors.rs`, `docs/org-dns.md`; https://docs.netbird.io/manage/networks, https://docs.netbird.io/manage/dns.
