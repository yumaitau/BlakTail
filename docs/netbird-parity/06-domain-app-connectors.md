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

## Status (2 October 2026)

**Done:** `blaktail-coord/src/app_connectors.rs`: node-token endpoints
`GET /v1/nodes/:id/connector/assignments` and
`POST /v1/nodes/:id/connector/resolutions` (requires the `app-connector`
capability, routing-peer membership and same organisation); validation rejects
loopback, unspecified, link-local, metadata (`169.254.169.254`,
`100.100.100.200`, `fd00:ec2::254`, mapped/NAT64 forms), multicast, reserved,
overlay pools, device WireGuard endpoints and any non-host prefix; any such
answer rejects the report, withdraws every lease and records a block (audited,
marked as possible rebinding when previously resolved). Leases
(`connector_leases`, slot 20) expire at TTL clamped to 30 s–5 min; each report
replaces the set, so changed/empty answers withdraw at once.
`resources.rs` selects a DNS resource's connector (lowest-metric online peer
with the capability), distributes its leases as host routes through the
existing peer-map path to authorised clients only, de-duplicates host routes
already claimed by another router, and returns `connector` state (answers,
expiry, reports, block reason) in resource detail. Agent:
`blaktaild/src/connector.rs` + `blaktaild up --app-connector` (Linux): resolves
A/AAAA with TTLs via `/etc/resolv.conf` nameservers (libc fallback), reports,
and installs forwarding only for accepted host routes via the subnet-router
path. Console resource detail shows answers, lease expiry, connector reports
and "not resolved"/"blocked: reason". Docs: `docs/app-connectors.md`.

**Proven by tests:** `app_connectors::integration` — two orgs resolving the
same name get isolated routes and cross-org reports are 404; TTL expiry and
changed/empty answers withdraw routes from client peer maps; rebinding to
metadata and other forbidden answers/prefixes fails closed and is audited;
non-connector, non-routing-peer, wrong-token and wrong-name reports rejected;
member writes rejected. Unit tests for forbidden ranges, TTL clamp, DNS wire
parsing (CNAME chains, NXDOMAIN, errors) and host-route filtering.

**Still needs live/field proof or a decision:** an end-to-end agent run on
Linux (real resolver, iptables forwarding, connector outage/restart); a packet-level
"adjacent port fails" check (the router allow-list for `forward-filter`
connectors is port-scoped and covered by a coordinator test; older connectors
still forward every port); pause/transfer lifecycle actions beyond
enable/disable/edit/delete; shared-IP exposure is documented, not mitigated.
