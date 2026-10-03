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
(`connector_leases`, slot 20) expire at TTL clamped to 30 s–5 min (90 s floor since 3 October 2026); each report
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

### Live lab (3 October 2026)

**Done:** `deploy/homelab/prove-app-connector.sh` with `deploy/homelab/connector-lab.py`
(coordinator driver and a small authoritative DNS server) and the shared
`deploy/homelab/labs.Dockerfile`. Linux connector (`blaktaild up --app-connector`)
on a WAN and site network, Linux client on the WAN only, lab DNS with TTL 5,
three HTTP hosts on TCP 8080/8081, run on `docker --context m3-max`.

**Proven live (passing run, ~6 min):** allowed port works through the
connector 25 s after resource creation, adjacent port (8081) and an
unresolved host refused, `BLAKTAIL-FWD` holds exactly client → `/32` TCP 8080;
a changed answer routes the new address after 23 s and withdraws the old host
route from the client in the same second; an answer inside a protected CIDR
resource is blocked after 25 s with the rebinding reason in resource detail
and every route withdrawn; a clean answer resumes after 24 s; a connector
outage (container restart) withdraws the client route after 86 s and the
restarted agent restores access within 1 s, adjacent port still refused.

**Bugs fixed by the lab:**
- Control-update long-polls (`/v1/nodes/:id/updates`) never refreshed
  `last_seen_at`, so an idle, connected node looked offline after 90 s, routing
  peers lost "online" for selection/failover and resources showed `stale`.
  Fixed in `list_updates`; test
  `app_connectors::integration::idle_long_polls_keep_a_connector_online`.
- Expired leases were filtered at read time but nothing bumped the control
  revision, so clients kept a silent connector's host routes until an
  unrelated change. `app_connectors::expire_leases` runs in the long-poll loop
  and bumps once (asserted in `connector_leases_reach_authorised_clients_and_expire`).
- The 30 s lease floor was shorter than the real report cadence (30 s interval
  checked on the 25 s loop, ~50 s), so every report re-added routes, audited
  `connector.routes_changed` and bumped the revision. Floor raised to 90 s and
  the agent now reports ~5 s early (`report_delay`, unit-tested), so reports
  arrive every ~25 s.

**Still needs live/field proof or a decision:** IPv6 answers, two-connector
failover, a real recursive resolver with CNAME chains, non-Linux clients, two
organisations with live connectors, pause/transfer lifecycle; shared-IP
exposure remains documented, not mitigated.
