# Prove real-world NAT traversal, HTTPS fallback and onshore relay operations

**Priority:** P0 release proof. **Depends on:** existing #24/#48, no new transport until proof of current ladder. **Area:** relay, coordinator discovery, agents, operations.

## Gap and outcome

NetBird documents NAT traversal and connection fallback. BlakTail has direct/UDP relay code and `https_fallback` helpers, but project status explicitly says independent-NAT forced-relay proof is still open. Infrastructure also constrains a relay to one in-memory registration task. Closed tickets and a successful two-node direct path cannot establish production connectivity.

## Scope

- Build reproducible independent-NAT/corporate-firewall lab with direct UDP disabled, restricted UDP, symmetric NAT, mobile switch and proxy cases. Record transport selection, latency, path transition, encrypted payload property, reconnect and token expiry.
- Decide multi-relay discovery/registration consistency, regional residency, capacity, draining, health and failover. Ensure an Australian endpoint is actually selected; no arbitrary offshore fallback. Add resource quotas, DDoS and per-org isolation without decrypting WireGuard payload.
- Only after UDP proof, implement HTTPS relay transport end to end if still necessary: approved TLS endpoint, bounded streams, redirects rejected, proxy credentials protected, clear hysteresis and observability. Helper validation alone does not count.

## Acceptance / proof

Independent ISP/NAT test passes bidirectional IPv4/IPv6 and DNS while all direct paths are blocked, or documented precise failure. Kill primary relay and prove failover with bounded interruption. Encrypted packet capture, metrics and no-leak review attached; deployment playbook covers capacity and AU-only placement. iPhone result tracked under draft 20.

**Evidence:** `docs/project-status.md`, `blaktail-coord/src/https_fallback.rs`, `deploy/aws/variables.tf`, closed #24/#48; https://docs.netbird.io/about-netbird/understanding-nat-and-connectivity.

## Status (2 October 2026)

**Done:**
- Relay entries may declare a region (`host:port#region`); configuration
  validation rejects non-Australian declarations and the coordinator drops
  them again before advertising (`blaktail-config::split_relay_entry`,
  `blaktail-coord/src/operations.rs::relay_directory`). Agents receive
  `relay_endpoints` (endpoint + region) beside the legacy `relays` list.
- Agent selection (`blaktaild/src/relay_select.rs`): only declared-Australian
  relays, first non-backing-off relay in coordinator order (so peers converge
  on the same relay), exponential back-off 30 s → 10 min, bounded retry when
  all relays fail, and fail-back only after an authenticated probe
  (`blaktail_relay::probe`) succeeds. Failover/fail-back are logged with
  counts; `blaktaild status --json` exposes `active_relay` and
  `relay_failovers`.
- Coordinator-side relay reachability on the operator health view.
- `deploy/homelab/prove-relay-failover.sh` plus a `relay-secondary` service
  (profile `relay-failover`) in `compose.homelab.yml`: stop primary, require
  traffic via secondary within a budget, require both agents to fail back.
- HTTPS/WebSocket fallback (ADR 0004) deliberately not implemented; status
  documented in `docs/relay.md`.

**Proven by tests:** `relay_select::tests::*` (AU filtering, deterministic
choice, back-off doubling/cap/reset, bounded all-failed retry, probe-gated
fail-back), `blaktail-relay` `probe_proves_authenticated_reachability_only`
and `observed_parser_rejects_other_ids_and_zero_ports`,
`blaktail-config` `relay_entries_may_declare_only_australian_regions`,
coordinator `agents_receive_only_australian_relays_in_configured_order` and
the health-view relay probe assertions.

**Still needs live/field proof or a decision:**
- The failover drill has **not been run**; record its timings before claiming
  bounded interruption. Worst-case detection is about 75 s plus one poll.
- Independent-ISP / corporate-firewall / symmetric-NAT / mobile-switch lab,
  encrypted packet capture and no-leak review remain open (#24).
- Relay region is the operator's declaration; physical placement cannot be
  verified by software. Relay capacity, draining and per-org quotas beyond the
  existing per-source/per-node rate limits are not designed yet.
