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

## Status (2 October 2026) — round 2: HTTPS fallback and lab proof

**Done:**
- ADR 0004 accepted and built: `blaktail-relay` serves the same frames as
  binary WebSocket messages over TLS (`blaktail_relay::wss`), sharing the UDP
  registration table, capability tokens and rate limits. Bounded frames,
  64-frame per-connection queue, 10 s handshake/write timeouts, 50 s idle
  close with 20 s pings (ALB-compatible), 4,096-connection cap, path check,
  text frames refused; plain-WebSocket mode only behind a TLS-terminating
  balancer. New metrics for WSS connections, rejections and queue drops.
- Coordinator: relay entries take `;wss=wss://…`; the URL is advertised only
  if `https_fallback::approved_endpoint` accepts it (`.au`, TLS, no
  credentials). Config validation rejects other suffixes.
- Clients (`blaktaild`, iPhone): UDP → WSS after three silent UDP probe rounds,
  back after three answered rounds; redirects never followed; optional HTTP
  CONNECT proxy with credentials from env/file only (never argv or logs);
  private CA via `BLAKTAIL_RELAY_WSS_CA_FILE`. `status --json` reports
  `relay_link` (`udp`/`wss`); the coordinator heartbeat keeps the `relay`
  vocabulary.
- Relay health window shortened from 75 s to 50 s (probe rounds are 25 s, 5 s
  after a miss).
- Self-contained lab harness `deploy/homelab/relay-lab.sh`; `prove-relay-nat.sh`
  and `prove-relay-failover.sh` rewritten onto it (they depended on the
  homelab stack and SSH) and new `prove-relay-wss.sh`. All three passed on
  `m3-max`; results in `docs/relay.md`.

**Proven by tests:** relay `wss::tests` (UDP↔WSS over TLS, untrusted cert
refused, WSS↔WSS with forged token refused and registration dropped on
close, oversized/text frames close, slowloris/wrong path/connection cap,
idle close, full queue drops, redirect not followed, CONNECT proxy 407 then
success with credentials, proxy settings from env/file, URL policy);
`blaktaild` `blocked_udp_falls_back_to_wss_relay`; proto ladder/selection
tests; config and coordinator WSS-URL approval tests. Lab: direct UDP dropped
→ relay in 54 s; all UDP dropped → WSS in 52–55 s with only TLS/443 on the
wire, promotion back in 111–124 s; failover with first ping after 71 s and
fail-back in 48 s.

**Still needs live/field proof or a decision:**
- Independent-ISP, symmetric-NAT, mobile-switch and IPv6 runs (#24); a real
  inspecting corporate proxy; an ALB-fronted WSS relay; packet-capture
  no-leak review by someone other than the author.
- Failover interruption is ~70 s on one host; whether that is acceptable, or
  needs a faster health signal, is a product decision.
- Relay capacity, draining and per-org quotas are still not designed; behind
  an ALB the per-source limit sees the balancer address.
