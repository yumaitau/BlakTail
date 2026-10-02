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
