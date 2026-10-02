# Evaluate optional post-quantum tunnel hardening without weakening WireGuard

**Priority:** decision / P2. **Depends on:** draft 21 transport proof and independent security review. **Area:** agent cryptography, key lifecycle.

## Gap and outcome

NetBird documents an optional post-quantum mode; its source includes Rosenpass integration. BlakTail currently uses WireGuard. Avoid a premature crypto feature or misleading “quantum-safe” marketing. Determine whether an optional hybrid rekey layer answers a real long-term confidentiality requirement for BlakTail's data and onshore use cases.

## Decision work

- Document adversary, recorded-traffic horizon, algorithm/project maintenance, platform support, CPU/battery cost, key provenance, handshake/rekey/reconnect and compatibility with relay, mobile and old peers.
- Prototype only behind explicit opt-in and version negotiation; no silent fallback from requested stronger mode. Preserve authenticated WireGuard transport, protect post-quantum key material on each platform and record whether intermediate control plane can downgrade.
- Obtain independent cryptographic review and clear administrator-facing status, upgrade and recovery instructions before GA. Never write a custom KEM or advertise unconditional quantum resistance.

## Acceptance / proof

Security ADR compares deferral versus hybrid option; if implemented, interop and downgrade tests cover mixed versions, relay failover, compromised coordinator, lost local key and mobile battery. Console shows actual negotiated protection per peer, not account-wide aspirational badge.

**Evidence:** `README.md` technical overview, `blaktaild/src/lib.rs`; https://docs.netbird.io/client/post-quantum-cryptography, https://github.com/netbirdio/netbird/tree/main/client/internal/rosenpass.
