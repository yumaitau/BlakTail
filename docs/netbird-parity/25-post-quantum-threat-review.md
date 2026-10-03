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

## Status (2 October 2026)

**Done:** decision record drafted at [`docs/adr/0009-post-quantum.md`](../adr/0009-post-quantum.md) with gates, constraints and a recommendation: defer; never a custom KEM; any prototype must be opt-in, per-peer negotiated and independently reviewed.
**Proven by tests:** not applicable — decision only; no code or navigation added.
**Still needs live/field proof or a decision:** product-owner sign-off on the ADR (status stays *proposed* until then) and independent security review.

## Status (3 October 2026, second round)

**Done:** product owner approved the opt-in hybrid PSK; [ADR 0009](../adr/0009-post-quantum.md) is Accepted with its constraints as requirements. Agent `blaktaild/src/pq.rs`: in-tunnel exchange (TCP 51822, Linux listener bound to the WireGuard interface) using RustCrypto `ml-kem` ML-KEM-768 plus X25519, HKDF-SHA256 over both secrets salted with a transcript of both WireGuard keys, an epoch and every public value; key confirmation both ways; PSK installed per peer via `wg … preshared-key /dev/stdin` (Linux) or boringtun UAPI (macOS, re-sent on every `replace_peers`); two-minute rotation, ten-minute lifetime then degraded, stale-handshake revert, replay/old-epoch rejection, 0600 persistence; `require` blocks the pair except the exchange (iptables raw chain `BLAKTAIL-PQ`), with the exchange port allowed through the ACL chain; agents advertise `pq-psk` (opt out with `BLAKTAIL_DISABLE_PQ_PSK=1`) and report per-peer state. Coordinator `blaktail-coord/src/post_quantum.rs` + migration slot 32: org policy off/prefer/require with symmetric tag-pair rules and a block flag (owner-only `manage_security`, audited, optimistic revision), per-peer `pq {mode, capable, block}` in peer maps, `PUT /v1/nodes/:id/pq-state` (deny-unknown-fields, same-org peers only), `GET/PUT /v1/orgs/:org/post-quantum`. Console: **Tunnel protection** page (policy, agent support, per-peer table) and a per-peer protection section on device detail; labels "Classical", "Hybrid PQ (ML-KEM-768 + X25519), rotated Ns ago", "Required but not established"; no account-wide badge. Docs: [post-quantum.md](../post-quantum.md).
**Proven by tests:** agent unit tests for transcript binding (swapped WireGuard keys, epoch and each secret change the PSK), both-sides agreement and key confirmation, forged confirmation and wrong-role/wrong-peer refusal, replayed/old-epoch `Init` rejected (pure and on the wire, never installing a key), downgrade reported and blocked under `require` (peer or local not capable, block unsupported reported), expiry → degraded/fail closed, raw-table rule plan, and an in-process two-agent runtime test over loopback TCP (same PSK on both fake devices, block lifted, then capability withdrawn → not established, blocked, key cleared). Coordinator tests: tag-pair resolution, peer maps carry policy and capability but no key material and are unchanged while off, owner-only writes (admin, network admin, auditor, member refused), cross-org read/write refused, validation (duplicate pair, unknown field, bad mode), stale revision → 409, audit row, agent reports validated (unknown field incl. `psk`, bad state/algorithm refused), cross-org peer ids dropped, console view keyless. Live lab `deploy/homelab/prove-post-quantum.sh` on m3-max passed: kernel WireGuard, `require` → both established in 28 s, same non-zero PSK on both sides, ping works, rotation epoch 1 → 2 in 98 s, then agent b without the capability → a reports `required_not_established`/`peer_not_capable`, PSK cleared, raw block installed, ping blocked. Linux clippy clean on m3-max.
**Still needs live/field proof or a decision:** independent cryptographic review of the exchange (GA gate; the exchange protocol is BlakTail's own, though no KEM was written); macOS boringtun path on hardware (compiled, not lab-run); iOS, Android and Windows clients (do not advertise `pq-psk`); mobile CPU/battery measurement; mixed-version, relay-failover and compromised-coordinator drills across independent networks (a coordinator can still withhold the capability bit, which shows as "Required but not established", not as protected); macOS cannot block under `require`.
