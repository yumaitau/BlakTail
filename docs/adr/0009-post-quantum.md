# ADR 0009 — Optional post-quantum tunnel hardening (draft 25)

- Status: proposed — recommendation **defer**; independent review required before any prototype ships
- Date: 2026-10-02

## Context

BlakTail tunnels are WireGuard (Noise IK, Curve25519, ChaCha20-Poly1305,
BLAKE2s). WireGuard supports an optional 32-byte pre-shared key mixed into the
handshake. Some products add a hybrid post-quantum layer (for example
Rosenpass, which periodically derives a PSK through a post-quantum KEM and
installs it into WireGuard). The concern is "harvest now, decrypt later":
recorded traffic decrypted by a future quantum adversary.

## Threat assessment

- **Adversary.** A party able to record overlay ciphertext today (ISP,
  transit, relay operator) and to run a cryptographically relevant quantum
  computer in future.
- **Horizon.** Matters for data that must stay confidential for decades
  (cultural knowledge, health, legal). Most device-management traffic has a
  short horizon.
- **What a PSK layer protects.** A per-peer PSK rotated by a PQ KEM protects
  confidentiality of future-recorded sessions. It does not provide PQ
  authentication; the Curve25519 identity remains classical.
- **Relay.** The relay forwards ciphertext and never sees keys; a PSK layer
  does not change relay trust.
- **Coordinator.** The coordinator must never distribute or learn PSKs. A
  coordinator-distributed PSK adds no PQ protection against a compromised
  coordinator and must not be built.

## Options

1. **Defer** (recommended now). Keep WireGuard as is. Revisit when the
   transport ladder (draft 21) is proven and a user with a long-horizon
   confidentiality requirement exists.
2. **Hybrid PSK via an established, reviewed implementation** (e.g. Rosenpass)
   negotiated per peer pair, opt-in per organisation, with version
   negotiation and no silent downgrade once both peers advertise it. Requires
   per-platform support (Linux, macOS, Windows, iOS Network Extension memory
   limits, Android) and battery/CPU measurement.
3. **Custom KEM integration.** Rejected. BlakTail will not write its own KEM
   or handshake.

## Constraints for any future prototype

- Opt-in, per-peer negotiated, visible per peer in the console as the
  *actually negotiated* protection, never an account-wide badge.
- If a peer requested PQ mode and the other side cannot do it, the connection
  state says so; no silent fallback is labelled as protected.
- Mixed-version, relay failover, lost local key and compromised-coordinator
  downgrade tests; independent cryptographic review before GA.
- No "quantum-safe" marketing.
