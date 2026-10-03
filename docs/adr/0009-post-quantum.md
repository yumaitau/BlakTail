# ADR 0009 — Optional post-quantum tunnel hardening (draft 25)

- Status: **Accepted** (3 October 2026) — opt-in hybrid PSK built; independent review required before GA
- Date: 2026-10-02 (proposed), 2026-10-03 (accepted)

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

## Decision (3 October 2026)

The product owner approved building option 2 as an **opt-in hybrid PSK**,
with the constraints below kept as requirements. What shipped
([post-quantum.md](../post-quantum.md)):

- Peers that both advertise the `pq-psk` capability, and whose organisation
  policy for that pair is `prefer` or `require`, run a three-message exchange
  **inside** their existing WireGuard tunnel (TCP 51822 on the overlay
  address, Linux listener bound to the WireGuard interface). The classical
  WireGuard session authenticates it.
- ML-KEM-768 comes from the maintained RustCrypto `ml-kem` crate (FIPS 203);
  X25519 from `x25519-dalek`. HKDF-SHA256 over both shared secrets, salted
  with a transcript hash binding both WireGuard public keys, an epoch
  counter and every public value, gives the PSK and a separate
  key-confirmation key. No KEM was written.
- The exchange itself is a small BlakTail protocol (Init, Resp + confirm,
  Confirm, Ack), not Rosenpass. This departs from the earlier "no own
  handshake" preference; it is the main reason independent review is a GA
  gate. Rosenpass was not embedded because it runs as its own service on a
  separate UDP port and needs its long-term public keys distributed to
  peers (which here would mean through the coordinator); the in-tunnel
  exchange needs neither.
- The key is installed as the WireGuard PSK for that peer on both sides
  (`wg set … preshared-key /dev/stdin` on Linux; boringtun UAPI on macOS),
  rotated every two minutes, re-established on reconnect, kept until a
  ten-minute lifetime when rotation fails, then reported degraded.
- The coordinator delivers per-pair mode, peer capability and the block flag
  in peer maps, and stores what agents report (state, mode, epoch, last
  rotation time, algorithm string, blocked). It has no field for key
  material and refuses reports with unknown fields.

## Constraints (now requirements)

- Opt-in, per-peer negotiated, visible per peer in the console as the
  *actually negotiated* protection, never an account-wide badge.
- If a peer requested PQ mode and the other side cannot do it, the connection
  state says so; no silent fallback is labelled as protected.
- Mixed-version, relay failover, lost local key and compromised-coordinator
  downgrade tests; independent cryptographic review before GA.
- No "quantum-safe" marketing.
- Coordinator never generates, relays or stores a PSK.

## Status of the requirements

| Requirement | Where it holds |
|---|---|
| No custom KEM | `ml-kem` crate; protocol only combines KEM + DH outputs |
| Per-peer negotiated, opt-in | org policy off by default; both peers must advertise `pq-psk` |
| No silent downgrade | `require` reports `required_not_established` and (by default) blocks the pair on Linux; `prefer` shows "Classical" |
| Coordinator never sees PSKs | no schema column or request field; tests assert peer maps and console responses carry no key material |
| Actual state per peer | `/devices/{id}` and `/tunnel-protection` show each agent's report; no account-wide badge |
| No "quantum-safe" wording | console and docs name the algorithms and the classical-authentication limit |
| Independent review before GA | **open** |
| Mobile battery, Windows, iOS, Android | **open**: not implemented on those clients; they never advertise `pq-psk` |
