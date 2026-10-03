# Hybrid post-quantum pre-shared keys

BlakTail can add an optional, per-peer WireGuard pre-shared key (PSK) derived
from a hybrid ML-KEM-768 + X25519 exchange. It is **off by default**. The
decision record is [ADR 0009](adr/0009-post-quantum.md).

## What it protects, and what it does not

- **Protects:** confidentiality of recorded tunnel traffic against an
  adversary who records ciphertext today and later has a quantum computer
  able to break Curve25519 ("harvest now, decrypt later"). WireGuard mixes the
  PSK into every handshake, so breaking the classical key exchange alone is
  no longer enough to recover session keys.
- **Does not protect:** authentication. Device identity is still the
  classical WireGuard Curve25519 key. A future attacker who can break
  Curve25519 *during* a live session could impersonate a device. This is a
  hardening layer, not "quantum-safe" networking, and BlakTail does not
  describe it that way.
- **Not reviewed:** the exchange protocol has not had an independent
  cryptographic review. That review is a GA gate. Treat the feature as an
  opt-in hardening option until then.
- The relay and the coordinator never see a PSK. The relay forwards
  WireGuard ciphertext as before.
- **Coordinator trust:** policy and the peer's capability bit come from the
  coordinator. A compromised coordinator cannot learn a PSK, but it can turn
  the policy off (classical, shown as "Classical" and in the audit log) or
  claim a peer is not capable (shown as "Required but not established"). It
  cannot make a classical pair appear protected, because the state shown is
  what each agent reports about its own WireGuard device.

## How it works

1. An owner sets the organisation policy on **Tunnel protection**
   (`/tunnel-protection`): `off`, `prefer` or `require`, optional symmetric
   tag-pair rules (the strongest matching rule wins; no match uses the
   default), and whether to block a pair's traffic while `require` is unmet
   (on by default). Changes are audited (`post_quantum.policy_updated`) and
   need the `manage_security` permission (owners).
2. The coordinator adds `pq: {mode, capable, block}` to each peer in the
   agent's peer map. `capable` says whether that peer's agent advertises the
   `pq-psk` capability. Nothing else, and never key material.
3. When both agents of a pair are capable and the mode is not `off`, the
   agent with the lower WireGuard public key connects to the other's overlay
   address on TCP 51822 **inside** the WireGuard tunnel. On Linux the
   listener is bound to the WireGuard interface, so only traffic that a
   WireGuard session authenticated reaches it. The exchange itself is also
   authenticated by both WireGuard static keys (step 5), so a local process
   that binds port 51822 first (the port is not privileged) cannot complete
   it.
4. Three messages and an acknowledgement:
   - `Init`: epoch, both WireGuard public keys, a fresh X25519 public key and
     a fresh ML-KEM-768 encapsulation key.
   - `Resp`: a fresh X25519 public key, the ML-KEM ciphertext and a key
     confirmation tag.
   - `Confirm`: the initiator's confirmation tag. The responder installs the
     key, then sends `Ack`; the initiator installs on `Ack`.
5. Key derivation (protocol version 2): `HKDF-SHA256(salt = SHA-256(label,
   version, epoch, initiator WG key, responder WG key, every public value),
   ikm = ML-KEM shared secret || X25519 shared secret || static agreement)`,
   expanded separately into the 32-byte PSK and a key-confirmation key. The
   static agreement is X25519(own WireGuard private key, peer's WireGuard
   public key); both sides compute the same value and nobody without one of
   the two WireGuard private keys can. Each side's confirmation tag (HMAC
   under the confirmation key over the transcript) therefore proves it holds
   its WireGuard private key: a squatter on either end fails confirmation and
   nothing is installed. A low-order peer key is refused. Swapping the
   WireGuard keys, the epoch or any public value gives a different PSK.
   ML-KEM-768 is the RustCrypto `ml-kem` crate (FIPS 203); BlakTail does not
   implement a KEM. Version 1 agents (without the static agreement) cannot
   pair with version 2 agents; the exchange fails with `version` until both
   are upgraded.
6. The PSK is installed for that one peer: Linux runs `wg set <if> peer <key>
   preshared-key /dev/stdin` and writes the key on `wg`'s stdin (never argv,
   never a temporary file); macOS writes it through boringtun's UAPI socket and
   re-sends it on every peer reconfiguration.
7. Rotation every two minutes. Each side remembers the newest accepted epoch;
   an older or replayed `Init` is rejected with `stale_epoch`.

## States shown per peer

Each device's agent reports, for every peer, what it actually has. The
console shows it on the device page and on **Tunnel protection**; there is no
account-wide badge.

| Agent state | Console label | Meaning |
|---|---|---|
| `classical` | Classical | Policy off, or `prefer` and one side is not capable |
| `negotiating` | Classical (hybrid PQ negotiating) | `prefer`, both capable, no key yet |
| `established` | Hybrid PQ (ML-KEM-768 + X25519), rotated Ns ago | A key from the current lifetime is installed |
| `degraded` | Hybrid PQ key expired (rotation failing) | `prefer`: the last key is older than ten minutes; it stays installed |
| `required_not_established` | Required but not established | `require` and no current key: peer or local agent not capable, not yet agreed, or rotation failed past the lifetime |

There is no silent downgrade. Under `require`, a pair without a current key
is reported as above and, with blocking on, the Linux agent drops all traffic
to and from that peer's routes except the exchange (iptables `mangle` table
chain `BLAKTAIL-PQ` on `PREROUTING` and `OUTPUT`, IPv4 and IPv6). Only these
pass: the peer opening a connection to our port 51822, packets from the
peer's port 51822 that conntrack sees as `ESTABLISHED` replies to a
connection we opened, and the mirror of both outbound. A packet that merely
carries source or destination port 51822 to some other port is dropped. The
chain sits in `mangle` rather than `raw` because connection state is only
known after conntrack; older agents' `raw` chains are removed on upgrade. macOS agents report the state but
cannot block (`block_not_supported_here`); the Linux side of the pair still
blocks.

## Failure handling

- **Rotation fails** (peer unreachable, timeout): the last good key stays
  installed until it is ten minutes old, then the pair is `degraded`
  (`prefer`) or `required_not_established` and blocked (`require`).
- **Keys diverge** (an `Ack` lost, one side restored an old key): WireGuard
  handshakes stop. After 200 seconds without a handshake the agent clears the
  PSK so the tunnel can carry a fresh exchange. Under `require` the pair is
  blocked meanwhile.
- **Agent restart:** keys are kept beside the WireGuard private key in
  `pq-psk.json` (mode 0600, same protection as `private.key`) and reinstalled
  if younger than ten minutes, so a restart does not leave the pair mismatched.
- **Lost local state:** the restarted side starts at epoch 1; the responder
  rejects it with its newest epoch and the initiator moves past it.
- **Policy off or peer stops advertising `pq-psk`:** the PSK is cleared on
  the next peer map.
- To stop advertising the capability on one device, start `blaktaild` with
  `BLAKTAIL_DISABLE_PQ_PSK=1`.

## Platform support

| Platform | Exchange | Blocking under require |
|---|---|---|
| Linux (kernel WireGuard or the `boringtun` binary via `wg`) | Yes | Yes (iptables mangle table) |
| macOS agent (boringtun UAPI) | Yes (code path; not lab-proven) | No, reported |
| iOS, Android, Windows | No; they do not advertise `pq-psk` | — |
| WireGuard-only devices | No | Under `require` they are blocked; add an `off` tag-pair rule to exempt them |

Default routes (`0.0.0.0/0`, `::/0`) are not covered by the block on the
client side, because dropping them would cut the host off; the exit node's
own agent blocks the pair from its side.

## Live lab (m3-max, 3 October 2026)

`deploy/homelab/prove-post-quantum.sh` builds a lab image on the
`m3-max` Docker context, starts a coordinator and two privileged Linux agents
on kernel WireGuard, and checks baseline, `require`, rotation and downgrade.
Results are recorded below.

Run on 3 October 2026 (OrbStack Linux 7.0 kernel WireGuard, Debian
bookworm agents, SQLite coordinator, self-signed lab CA):

```
== enrol two agents (kernel WireGuard)
ok baseline classical tunnel (100.64.0.1 <-> 100.64.0.2), no PSK
== policy require
policy mode=require revision=1
ok both agents report established after 28s
ok wg shows the same non-zero PSK on both sides (fingerprint compared, not printed)
ok ping a -> b with the hybrid PSK installed
{"device": "pq-a", "peer": "pq-b", "state": "established", "mode": "require",
 "algorithm": "ml-kem-768+x25519", "epoch": 1, "rotated_seconds_ago": 29, "blocked": false}
== rotation (every 120s)
ok PSK rotated after 98s (epoch 1 -> 2), both sides agree, ping works
== downgrade: b restarts without the pq-psk capability
ok a reports b: required_not_established, reason peer_not_capable, blocked
ok PSK cleared, raw-table block installed, ping a -> b blocked
{"device": "pq-a", "peer": "pq-b", "state": "required_not_established",
 "reason": "peer_not_capable", "blocked": true}
{"device": "pq-b", "peer": "pq-a", "state": "required_not_established",
 "reason": "local_not_capable", "blocked": true}
post_quantum lab passed
```

The driver also checks that the coordinator's per-peer view never mentions
`psk`, `preshared` or `private`. Agent logs show `post-quantum PSK installed
(initiator) epoch=1` at 00:41:14 and `epoch=2` at 00:43:14 UTC, matching the
two-minute rotation. The lab proves Linux agent and coordinator behaviour on
one Docker host. It does not prove the macOS path, independent networks,
relay failover with PQ, mobile cost, or cryptographic soundness.

That run predates protocol version 2 (WireGuard static-key agreement in the
derivation) and the `mangle`/conntrack block rules; both are covered by unit
tests (`pq::tests::exchange_without_the_wireguard_private_key_fails`,
`pq::tests::block_rules_keep_only_the_exchange_port_and_skip_default_routes`)
and the driver now checks the `mangle` chain, but the lab has not been re-run.

## Still open

- Independent cryptographic review of the exchange (GA gate).
- macOS path proven on hardware; iOS, Android and Windows support.
- CPU and battery measurement on mobile devices.
- Mixed-version and relay-failover drills across independent networks.
