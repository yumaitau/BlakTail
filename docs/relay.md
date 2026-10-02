# Australia-pinned relay

`blaktail-relay` forwards opaque encrypted UDP payloads when direct WireGuard paths
are unavailable. It refuses to start unless `BLAKTAIL_REGION` is one of the explicit
Australian AWS, Azure, or Google Cloud region identifiers.

```sh
BLAKTAIL_REGION=ap-southeast-2 \
BLAKTAIL_RELAY_BIND=0.0.0.0:3478 \
BLAKTAIL_RELAY_AUTH_SECRET="$(openssl rand -hex 32)" \
  cargo run -p blaktail-relay --release
```

Coordinator and relay must share `BLAKTAIL_RELAY_AUTH_SECRET`. Keep it distinct
from `BLAKTAIL_AUTH_HMAC_SECRET`: relay compromise must not permit console-session
forgery.

Protocol frames use one-byte opcode plus 16-byte node id:

- `REGISTER` (`1`): node id, expiry, HMAC-SHA256 capability minted by coordinator.
- `SEND` (`2`): destination id plus up to 2,048 bytes of opaque encrypted payload.
- `FORWARDED` (`3`): source id plus opaque payload.
- `PING`/`OBSERVED` (`4`/`5`): authenticated reflexive-address probe.
- `DIRECT` (`6`): source id plus opaque WireGuard ciphertext sent peer to peer.
- `PUNCH`/`PUNCH_ACK` (`7`/`8`): source id plus a random 64-bit challenge.

Registrations expire by capability time and after 120 seconds idle. Clients refresh
every 30 seconds. Relay applies per-source token-bucket limits, rejects oversized
frames, and exposes Prometheus text metrics on `127.0.0.1:9702` by default. It never
decrypts or logs tunnel payloads.

The relay also acts as a minimal STUN-like discovery service. It returns the source
address of each authenticated client socket; the agent reports that reflexive
candidate to the coordinator every 60 seconds alongside the node's configured direct
endpoint. Peer candidates expire after 180 seconds. While encrypted traffic continues
over the relay, both agents exchange a nonce challenge directly. Only an
acknowledgement from the exact advertised socket promotes the path to peer-to-peer
UDP. WireGuard still authenticates and encrypts every promoted data packet. A stale
direct handshake automatically returns the peer to relay transport; the agent
periodically retries the original configured endpoint. Missing `OBSERVED` replies
expire relay health and the agent rotates to another advertised relay address.

Current registration state is in-memory. Run exactly one relay task per advertised
endpoint; horizontal scale requires sharded endpoint discovery, not a UDP load
balancer spraying nodes across independent task maps.

## Several relays: order, region and failover

List relays in `coordinator.relays` (or `BLAKTAIL_RELAYS`) in priority order.
Each entry may declare its region after `#`; untagged entries inherit
`coordinator.region`:

```sh
BLAKTAIL_RELAYS="relay-syd-a.example.org.au:3478#ap-southeast-2,relay-mel.example.org.au:3478#australia-southeast2"
```

- Configuration validation rejects an entry whose declared region is not an
  approved Australian identifier, and the coordinator drops any such entry
  again before advertising, so agents are never handed an offshore fallback.
  The region is the operator's declaration about where the relay runs;
  BlakTail cannot verify a server's physical location.
- Agents receive the list in that order with each relay's region and ignore
  any entry not declared Australian.
- Because registrations are per relay, two peers can only relay through the
  *same* relay. Every agent therefore picks the **first relay in list order
  that is not backing off**. When a relay stops answering authenticated
  probes for 75 seconds the agent fails over to the next one and backs the
  failed relay off for 30 seconds, doubling to at most 10 minutes. If every
  relay is backing off, the agent retries the one whose back-off ends first.
- When a higher-priority relay's back-off ends, the agent sends one
  authenticated `REGISTER`+`PING` probe from a separate socket. Only an
  `OBSERVED` reply moves it back; a failed probe extends the back-off. This is
  how agents converge on the same relay after a primary returns.
- Failover is not instantaneous: worst case is roughly the 75-second health
  window plus one poll interval. Peers already on a direct path are unaffected.
- `blaktaild status --json` shows `active_relay` and `relay_failovers`; the
  agent logs each failover and fail-back with the relay address and back-off.
- The console's **Operator health** page probes each advertised relay from the
  coordinator with a throwaway identity and a 60-second capability. That
  proves the relay is up and shares the coordinator's secret; it is not proof
  that every device's network can reach it.

`deploy/homelab/prove-relay-failover.sh` is the failover drill: two agents with
direct UDP dropped, two relays, stop the primary, require traffic through the
secondary within a budget, then require both agents to fail back. It runs on a
single Docker host, so it exercises selection and failover logic, not
independent-ISP NAT. It has not yet been run against this code; record the
result here when it passes.

## HTTPS / WebSocket fallback (ADR 0004)

Not implemented. `blaktail-coord/src/https_fallback.rs` holds the transport
ladder and Australian-origin approval helpers only; no agent or relay speaks an
HTTPS relay transport. Networks that block all outbound UDP cannot use
BlakTail today. Per ADR 0004, the transport is built only after the UDP
ladder is proven across independent NATs.
