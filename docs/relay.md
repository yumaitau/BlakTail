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
every 25 seconds (every 5 seconds while a probe is unanswered). Relay applies per-source token-bucket limits, rejects oversized
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
  probes for 50 seconds the agent fails over to the next one and backs the
  failed relay off for 30 seconds, doubling to at most 10 minutes. If every
  relay is backing off, the agent retries the one whose back-off ends first.
- When a higher-priority relay's back-off ends, the agent sends one
  authenticated `REGISTER`+`PING` probe from a separate socket. Only an
  `OBSERVED` reply moves it back; a failed probe extends the back-off. This is
  how agents converge on the same relay after a primary returns.
- Failover is not instantaneous: worst case is roughly the 50-second health
  window plus one 25-second agent loop. Peers already on a direct path are
  unaffected. The same selection rules (`blaktail-relay-proto::select`) run in
  the iPhone and Android tunnels.
- `blaktaild status --json` shows `active_relay`, `relay_failovers` and
  `relay_link` (`udp` or `wss`); the agent logs each failover, fail-back and
  link change with the relay address and back-off.
- The console's **Operator health** page probes each advertised relay from the
  coordinator with a throwaway identity and a 60-second capability. That
  proves the relay is up and shares the coordinator's secret; it is not proof
  that every device's network can reach it.

## HTTPS / WebSocket fallback (ADR 0004)

Some networks drop all outbound UDP. For them each relay can also accept the
same frames as binary WebSocket messages over TLS on TCP 443. A UDP client and
a WSS client registered on the same relay process reach each other, because
both feed one registration table.

Relay side (flags or environment; paths, not secrets):

```sh
BLAKTAIL_RELAY_WSS_BIND=0.0.0.0:443 \
BLAKTAIL_RELAY_WSS_CERT_FILE=/etc/blaktail/relay.crt \
BLAKTAIL_RELAY_WSS_KEY_FILE=/etc/blaktail/relay.key \
  blaktail-relay            # plus the usual UDP settings above
```

- `BLAKTAIL_RELAY_WSS_PATH` (default `/v1/relay`) is the only path that
  upgrades; anything else gets 404.
- Behind a TLS-terminating load balancer (an AWS ALB HTTPS listener) set
  `BLAKTAIL_RELAY_WSS_BEHIND_TLS_PROXY=true` and omit the certificate; the
  relay then serves plain WebSocket to the balancer. Starting the listener
  with neither a certificate nor that flag is refused. The ALB needs sticky
  WebSocket support (standard) and an idle timeout of at least 60 seconds;
  the relay pings every 20 seconds and closes connections silent for 50.
- Same capability tokens as UDP (HMAC, node id, expiry). One connection
  carries one registration; closing it drops the registration at once.
- Bounds: frames over 2,065 bytes (`SEND` header + 2,048-byte payload) or any
  text message close the connection; handshakes must finish within 10 s
  (slowloris); at most 4,096 concurrent connections; each connection has a
  64-frame outbound queue and excess frames are dropped as UDP would drop
  them; a peer that does not read for 10 s is disconnected. Per-source and
  per-node rate limits are shared with UDP. Behind an ALB the per-source
  limit sees the ALB's address, so the per-node limit is what bounds abuse.
- Metrics add `blaktail_relay_wss_connections`,
  `blaktail_relay_wss_rejected_total` and
  `blaktail_relay_dropped_total{reason="stream_queue_full"}`.

Coordinator side: append the approved URL to the relay entry it fronts, so
clients only ever use the WSS listener of the relay they selected:

```sh
BLAKTAIL_RELAYS="relay-syd-a.example.org.au:3478#ap-southeast-2;wss=wss://relay-syd-a.example.org.au/v1/relay"
```

Configuration validation requires `wss://`, a host and no credentials. The
coordinator advertises the URL only if it also passes the HTTPS fallback
origin policy (`https_fallback::approved_endpoint`: TLS and an `.au` host);
otherwise it logs an error and advertises the UDP relay without a fallback.
A `.au` host name is an origin rule, not proof of where the server runs.

Client behaviour (desktop agents, iPhone; Android is UDP-only for now):

- UDP is always preferred. Each probe round sends `REGISTER`+`PING` over UDP.
  Three unanswered rounds in a row (about 15 seconds at start-up) move relay
  frames to the WebSocket of the *same* relay; UDP probes continue every 25
  seconds and three answered rounds in a row promote back to UDP.
- The reflexive address reported to the coordinator for hole punching comes
  only from UDP replies, never from the TCP connection.
- The agent never follows redirects: any answer other than `101 Switching
  Protocols`, including `3xx`, is a failed connect. TLS uses the public web
  PKI roots plus an optional private CA from `BLAKTAIL_RELAY_WSS_CA_FILE`.
- HTTP CONNECT proxies: `BLAKTAIL_RELAY_PROXY=http://proxy.example.org.au:3128`
  (or the standard `HTTPS_PROXY`). Credentials come from the URL's user info
  in that environment variable, or `BLAKTAIL_RELAY_PROXY_USER` with
  `BLAKTAIL_RELAY_PROXY_PASSWORD` or `BLAKTAIL_RELAY_PROXY_PASSWORD_FILE`.
  They are never accepted as command-line arguments and never logged; a
  `407` is reported as "relay proxy requires valid credentials". Proxies that
  intercept TLS must present a certificate the agent trusts, otherwise the
  connection fails closed.
- `blaktaild status --json` reports `relay_link: "wss"`. The coordinator
  heartbeat keeps the existing `relay` transport value (the topology and
  console vocabulary is unchanged), so the console shows WSS-relayed peers as
  relayed.

## Lab results (single Docker host, 3 October 2026)

`deploy/homelab/relay-lab.sh` builds one image from the committed tree and
runs a coordinator, one or two relays (UDP 3478 + WSS 443 with a throwaway
CA) and two Linux agents on a private network, with no console, no shared
stack and no SSH to the Docker host. Every container, network and volume is
removed on exit. These runs used Docker context `m3-max` (OrbStack, 16 CPU).
They prove the agent and relay logic on one host, **not** independent-ISP
NAT, a real corporate proxy or a physical phone.

| Script | What it forces | Result |
| --- | --- | --- |
| `prove-relay-nat.sh` | Direct UDP between the agents dropped (iptables) | Passed. WireGuard endpoints moved to the local forwarder and `relay_link=udp`; overlay ping both ways after 54 s; 20/20 pings, rtt avg 0.9 ms; relay `forwards_total` 48, no WSS connections. |
| `prove-relay-wss.sh` | Every UDP datagram on `eth0` dropped both ways (no direct path, no UDP relay) | Passed (three runs on the final code). Both agents reported `relay_link=wss` and pinged both ways after 52–55 s; 20/20 pings; relay `wss_connections` 2, `forwards_total` 56–58; about 25 UDP datagrams per agent dropped by the firewall; a 3-second `eth0` capture during traffic saw 27–32 TLS/443 packets and no UDP. After UDP was restored both agents promoted back to the UDP relay in 111–124 s. |
| `prove-relay-failover.sh` | Direct UDP dropped, two relays, primary stopped then restarted | Passed. Both agents on the primary after 57 s; primary stopped: first overlay ping after 71 s and both agents on the secondary after 72 s (`relay_failovers` 1 each, budget 150 s); primary restarted: both failed back together in 48 s. |

All three ran on the final code of this change (worktree commit `999bd44`, later squashed into the commit that added this section). An earlier failover run
with the previous 75-second health window took 98 s; the window is now 50 s.
An earlier WSS run promoted only one agent back to UDP within 180 s: a WSS
`REGISTER` raced the UDP probe and the relay (one address per node) answered
on the wrong link. Clients now re-register over WSS only while UDP is still
unanswered. The roughly 55-second convergence is the agent's direct-path
timeout before it moves a peer to the relay, plus (for WSS) three 5-second UDP
probe rounds; promotion back is three answered 25-second rounds plus one agent
loop. The previous homelab-only versions of these scripts depended on a
long-lived stack, a console database and SSH to the Docker host; they were
replaced by this harness.

### WSS behind a TLS-terminating proxy, UDP blocked mid-session (4 October 2026)

Production symptom: two agents relaying over UDP, then a firewall dropping
all non-DNS UDP on `eth0`. Both agents moved to `relay_link=wss`, the relay
counted two WSS connections and rising `registers_total`, but
`forwards_total` stayed flat and overlay ping never recovered, even after
UDP was restored. `prove-relay-wss.sh` had passed because it blocks UDP
before the agents start and its relay terminates TLS itself.

Root cause (agent only): each peer's forwarder task in
`blaktaild/src/relay_client.rs` returned on the first failed send. A local
iptables `OUTPUT` drop makes Linux `sendto` fail with `EPERM`, so the first
WireGuard datagram sent after the block, while the ladder was still probing
UDP, ended the task. The forwarder stayed registered and `ensure_forwarder`
kept handing back its port, so WireGuard wrote into a socket nobody read
(lab: `Recv-Q` 229 248 bytes on the 127.0.0.1 forwarder port) on every link
until the agent restarted. REGISTER/PING come from a different task, which
is why the WebSocket looked healthy. The relay, the proxy path and the
mobile cores were not at fault: the relay keys WebSockets by connection
id, not address, and the iOS and Android shells already ignore datagram
send errors.

Fix: a failed send drops that datagram (with at most one warning per peer
every 30 s) and the task keeps running; `ensure_forwarder` also replaces a
forwarder whose task has ended, and the next path refresh re-points
WireGuard at the new port. Only `blaktaild` changes; the relay image does
not need redeploying. Regression tests: `forwarder_survives_failed_sends`,
`ensure_forwarder_replaces_a_stopped_forwarder` and
`udp_blocked_mid_session_recovers_over_proxied_wss` (UDP relay first, then
sends fail with EPERM, WebSocket through a TCP proxy; it fails on the old
code).

`prove-relay-wss-proxy.sh` puts nginx (TLS on 443 for a separate host name,
WebSocket upgrade, 60 s read/send timeout like an ALB) in front of the
relay's plain listener on 8080 (`BLAKTAIL_RELAY_WSS_BEHIND_TLS_PROXY=true`),
drops direct UDP between the agents, and drops non-DNS UDP with the
production rules. After the WebSocket carries traffic it idles 75 s, pings
again, restores UDP and waits for promotion back.

| Variant | Before the fix (`c6f7ad3`) | After the fix |
| --- | --- | --- |
| `midsession` | Failed. UDP relay ping after 54 s (`forwards_total` 46); after the block both agents reached `relay_link=wss` with `wss_connections` 2, but no ping in 180 s and `forwards_total` stayed 46; forwarder `Recv-Q` 229 248 (a) and 24 192 (b). | Passed. UDP relay after 53 s; ping both ways over the proxied WebSocket 69 s after the block; 20/20 pings, `forwards_total` 106 → 164; ping after 75 s idle; promoted back to UDP 92 s after restore. |
| `blocked-first` | Not run. | Passed. Ping both ways over the WebSocket after 62 s; 20/20 pings, `forwards_total` 24 → 64; ping after 75 s idle; promoted back to UDP in 106 s. |

Still open (draft 21): independent-ISP and symmetric-NAT runs, a real
corporate proxy (CONNECT is covered only by an in-process test proxy), a
real AWS ALB (the nginx lab stands in for it), IPv6, relay capacity and draining, and physical-device runs
for iPhone and Android.
