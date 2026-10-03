# ADR 0004 — HTTPS fallback transport for constrained networks (issue #48)

- Status: Accepted (3 October 2026); implemented as described below
- Date: 2026-09-03 (proposed), 2026-10-03 (accepted)

## Context

The data plane is WireGuard over UDP with an Australian relay as the
encrypted fallback. Some corporate networks block all non-TCP egress, so a
UDP-only agent cannot reach peers or the relay from behind those proxies.
The Rust agent stack (`tokio`, `reqwest` with `rustls-tls`) already speaks
HTTPS, and production-style deploys put the control plane behind an
ALB/Fargate path. The question is which TCP/443-friendly fallback to
implement first when UDP is unavailable.

Prior art in this repo: ADR 0002 chose bounded HTTPS long-poll for
control-plane updates because the isolated AWS topology caps Gateway waits
at ~30s — a reminder that any fallback must fit ALB idle timeouts and
plain corporate-proxy behaviour, not just raw throughput.

## Options compared

| Option | How it works | ALB / Fargate fit | Corporate proxy traversal | Rust stack cost |
| --- | --- | --- | --- | --- |
| HTTP/2 streaming / CONNECT | Agent opens a CONNECT tunnel (or long-lived H2 stream) through the proxy; WireGuard/relay frames ride inside | ALB supports HTTP/2 to targets with care; CONNECT forwarding through ALB is awkward and Fargate security-group wiring is custom | CONNECT works only where the proxy allows it; many allow CONNECT solely to 443, which is fine, but inspection proxies may interfere | New framing plus proxy-auth handling in the agent |
| WebSocket over 443 | Agent upgrades an HTTPS connection to a WebSocket; relay frames ride as binary messages | ALB has native WebSocket (sticky, idle-timeout) support; Fargate target setup is standard | WebSocket handshake is plain HTTPS, so it passes the widest set of proxies, including ones that only allow 443 outbound | `tokio-tungstenite` (or equivalent) in agent + relay; well-trodden |
| TLS-framed TCP | Agent opens a direct TLS-over-TCP stream to the relay and frames datagrams itself | Works end-to-end but bypasses HTTP routing, so ALB HTTP features do not apply; needs NLB/TCP target instead | Fails closed wherever the proxy only permits HTTP(S) — the common corporate case | Custom framing plus its own keepalive/reconnect |

## Decision

Recommend **WebSocket-over-443 first** for proxy traversal: it looks like
ordinary HTTPS to middleboxes, has first-class ALB support, and needs no
per-proxy CONNECT permission beyond what browsers already get.

Explicit caveats:

- This ADR records a recommendation, not an implementation. The relay
  protocol today is UDP (`REGISTER`/`SEND`/`FORWARDED`); a WebSocket relay
  listener, agent fallback trigger (UDP failure detection), and path
  promotion back to direct UDP all still need building.
- A test is needed before any release claim: an agent behind a
  TCP-443-only egress (simulated proxy) must hold a working tunnel through
  the fallback, with relay metrics showing the shift.
- ADR 0002's 25-second wait cap and Gateway constraints still apply to the
  control plane; this fallback concerns the data path only.
- TLS-framed TCP stays a possible later optimisation for non-proxied
  networks where HTTP overhead matters; it is not the first fallback
  because it fails exactly where the fallback is needed most.

## Implementation (3 October 2026)

Accepted and built as WebSocket-over-443. The caveats above remain
requirements:

- `blaktail-relay` serves `REGISTER`/`SEND`/`PING` frames as binary WebSocket
  messages over TLS (`blaktail_relay::wss`, tokio-tungstenite + rustls with the
  `ring` provider) next to UDP, sharing one registration table, the same
  capability tokens and the same rate limits. Bounded: frame size, 64-frame
  per-connection queue, 10 s handshake and write timeouts, 50 s idle close
  with 20 s server pings (inside ALB's 60 s default), 4,096 connections.
  `BLAKTAIL_RELAY_WSS_BEHIND_TLS_PROXY` serves plain WebSocket only behind a
  TLS-terminating balancer.
- The coordinator advertises a WSS URL per relay (`;wss=` suffix on the relay
  entry) only when it passes `https_fallback::approved_endpoint` (TLS, `.au`
  host, no credentials).
- Clients (`blaktaild`, the iPhone tunnel) climb UDP → WSS after three
  unanswered UDP probe rounds and promote back after three answered rounds
  (`blaktail_relay_proto::ladder`). Redirects are never followed. Optional
  HTTP CONNECT proxy with credentials from the environment or a file only.
  Android stays on UDP: the platform SDK has no WebSocket client.
- Test evidence: in-process relay tests (UDP↔WSS, WSS↔WSS, forged tokens,
  oversize/text frames, slowloris, connection cap, idle close, full queue,
  redirect refusal, CONNECT proxy with and without credentials), an agent
  test with the UDP relay black-holed, and the single-host lab
  `deploy/homelab/prove-relay-wss.sh` (all UDP dropped on both agents; overlay
  traffic over TLS/443; promotion back to UDP when restored). See
  [relay.md](../relay.md#lab-results-single-docker-host-3-october-2026).
- Not yet proven: a real corporate (inspecting) proxy, an ALB-fronted relay,
  independent ISPs and physical phones. TLS-framed TCP was not built.
