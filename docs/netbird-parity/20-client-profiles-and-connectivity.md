# Per-device connection profiles, split tunnelling and mobile relay parity

**Priority:** P1 for iPhone relay, P2 for profiles/split tunnel. **Depends on:** draft 21 relay proof and draft 19 platform acceptance. **Area:** agents, native UI, tunnel settings.

## Gap and outcome

NetBird clients support profiles, reconnect/autostart, inbound blocking and split-tunnelling choices. BlakTail iPhone is direct UDP only while Linux/macOS have relay logic; a user can see linked organisations but connection behaviour across multiple independent credentials needs precise specification. Do not replace BlakTail's All networks experience with one-active-account switching.

## Scope

- Define profile as local endpoint/organisation/certificate/state, not identity merger. Show connected profile(s), route ownership, DNS domain, exclusions and conflicts; never let one organisation's key or peer map leak into another. Support safe connect-on-startup, captive/offline recovery and optional block-inbound mode where firewall APIs permit.
- Design split tunnel per app/domain/CIDR with transparent limitations per OS and explicit DNS leak tests; fail closed for protected internal names. Do not silently funnel all Internet traffic through a selected exit node.
- Bring iPhone tunnel to Australian relay/hole-punch path or visibly mark no fallback; review packet-tunnel memory, background wake, token rotation and Network Extension lifecycle. Preserve local native accessibility and recovery messages.

## Acceptance / proof

Two independent org profiles with overlapping private CIDRs never cross-route or share names; connect/disconnect/restart preserves intended state. On iPhone across independent NATs, forced direct-UDP failure continues encrypted traffic over approved relay, with observed transport shown; if impossible, no parity claim. Split exclusions and internal DNS proven by packet capture on supported OS.

**Evidence:** `README.md`, `docs/ios.md`, `apps/ios/Tunnel/TunnelSession.swift`; https://docs.netbird.io/client/profiles, https://docs.netbird.io/client/block-inbound-connections, https://docs.netbird.io/client/connect-on-startup.

## Status (2 October 2026)

**Done:**
- iPhone relay inspected: `blaktail-ios-wg` has no relay client (Android
  shares the same gap; Windows has relay only because it runs `blaktaild`).
  `docs/ios.md` now documents exactly what is missing (relay socket and
  framing, reflexive endpoint report, per-peer path state machine, AU-only
  selection, observed-transport UI) and recommends moving the relay client
  into a shared crate behind the existing C ABI. No parity is claimed.
- Desktop agents gained deterministic AU-only multi-relay failover (draft 21),
  which a future mobile relay must mirror so peers share a relay.

**Proven by tests:** none for iPhone in this change (no Swift changes).

**Still needs live/field proof or a decision:**
- iPhone/Android relay implementation and a physical-device test across
  independent NATs with forced direct-UDP failure.
- Profiles, split tunnelling, block-inbound and connect-on-startup design and
  implementation were not started; the two-org overlapping-CIDR test remains
  open.

## Status (2 October 2026) — round 2: mobile relay

**Done:**
- Relay protocol, AU-only ordered selection with back-off/fail-back, the
  UDP → WSS link ladder and per-peer direct/relay hysteresis moved into a new
  dependency-free crate `blaktail-relay-proto`, used by `blaktail-relay`,
  `blaktaild` (selection now wraps it) and the mobile core.
- `blaktail-ios-wg` exposes it over the C ABI (`blaktail_relay_*`, header
  updated) and JNI (`NativeTunnel.relay*`). No retained buffers; a few hundred
  bytes per peer, for the Network Extension memory limit.
- iPhone: `TunnelSession` passes `relay_endpoints`/token/expiry and peer node
  ids on every poll, keeps one `NWUDPSession` per relay and a
  `URLSessionWebSocketTask` for the approved WSS fallback (redirects refused),
  feeds direct-path receipts back for hysteresis, and answers a provider
  message with the observed transport. *This iPhone* shows **Path**: Direct,
  Australian relay, or Australian relay over HTTPS, with peer counts.
- Android: `TunnelService` refreshes relay settings from the coordinator, runs
  a protected relay UDP socket and the same Rust decisions; the notification
  shows the path. UDP relay only (no platform WebSocket client).
- Profiles, split tunnelling, block-inbound and connect-on-startup were not
  started in this round.

**Proven by tests:** `blaktail-relay-proto` mobile tests (registration, SEND
wrapping, FORWARDED only from the active relay and known peers, UDP→WSS and
back, Android never leaving UDP, failover after silence and probe-gated
fail-back, token refresh, WSS re-registration stopping once UDP answers);
`blaktail-ios-wg` C ABI tests; `swift test` for BlakTailCore (relay endpoint
decoding) and BlakTailPhone (transport status decoding, cleared when
disconnected); `cargo build -p blaktail-ios-wg --target aarch64-apple-ios-sim`
and an `xcodebuild` simulator build of the app plus packet tunnel. The JNI
code passes `cargo clippy --features jni` on the host.

**Still needs live/field proof or a decision:**
- No physical iPhone or Android run: forced direct-UDP failure across
  independent NATs, background wake, capability rotation and extension
  restart are unproven, so there is still no parity claim.
- Android was **not built**: no Android Rust target or Kotlin/Gradle toolchain
  on this machine; the Kotlin changes are reviewed, not compiled.
- Phones do not report a reflexive address or hole-punch, and fail back to a
  higher-priority relay only via UDP probes.
- The two-org overlapping-CIDR profile test remains open.
