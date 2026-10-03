# iPhone app

Native SwiftUI client for iPhone. It signs in through the onshore console
(Better Auth), stores the session token in Keychain, shows every machine
across every authorised network workspace, and enrols **this iPhone** as a
WireGuard node on the same coordinator path as `blaktaild`.

The packet tunnel is a Network Extension (`NEPacketTunnelProvider`). The
dataplane is the in-repo `blaktail-ios-wg` crate (boringtun). There is no
`blaktaild` LaunchDaemon on iOS.

**Choice:** native SwiftUI, following
[Apple's Human Interface Guidelines](https://developer.apple.com/design/human-interface-guidelines/).

**Minimum iOS:** iOS 17 (`IPHONEOS_DEPLOYMENT_TARGET` / Package.swift `iOS(.v17)`).
iPhone only (`TARGETED_DEVICE_FAMILY = 1`).

## Layout

| Path | Role |
| --- | --- |
| `apps/ios/Sources/BlakTailPhone` | Sign-in, This iPhone, All networks, Settings |
| `apps/ios/Tunnel` | Packet-tunnel extension |
| `apps/ios/App/BlakTailPhoneApp.swift` | `@main` WindowGroup |
| `blaktail-ios-wg` | boringtun C ABI used by the extension |
| `apps/macos/Sources/BlakTailCore` | Shared console client, coordinator client, Keychain, tagline |
| `apps/console/src/app/desktop` | Browser sign-in page for ASWebAuthenticationSession |
| `apps/console/src/app/api/desktop` | Session, join-key, inventory, rename, route, and revoke APIs |

The phone reuses the desktop console bridge. Join keys are minted through the
console, then the phone registers with the coordinator itself. Join keys are
never stored, logged, or passed on argv.

## Build (on a Mac)

```sh
cd apps/ios
swift test
open BlakTailPhone.xcodeproj
```

Device and simulator tunnel builds need Rust Apple targets:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
```

Select an iPhone simulator or device, then Run. Set the app bundle ID to
`au.org.blaktail.ios` and the extension to `au.org.blaktail.ios.tunnel`. A paid
Apple Developer team is required to run a Network Extension on a physical
iPhone.

## Client flow

The root scene is a three-tab iPhone layout:

- **This iPhone** — enrol, connect, disconnect (pause), or leave the network.
  Colour is never the only status signal: every connection state has a symbol
  and a word.
- **Networks** — `NavigationStack` with native search, a network filter, pull to
  refresh, and endpoint rows.
- **Settings** — console URL, device name, account, onshore region, and the
  shared project mission.

Enrolment matches the Mac agent:

1. An owner or admin signs in and chooses a network.
2. The app mints a one-use join key from `/api/desktop/join-key`.
3. It generates an X25519 WireGuard keypair and `POST`s `/v1/nodes/register`
   with an empty `allowed_ips` list. The coordinator assigns the overlay
   addresses.
4. Node token and private key stay in the shared Keychain group
   `TEAMID.au.org.blaktail.ios.shared`.
5. The packet tunnel starts, polls `/v1/nodes/{id}/peers?ipv6=true`, and
   encrypts overlay traffic with boringtun (MTU 1280).

Disconnect pauses the tunnel and keeps enrolment. Leave network revokes the
node credential. Members still cannot mint join keys; an owner or admin must
enrol the phone, as on the Mac.

Peers are reached directly over UDP when that works, and through the
Australian relay otherwise; see below.

## Relay fallback

The packet tunnel now carries encrypted WireGuard datagrams through the same
Australian relays as the desktop agents. Rust decides, Swift owns the
sockets:

- The relay protocol, the Australian-only ordered relay choice with back-off
  and fail-back, the UDP → WSS ladder and the per-peer direct/relay
  hysteresis live in `blaktail-relay-proto` (shared with `blaktaild` and the
  relay). `blaktail-ios-wg` exposes it over the C ABI (`blaktail_relay_*` in
  `blaktail-ios-wg/include/blaktail_ios_wg.h`). The core keeps a few hundred
  bytes per peer and retains no packet buffers, to stay inside the Network
  Extension memory limit.
- `TunnelSession.swift` passes the coordinator's `relay_endpoints` (endpoint,
  region, approved `wss://` URL), `relay_token` and `relay_expires_at` from
  every peers poll, plus each peer's node id. Offshore relays are dropped in
  Rust. It keeps one `NWUDPSession` per relay endpoint and, when the core
  says UDP is blocked, one `URLSessionWebSocketTask` to the approved WSS URL
  (system trust store and proxy settings; redirects refused; text frames
  close the link).
- Per peer: direct UDP first. If 15 seconds pass with traffic sent and
  nothing decrypted from the direct path, that peer moves to the relay. While
  relayed, outbound ciphertext is duplicated to the direct endpoint for 10
  seconds every 30 seconds; two decrypted direct datagrams move it back.
  Peers with no advertised endpoint always use the relay.
- Relay link: UDP first; three unanswered UDP probe rounds (about 15 s) move
  relay frames to the WebSocket of the same relay, and three answered rounds
  move them back. A relay silent for 50 seconds on every link is failed over
  to the next Australian relay.
- **This iPhone → Path** shows the observed transport while connected:
  *Direct*, *Australian relay*, *Australian relay over HTTPS*, or *No active
  peers yet*, with relayed/direct peer counts. The app reads it from the
  tunnel with a provider message; it carries no tokens or keys.

Not done: the iPhone does not report its own reflexive address to the
coordinator and does not run the desktop hole-punch (`PUNCH`) exchange, so a
relayed iPhone peer returns to direct only when its advertised endpoint
works. Fail-back to a higher-priority relay is probed over UDP only, so an
iPhone stuck on WSS stays on its current relay until that relay fails.

Proof so far: Rust unit tests for the state machine and the C ABI
(`blaktail-relay-proto`, `blaktail-ios-wg`), `swift test`, and a simulator
build of the app and packet tunnel with `xcodebuild`. **No physical iPhone has
run this across independent NATs**; there is no parity claim until that
drill (forced direct-UDP failure, observed transport shown, background wake,
capability rotation, extension restart) is recorded.

## Sign in

1. Set the onshore console URL in Settings (Australian-hosted HTTPS only;
   `http://127.0.0.1` is allowed for a local proof).
2. **Sign in** opens `ASWebAuthenticationSession` against `/desktop/auth`.
3. After sign-in, the console redirects to `blaktail://auth/callback#token=…`.
   The token is stored in Keychain (`au.org.blaktail.ios` /
   `better-auth.session_token`).
4. **Sign out** deletes that Keychain item. It does not revoke this iPhone or
   other endpoints.

About BlakTail shows the shared project mission:

> Built by Indigenous Australians for Indigenous Australian organisations. Data stays onshore, Indigenous Australian organisations stay in control, and the code stays public.

## Australian English

UI copy uses Australian English (organisation, cancelled, unauthorised).

## Accessibility

- VoiceOver labels on every control; icon-only buttons include a spoken name
- Endpoint rows combine name, network, and credential state
- Status uses a symbol plus text
- Tap targets are at least 44×44 points
- Dynamic Type through system text styles
- Reduce Motion is honoured for the signed-in transition
- Focus returns to the trigger after revoke, leave, and sign-out confirmations

## Notarisation and TestFlight

Signing, notarisation, and TestFlight upload are **manual operator steps**, not
CI jobs. CI must not purchase, renew, or upload payment-backed signing
certificates.

## Manual validation

On a current iPhone (17+), with an onshore console and a paid signing team:

1. Launch BlakTail and set the console URL.
2. Sign in, then confirm **All networks** contains endpoints from every
   membership without changing accounts.
3. On **This iPhone**, connect as an owner or admin. Confirm the phone appears
   in the console inventory with a coordinator-assigned address.
4. Confirm another enrolled device can reach the phone's overlay address.
5. Disconnect, confirm enrolment is retained, then connect again without minting
   a new join key.
6. Search by friendly name, technical name, MagicDNS name, address, tag, and
   network.
7. Rename an endpoint, reload, and confirm the friendly name persists while its
   technical and MagicDNS names do not change.
8. As a member, confirm this iPhone cannot self-enrol and endpoint controls are
   read-only. As an owner or admin, approve an advertised route.
9. Start a revoke, confirm a destructive warning appears, then cancel.
10. Leave the network from This iPhone and confirm the node is revoked.
11. Confirm Settings shows Sydney / `ap-southeast-2` and the shared mission.
12. Test VoiceOver on the tab bar, This iPhone status, endpoint rows, and
    confirmations.
13. Sign out. Confirm the session token is gone and other endpoints remain
    enrolled on the coordinator.

## CI

`.github/workflows/ios-phone.yml` runs `swift test` on hosted `macos-latest`
runners (Xcode present; this proves the iPhone package and the shared
coordinator client). The same workflow tests `blaktail-ios-wg` on Ubuntu.
`scripts/validate-ios-phone.sh` checks structure and the locked tagline on any
host. CI must not purchase signing certificates or run a signed device tunnel.
