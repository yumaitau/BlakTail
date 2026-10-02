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
