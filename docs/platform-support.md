# Platform support

BlakTail is pre-release: **no platform is "supported" in the released-product
sense yet**, because no signed release has been installed and drilled on clean
hosts (see [releases.md](releases.md)). This table separates what exists in
code from what has been proven. "Experimental" means the code exists and
builds where noted, but nobody has recorded the per-platform acceptance drill.

## Matrix

| Platform | Component | Status | Built in CI | Device proof recorded | Relay fallback | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Linux (x86_64, aarch64) | `blaktaild` (kernel WireGuard) | Most mature; pre-release | Yes (tests, clippy) | Two-node drills in Docker/VMs and a Sydney AWS smoke; no clean-host signed-package drill | Yes, multi-relay failover in code | Subnet router and exit node are Linux-only |
| macOS (Apple silicon, Intel) | `blaktaild` (boringtun + `utun`) | Pre-release | Release workflow builds on macOS; tests run on Linux CI | Developer machines only | Yes | LaunchDaemon; packages must be Developer ID signed and notarised |
| macOS | Desktop manager app | Pre-release | `swift test` | Developer machines only | n/a (uses agent) | See [macos-desktop.md](macos-desktop.md) |
| iPhone (iOS 17+) | SwiftUI app + packet tunnel | Experimental | `swift test`; device tunnel not built in CI | Not recorded | In code: UDP relay and WSS fallback via the shared Rust core; simulator build only, no device proof | See [ios.md](ios.md#relay-fallback) |
| Windows | `blaktaild` with WinTun + boringtun | **Experimental** | No Windows build job | **None** — no Windows binary has been produced from this tree | Yes in code (shared agent logic), unproven | Needs `wintun.dll`; see [windows-agent.md](windows-agent.md) |
| Android | Kotlin app, `VpnService`, Rust boringtun via JNI | **Experimental** | No | **None** — no physical-device run recorded | In code: UDP relay only (no WSS), not compiled in this tree's CI | No signed distribution until a device drill passes |
| Linux desktop | `apps/linux-tray` (GTK AppIndicator) | Experimental | No (local Python unit tests) | Not recorded | n/a (controls the agent) | See [apps/linux-tray/README.md](../apps/linux-tray/README.md) |

Nothing on this page is a claim of App Store, Play Store or Microsoft Store
availability; Store distribution is not planned for Windows.

## What "supported" will require, per platform

A platform moves out of experimental only when a recorded drill on a clean
host covers: signed package install, enrolment with browser approval, two-way
IPv4 and IPv6 traffic, MagicDNS, a route or policy change taking effect,
forced relay with direct UDP blocked, reboot persistence, revoke, reinstall
and uninstall. The control endpoint stays the operator's onshore coordinator.

## Appliances and containers

Not supported as named products. BlakTail has a Linux agent container used by
the homelab and AWS proof harnesses, but no tested install or update path for
OPNsense/pfSense, OpenWrt, Synology, Proxmox, TrueNAS or similar. Running the
Linux agent on such a host may work where kernel WireGuard and systemd (or an
equivalent supervisor) exist; treat that as unsupported until a reproducible
install, upgrade and network test is published for that vendor. No Snap-only
Linux path will be offered.
