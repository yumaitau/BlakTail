# Ship and verify Windows, Android and Linux desktop clients without false platform claims

**Priority:** P1 for Windows/Android, P2 for Linux shell and appliance ports. **Depends on:** draft 23 release pipeline, draft 21 transport proof. **Area:** native clients and agents.

## Gap and outcome

NetBird provides Windows, macOS, Linux, iOS, Android and platform-specific install paths (routers/NAS/TV). BlakTail README claims Linux/macOS agents and a direct-UDP iPhone; Windows is unshipped, Linux tray is scaffold-level, and `apps/android` source exists without release proof. Closed #11/#12 are not platform acceptance. Separate implementation from published, signed and device-verified support.

## Scope

- Windows: userspace WireGuard/WinTun service, protected key storage, install/upgrade/uninstall, native connection/status UI, accessibility and CLI parity, relay and DNS. Follow repo's Rust-agent constraint and avoid Microsoft Store requirement.
- Android: review existing app/tunnel code, VPN service lifecycle, foreground/background restrictions, enrollment, DNS, IPv6, relay and key storage; add signed distribution only after physical-device verification. Linux tray: replace scaffold with supported local-agent controls, not an embedded duplicate daemon.
- Document appliance/container compatibility separately (OPNsense/pfSense, OpenWrt, Synology, Proxmox, Docker, etc.). Don't assert vendor support until reproducible install/update/network tests exist; no Snap-only Linux path.

## Acceptance / proof

Per claimed OS, clean-host two-node test covers enrollment, bidirectional traffic, MagicDNS, route/policy, NAT relay, reboot, revoke, reinstall and uninstall. CI builds on native target, packages are signed/verifiable, and release matrix marks experimental vs supported. Onshore control endpoint remains operator-selected.

**Evidence:** `README.md`, `docs/project-status.md`, `docs/windows-agent.md`, `apps/android`, `apps/linux-tray/README.md`; https://docs.netbird.io/get-started/install, https://docs.netbird.io/client/desktop-app.

## Status (2 October 2026)

**Done:**
- `docs/platform-support.md`: platform matrix separating code from proof;
  Windows and Android marked experimental with no device proof, iPhone without
  relay, appliances/containers explicitly unsupported, no Snap-only path.
- Linux tray (`apps/linux-tray/main.py`) replaced: drives the systemd-managed
  agent (service state, Details via `blaktaild status --json`, Connect with
  browser approval via `xdg-open`, Disconnect = stop + `pause`), privileged
  actions through pkexec, no embedded daemon, "leave network" not offered.
- New local control interface `blaktaild status --json` (no node token,
  relay capability or keys). No unprivileged socket added: state is root-only
  and group provisioning would be needed first (documented).

**Proven by tests:** `apps/linux-tray/test_main.py` (status parsing, summary,
enrolment URL detection), `blaktaild` `status_json_reports_relay_selection_without_credentials`.

**Still needs live/field proof or a decision:**
- No Windows binary built; no Android or Windows physical-device drill; no
  clean Ubuntu GNOME validation of the tray; no packaging or signing for any
  of these. Swift/Android/Windows code was not touched or built in this change.
