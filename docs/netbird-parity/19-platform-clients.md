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

### Live lab (3 October 2026)

**Proven live:** `deploy/homelab/prove-clean-install.sh` (Docker context `m3-max`, 245 s) builds the release packages with `deploy/docker/agent-package.Dockerfile`, serves them from a lab HTTPS release server, and runs the unmodified `scripts/install-agent.sh` on fresh `debian:bookworm` and `ubuntu:24.04` systemd containers. A tampered package, `BLAKTAIL_REQUIRE_SIGNATURE=1` without cosign, and (cosign v2.4.1 installed) a bundle that does not verify were all refused before anything was installed; the genuine package installed through the checksum path (6 s Debian, 13 s Ubuntu). Debian enrolled with the join key on stdin, Ubuntu with `BLAKTAIL_JOIN_KEY`; about 1,200 snapshots of every `/proc/*/cmdline` per host, taken every 50 ms during enrolment, never contained the key. Under `blaktaild.service` the hosts pinged each other over the overlay, again after `systemctl restart` with unchanged addresses; owner revocation of Ubuntu removed it from Debian's peers within 1 s and cut traffic both ways; uninstall left no binary, unit, state, interface, iptables chain or policy rule, and both nodes show as revoked.
**Bugs found and fixed:** `install-agent.sh` used bare `dpkg -i`, which leaves the package unconfigured on a host without its dependencies (now `apt-get install`, or `dnf install` for RPMs); `blaktaild down` on a node already revoked from the console failed with 401 and left `blaktail0` and `BLAKTAIL-ACL` behind (now cleans up locally and says so; `blaktaild` test `revoke_reports_a_credential_the_coordinator_no_longer_accepts`); a failed `/etc/resolv.conf` rewrite left the agent's backup (and a temporary file in `/etc`) behind, so every later attempt and `down` misreported that the file had "changed after BlakTail configured it" (test `failed_resolv_conf_write_leaves_no_backup_or_temporary_file`, Linux only).
**Still unproven:** a Sigstore bundle that verifies (needs a tagged GitHub release), RPM hosts, macOS packages, x86_64, a real VM reboot. The lab pins the WireGuard listen port with `wg set` (the agent picks a random port and the lab has no relay). Under the hardened unit, MagicDNS cannot rewrite `/etc/resolv.conf` on hosts without `systemd-resolved` or `resolvconf` (documented in `docs/linux-agent.md`).
