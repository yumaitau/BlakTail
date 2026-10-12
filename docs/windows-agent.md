# Windows node agent (issue #11)

**Status: experimental.** `blaktaild` builds and runs on Windows (x86_64,
MSVC) and has passed a single-machine lab run as a real Windows service (see
[Validation](#validation-record) below). No two-machine drill, signed package
or clean-host install has been recorded, so Windows is not supported in the
release sense; see [platform-support.md](platform-support.md).

The windowed Windows client is not built. What is built is `blaktaild` (the
same agent as Linux and macOS), `blaktail-windows` (the sign-in callback
helper, as for the Mac and iPhone apps), and two PowerShell scripts in
`packaging/windows/`.

## How it works

- **Tunnel.** `WindowsNetwork` (`blaktaild/src/windows.rs`) creates a WinTun
  adapter named after the interface (default `blaktail0`) with a stable GUID
  derived from that name, and runs WireGuard in userspace through the shared
  boringtun engine (`blaktail-ios-wg`, the same core as iPhone and Android).
  One thread sleeps on WinTun's read-wait event; the other blocks on the UDP
  socket with a 250 ms timeout that also drives WireGuard timers. An idle
  tunnel uses no measurable CPU.
- **Addresses and routes.** Set with the IP Helper API on the adapter LUID:
  the node's IPv4 and IPv6 addresses with their prefix lengths (no duplicate
  address detection, so they are usable at once), MTU 1280 for both families,
  and one on-link route per peer allowed IP, kept in step with every peer
  change. Stale addresses (a renumber) and routes left by an earlier run are
  removed. Exit-node default routes are not installed: subnet and exit
  routing stay Linux-only.
- **MagicDNS.** The agent's resolver listens on the node's overlay address, as
  on Linux and macOS. An NRPT rule (`BlakTail-<interface>`, under
  `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`,
  the location `Add-DnsClientNrptRule` uses) sends the MagicDNS domain and any
  published DNS suffixes to that resolver only; every other name resolves as
  before. Use full names (`host.<org>.blaktail`); Windows applies a search
  suffix only on interfaces that have DNS servers, so short names are not set
  up. If Group Policy defines NRPT rules, Windows ignores local ones; the agent
  logs a warning when it sees that.
- **Stopping.** In a console, Ctrl+C, Ctrl+Break, closing the window, logoff
  and shutdown all stop the agent cleanly (a second Ctrl+C ends it at once).
  As a service, Stop and Preshutdown do the same. Clean stop removes the NRPT
  rule, routes, addresses and the adapter. If the process is killed, WinTun
  removes the adapter (and with it the routes and addresses) when the process
  exits; only the NRPT rule would remain, and the next start replaces it.
- **State.** `C:\ProgramData\BlakTail` by default. The agent creates it, and
  every secret file in it, with an ACL of SYSTEM and Administrators only,
  inheritance from `C:\ProgramData` removed (by default `BUILTIN\Users` can
  read there), and Administrators as owner: the Windows form of the 0700/0600
  state on Linux and macOS. It reapplies this on every start.
- **Service.** `blaktaild run --service` connects to the Service Control
  Manager, reports StartPending until the tunnel is up and then Running, and
  reports Stopped with exit code 0, or service-specific code 1 when the agent
  failed (the reason also goes to the Application event log, source
  `BlakTail`). The service logs to `blaktaild.log` in the state directory
  (rotated at 16 MiB to `blaktaild.log.1`). `blaktaild run` without
  `--service` is the same agent in a console, logging to the console.
- **UDP on Windows.** Windows reports an ICMP port-unreachable for an earlier
  send as `WSAECONNRESET` from the next receive on the same UDP socket. The
  relay client, MagicDNS resolver, relay server and WireGuard socket treat that
  as a no-op instead of ending their receive loops (before this fix one
  unreachable peer port could silently stop relay traffic).

## Install (from source)

From an elevated PowerShell prompt, with the pinned Rust toolchain and the
MSVC build tools:

```powershell
cargo build --release -p blaktaild
# Download WinTun 0.14.1, check the pinned SHA-256 and WireGuard LLC
# signature, and put the right wintun.dll beside blaktaild.exe.
.\packaging\windows\fetch-wintun.ps1 -Destination .\target\release

# Enrol (browser approval, or a join key on stdin / BLAKTAIL_JOIN_KEY).
.\target\release\blaktaild.exe up --coord https://coord.example:8443 --coord-ca C:\BlakTail\ca.crt --exit-after-join

# Install and start the service (checks wintun.dll, restricts the state
# directory, adds an inbound UDP firewall rule for blaktaild.exe, and sets
# restart-on-failure).
.\packaging\windows\install-blaktail-service.ps1 -Binary .\target\release\blaktaild.exe -CoordCa C:\BlakTail\ca.crt

Get-Service BlakTail
Get-Content C:\ProgramData\BlakTail\blaktaild.log -Tail 20

# Remove the service and firewall rule (enrolment stays; `blaktaild down`
# revokes the node).
.\packaging\windows\install-blaktail-service.ps1 -Uninstall
```

`blaktaild.exe` loads `wintun.dll` only from its own directory, never from
`PATH` or the working directory. Without it the agent stops with the path it
looked in and how to fetch the DLL.

The service never takes a join key on the command line; enrolment happens
once with `up`, and the service runs the persisted `run`.

## Validation record

2026-10-12, one Windows 11 x64 VM (10.0.26300), debug build, coordinator
(SQLite) and relay built natively on Windows and run on loopback with a
private CA. Node A was the installed service (LocalSystem). Node B was a
second elevated `blaktaild run` (own state directory and interface
`blaktail1`) enrolled to the same coordinator. Shown:

- **Service.** Install script → Running in about 3 s, still Running after
  65 s; Stop-Service in about 250 ms to Stopped, exit code 0; Start-Service
  and Restart-Service bring it back; `-Uninstall` removes service and firewall
  rule. Restart-on-failure configured (`sc qfailure`). A service that cannot
  open its log stops within about 2 s with service-specific code 1 and an
  event log entry, instead of the SCM's 30-second start timeout.
- **Adapter.** `blaktail0` up with `100.64.0.1/32` and `fd04:…::1/128`
  (`PrefixOrigin Manual`, `Preferred`), NlMtu 1280 for both families.
- **ACLs.** Straight after `blaktaild up`, before any install script:
  `icacls` shows only `NT AUTHORITY\SYSTEM:(F)` and
  `BUILTIN\Administrators:(F)` on the state directory (`(OI)(CI)`),
  `private.key` and `state.json`; owner Administrators.
- **Routes.** `Get-NetRoute` shows `100.64.0.2/32` and `fd04:…::2/128`
  (NetMgmt, metric 0) on A's interface and A's addresses on B's interface.
- **WireGuard.** Both nodes log `WireGuard handshake completed` with the peer
  (via the relay; this setup has no direct endpoints). Per-direction transport
  counters: 20 pings from A's address moved A's tx and B's rx by exactly 1200
  bytes (20 × 60-byte ICMP packets); 20 pings from B moved B's tx and A's rx by
  1200 bytes. So every packet was encrypted, relayed and decrypted at the
  other node.
- **MagicDNS.** With the service running, NRPT shows
  `.<org>.blaktail → 100.64.0.1`. `Resolve-DnsName node-b.<org>.blaktail`
  returns `100.64.0.2` (A) and `fd04:…::2` (AAAA); other names still resolve.
- **Teardown.** After Stop-Service, Ctrl+C or Ctrl+Break: no `blaktaild`
  process, no BlakTail adapter, no overlay addresses or routes, no
  BlakTail NRPT rule; other NRPT rules untouched.
- **Idle CPU.** 15.6 ms of CPU in 30 s for the running service (0.05 % of one
  core), 17 threads, 32 MB working set.
- **Tests.** `cargo test -p blaktaild -p blaktail-config` pass on Windows;
  `cargo build -p blaktaild` is warning-free on Windows.

Not shown:

- **Ping replies on one host.** Both overlay addresses belong to the same
  machine, so although ping packets crossed the tunnel (counters above), the
  replies did not reach `ping`, and MagicDNS queries timed out while node B's
  route captured traffic for A's resolver address. Neither happens with one
  node per machine, but two-machine IPv4/IPv6 ping and MagicDNS remain to be
  shown.
- Direct (non-relay) UDP paths, NAT traversal and the firewall rule with
  inbound traffic from another machine.
- Reboot persistence, ARM64, release builds, signed packages, Group Policy
  NRPT environments.
- Linux and macOS builds after these changes were not compiled on this
  machine (no Linux cross C compiler for `ring`). Shared code changed only in
  `main` (explicit runtime instead of `#[tokio::main]`, stop signal helper),
  the state-directory helper and the UDP receive loops; Unix behaviour is
  meant to be identical and needs the usual CI run to confirm.

## Constraints

- **Rust only.** No C#/Go sidecar, no third-party closed agent.
- **No Store listing.** Distribution is direct download / `winget`, never
  the Microsoft Store.
- Same onshore/metadata rules as every other agent: the coordinator and
  relay can still see metadata (see `docs/project-status.md`).
- Remote jobs, subnet routing, exit nodes and app connectors stay Linux-only
  (macOS for remote jobs); the agent refuses them on Windows.

## CI note (why no Windows job yet)

The Windows code now compiles and its unit tests pass on
`x86_64-pc-windows-msvc`. The next step is a hosted-runner `cargo build`,
`cargo test` and `cargo clippy` job for that target in
`.github/workflows/agent-release.yml`, before any packaging job. It is not
added here.
