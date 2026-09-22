# Windows node agent plan (issue #11)

The windowed Windows client is not built. The tool that is built is
`blaktail-windows` (same sign-in callback as the Mac and iPhone apps) plus
`packaging/windows/install-blaktail-service.ps1` for `blaktaild run`.
The userspace tunnel backend is still the open cut below.

## Direction

- **Rust userspace WireGuard plan.** Reuse the existing `blaktaild` core
  (enrolment, coordinator HTTPS, peer reconciliation, relay client) and add
  a Windows userspace WireGuard backend (same approach as macOS: userspace
  implementation today, no kernel driver in the first cut).
- **Same flows as macOS/Linux.** `blaktaild up` prints a ten-minute console
  enrolment URL, the operator approves in the browser, `blaktaild status`
  confirms the tunnel. Behaviour, flags, and credential storage rules
  (mode-restricted local state, no keys in argv) match the other agents.
- **Manual two-device validation.** Before any release claim: two Windows
  machines enrolled against the same coordinator, bidirectional IPv4/IPv6
  ping plus MagicDNS, same as the Linux two-VM drill in
  `docs/two-node-drill.md`.

## Service install notes

- Install via the published agent artifact (expected: signed `.msi` or
  `winget` package once `docs/releases.md` covers Windows; until then,
  build from source with the pinned Rust toolchain).
- Register as a Windows service with `sc.exe` (create/start/query), running
  the persisted-state equivalent of `blaktaild run` after enrolment.
- The service must not take a join key on the command line; prefer the same
  stdin/environment handoff the Linux agent documents, or an
  administrator-only config file with tight ACLs (exact path TBD at
  implementation time).

## Constraints

- **Rust only.** No C#/Go sidecar, no third-party closed agent.
- **No Store listing.** Distribution is direct download / `winget`, never
  the Microsoft Store.
- Same onshore/metadata rules as every other agent: the coordinator and
  relay can still see metadata (see `docs/project-status.md`).

## CI note (why no Windows job yet)

A `cargo check --target x86_64-pc-windows-msvc` job in
`.github/workflows/agent-release.yml` would need that target toolchain
installed on the runner, and the agent has Windows-only code paths that do
not exist yet — the check would fail on day one and block releases. So the
Windows job is **documented here instead of added**: when the userspace
backend lands behind `cfg(windows)` gating, add a hosted-runner
`cargo check` (and later `cargo test`/`cargo clippy`) job for
`x86_64-pc-windows-msvc` first, before any packaging job.
