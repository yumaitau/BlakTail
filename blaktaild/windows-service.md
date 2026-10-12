# Windows service note (issue #11)

`blaktaild` runs as a Windows service with `run --service`. Install it with
`packaging/windows/install-blaktail-service.ps1`; see
`docs/windows-agent.md` for how it works and how it was validated.

```powershell
# Once, elevated: enrol (browser approval or a join key on stdin).
.\blaktaild.exe up --coord https://coord.example:8443 --coord-ca C:\BlakTail\ca.crt --exit-after-join

# Install, start, check, remove.
.\install-blaktail-service.ps1 -Binary .\blaktaild.exe -CoordCa C:\BlakTail\ca.crt
Get-Service BlakTail
Get-Content C:\ProgramData\BlakTail\blaktaild.log -Tail 20
.\install-blaktail-service.ps1 -Uninstall
```

The registered command line is

```text
"C:\...\blaktaild.exe" run --service=BlakTail [--coord-ca "..."] [--state-dir "..."]
```

- The service runs the persisted-state `run`, never `up` with a join key in
  argv. Join keys for automation arrive via stdin or `BLAKTAIL_JOIN_KEY`.
- `--service[=NAME]` connects to the Service Control Manager. Without it,
  `blaktaild run` is the same agent in a console (Ctrl+C or Ctrl+Break stop
  it cleanly), which is the way to debug.
- Start: StartPending until the WinTun adapter, addresses and routes are up,
  then Running. Stop and Preshutdown remove the MagicDNS NRPT rule, routes,
  addresses and adapter, then report Stopped (exit 0; service-specific 1 when
  the agent failed, with the reason in the Application event log).
- Logs: `blaktaild.log` in the state directory, SYSTEM and Administrators
  only, rotated at 16 MiB.
- `wintun.dll` (WinTun 0.14.1) must sit beside `blaktaild.exe`;
  `packaging/windows/fetch-wintun.ps1` downloads and verifies it.
