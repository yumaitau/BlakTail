# Linux tray scaffold (issue #12)

Honest scaffold — **not a finished desktop app**. This directory holds the
starting point for a Linux system-tray manager that drives the existing
`blaktaild` CLI on the same host. Nothing here is packaged, released, or
covered by CI yet.

## Scope

- Tray actions: **Connect** / **Disconnect** / **Status** / **Sign-in via
  local agent socket**. All actions shell out to the installed `blaktaild`
  binary (`up`, `down`, `pause`, `status`) or query the local agent
  socket/status endpoint on this machine — no new network protocol.
- Connect must work **without CLI acceptance**: opening the tray "Connect"
  item prints/queues the same ten-minute console enrolment URL that
  `blaktaild up` prints, so approval still happens in the browser. The tray
  never approves a node by itself.
- Manual validation target: **Ubuntu 26.04**, GNOME, built from source.
- Explicitly out of scope: Snap-only distribution, auto-start/packaging,
  Wayland portal work, and any enrolment shortcut that skips browser approval.

## Layout

- `main.py` — minimal tray entry point. Prefers GTK `AppIndicator3` when
  available, falls back to `pystray`, and otherwise runs a `--status`
  one-shot CLI mode so the file still does something useful on a headless
  host. `TODO` markers show exactly what is stubbed.

## Try it (Ubuntu 26.04, manual)

```sh
# blaktaild must already be installed from source (see docs/linux-agent.md).
python3 apps/linux-tray/main.py --status
python3 apps/linux-tray/main.py   # tray icon when GTK/AppIndicator is present
```

`TODO(issue-12)`: verify on a clean Ubuntu 26.04 GNOME install with
`gir1.2-appindicator3-0.1` / `python3-gi` present and record the result here.
No Snap-only path will be accepted for this validation.

## What is still missing

- Real status parsing against `blaktaild status` output (currently
  best-effort text passthrough).
- Local agent socket reader (currently shells out to the CLI).
- `.deb`-adjacent autostart entry, icon assets, and any packaging.
- Tests and CI wiring.
