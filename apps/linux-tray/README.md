# Linux tray (experimental)

A small GTK AppIndicator tray that controls the **installed, systemd-managed
`blaktaild`** on the same host. It is not a second daemon and holds no keys.
Not packaged, not released, and not yet validated on a clean desktop.

## What it does

| Menu item | What runs | Privilege |
| --- | --- | --- |
| Status label (every 10 s) | `systemctl is-active blaktaild` | none |
| Details | `blaktaild status --json` | pkexec (state under `/var/lib/blaktail` is root-only) |
| Connect, already enrolled | `systemctl start blaktaild` | pkexec |
| Connect, not enrolled | `blaktaild up --exit-after-join`, opens the printed approval URL with `xdg-open`, then `systemctl enable --now blaktaild` | pkexec |
| Disconnect | `systemctl stop blaktaild`, then `blaktaild pause` (interface and DNS removed, enrolment kept) | pkexec |

The tray never approves a node: approval still happens in the console in a
browser. "Leave network" (`blaktaild down`, which revokes the node) is
deliberately not in the menu.

`blaktaild status --json` is the local control interface. It prints one JSON
object with the node name, overlay address, coordinator, credential state,
peer list, DNS health, eligible Australian relays, the relay in use and the
failover count. It never prints the node token, relay capability, private
key or a join key. No unprivileged status socket was added: enrolment state
is root-only by design, and a group-readable socket would need group
provisioning in the packages first. Polkit rules can allow an administrator
group to run these actions without a password prompt.

## Try it

```sh
# blaktaild installed from source or a package (see docs/linux-agent.md)
sudo apt install gir1.2-ayatanaappindicator3-0.1 python3-gi   # or gir1.2-appindicator3-0.1
python3 apps/linux-tray/main.py --status        # one-shot summary
python3 apps/linux-tray/main.py --coord https://coord.example.org.au
python3 -m unittest apps/linux-tray/test_main.py
```

Without AppIndicator3 the tray prints a one-shot status and exits.

## Not yet proven

- Manual validation on a clean Ubuntu 26.04 GNOME desktop (connect,
  disconnect, reboot, enrol) has not been recorded.
- No icon assets, autostart entry or package. No Snap-only path will be
  accepted.
- GUI actions run in the GTK main thread; a pkexec prompt blocks the menu
  until answered.
