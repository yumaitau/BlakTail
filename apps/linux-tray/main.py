#!/usr/bin/env python3
"""BlakTail Linux tray: local controls for the installed blaktaild agent.

The tray never runs a second daemon and never approves a node. It drives the
systemd-managed `blaktaild` on this host:

- Status: `systemctl is-active blaktaild` (no privilege) for the menu label;
  "Details" runs `blaktaild status --json` through pkexec because enrolment
  state under /var/lib/blaktail is root-only.
- Connect: if enrolled, start the service. If not, run `blaktaild up` and open
  the printed browser-approval URL with xdg-open; approval still happens in
  the console.
- Disconnect: stop the service, then `blaktaild pause` so the interface and
  DNS are removed while enrolment is kept. "Leave network" is not offered
  here; use `blaktaild down` deliberately from a terminal.

Usage:
    python3 main.py [--status] [--coord URL]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import threading

BLAKTAILD = "blaktaild"
SERVICE = "blaktaild"
URL_PATTERN = re.compile(r"https://\S+")


def privileged(args: list[str]) -> list[str]:
    """Prefix a command with pkexec unless already root."""
    if os.geteuid() == 0:
        return args
    if shutil.which("pkexec") is None:
        raise RuntimeError("pkexec is required for this action; run it from a terminal with sudo.")
    return ["pkexec", *args]


def run(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


def service_state() -> str:
    """systemd ActiveState for blaktaild: active, inactive, failed, unknown."""
    if shutil.which("systemctl") is None:
        return "unknown"
    try:
        result = run(["systemctl", "is-active", SERVICE], timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    return (result.stdout or "").strip() or "unknown"


def parse_status(text: str) -> dict:
    """Parse `blaktaild status --json`. Unknown or malformed output is
    reported as not joined rather than guessed."""
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return {"joined": False, "error": "unreadable agent status"}
    if not isinstance(value, dict):
        return {"joined": False, "error": "unreadable agent status"}
    return value


def summarise(status: dict, service: str) -> str:
    """One accessible, colour-independent line per fact."""
    if not status.get("joined"):
        reason = status.get("error")
        return "Not enrolled on this computer." + (f" ({reason})" if reason else "")
    lines = [
        f"Service: {service}",
        f"Name: {status.get('dns_name') or 'unknown'}",
        f"Address: {status.get('address') or 'unknown'}",
        f"Coordinator: {status.get('coordinator') or 'unknown'}",
        f"Credential: {status.get('credential') or 'unknown'}",
        f"Peers: {len(status.get('peers') or [])}",
        f"DNS: {status.get('dns_health') or 'unknown'}",
    ]
    relay = status.get("active_relay")
    lines.append(f"Relay: {relay}" if relay else "Relay: not in use")
    failovers = status.get("relay_failovers") or 0
    if failovers:
        lines.append(f"Relay failovers since start: {failovers}")
    return "\n".join(lines)


def find_enrolment_url(line: str) -> str | None:
    match = URL_PATTERN.search(line)
    return match.group(0) if match else None


def read_status() -> dict:
    exe = shutil.which(BLAKTAILD)
    if exe is None:
        return {"joined": False, "error": f"{BLAKTAILD} not found on PATH"}
    try:
        result = run(privileged([exe, "status", "--json"]))
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        return {"joined": False, "error": str(error)}
    if result.returncode != 0:
        return {"joined": False, "error": "status was cancelled or failed"}
    return parse_status(result.stdout)


def do_status() -> str:
    return summarise(read_status(), service_state())


def do_connect(coord: str | None, notify) -> str:
    status = read_status()
    if status.get("joined"):
        result = run(privileged(["systemctl", "start", SERVICE]))
        return "Connecting." if result.returncode == 0 else "Could not start blaktaild."
    exe = shutil.which(BLAKTAILD)
    if exe is None:
        return f"{BLAKTAILD} not found on PATH; install the agent first."
    args = [exe, "up", "--exit-after-join"]
    if coord:
        args += ["--coord", coord]
    process = subprocess.Popen(
        privileged(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    def follow() -> None:
        assert process.stdout is not None
        opened = False
        for line in process.stdout:
            url = find_enrolment_url(line)
            if url and not opened and shutil.which("xdg-open"):
                subprocess.Popen(["xdg-open", url])
                opened = True
                notify(f"Approve this computer in the browser:\n{url}")
        code = process.wait()
        if code == 0:
            run(privileged(["systemctl", "enable", "--now", SERVICE]))
            notify("Enrolled. BlakTail is connecting.")
        else:
            notify("Enrolment did not finish. Run 'sudo blaktaild up' in a terminal for details.")

    threading.Thread(target=follow, daemon=True).start()
    return "Opening browser approval…"


def do_disconnect() -> str:
    exe = shutil.which(BLAKTAILD)
    if exe is None:
        return f"{BLAKTAILD} not found on PATH."
    stopped = run(privileged(["systemctl", "stop", SERVICE]))
    if stopped.returncode != 0:
        return "Could not stop blaktaild."
    paused = run(privileged([exe, "pause"]))
    return "Disconnected; enrolment kept." if paused.returncode == 0 else "Stopped, but pause failed."


def try_gtk_tray(coord: str | None) -> bool:
    try:
        import gi  # type: ignore

        gi.require_version("Gtk", "3.0")
        gi.require_version("AppIndicator3", "0.1")
        from gi.repository import AppIndicator3, GLib, Gtk  # type: ignore
    except (ImportError, ValueError):
        return False

    indicator = AppIndicator3.Indicator.new(
        "blaktail", "network-vpn", AppIndicator3.IndicatorCategory.APPLICATION_STATUS
    )
    indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
    indicator.set_title("BlakTail")
    menu = Gtk.Menu()
    state_item = Gtk.MenuItem(label="BlakTail: checking…")
    state_item.set_sensitive(False)
    menu.append(state_item)

    def show(message: str) -> bool:
        dialog = Gtk.MessageDialog(
            message_type=Gtk.MessageType.INFO, buttons=Gtk.ButtonsType.CLOSE, text="BlakTail"
        )
        dialog.format_secondary_text(message)
        dialog.run()
        dialog.destroy()
        return False

    def notify(message: str) -> None:
        GLib.idle_add(show, message)

    def refresh() -> bool:
        state_item.set_label(f"BlakTail: {service_state()}")
        return True

    def add(label: str, action) -> None:
        item = Gtk.MenuItem(label=label)
        item.connect("activate", lambda _w: (show(action()), refresh()))
        menu.append(item)

    add("Connect", lambda: do_connect(coord, notify))
    add("Disconnect", do_disconnect)
    add("Details", do_status)
    quit_item = Gtk.MenuItem(label="Quit")
    quit_item.connect("activate", Gtk.main_quit)
    menu.append(quit_item)
    menu.show_all()
    indicator.set_menu(menu)
    refresh()
    GLib.timeout_add_seconds(10, refresh)
    Gtk.main()
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BlakTail Linux tray")
    parser.add_argument("--status", action="store_true", help="print status and exit")
    parser.add_argument("--coord", default=None, help="coordinator URL for first enrolment")
    args = parser.parse_args(argv)
    if args.status:
        print(do_status())
        return 0
    if try_gtk_tray(args.coord):
        return 0
    print("GTK AppIndicator3 is unavailable; printing status instead.", file=sys.stderr)
    print(do_status())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
