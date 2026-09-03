#!/usr/bin/env python3
"""BlakTail Linux tray scaffold (issue #12).

Honest scaffold, not a finished app. Drives the installed `blaktaild` CLI
on this host and shows status via the local CLI/socket. Connect reuses the
normal `blaktaild up` browser-approval flow -- the tray never approves a
node by itself.

Usage:
    python3 main.py [--status] [--coord URL] [--coord-ca PATH]

TODO(issue-12): parse `blaktaild status` into structured fields instead of
    passing text through.
TODO(issue-12): read the local agent socket directly instead of shelling
    out to the CLI for status.
TODO(issue-12): implement sign-in helper that surfaces the ten-minute
    console enrolment URL `blaktaild up` prints (Connect without CLI
    acceptance still requires browser approval).
TODO(issue-12): manual validation on Ubuntu 26.04 GNOME with AppIndicator;
    record result in README.md. No Snap-only path.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys

BLAKTAILD = "blaktaild"


def run_blaktaild(*args: str) -> str:
    """Run blaktaild and return stdout as text (best-effort passthrough)."""
    exe = shutil.which(BLAKTAILD)
    if exe is None:
        return f"error: {BLAKTAILD} not found on PATH; install it from source first."
    try:
        proc = subprocess.run(
            [exe, *args], capture_output=True, text=True, timeout=30
        )
    except subprocess.TimeoutExpired:
        return "error: blaktaild timed out after 30s."
    out = (proc.stdout or "") + (proc.stderr or "")
    return out.strip() or "(no output)"


def do_status() -> str:
    # TODO(issue-12): structured parse of `blaktaild status` fields
    # (address, peers, relay/path, credential expiry).
    return run_blaktaild("status")


def do_connect(coord: str | None, coord_ca: str | None) -> str:
    # TODO(issue-12): surface the printed enrolment URL in a dialog that the
    # operator can open in a browser. For now, print CLI output verbatim so
    # the URL is visible and nothing is auto-approved.
    args = ["up"]
    if coord:
        args += ["--coord", coord]
    if coord_ca:
        args += ["--coord-ca", coord_ca]
    return run_blaktaild(*args)


def do_disconnect() -> str:
    # `pause` is reversible and keeps enrolment; `down` revokes it.
    # TODO(issue-12): offer pause vs down choice in the tray menu.
    return run_blaktaild("pause")


def try_gtk_tray(handlers: dict) -> bool:
    """Start a GTK AppIndicator tray. Returns True if it ran."""
    try:
        import gi  # type: ignore

        gi.require_version("Gtk", "3.0")
        try:
            gi.require_version("AppIndicator3", "0.1")
            from gi.repository import AppIndicator3, Gtk  # type: ignore
        except (ImportError, ValueError):
            return False

        indicator = AppIndicator3.Indicator.new(
            "blaktail",
            "network-vpn",
            AppIndicator3.IndicatorCategory.APPLICATION_STATUS,
        )
        indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        # TODO(issue-12): ship a real icon asset; stock name is a placeholder.
        indicator.set_title("BlakTail")

        menu = Gtk.Menu()

        def add_item(label: str, fn) -> None:
            item = Gtk.MenuItem(label=label)
            item.connect("activate", lambda _w: print(fn()))
            menu.append(item)

        add_item("Connect", handlers["connect"])
        add_item("Disconnect", handlers["disconnect"])
        add_item("Status", handlers["status"])
        # TODO(issue-12): sign-in item that opens the enrolment URL in a
        # browser via xdg-open instead of printing it.
        add_item("Sign in (browser approval)", handlers["connect"])
        quit_item = Gtk.MenuItem(label="Quit")
        quit_item.connect("activate", Gtk.main_quit)
        menu.append(quit_item)
        menu.show_all()
        indicator.set_menu(menu)
        Gtk.main()
        return True
    except ImportError:
        return False


def try_pystray(handlers: dict) -> bool:
    """Start a pystray fallback icon. Returns True if it ran."""
    try:
        import pystray  # type: ignore
        from pystray import Menu, MenuItem  # type: ignore
    except ImportError:
        return False

    # TODO(issue-12): real icon image; no asset exists yet.
    icon = pystray.Icon(
        "blaktail",
        None,
        "BlakTail",
        Menu(
            MenuItem("Connect", lambda: print(handlers["connect"]())),
            MenuItem("Disconnect", lambda: print(handlers["disconnect"]())),
            MenuItem("Status", lambda: print(handlers["status"]())),
        ),
    )
    icon.run()
    return False  # only reached after the icon loop exits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--status", action="store_true",
                        help="print blaktaild status and exit (no tray)")
    parser.add_argument("--coord", default=None, help="coordinator URL")
    parser.add_argument("--coord-ca", default=None, help="coordinator CA path")
    args = parser.parse_args(argv)

    handlers = {
        "connect": lambda: do_connect(args.coord, args.coord_ca),
        "disconnect": do_disconnect,
        "status": do_status,
    }

    if args.status:
        print(handlers["status"]())
        return 0

    if try_gtk_tray(handlers):
        return 0
    print("note: GTK AppIndicator3 unavailable; trying pystray fallback.",
          file=sys.stderr)
    if try_pystray(handlers):
        return 0
    print("note: no tray backend available; printing one-shot status.",
          file=sys.stderr)
    print(handlers["status"]())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
