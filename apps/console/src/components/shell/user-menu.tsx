"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useTransition } from "react";
import { LogOut, ShieldCheck, UserRound, FileLock2 } from "lucide-react";
import { authClient } from "@/lib/auth-client";
import { usePopover } from "./use-popover";

function initials(name: string, email: string) {
  const parts = (name || email).split(/[\s@._-]+/u).filter(Boolean);
  return ((parts[0]?.[0] ?? "?") + (parts[1]?.[0] ?? "")).toUpperCase();
}

export function UserMenu({ name, email, role }: { name: string; email: string; role: string }) {
  const router = useRouter();
  const { open, setOpen, root, trigger } = usePopover();
  const [pending, startTransition] = useTransition();
  return (
    <div className="user-menu" ref={root}>
      <button
        ref={trigger}
        type="button"
        className="avatar"
        aria-haspopup="true"
        aria-expanded={open}
        aria-controls="user-menu"
        aria-label={`Account menu for ${name || email}`}
        onClick={() => setOpen(!open)}
      >
        {initials(name, email)}
      </button>
      {open ? (
        <div className="popover user-popover" id="user-menu">
          <div className="popover-identity">
            <strong>{name}</strong>
            <span>{email}</span>
            <span>{role}</span>
          </div>
          <ul>
            <li>
              <Link className="popover-item" href="/settings#account" onClick={() => setOpen(false)}>
                <UserRound aria-hidden="true" size={16} /> Account
              </Link>
            </li>
            <li>
              <Link
                className="popover-item"
                href="/settings#account-security"
                onClick={() => setOpen(false)}
              >
                <ShieldCheck aria-hidden="true" size={16} /> Account security
              </Link>
            </li>
            <li>
              <Link className="popover-item" href="/privacy" onClick={() => setOpen(false)}>
                <FileLock2 aria-hidden="true" size={16} /> Privacy and data handling
              </Link>
            </li>
            <li>
              <button
                type="button"
                className="popover-item"
                disabled={pending}
                onClick={() =>
                  startTransition(async () => {
                    await authClient.signOut();
                    router.replace("/sign-in");
                    router.refresh();
                  })
                }
              >
                <LogOut aria-hidden="true" size={16} /> {pending ? "Signing out…" : "Sign out"}
              </button>
            </li>
          </ul>
        </div>
      ) : null}
    </div>
  );
}
