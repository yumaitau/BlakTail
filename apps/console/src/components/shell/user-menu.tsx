"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useTransition } from "react";
import { LogOut, ShieldCheck, UserRound, FileLock2 } from "lucide-react";
import { authClient } from "@/lib/auth-client";
import { Spinner } from "../ui/button";
import { toast } from "../ui/toast";
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
            <span className="cell-break">{email}</span>
            {role ? <span>{role}</span> : null}
          </div>
          <ul>
            <li>
              <Link className="popover-item" href="/settings#account" onClick={() => setOpen(false)}>
                <UserRound aria-hidden="true" size={16} /> Profile and settings
              </Link>
            </li>
            <li>
              <Link
                className="popover-item"
                href="/settings#account-security"
                onClick={() => setOpen(false)}
              >
                <ShieldCheck aria-hidden="true" size={16} /> Password and two-step
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
                aria-busy={pending || undefined}
                onClick={() =>
                  startTransition(async () => {
                    const result = await authClient.signOut().catch(() => ({ error: true }));
                    if (result && "error" in result && result.error) {
                      toast.error("You weren't signed out. Check your connection and try again.");
                      return;
                    }
                    router.replace("/sign-in");
                    router.refresh();
                  })
                }
              >
                {pending ? <Spinner /> : <LogOut aria-hidden="true" size={16} />}{" "}
                {pending ? "Signing out…" : "Sign out"}
              </button>
            </li>
          </ul>
        </div>
      ) : null}
    </div>
  );
}
