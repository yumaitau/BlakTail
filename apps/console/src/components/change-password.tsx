"use client";

import { useState, useTransition } from "react";
import { authClient } from "@/lib/auth-client";

const MIN_LENGTH = 10;

/** Changes the signed-in person's own password and signs out their other sessions. */
export function ChangePassword() {
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  return (
    <div className="panel stack">
      <div>
        <h2>Password</h2>
        <p className="muted">
          Change the password you use to sign in. Other browsers and devices
          signed in with it are signed out; this one stays signed in.
        </p>
      </div>
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
      {notice ? (
        <p className="muted" role="status">
          {notice}
        </p>
      ) : null}
      <form
        onSubmit={(event) => {
          event.preventDefault();
          const formElement = event.currentTarget;
          const form = new FormData(formElement);
          const currentPassword = String(form.get("currentPassword") ?? "");
          const newPassword = String(form.get("newPassword") ?? "");
          const confirmPassword = String(form.get("confirmPassword") ?? "");
          setError(null);
          setNotice(null);
          if (newPassword.length < MIN_LENGTH) {
            setError(`Use at least ${MIN_LENGTH} characters.`);
            return;
          }
          if (newPassword !== confirmPassword) {
            setError("The new passwords don't match.");
            return;
          }
          if (newPassword === currentPassword) {
            setError("Choose a password different from your current one.");
            return;
          }
          startTransition(async () => {
            const result = await authClient.changePassword({
              currentPassword,
              newPassword,
              revokeOtherSessions: true,
            });
            if (result.error) {
              setError(result.error.message ?? "Your password was not changed.");
              return;
            }
            formElement.reset();
            setNotice("Password changed. Other sessions were signed out.");
          });
        }}
      >
        <label>
          Current password
          <input
            name="currentPassword"
            type="password"
            autoComplete="current-password"
            required
          />
        </label>
        <label>
          New password
          <input
            name="newPassword"
            type="password"
            autoComplete="new-password"
            minLength={MIN_LENGTH}
            required
          />
        </label>
        <label>
          Confirm new password
          <input
            name="confirmPassword"
            type="password"
            autoComplete="new-password"
            minLength={MIN_LENGTH}
            required
          />
        </label>
        <button type="submit" disabled={pending}>
          {pending ? "Changing…" : "Change password"}
        </button>
      </form>
    </div>
  );
}
