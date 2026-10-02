"use client";

import { useState, useTransition } from "react";
import { authClient } from "@/lib/auth-client";

/** Second step of a password sign-in for an identity with TOTP enabled. */
export function TwoFactorChallenge({
  onVerified,
  onCancel,
}: {
  onVerified: () => void;
  onCancel: () => void;
}) {
  const [useBackup, setUseBackup] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        const code = String(new FormData(event.currentTarget).get("code") ?? "")
          .replace(/\s+/g, "")
          .trim();
        setError(null);
        startTransition(async () => {
          const result = useBackup
            ? await authClient.twoFactor.verifyBackupCode({ code })
            : await authClient.twoFactor.verifyTotp({ code });
          if (result.error) {
            setError(
              result.error.message ??
                "That code was not accepted. Check the time on your authenticator and try again.",
            );
            return;
          }
          onVerified();
        });
      }}
    >
      <p className="muted">
        {useBackup
          ? "Enter one of your unused recovery codes. Each code works once."
          : "Enter the six-digit code from your authenticator app."}
      </p>
      <label>
        {useBackup ? "Recovery code" : "Verification code"}
        <input
          key={useBackup ? "backup" : "totp"}
          name="code"
          required
          autoFocus
          autoComplete="one-time-code"
          inputMode={useBackup ? "text" : "numeric"}
          pattern={useBackup ? undefined : "[0-9 ]{6,7}"}
          maxLength={useBackup ? 32 : 7}
        />
      </label>
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
      <button type="submit" disabled={pending}>
        {pending ? "Checking…" : "Verify and continue"}
      </button>
      <button
        type="button"
        className="secondary"
        disabled={pending}
        onClick={() => {
          setError(null);
          setUseBackup((value) => !value);
        }}
      >
        {useBackup ? "Use authenticator code instead" : "Use a recovery code"}
      </button>
      <button type="button" className="secondary" disabled={pending} onClick={onCancel}>
        Start again
      </button>
    </form>
  );
}
