"use client";

import { useRef, useState, useTransition } from "react";
import { authClient } from "@/lib/auth-client";
import { authErrorMessage } from "@/lib/errors";
import { Button } from "./ui/button";
import { FormField } from "./ui/form-field";

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
  const inputRef = useRef<HTMLInputElement>(null);

  return (
    <form
      className="auth-form"
      noValidate
      aria-labelledby="two-step-title"
      onSubmit={(event) => {
        event.preventDefault();
        const code = String(new FormData(event.currentTarget).get("code") ?? "")
          .replace(/\s+/g, "")
          .trim();
        if (!useBackup && !/^\d{6}$/u.test(code)) {
          setError("Enter the six-digit code from your authenticator app.");
          inputRef.current?.focus();
          return;
        }
        if (useBackup && code.length < 6) {
          setError("Enter one of your recovery codes.");
          inputRef.current?.focus();
          return;
        }
        setError(null);
        startTransition(async () => {
          const result = useBackup
            ? await authClient.twoFactor.verifyBackupCode({ code })
            : await authClient.twoFactor.verifyTotp({ code });
          if (result.error) {
            setError(
              authErrorMessage(
                result.error,
                useBackup
                  ? "That recovery code wasn't accepted. Check it and try again."
                  : "That code wasn't accepted. Check the time on your device and try the next code.",
              ).message,
            );
            inputRef.current?.select();
            return;
          }
          onVerified();
        });
      }}
    >
      <div className="auth-card-head">
        <h2 id="two-step-title">Two-step verification</h2>
        <p className="auth-step-note">
          {useBackup
            ? "Enter one of your unused recovery codes. Each code works once."
            : "Enter the six-digit code from your authenticator app."}
        </p>
      </div>
      <FormField label={useBackup ? "Recovery code" : "Verification code"} error={error}>
        <input
          ref={inputRef}
          key={useBackup ? "backup" : "totp"}
          name="code"
          autoFocus
          autoComplete="one-time-code"
          inputMode={useBackup ? "text" : "numeric"}
          maxLength={useBackup ? 32 : 7}
          className={useBackup ? "mono" : "mono otp-input"}
        />
      </FormField>
      <Button type="submit" loading={pending} loadingLabel="Checking…" data-testid="two-step-submit">
        Verify and continue
      </Button>
      <div className="auth-alt-actions">
        <Button
          variant="ghost"
          size="sm"
          disabled={pending}
          onClick={() => {
            setError(null);
            setUseBackup((value) => !value);
          }}
        >
          {useBackup ? "Use an authenticator code instead" : "Use a recovery code"}
        </Button>
        <Button variant="ghost" size="sm" disabled={pending} onClick={onCancel}>
          Start again
        </Button>
      </div>
    </form>
  );
}
