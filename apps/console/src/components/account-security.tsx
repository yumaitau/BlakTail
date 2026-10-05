"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { authClient } from "@/lib/auth-client";
import { authErrorMessage, toUserError } from "@/lib/errors";

type Enrolment = { totpURI: string; backupCodes: string[] };

function totpSecret(uri: string): string {
  try {
    return new URL(uri).searchParams.get("secret") ?? "";
  } catch {
    return "";
  }
}

/** Personal two-step verification for the signed-in password identity. */
export function AccountSecurity({
  hasPassword,
  twoFactorEnabled,
  requiredByPolicy,
}: {
  hasPassword: boolean;
  twoFactorEnabled: boolean;
  requiredByPolicy: boolean;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [enrolment, setEnrolment] = useState<Enrolment | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);

  if (!hasPassword) {
    return (
      <div className="panel stack">
        <h2>Two-step verification</h2>
        <p className="muted">
          You signed in through your organisation&apos;s identity provider.
          Its own multi-factor policy protects this sign-in; BlakTail does
          not add a second code to single sign-on.
        </p>
      </div>
    );
  }

  const run = (work: () => Promise<void>) => {
    setError(null);
    setNotice(null);
    startTransition(async () => {
      try {
        await work();
      } catch (caught) {
        setError(toUserError(caught, "That did not work.").message);
      }
    });
  };

  return (
    <div className="panel stack">
      <div>
        <h2>Two-step verification</h2>
        <p className="muted">
          Password sign-ins also ask for a code from an authenticator app.
          Recovery codes let you in if you lose the device; store them
          offline. {twoFactorEnabled ? "Status: on." : "Status: off."}
          {requiredByPolicy && !twoFactorEnabled
            ? " Your organisation requires it before you can change shared settings."
            : ""}
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
      {codes ? (
        <div className="stack">
          <p>
            <strong>Recovery codes — shown once.</strong> Each works once.
          </p>
          <pre className="mono">{codes.join("\n")}</pre>
        </div>
      ) : null}
      {!twoFactorEnabled && !enrolment ? (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            const password = String(new FormData(event.currentTarget).get("password") ?? "");
            run(async () => {
              const result = await authClient.twoFactor.enable({ password });
              if (result.error || !result.data) {
                throw new Error(authErrorMessage(result.error, "Could not start set-up.").message);
              }
              const data = result.data as Partial<Enrolment>;
              if (!data.totpURI) throw new Error("Authenticator set-up was not returned.");
              setEnrolment({ totpURI: data.totpURI, backupCodes: data.backupCodes ?? [] });
              setCodes(data.backupCodes ?? null);
            });
          }}
        >
          <label>
            Current password
            <input name="password" type="password" autoComplete="current-password" required />
          </label>
          <button type="submit" disabled={pending}>
            {pending ? "Starting…" : "Set up an authenticator app"}
          </button>
        </form>
      ) : null}
      {enrolment && !twoFactorEnabled ? (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            const code = String(new FormData(event.currentTarget).get("code") ?? "").replace(
              /\s+/g,
              "",
            );
            run(async () => {
              const result = await authClient.twoFactor.verifyTotp({ code });
              if (result.error) throw new Error(authErrorMessage(result.error, "That code was not accepted.").message);
              setEnrolment(null);
              setNotice("Two-step verification is on.");
              router.refresh();
            });
          }}
        >
          <p className="muted">
            Add this key to your authenticator app (time-based, six digits),
            then enter the code it shows.
          </p>
          <label>
            Set-up key
            <input className="mono" readOnly value={totpSecret(enrolment.totpURI)} />
          </label>
          <label>
            Set-up link
            <input className="mono" readOnly value={enrolment.totpURI} />
          </label>
          <label>
            Verification code
            <input
              name="code"
              required
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9 ]{6,7}"
              maxLength={7}
            />
          </label>
          <button type="submit" disabled={pending}>
            {pending ? "Checking…" : "Turn on two-step verification"}
          </button>
        </form>
      ) : null}
      {twoFactorEnabled ? (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            const password = String(form.get("password") ?? "");
            const intent = (event.nativeEvent as SubmitEvent).submitter?.getAttribute("value");
            run(async () => {
              if (intent === "codes") {
                const result = await authClient.twoFactor.generateBackupCodes({ password });
                if (result.error || !result.data) {
                  throw new Error(authErrorMessage(result.error, "Could not create recovery codes.").message);
                }
                setCodes((result.data as { backupCodes: string[] }).backupCodes);
                setNotice("Old recovery codes no longer work.");
                return;
              }
              const result = await authClient.twoFactor.disable({ password });
              if (result.error) throw new Error(authErrorMessage(result.error, "Could not turn it off.").message);
              setCodes(null);
              setNotice("Two-step verification is off.");
              router.refresh();
            });
          }}
        >
          <label>
            Current password
            <input name="password" type="password" autoComplete="current-password" required />
          </label>
          <button type="submit" value="codes" className="secondary" disabled={pending}>
            Replace recovery codes
          </button>
          <button type="submit" value="disable" className="danger" disabled={pending}>
            Turn off two-step verification
          </button>
          {requiredByPolicy ? (
            <p className="muted">
              Your organisation requires two-step verification for your role.
              Turning it off blocks your changes until you turn it back on.
            </p>
          ) : null}
        </form>
      ) : null}
    </div>
  );
}
