"use client";

import { useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { authClient } from "@/lib/auth-client";
import { authErrorMessage } from "@/lib/errors";
import { Alert } from "./ui/alert";
import { StatusPill } from "./ui/badge";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormField } from "./ui/form-field";
import { SecretPanel } from "./ui/secret-panel";
import { Section } from "./ui/section";
import { toast } from "./ui/toast";

type Enrolment = { totpURI: string; backupCodes: string[] };

function totpSecret(uri: string): string {
  try {
    return new URL(uri).searchParams.get("secret") ?? "";
  } catch {
    return "";
  }
}

const DESCRIPTION =
  "Password sign-ins also ask for a six-digit code from an authenticator app. Recovery codes get you in if you lose the device.";

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
  const [enrolment, setEnrolment] = useState<Enrolment | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [errors, setErrors] = useState<{ password?: string; code?: string }>({});
  const [confirmOff, setConfirmOff] = useState(false);
  const passwordRef = useRef<HTMLInputElement>(null);

  if (!hasPassword) {
    return (
      <Section id="two-step" headingLevel={3} title="Two-step verification" description={DESCRIPTION}>
        <Alert tone="info" title="Handled by your identity provider">
          You signed in through your organisation&apos;s single sign-on. Its own multi-factor
          rules protect this sign-in, so BlakTail doesn&apos;t ask for a second code.
        </Alert>
      </Section>
    );
  }

  function readPassword(): string | null {
    const password = passwordRef.current?.value ?? "";
    if (!password) {
      setErrors({ password: "Enter your current password." });
      passwordRef.current?.focus();
      return null;
    }
    setErrors({});
    return password;
  }

  function failPassword(error: { code?: string; message?: string; status?: number } | null | undefined, fallback: string) {
    const user = authErrorMessage(error, fallback);
    if (error?.code?.toUpperCase() === "INVALID_PASSWORD") {
      setErrors({ password: user.message });
      passwordRef.current?.focus();
    } else {
      toast.error(user.message, { reference: user.ref });
    }
  }

  const status = (
    <StatusPill tone={twoFactorEnabled ? "success" : requiredByPolicy ? "warning" : "muted"}>
      {twoFactorEnabled ? "On" : "Off"}
    </StatusPill>
  );

  return (
    <Section id="two-step" headingLevel={3} title="Two-step verification" description={DESCRIPTION} actions={status}>
      {requiredByPolicy && !twoFactorEnabled ? (
        <Alert tone="warning" title="Your organisation requires this">
          Owners and admins who sign in with a password need two-step verification before they
          can change shared settings. Turn it on below.
        </Alert>
      ) : null}

      {codes ? (
        <SecretPanel
          title="Save your recovery codes now"
          label="Recovery codes"
          secret={codes}
          description="Each code works once, if you lose your authenticator. This is the only time they're shown; earlier codes no longer work. Print them or keep them in your password manager."
          doneLabel="I've saved them"
          onDone={() => setCodes(null)}
        />
      ) : null}

      {!twoFactorEnabled && !enrolment ? (
        <form
          className="form-row"
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            const password = readPassword();
            if (!password) return;
            startTransition(async () => {
              const result = await authClient.twoFactor.enable({ password });
              if (result.error || !result.data) {
                failPassword(result.error, "Two-step set-up couldn't start. Try again.");
                return;
              }
              const data = result.data as Partial<Enrolment>;
              if (!data.totpURI) {
                toast.error("Two-step set-up couldn't start. Try again.");
                return;
              }
              setEnrolment({ totpURI: data.totpURI, backupCodes: data.backupCodes ?? [] });
            });
          }}
        >
          <FormField label="Current password" required error={errors.password}>
            <input ref={passwordRef} name="password" type="password" autoComplete="current-password" />
          </FormField>
          <Button type="submit" loading={pending} loadingLabel="Starting…">
            Set up an authenticator app
          </Button>
        </form>
      ) : null}

      {enrolment && !twoFactorEnabled ? (
        <form
          className="ui-form"
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            const code = String(new FormData(event.currentTarget).get("code") ?? "").replace(/\s+/g, "");
            if (!/^\d{6}$/u.test(code)) {
              setErrors({ code: "Enter the six-digit code your app shows." });
              return;
            }
            setErrors({});
            startTransition(async () => {
              const result = await authClient.twoFactor.verifyTotp({ code });
              if (result.error) {
                setErrors({
                  code: authErrorMessage(result.error, "That code wasn't accepted. Check your device's clock and try the next code.").message,
                });
                return;
              }
              setCodes(enrolment.backupCodes.length ? enrolment.backupCodes : null);
              setEnrolment(null);
              toast.success("Two-step verification is on");
              router.refresh();
            });
          }}
        >
          <p className="muted">
            Add this key to your authenticator app (time-based, six digits), or open the set-up
            link on the device that has the app. Then enter the code it shows.
          </p>
          <FormField label="Set-up key" hint="Type this into the app if you can't use the link.">
            <input className="mono" readOnly value={totpSecret(enrolment.totpURI)} onFocus={(event) => event.currentTarget.select()} />
          </FormField>
          <FormField label="Set-up link">
            <input className="mono" readOnly value={enrolment.totpURI} onFocus={(event) => event.currentTarget.select()} />
          </FormField>
          <FormField label="Code from your app" required error={errors.code}>
            <input
              name="code"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={7}
            />
          </FormField>
          <div className="actions">
            <Button type="submit" loading={pending} loadingLabel="Checking…">
              Turn on two-step verification
            </Button>
            <Button variant="secondary" disabled={pending} onClick={() => setEnrolment(null)}>
              Cancel
            </Button>
          </div>
        </form>
      ) : null}

      {twoFactorEnabled ? (
        <p className="muted">Enter your current password to replace your recovery codes or turn this off.</p>
      ) : null}
      {twoFactorEnabled ? (
        <form
          className="form-row"
          noValidate
          onSubmit={(event) => event.preventDefault()}
        >
          <FormField label="Current password" required error={errors.password}>
            <input ref={passwordRef} name="password" type="password" autoComplete="current-password" />
          </FormField>
          <div className="actions">
            <Button
              variant="secondary"
              loading={pending && !confirmOff}
              loadingLabel="Replacing…"
              disabled={pending}
              onClick={() => {
                const password = readPassword();
                if (!password) return;
                startTransition(async () => {
                  const result = await authClient.twoFactor.generateBackupCodes({ password });
                  if (result.error || !result.data) {
                    failPassword(result.error, "New recovery codes couldn't be created. Try again.");
                    return;
                  }
                  setCodes((result.data as { backupCodes: string[] }).backupCodes);
                  toast.success("New recovery codes created", { description: "Your old codes no longer work." });
                });
              }}
            >
              Replace recovery codes
            </Button>
            <Button
              variant="quiet-danger"
              disabled={pending}
              onClick={() => {
                if (readPassword()) setConfirmOff(true);
              }}
            >
              Turn off two-step verification
            </Button>
          </div>
        </form>
      ) : null}

      <ConfirmDialog
        open={confirmOff}
        title="Turn off two-step verification?"
        description={
          requiredByPolicy
            ? "Your organisation requires it for your role. Until you turn it back on you can sign in, but you can't change shared settings."
            : "Password sign-ins will only need your password. Your recovery codes stop working."
        }
        confirmText="turn off"
        confirmLabel="Turn off"
        pending={pending}
        onCancel={() => setConfirmOff(false)}
        onConfirm={() => {
          const password = passwordRef.current?.value ?? "";
          startTransition(async () => {
            const result = await authClient.twoFactor.disable({ password });
            setConfirmOff(false);
            if (result.error) {
              failPassword(result.error, "Two-step verification wasn't turned off. Try again.");
              return;
            }
            setCodes(null);
            if (passwordRef.current) passwordRef.current.value = "";
            toast.success("Two-step verification is off");
            router.refresh();
          });
        }}
      />
    </Section>
  );
}
