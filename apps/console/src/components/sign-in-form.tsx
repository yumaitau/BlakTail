"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useRef, useState, useTransition } from "react";
import { authClient } from "@/lib/auth-client";
import { authErrorMessage } from "@/lib/errors";
import { TAGLINE } from "@/lib/tagline";
import { PathMotif } from "./path-motif";
import { TwoFactorChallenge } from "./two-factor-challenge";
import { Alert } from "./ui/alert";
import { Button } from "./ui/button";
import { FormField } from "./ui/form-field";
import { Wordmark } from "./wordmark";

type Field = "email" | "password";

export function SignInForm({
  nextPath = "/control-center",
  errorMessage,
  organisationId,
}: {
  nextPath?: string;
  errorMessage?: string;
  organisationId?: string;
}) {
  const router = useRouter();
  const [error, setError] = useState<{ message: string; ref?: string } | null>(
    errorMessage ? { message: errorMessage } : null,
  );
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<Field, string>>>({});
  const [pending, startTransition] = useTransition();
  const [ssoOrganisation, setSsoOrganisation] = useState<string | null>(organisationId ?? null);
  const [secondStep, setSecondStep] = useState(false);
  const formRef = useRef<HTMLFormElement>(null);

  async function lookUpSso(email: string) {
    if (!email.includes("@")) {
      setSsoOrganisation(organisationId ?? null);
      return;
    }
    try {
      const response = await fetch(`/api/oidc/discover?email=${encodeURIComponent(email)}`);
      if (!response.ok) return;
      const body = (await response.json()) as { organisationId?: string | null };
      setSsoOrganisation(body.organisationId ?? organisationId ?? null);
    } catch {
      /* Discovery is a convenience; the password form still works. */
    }
  }

  return (
    <div className="auth-screen">
      <main className="auth-form-col" id="main">
        <div className="sign-in-card panel">
          <div className="auth-card-head">
            <Wordmark href="/sign-in" />
            <h1>Sign in</h1>
            <p className="tagline">{TAGLINE}</p>
          </div>
          {secondStep ? (
            <TwoFactorChallenge
              onVerified={() => {
                router.replace(nextPath);
                router.refresh();
              }}
              onCancel={() => setSecondStep(false)}
            />
          ) : (
            <form
              ref={formRef}
              className="auth-form"
              noValidate
              onSubmit={(event) => {
                event.preventDefault();
                const form = new FormData(event.currentTarget);
                const email = String(form.get("email") ?? "").trim();
                const password = String(form.get("password") ?? "");
                const next: Partial<Record<Field, string>> = {};
                if (!/^[^\s@]+@[^\s@]+$/u.test(email)) next.email = "Enter your email address.";
                if (!password) next.password = "Enter your password.";
                setFieldErrors(next);
                setError(null);
                const first = (Object.keys(next) as Field[])[0];
                if (first) {
                  formRef.current?.querySelector<HTMLInputElement>(`[name="${first}"]`)?.focus();
                  return;
                }
                startTransition(async () => {
                  const result = await authClient.signIn.email({ email, password });
                  if (result.error) {
                    const user = authErrorMessage(result.error, "Sign-in failed. Check your email and password.");
                    setError({ message: user.message, ref: user.ref });
                    return;
                  }
                  if ((result.data as { twoFactorRedirect?: boolean } | null)?.twoFactorRedirect) {
                    setSecondStep(true);
                    return;
                  }
                  router.replace(nextPath);
                  router.refresh();
                });
              }}
            >
              {error ? (
                <Alert tone="error" reference={error.ref}>
                  {error.message}
                </Alert>
              ) : null}
              <FormField label="Email" error={fieldErrors.email}>
                <input
                  name="email"
                  type="email"
                  autoComplete="username"
                  onBlur={(event) => {
                    void lookUpSso(event.currentTarget.value);
                  }}
                />
              </FormField>
              <FormField label="Password" error={fieldErrors.password}>
                <input name="password" type="password" autoComplete="current-password" />
              </FormField>
              <Button type="submit" loading={pending} loadingLabel="Signing in…" data-testid="sign-in-submit">
                Sign in
              </Button>
            </form>
          )}
          {secondStep ? null : (
            <details className="sso-disclosure" {...(ssoOrganisation ? { open: true } : {})}>
              <summary>Use organisation single sign-on</summary>
              <form action="/api/oidc/start" method="get">
                <input type="hidden" name="redirect" value={nextPath} />
                <input type="hidden" name="organisation" value={ssoOrganisation ?? ""} />
                <p className="muted auth-footnote">
                  {ssoOrganisation
                    ? "Your email's organisation uses its own identity provider. Single sign-on is the usual way in; a password is the break-glass path."
                    : "Enter your work email above. If your organisation has single sign-on, you can use it here."}
                </p>
                <Button type="submit" variant="secondary" disabled={!ssoOrganisation}>
                  Continue with organisation SSO
                </Button>
              </form>
            </details>
          )}
          <p className="muted auth-footnote">
            <Link href="/privacy">Privacy and data handling</Link>
          </p>
        </div>
      </main>
      <aside className="auth-brand-col" aria-hidden="true">
        <PathMotif />
        <div className="auth-brand-copy">
          <p className="auth-kicker">Private path</p>
          <p>A private path between your organisation&apos;s devices.</p>
          <p className="muted">Your network. Your rules. Your country.</p>
        </div>
      </aside>
    </div>
  );
}
