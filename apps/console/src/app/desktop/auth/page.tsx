"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { FormEvent, Suspense, useEffect, useRef, useState, useTransition } from "react";
import { PathMotif } from "@/components/path-motif";
import { TwoFactorChallenge } from "@/components/two-factor-challenge";
import { Alert, Button, FormField, Skeleton } from "@/components/ui";
import { Wordmark } from "@/components/wordmark";
import { authClient } from "@/lib/auth-client";
import { authErrorMessage } from "@/lib/errors";
import { TAGLINE } from "@/lib/tagline";

type Field = "email" | "password";

function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="auth-screen">
      <main className="auth-form-col" id="main">
        <div className="sign-in-card panel">{children}</div>
      </main>
      <aside className="auth-brand-col" aria-hidden="true">
        <PathMotif />
        <div className="auth-brand-copy">
          <p className="auth-kicker">Desktop</p>
          <p>A private path between your organisation&apos;s devices.</p>
          <p className="muted">Your network. Your rules. Your country.</p>
        </div>
      </aside>
    </div>
  );
}

function Checking() {
  return (
    <AuthLayout>
      <div className="auth-card-head">
        <Wordmark href="/desktop/auth" />
        <h1>Desktop sign-in</h1>
      </div>
      <Skeleton lines={3} label="Checking your session" />
      <p className="muted auth-footnote">Checking whether you&apos;re already signed in…</p>
    </AuthLayout>
  );
}

function DesktopAuthInner() {
  const router = useRouter();
  const params = useSearchParams();
  const redirectURI = params.get("redirect_uri") ?? "blaktail://auth/callback";
  const [error, setError] = useState<{ message: string; ref?: string } | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<Field, string>>>({});
  const [pending, startTransition] = useTransition();
  const [checking, setChecking] = useState(true);
  const [secondStep, setSecondStep] = useState(false);
  const formRef = useRef<HTMLFormElement>(null);
  const finish = () => {
    window.location.href = `/api/desktop/auth/callback?redirect_uri=${encodeURIComponent(redirectURI)}`;
  };

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const session = await authClient.getSession();
        if (cancelled) return;
        if (session.data?.session) {
          window.location.href = `/api/desktop/auth/callback?redirect_uri=${encodeURIComponent(redirectURI)}`;
          return;
        }
      } catch {
        /* Fall through to the sign-in form. */
      }
      if (!cancelled) setChecking(false);
    })();
    return () => {
      cancelled = true;
    };
  }, [redirectURI]);

  function onSubmit(event: FormEvent<HTMLFormElement>) {
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
      finish();
      router.refresh();
    });
  }

  if (checking) return <Checking />;

  return (
    <AuthLayout>
      <div className="auth-card-head">
        <Wordmark href="/desktop/auth" />
        <h1>Desktop sign-in</h1>
        <p className="tagline">{TAGLINE}</p>
      </div>
      {secondStep ? (
        <TwoFactorChallenge onVerified={finish} onCancel={() => setSecondStep(false)} />
      ) : (
        <form ref={formRef} className="auth-form" noValidate onSubmit={onSubmit}>
          {error ? (
            <Alert tone="error" reference={error.ref}>
              {error.message}
            </Alert>
          ) : null}
          <FormField label="Email" error={fieldErrors.email}>
            <input name="email" type="email" autoComplete="username" />
          </FormField>
          <FormField label="Password" error={fieldErrors.password}>
            <input name="password" type="password" autoComplete="current-password" />
          </FormField>
          <Button type="submit" loading={pending} loadingLabel="Signing in…">
            Sign in and return to the app
          </Button>
        </form>
      )}
      <p className="muted auth-footnote">
        Sessions stay in your onshore Postgres. The Mac app keeps its session token in Keychain and
        never logs the join key.
      </p>
    </AuthLayout>
  );
}

export default function DesktopAuthPage() {
  return (
    <Suspense fallback={<Checking />}>
      <DesktopAuthInner />
    </Suspense>
  );
}
