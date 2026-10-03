"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { FormEvent, Suspense, useEffect, useState, useTransition } from "react";
import { PathMotif } from "@/components/path-motif";
import { TwoFactorChallenge } from "@/components/two-factor-challenge";
import { Wordmark } from "@/components/wordmark";
import { authClient } from "@/lib/auth-client";
import { TAGLINE } from "@/lib/tagline";

function DesktopAuthInner() {
  const router = useRouter();
  const params = useSearchParams();
  const redirectURI =
    params.get("redirect_uri") ?? "blaktail://auth/callback";
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const [checking, setChecking] = useState(true);
  const [secondStep, setSecondStep] = useState(false);
  const finish = () => {
    window.location.href = `/api/desktop/auth/callback?redirect_uri=${encodeURIComponent(redirectURI)}`;
  };

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const session = await authClient.getSession();
      if (cancelled) return;
      if (session.data?.session) {
        window.location.href = `/api/desktop/auth/callback?redirect_uri=${encodeURIComponent(redirectURI)}`;
        return;
      }
      setChecking(false);
    })();
    return () => {
      cancelled = true;
    };
  }, [redirectURI]);

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const email = String(form.get("email") ?? "");
    const password = String(form.get("password") ?? "");
    setError(null);
    startTransition(async () => {
      const result = await authClient.signIn.email({ email, password });
      if (result.error) {
        setError(
          result.error.message ??
            "Sign-in failed. Check your email and password.",
        );
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

  if (checking) {
    return (
      <main className="sign-in">
        <div className="sign-in-card panel">
          <div className="skeleton" aria-busy="true">
            <div className="skeleton-line" />
            <div className="skeleton-line" />
            <p className="muted">Checking your session…</p>
          </div>
        </div>
      </main>
    );
  }

  return (
    <div className="auth-screen">
      <div className="auth-form-col">
        <div className="sign-in-card panel">
          <div className="stack">
            <div>
              <Wordmark href="/desktop/auth" />
              <h1>Desktop sign-in</h1>
              <p className="tagline">{TAGLINE}</p>
            </div>
            {secondStep ? (
              <TwoFactorChallenge onVerified={finish} onCancel={() => setSecondStep(false)} />
            ) : (
            <form onSubmit={onSubmit}>
              <label>
                Email
                <input
                  name="email"
                  type="email"
                  autoComplete="username"
                  required
                />
              </label>
              <label>
                Password
                <input
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  minLength={10}
                />
              </label>
              {error ? (
                <p className="error" role="alert">
                  {error}
                </p>
              ) : null}
              <button type="submit" disabled={pending}>
                {pending ? "Signing in…" : "Sign in and return to the app"}
              </button>
            </form>
            )}
            <p className="muted">
              Sessions stay in your onshore Postgres. The Mac app stores the session
              token in Keychain and never logs the join key.
            </p>
          </div>
        </div>
      </div>
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

export default function DesktopAuthPage() {
  return (
    <Suspense
      fallback={
        <main className="sign-in">
          <div className="sign-in-card panel">
            <p className="muted">Loading…</p>
          </div>
        </main>
      }
    >
      <DesktopAuthInner />
    </Suspense>
  );
}
