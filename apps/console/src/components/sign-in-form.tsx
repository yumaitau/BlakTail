"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { authClient } from "@/lib/auth-client";
import { TAGLINE } from "@/lib/tagline";
import { PathMotif } from "./path-motif";
import { Wordmark } from "./wordmark";

export function SignInForm({
  nextPath = "/devices",
  errorMessage,
  organisationId,
}: {
  nextPath?: string;
  errorMessage?: string;
  organisationId?: string;
}) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(errorMessage ?? null);
  const [pending, startTransition] = useTransition();
  const [ssoOrganisation, setSsoOrganisation] = useState<string | null>(
    organisationId ?? null,
  );

  async function lookUpSso(email: string) {
    if (!email.includes("@")) {
      setSsoOrganisation(organisationId ?? null);
      return;
    }
    const response = await fetch(`/api/oidc/discover?email=${encodeURIComponent(email)}`);
    if (!response.ok) return;
    const body = (await response.json()) as { organisationId?: string | null };
    setSsoOrganisation(body.organisationId ?? organisationId ?? null);
  }

  return (
    <div className="auth-screen">
      <div className="auth-form-col">
        <div className="sign-in-card panel">
          <div className="stack">
            <div>
              <Wordmark href="/sign-in" />
              <h1>Sign in</h1>
              <p className="tagline">{TAGLINE}</p>
            </div>
            <form
              onSubmit={(event) => {
                event.preventDefault();
                const form = new FormData(event.currentTarget);
                const email = String(form.get("email") ?? "");
                const password = String(form.get("password") ?? "");
                setError(null);
                startTransition(async () => {
                  const result = await authClient.signIn.email({
                    email,
                    password,
                  });
                  if (result.error) {
                    setError(
                      result.error.message ??
                        "Sign-in failed. Check your email and password.",
                    );
                    return;
                  }
                  router.replace(nextPath);
                  router.refresh();
                });
              }}
            >
              <label>
                Email
                <input
                  name="email"
                  type="email"
                  autoComplete="username"
                  required
                  onBlur={(event) => {
                    void lookUpSso(event.currentTarget.value);
                  }}
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
              {error ? <p className="error">{error}</p> : null}
              <button type="submit" disabled={pending} data-testid="sign-in-submit">
                {pending ? "Signing in…" : "Sign in"}
              </button>
            </form>
            <details
              className="sso-disclosure"
              {...(ssoOrganisation ? { open: true } : {})}
            >
              <summary>Use organisation single sign-on</summary>
              <form action="/api/oidc/start" method="get">
                <input type="hidden" name="redirect" value={nextPath} />
                <input type="hidden" name="organisation" value={ssoOrganisation ?? ""} />
                {ssoOrganisation ? (
                  <p className="muted">
                    This email domain uses your organisation&apos;s identity
                    provider. Single sign-on is the usual path. Password remains
                    the break-glass path.
                  </p>
                ) : (
                  <p className="muted">
                    Enter your work email above. If that domain is configured,
                    single sign-on is offered here.
                  </p>
                )}
                <button type="submit" className="secondary" disabled={!ssoOrganisation}>
                  Continue with organisation SSO
                </button>
              </form>
            </details>
            <p className="muted">
              <Link href="/privacy">Privacy and data handling</Link>
            </p>
          </div>
        </div>
      </div>
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
