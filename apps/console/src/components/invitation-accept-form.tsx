"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useRef, useState, useTransition } from "react";
import { authClient } from "@/lib/auth-client";
import { TAGLINE } from "@/lib/tagline";
import { PathMotif } from "./path-motif";
import { Alert } from "./ui/alert";
import { Button } from "./ui/button";
import { FormField } from "./ui/form-field";
import { Wordmark } from "./wordmark";

type Field = "email" | "name" | "password";
const MIN_PASSWORD = 10;

export function InvitationAcceptForm({
  token,
  signedInEmail,
}: {
  token: string;
  signedInEmail: string | null;
}) {
  const router = useRouter();
  const [error, setError] = useState<{ message: string; ref?: string } | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<Field, string>>>({});
  const [pending, startTransition] = useTransition();
  const formRef = useRef<HTMLFormElement>(null);

  return (
    <div className="auth-screen">
      <main className="auth-form-col" id="main">
        <div className="sign-in-card panel">
          <div className="auth-card-head">
            <Wordmark href="/sign-in" />
            <h1>Accept invitation</h1>
            <p className="tagline">{TAGLINE}</p>
          </div>
          {!token ? (
            <Alert tone="error" title="This invitation link isn't valid">
              It may be incomplete or already used. Ask the person who invited you to send a new
              invitation.
            </Alert>
          ) : (
            <form
              ref={formRef}
              className="auth-form"
              noValidate
              onSubmit={(event) => {
                event.preventDefault();
                const form = new FormData(event.currentTarget);
                const email = signedInEmail ?? String(form.get("email") ?? "").trim();
                const name = String(form.get("name") ?? "").trim();
                const password = String(form.get("password") ?? "");
                const next: Partial<Record<Field, string>> = {};
                if (!signedInEmail) {
                  if (!/^[^\s@]+@[^\s@]+$/u.test(email)) next.email = "Enter the email address the invitation was sent to.";
                  if (!name) next.name = "Enter your name.";
                  if (password.length < MIN_PASSWORD) next.password = `Use at least ${MIN_PASSWORD} characters.`;
                }
                setFieldErrors(next);
                setError(null);
                const first = (Object.keys(next) as Field[])[0];
                if (first) {
                  formRef.current?.querySelector<HTMLInputElement>(`[name="${first}"]`)?.focus();
                  return;
                }
                startTransition(async () => {
                  let response: Response;
                  try {
                    response = await fetch("/api/invitations/accept", {
                      method: "POST",
                      headers: { "content-type": "application/json" },
                      body: JSON.stringify(signedInEmail ? { token } : { token, email, name, password }),
                    });
                  } catch {
                    setError({ message: "BlakTail couldn't be reached. Check your connection and try again." });
                    return;
                  }
                  const result = (await response.json().catch(() => ({}))) as { error?: string; ref?: string };
                  if (!response.ok) {
                    setError({
                      message: result.error ?? "This invitation is invalid or has expired.",
                      ref: result.ref,
                    });
                    return;
                  }
                  if (!signedInEmail) {
                    const signIn = await authClient.signIn.email({ email, password });
                    if (signIn.error) {
                      setError({ message: "Your account is ready, but signing in didn't finish. Sign in with your new password." });
                      return;
                    }
                  }
                  router.replace("/devices");
                  router.refresh();
                });
              }}
            >
              {error ? (
                <Alert tone="error" reference={error.ref}>
                  {error.message}
                </Alert>
              ) : null}
              {signedInEmail ? (
                <p className="auth-step-note">
                  You&apos;re signed in as <strong>{signedInEmail}</strong>. Accepting adds this
                  organisation to the same sign-in; your other organisations stay connected.
                </p>
              ) : (
                <>
                  <FormField label="Invited email" error={fieldErrors.email}>
                    <input name="email" type="email" autoComplete="username" />
                  </FormField>
                  <FormField label="Your name" error={fieldErrors.name}>
                    <input name="name" autoComplete="name" maxLength={128} />
                  </FormField>
                  <FormField
                    label="Create a password"
                    hint={`At least ${MIN_PASSWORD} characters.`}
                    error={fieldErrors.password}
                  >
                    <input name="password" type="password" autoComplete="new-password" maxLength={128} />
                  </FormField>
                </>
              )}
              <Button type="submit" loading={pending} loadingLabel="Accepting…">
                {signedInEmail ? "Join organisation" : "Accept invitation"}
              </Button>
            </form>
          )}
          <p className="muted auth-footnote">
            An invitation works once, and only for the organisation and role it was sent for.
          </p>
          {!signedInEmail ? (
            <p className="muted auth-footnote">
              Already have an account? <Link href="/sign-in">Sign in</Link>, then open this
              invitation again.
            </p>
          ) : null}
        </div>
      </main>
      <aside className="auth-brand-col" aria-hidden="true">
        <PathMotif />
        <div className="auth-brand-copy">
          <p className="auth-kicker">Invitation</p>
          <p>A private path between your organisation&apos;s devices.</p>
          <p className="muted">Your network. Your rules. Your country.</p>
        </div>
      </aside>
    </div>
  );
}
