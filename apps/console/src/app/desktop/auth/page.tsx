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

/** The only callback the console hands codes to (see desktop-auth-core.ts). */
const CALLBACK = "blaktail://auth/callback";

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

/** The app's PKCE request. The server validates it again before issuing a code. */
function appRequest(params: URLSearchParams): { state: string; codeChallenge: string } | null {
  const state = params.get("state") ?? "";
  const codeChallenge = params.get("code_challenge") ?? "";
  const ok =
    params.get("redirect_uri") === CALLBACK &&
    params.get("code_challenge_method") === "S256" &&
    /^[A-Za-z0-9\-._~]{16,256}$/.test(state) &&
    /^[A-Za-z0-9_-]{43}$/.test(codeChallenge);
  return ok ? { state, codeChallenge } : null;
}

function DesktopAuthInner() {
  const router = useRouter();
  const params = useSearchParams();
  const request = appRequest(params);
  const [error, setError] = useState<{ message: string; ref?: string } | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<Field, string>>>({});
  const [pending, startTransition] = useTransition();
  const [checking, setChecking] = useState(true);
  const [secondStep, setSecondStep] = useState(false);
  const [approvalEmail, setApprovalEmail] = useState<string | null>(null);
  const [approving, setApproving] = useState(false);
  const formRef = useRef<HTMLFormElement>(null);

  async function loadSignedInEmail(): Promise<string | null> {
    try {
      const session = await authClient.getSession();
      return session.data?.user?.email ?? null;
    } catch {
      return null;
    }
  }

  const finish = () => {
    void loadSignedInEmail().then(setApprovalEmail);
    router.refresh();
  };

  useEffect(() => {
    let cancelled = false;
    void loadSignedInEmail().then((email) => {
      if (cancelled) return;
      setApprovalEmail(email);
      setChecking(false);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  /** Explicit consent: only a press of Allow issues a code to the app. */
  async function allow() {
    if (!request) return;
    setApproving(true);
    setError(null);
    try {
      const response = await fetch("/api/desktop/auth/authorize", {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          redirect_uri: CALLBACK,
          state: request.state,
          code_challenge: request.codeChallenge,
          code_challenge_method: "S256",
        }),
      });
      const body = (await response.json().catch(() => ({}))) as {
        redirect?: string;
        error?: string;
      };
      if (!response.ok || !body.redirect?.startsWith(`${CALLBACK}?`)) {
        setError({ message: body.error ?? "Could not approve the app sign-in." });
        setApproving(false);
        return;
      }
      window.location.assign(body.redirect);
    } catch {
      setError({ message: "Could not reach the console. Try again." });
      setApproving(false);
    }
  }

  function deny() {
    if (!request) return;
    const url = new URL(CALLBACK);
    url.searchParams.set("error", "access_denied");
    url.searchParams.set("state", request.state);
    window.location.assign(url.toString());
  }

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
    });
  }

  if (checking) return <Checking />;

  if (!request) {
    return (
      <AuthLayout>
        <div className="auth-card-head">
          <Wordmark href="/desktop/auth" />
          <h1>Desktop sign-in</h1>
        </div>
        <Alert tone="error">
          This sign-in link is incomplete. Update the BlakTail app, then choose Sign in in the app
          again.
        </Alert>
      </AuthLayout>
    );
  }

  if (approvalEmail) {
    return (
      <AuthLayout>
        <div className="auth-card-head">
          <Wordmark href="/desktop/auth" />
          <h1>Allow the BlakTail app?</h1>
        </div>
        {error ? (
          <Alert tone="error" reference={error.ref}>
            {error.message}
          </Alert>
        ) : null}
        <p>
          The BlakTail app on this device is asking to sign in as <strong>{approvalEmail}</strong>.
          It will be able to see and manage devices and mint join keys, within your role.
        </p>
        <p className="muted">Only allow this if you just chose Sign in in the BlakTail app yourself.</p>
        <Button type="button" onClick={allow} loading={approving} loadingLabel="Allowing…">
          Allow and return to the app
        </Button>
        <Button type="button" variant="ghost" onClick={deny} disabled={approving}>
          Cancel
        </Button>
        <p className="muted auth-footnote">
          The app gets its own sign-in, not this browser&apos;s. It ends when you sign out of the
          app, when this browser session ends, or after 30 days.
        </p>
      </AuthLayout>
    );
  }

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
            Sign in
          </Button>
        </form>
      )}
      <p className="muted auth-footnote">
        Sessions stay in your onshore Postgres. The app keeps its own sign-in in the device keychain
        and never logs the join key.
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
