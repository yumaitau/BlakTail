import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { SignInForm } from "@/components/sign-in-form";
import { auth } from "@/lib/auth";
import { safeDetail } from "@/lib/errors";

function safeNext(value: string | string[] | undefined): string {
  const path = Array.isArray(value) ? value[0] : value;
  return path?.startsWith("/enroll?code=") ? path : "/control-center";
}

export default async function SignInPage({
  searchParams,
}: {
  searchParams: Promise<{
    next?: string | string[];
    error?: string | string[];
    organisation?: string | string[];
  }>;
}) {
  const params = await searchParams;
  const nextPath = safeNext(params.next);
  const rawError = Array.isArray(params.error) ? params.error[0] : params.error;
  // The query string is attacker-controlled: show it only if it reads like
  // one of our plain sentences, otherwise a generic single sign-on message.
  const error = rawError
    ? (safeDetail(rawError, 240) ??
      "Single sign-on didn't finish. Try again, or ask your administrator to check the identity provider.")
    : undefined;
  const organisation = Array.isArray(params.organisation)
    ? params.organisation[0]
    : params.organisation;
  const session = await auth.api.getSession({
    headers: await headers(),
  });
  if (session) {
    redirect(nextPath);
  }
  return (
    <SignInForm
      nextPath={nextPath}
      errorMessage={error}
      organisationId={organisation}
    />
  );
}
