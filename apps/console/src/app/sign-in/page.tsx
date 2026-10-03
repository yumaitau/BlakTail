import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { SignInForm } from "@/components/sign-in-form";
import { auth } from "@/lib/auth";

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
  const error = Array.isArray(params.error) ? params.error[0] : params.error;
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
