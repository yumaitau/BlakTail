import { NextResponse } from "next/server";
import { OidcError, startOidcLogin } from "@/lib/oidc";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const organisationId = url.searchParams.get("organisation") ?? "";
  const redirectTo = url.searchParams.get("redirect") ?? "/control-center";
  if (!organisationId) {
    return NextResponse.redirect(
      new URL("/sign-in?error=organisation%20is%20required", url.origin),
    );
  }
  try {
    const location = await startOidcLogin(organisationId, redirectTo);
    return NextResponse.redirect(location);
  } catch (error) {
    const message = error instanceof OidcError ? error.message : "OIDC start failed";
    return NextResponse.redirect(
      new URL(`/sign-in?error=${encodeURIComponent(message)}`, url.origin),
    );
  }
}
