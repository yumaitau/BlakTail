import { errorText } from "@/lib/server-errors";
import { NextResponse } from "next/server";
import { startOidcLogin } from "@/lib/oidc";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const organisationId = url.searchParams.get("organisation") ?? "";
  const redirectTo = url.searchParams.get("redirect") ?? "/control-center";
  if (!organisationId) {
    return NextResponse.redirect(
      new URL("/sign-in?error=Choose%20an%20organisation%20to%20sign%20in%20to.", url.origin),
    );
  }
  try {
    const location = await startOidcLogin(organisationId, redirectTo);
    return NextResponse.redirect(location);
  } catch (error) {
    const message = errorText(error, "Single sign-on couldn't start.", "oidc start");
    return NextResponse.redirect(
      new URL(`/sign-in?error=${encodeURIComponent(message)}`, url.origin),
    );
  }
}
