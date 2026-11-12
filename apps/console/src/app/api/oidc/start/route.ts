import { errorText } from "@/lib/server-errors";
import { NextResponse } from "next/server";
import { headers } from "next/headers";
import { auth } from "@/lib/auth";
import { startOidcLogin } from "@/lib/oidc";
import { bindingCookie } from "@/lib/oidc-flow-core";
import { assertTrustedOrigin } from "@/lib/request-security";

function secureCookies(request: Request): boolean {
  return (process.env.BETTER_AUTH_URL ?? request.url).startsWith("https://");
}

function redirectWithBinding(
  request: Request,
  location: string,
  binding: string,
  status = 307,
) {
  const response = NextResponse.redirect(location, status);
  response.cookies.set(bindingCookie(binding, secureCookies(request)));
  return response;
}

/** Plain single sign-on. Never links, whatever session the browser has. */
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
    const started = await startOidcLogin(organisationId, redirectTo);
    return redirectWithBinding(request, started.location, started.binding);
  } catch (error) {
    const message = errorText(error, "Single sign-on couldn't start.", "oidc start");
    return NextResponse.redirect(
      new URL(`/sign-in?error=${encodeURIComponent(message)}`, url.origin),
    );
  }
}

/**
 * Explicit link from Settings: a same-origin form post by a signed-in user.
 * The state row records that user and session; the callback links only back
 * into them.
 */
export async function POST(request: Request) {
  const url = new URL(request.url);
  const settings = (message: string) =>
    NextResponse.redirect(
      new URL(`/settings?sso_link_error=${encodeURIComponent(message)}#identities`, url.origin),
      303,
    );
  try {
    assertTrustedOrigin(request);
  } catch {
    return NextResponse.json({ error: "Request origin is not allowed." }, { status: 403 });
  }
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) {
    return NextResponse.redirect(new URL("/sign-in", url.origin), 303);
  }
  const form = await request.formData().catch(() => null);
  const organisationId = String(form?.get("organisation") ?? "");
  if (!organisationId) {
    return settings("Choose an organisation to link.");
  }
  try {
    const started = await startOidcLogin(organisationId, "/settings", {
      userId: session.user.id,
      sessionId: session.session.id,
    });
    return redirectWithBinding(request, started.location, started.binding, 303);
  } catch (error) {
    return settings(errorText(error, "Single sign-on linking couldn't start.", "oidc link start"));
  }
}
