import { NextResponse } from "next/server";
import { headers } from "next/headers";
import { auth } from "@/lib/auth";
import {
  OidcError,
  completeOidcLogin,
  establishConsoleSession,
} from "@/lib/oidc";
import { ACTIVE_ORGANISATION_COOKIE, activeOrganisationCookieOptions } from "@/lib/session";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const error = url.searchParams.get("error");
  if (error) {
    return NextResponse.redirect(
      new URL(`/sign-in?error=${encodeURIComponent(error)}`, url.origin),
    );
  }
  const state = url.searchParams.get("state");
  const code = url.searchParams.get("code");
  if (!state || !code) {
    return NextResponse.json({ error: "state and code are required" }, { status: 400 });
  }
  try {
    const existing = await auth.api.getSession({ headers: await headers() });
    const completed = await completeOidcLogin({
      state,
      code,
      linkingUserId: existing?.user.id,
      linkingSessionCreatedAt: existing
        ? new Date(existing.session.createdAt)
        : undefined,
    });
    const sessionCookie = await establishConsoleSession(completed.userId);
    const redirectTo = completed.redirectTo.startsWith("/")
      ? completed.redirectTo
      : "/devices";
    const response = NextResponse.redirect(new URL(redirectTo, url.origin));
    response.cookies.set({
      name: sessionCookie.name,
      value: sessionCookie.value,
      httpOnly: sessionCookie.httpOnly,
      secure: sessionCookie.secure,
      sameSite: sessionCookie.sameSite,
      path: sessionCookie.path,
      maxAge: sessionCookie.maxAge,
    });
    response.cookies.set({
      name: ACTIVE_ORGANISATION_COOKIE,
      value: completed.organisationId,
      ...activeOrganisationCookieOptions,
    });
    return response;
  } catch (caught) {
    const message =
      caught instanceof OidcError ? caught.message : "OIDC sign-in failed";
    return NextResponse.redirect(
      new URL(`/sign-in?error=${encodeURIComponent(message)}`, url.origin),
    );
  }
}
