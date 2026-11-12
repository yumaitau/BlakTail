import { errorText } from "@/lib/server-errors";
import { NextResponse, type NextRequest } from "next/server";
import { headers } from "next/headers";
import { auth } from "@/lib/auth";
import {
  completeOidcLogin,
  establishConsoleSession,
} from "@/lib/oidc";
import {
  OIDC_BINDING_COOKIE,
  bindingCookie,
  sameOriginRedirect,
} from "@/lib/oidc-flow-core";
import { ACTIVE_ORGANISATION_COOKIE, activeOrganisationCookieOptions } from "@/lib/session";

function clearBinding(request: NextRequest, response: NextResponse): NextResponse {
  response.cookies.set(
    bindingCookie("", (process.env.BETTER_AUTH_URL ?? request.url).startsWith("https://")),
  );
  return response;
}

export async function GET(request: NextRequest) {
  const url = new URL(request.url);
  const error = url.searchParams.get("error");
  if (error) {
    return clearBinding(
      request,
      NextResponse.redirect(
        new URL(`/sign-in?error=${encodeURIComponent(error)}`, url.origin),
      ),
    );
  }
  const state = url.searchParams.get("state");
  const code = url.searchParams.get("code");
  if (!state || !code) {
    return NextResponse.json({ error: "state and code are required" }, { status: 400 });
  }
  try {
    // The current session matters only for a link this same session started
    // from Settings; it never turns a plain sign-in into a link.
    const existing = await auth.api.getSession({ headers: await headers() });
    const completed = await completeOidcLogin({
      state,
      code,
      binding: request.cookies.get(OIDC_BINDING_COOKIE)?.value ?? null,
      currentSession: existing
        ? {
            userId: existing.user.id,
            sessionId: existing.session.id,
            createdAt: new Date(existing.session.createdAt),
          }
        : null,
    });
    const response = NextResponse.redirect(
      sameOriginRedirect(completed.redirectTo, url.origin),
    );
    if (completed.linked) {
      // The session that asked for the link keeps going unchanged, including
      // how it signed in; linking is not a sign-in.
      return clearBinding(request, response);
    }
    const sessionCookie = await establishConsoleSession(completed.userId);
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
    return clearBinding(request, response);
  } catch (caught) {
    const message =
      errorText(caught, "Single sign-on didn't finish.", "oidc callback");
    return clearBinding(
      request,
      NextResponse.redirect(
        new URL(`/sign-in?error=${encodeURIComponent(message)}`, url.origin),
      ),
    );
  }
}
