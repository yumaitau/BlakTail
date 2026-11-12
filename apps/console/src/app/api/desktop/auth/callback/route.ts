import { cookies, headers } from "next/headers";
import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { escapeHtml, validDesktopRedirectUri } from "@/lib/desktop-auth-core";

/**
 * Completes desktop ASWebAuthenticationSession sign-in.
 * Prefer the fragment form so the session token is not sent to intermediate servers:
 *   blaktail://auth/callback#token=…
 *
 * Custom URL schemes are returned via a tiny HTML bounce because some stacks reject
 * non-http(s) Location headers. The bounce is a meta refresh and a link only (no
 * inline script), and the only accepted callback is exactly blaktail://auth/callback.
 */
export async function GET(request: Request) {
  const url = new URL(request.url);
  const redirectURI = validDesktopRedirectUri(url.searchParams.get("redirect_uri"));
  if (!redirectURI) {
    return NextResponse.json(
      { error: "redirect_uri must be blaktail://auth/callback." },
      { status: 400 },
    );
  }

  const session = await auth.api.getSession({
    headers: await headers(),
  });
  if (!session) {
    const signIn = new URL("/desktop/auth", url.origin);
    signIn.searchParams.set("redirect_uri", redirectURI);
    return NextResponse.redirect(signIn);
  }

  const token = session.session.token;
  const safe = escapeHtml(`${redirectURI}#token=${encodeURIComponent(token)}`);
  const html = `<!doctype html>
<html lang="en-AU">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="refresh" content="0;url=${safe}" />
    <title>Returning to BlakTail</title>
  </head>
  <body>
    <p>Returning to the BlakTail app… <a href="${safe}">Open the app</a> if nothing happens.</p>
  </body>
</html>`;
  return new NextResponse(html, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

/** Optional helper for clients that already hold a browser cookie jar. */
export async function POST() {
  const jar = await cookies();
  const token =
    jar.get("better-auth.session_token")?.value ??
    jar.get("__Secure-better-auth.session_token")?.value;
  if (!token) {
    return NextResponse.json({ error: "Unauthorised" }, { status: 401 });
  }
  return NextResponse.json({ token });
}
