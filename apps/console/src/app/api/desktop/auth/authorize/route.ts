import { jsonError, readJsonBody } from "@/lib/server-errors";
import { auth } from "@/lib/auth";
import { desktopCallbackUrl, parseAuthoriseRequest } from "@/lib/desktop-auth-core";
import { issueDesktopCode } from "@/lib/desktop-auth";
import {
  assertSameOrigin,
  consumeRateLimit,
  RequestSecurityError,
} from "@/lib/request-security";
import { OrganisationAccessError, resolveSessionContext } from "@/lib/session";

/**
 * Step 2 of desktop sign-in. Called by the `/desktop/auth` page only after the
 * signed-in person presses Allow: same-origin JSON with the browser session
 * cookie. Returns the `blaktail://auth/callback?code=…&state=…` URL the page
 * then opens. The code is useless without the app's PKCE verifier.
 */
export async function POST(request: Request): Promise<Response> {
  try {
    assertSameOrigin(request);
    const session = await auth.api.getSession({ headers: request.headers });
    if (!session) {
      return Response.json({ error: "Sign in first." }, { status: 401 });
    }
    await consumeRateLimit(`desktop:authorize:${session.user.id}`, 10 * 60, 20);
    const parsed = parseAuthoriseRequest(await readJsonBody(request));
    if ("error" in parsed) {
      return Response.json({ error: parsed.error }, { status: 400 });
    }
    // Refuse early for suspended identities or people with no active access.
    await resolveSessionContext(session);
    const code = await issueDesktopCode(session, parsed);
    return Response.json(
      { redirect: desktopCallbackUrl(parsed.redirectUri, code, parsed.state) },
      { headers: { "cache-control": "no-store" } },
    );
  } catch (error) {
    if (error instanceof RequestSecurityError) {
      const headers = error.retryAfter
        ? { "retry-after": String(error.retryAfter) }
        : undefined;
      return Response.json({ error: error.message }, { status: error.status, headers });
    }
    if (error instanceof OrganisationAccessError) {
      return Response.json({ error: error.message }, { status: 403 });
    }
    return jsonError(error, "Could not approve the app sign-in.", "desktop authorize");
  }
}
