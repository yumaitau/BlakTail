import { jsonError, readJsonBody } from "@/lib/server-errors";
import { DESKTOP_REDIRECT_URI } from "@/lib/desktop-auth-core";
import {
  DesktopTokenError,
  exchangeDesktopCode,
  revokeDesktopCredential,
} from "@/lib/desktop-auth";
import {
  consumeRateLimit,
  requestRateLimitIdentity,
  RequestSecurityError,
} from "@/lib/request-security";

const noStore = { "cache-control": "no-store" };

/**
 * Step 3 of desktop sign-in. The app swaps `{ code, code_verifier }` for a
 * desktop credential (`btd_…`, Bearer for `/api/desktop/*`). The credential is
 * separate from the browser session, stored hashed, and revocable.
 */
export async function POST(request: Request): Promise<Response> {
  try {
    await consumeRateLimit(`desktop:token:${requestRateLimitIdentity(request)}`, 10 * 60, 30);
    const body = (await readJsonBody(request)) as Record<string, unknown>;
    const redirectUri =
      body.redirect_uri === undefined ? DESKTOP_REDIRECT_URI : String(body.redirect_uri);
    const issued = await exchangeDesktopCode(body.code, body.code_verifier, redirectUri);
    return Response.json(
      {
        token: issued.token,
        token_type: "Bearer",
        expires_at: issued.expiresAt.toISOString(),
      },
      { headers: noStore },
    );
  } catch (error) {
    if (error instanceof RequestSecurityError) {
      const headers = error.retryAfter
        ? { "retry-after": String(error.retryAfter) }
        : undefined;
      return Response.json({ error: error.message }, { status: error.status, headers });
    }
    if (error instanceof DesktopTokenError) {
      return Response.json(
        { error: "invalid_grant", error_description: error.message },
        { status: 400, headers: noStore },
      );
    }
    return jsonError(error, "Could not complete the app sign-in.", "desktop token");
  }
}

/** App sign-out: revokes the presented desktop credential. */
export async function DELETE(request: Request): Promise<Response> {
  try {
    const revoked = await revokeDesktopCredential(request);
    if (!revoked) {
      return Response.json({ error: "Unauthorised" }, { status: 401 });
    }
    return new Response(null, { status: 204 });
  } catch (error) {
    return jsonError(error, "Could not sign the app out.", "desktop token revoke");
  }
}
