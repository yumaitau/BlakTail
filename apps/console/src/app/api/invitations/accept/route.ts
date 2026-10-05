import { jsonError, readJsonBody } from "@/lib/server-errors";
import { createHash } from "node:crypto";
import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { acceptInvitation, InvitationError } from "@/lib/invitations";
import {
  assertSameOrigin,
  consumeRateLimit,
  requestRateLimitIdentity,
  RequestSecurityError,
} from "@/lib/request-security";
import {
  ACTIVE_ORGANISATION_COOKIE,
  activeOrganisationCookieOptions,
} from "@/lib/session";

function errorResponse(error: unknown): Response {
  if (error instanceof RequestSecurityError) {
    const headers = error.retryAfter
      ? { "retry-after": String(error.retryAfter) }
      : undefined;
    return Response.json({ error: error.message }, { status: error.status, headers });
  }
  if (error instanceof InvitationError) {
    return Response.json({ error: error.message }, { status: error.status });
  }
  return jsonError(error, "The invitation couldn't be accepted.", "invitation accept");
}

export async function POST(request: Request): Promise<Response> {
  try {
    assertSameOrigin(request);
    const body = (await readJsonBody(request)) as Record<string, unknown>;
    const token = typeof body.token === "string" ? body.token : "";
    const tokenKey = createHash("sha256").update(token).digest("hex");
    await consumeRateLimit(
      `invitation:accept:${tokenKey}:${requestRateLimitIdentity(request)}`,
      15 * 60,
      10,
    );
    const session = await auth.api.getSession({ headers: request.headers });
    const result = await acceptInvitation({
      token,
      email: typeof body.email === "string" ? body.email : "",
      name: typeof body.name === "string" ? body.name : "",
      password: typeof body.password === "string" ? body.password : "",
      authenticatedUser: session
        ? { id: session.user.id, email: session.user.email }
        : undefined,
    });
    const response = NextResponse.json(
      {
        status: "accepted",
        email: result.email,
        accountCreated: result.accountCreated,
      },
      { status: result.accountCreated ? 201 : 200 },
    );
    response.cookies.set(
      ACTIVE_ORGANISATION_COOKIE,
      result.organisationId,
      activeOrganisationCookieOptions,
    );
    return response;
  } catch (error) {
    return errorResponse(error);
  }
}
