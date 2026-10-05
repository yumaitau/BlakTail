import { readJsonBody } from "@/lib/server-errors";
import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { requireConsoleContextFromSession } from "@/lib/desktop-auth";
import { assertSameOrigin, RequestSecurityError } from "@/lib/request-security";
import {
  ACTIVE_ORGANISATION_COOKIE,
  activeOrganisationCookieOptions,
  OrganisationAccessError,
} from "@/lib/session";

export async function POST(request: Request): Promise<Response> {
  try {
    assertSameOrigin(request);
    const session = await auth.api.getSession({ headers: request.headers });
    if (!session) {
      return NextResponse.json(
        { error: "Authentication required." },
        { status: 401 },
      );
    }
    const body = (await readJsonBody(request)) as Record<string, unknown>;
    const organisationId =
      typeof body.organisationId === "string" ? body.organisationId.trim() : "";
    if (!organisationId) {
      return NextResponse.json(
        { error: "Choose a workspace." },
        { status: 400 },
      );
    }
    const ctx = await requireConsoleContextFromSession(
      session,
      organisationId,
    );
    if (ctx.organisationId !== organisationId) {
      throw new OrganisationAccessError(
        "Your account does not have access to that workspace.",
      );
    }
    const response = new NextResponse(null, { status: 204 });
    response.cookies.set(
      ACTIVE_ORGANISATION_COOKIE,
      organisationId,
      activeOrganisationCookieOptions,
    );
    return response;
  } catch (error) {
    if (error instanceof RequestSecurityError) {
      return NextResponse.json(
        { error: error.message },
        { status: error.status },
      );
    }
    if (error instanceof OrganisationAccessError) {
      return NextResponse.json({ error: error.message }, { status: 403 });
    }
    console.error("Workspace switch failed", error);
    return NextResponse.json(
      { error: "Could not switch workspace." },
      { status: 500 },
    );
  }
}
