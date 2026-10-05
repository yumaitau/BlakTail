import { readJsonBody } from "@/lib/server-errors";
import { auth } from "@/lib/auth";
import { AssuranceError, requireSecurityAssurance } from "@/lib/auth-policy";
import { requireConsoleContextFromSession } from "@/lib/desktop-auth";
import {
  createInvitation,
  InvitationError,
  listPendingInvitations,
  revokeInvitation,
} from "@/lib/invitations";
import { assertSameOrigin, RequestSecurityError } from "@/lib/request-security";
import {
  activeOrganisationIdFromRequest,
  OrganisationAccessError,
} from "@/lib/session";

async function context(request: Request) {
  const session = await auth.api.getSession({ headers: request.headers });
  if (!session) return null;
  return requireConsoleContextFromSession(
    session,
    activeOrganisationIdFromRequest(request),
  );
}

function errorResponse(error: unknown): Response {
  if (error instanceof RequestSecurityError) {
    return Response.json({ error: error.message }, { status: error.status });
  }
  if (error instanceof InvitationError) {
    return Response.json({ error: error.message }, { status: error.status });
  }
  if (error instanceof OrganisationAccessError || error instanceof AssuranceError) {
    return Response.json({ error: error.message }, { status: 403 });
  }
  console.error("Invitation request failed", error);
  return Response.json({ error: "Invitation request failed." }, { status: 500 });
}

export async function GET(request: Request): Promise<Response> {
  try {
    const ctx = await context(request);
    if (!ctx) return Response.json({ error: "Authentication required." }, { status: 401 });
    const invitations = await listPendingInvitations(ctx);
    return Response.json(
      invitations.map((invitation) => ({
        ...invitation,
        expiresAt: invitation.expiresAt.toISOString(),
        createdAt: invitation.createdAt.toISOString(),
      })),
    );
  } catch (error) {
    return errorResponse(error);
  }
}

export async function POST(request: Request): Promise<Response> {
  try {
    assertSameOrigin(request);
    const ctx = await context(request);
    if (!ctx) return Response.json({ error: "Authentication required." }, { status: 401 });
    await requireSecurityAssurance(ctx);
    const body = (await readJsonBody(request)) as Record<string, unknown>;
    const result = await createInvitation(
      ctx,
      typeof body.email === "string" ? body.email : "",
      body.role === "admin" ? "admin" : "member",
    );
    return Response.json(
      {
        id: result.invitation.id,
        url: result.url,
        expiresAt: result.invitation.expiresAt.toISOString(),
      },
      { status: 201 },
    );
  } catch (error) {
    return errorResponse(error);
  }
}

export async function DELETE(request: Request): Promise<Response> {
  try {
    assertSameOrigin(request);
    const ctx = await context(request);
    if (!ctx) return Response.json({ error: "Authentication required." }, { status: 401 });
    await requireSecurityAssurance(ctx);
    const body = (await readJsonBody(request)) as Record<string, unknown>;
    await revokeInvitation(
      ctx,
      typeof body.invitationId === "string" ? body.invitationId : "",
    );
    return new Response(null, { status: 204 });
  } catch (error) {
    return errorResponse(error);
  }
}
