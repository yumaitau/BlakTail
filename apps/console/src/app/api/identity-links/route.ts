import { auth } from "@/lib/auth";
import {
  beginIdentityLink,
  completeIdentityLink,
  IdentityLinkError,
  recoverIdentity,
  resolveIdentityRoleConflict,
  suspendIdentity,
  unlinkIdentity,
} from "@/lib/identity-links";
import { isOrgRole, type OrgRole } from "@/lib/roles";
import {
  assertSameOrigin,
  RequestSecurityError,
} from "@/lib/request-security";
import { resolveSessionContext } from "@/lib/session";

async function context(request: Request) {
  const session = await auth.api.getSession({ headers: request.headers });
  return session ? resolveSessionContext(session) : null;
}

function errorResponse(error: unknown): Response {
  if (error instanceof RequestSecurityError) {
    const headers = error.retryAfter
      ? { "retry-after": String(error.retryAfter) }
      : undefined;
    return Response.json(
      { error: error.message },
      { status: error.status, headers },
    );
  }
  if (error instanceof IdentityLinkError) {
    const status =
      error.code === "owner_required" ||
      error.code === "owner_resolution_required"
        ? 403
        : 400;
    return Response.json({ error: error.message }, { status });
  }
  console.error("Identity-link request failed.");
  return Response.json(
    { error: "Identity-link request failed." },
    { status: 500 },
  );
}

function string(body: Record<string, unknown>, key: string): string {
  return typeof body[key] === "string" ? body[key] : "";
}

async function objectBody(
  request: Request,
): Promise<Record<string, unknown> | null> {
  const body = await request.json().catch(() => null);
  return body && typeof body === "object" && !Array.isArray(body)
    ? (body as Record<string, unknown>)
    : null;
}

function role(value: unknown): OrgRole | null {
  return isOrgRole(value) ? value : null;
}

export async function POST(request: Request): Promise<Response> {
  try {
    assertSameOrigin(request);
    const ctx = await context(request);
    if (!ctx) {
      return Response.json({ error: "Authentication required." }, { status: 401 });
    }
    const body = await objectBody(request);
    if (!body) {
      return Response.json({ error: "Request body must be an object." }, { status: 400 });
    }
    const operation = string(body, "operation");
    if (operation === "start") {
      const result = await beginIdentityLink(ctx);
      return Response.json(
        {
          challenge: result.token,
          expiresAt: result.expiresAt.toISOString(),
        },
        { status: 201 },
      );
    }
    if (operation === "complete") {
      const result = await completeIdentityLink(ctx, {
        token: string(body, "challenge"),
        currentPassword: string(body, "currentPassword"),
        email: string(body, "email"),
        password: string(body, "password"),
      });
      return Response.json(result, {
        status: result.ownerResolutionRequired ? 202 : 200,
      });
    }
    if (operation === "resolve-role") {
      const resolvedRole = role(body.resolvedRole);
      if (!resolvedRole) {
        return Response.json(
          { error: "Choose one of the existing roles." },
          { status: 400 },
        );
      }
      return Response.json(
        await resolveIdentityRoleConflict(
          ctx,
          string(body, "conflictId"),
          resolvedRole,
        ),
      );
    }
    return Response.json({ error: "Unknown operation." }, { status: 400 });
  } catch (error) {
    return errorResponse(error);
  }
}

export async function DELETE(request: Request): Promise<Response> {
  try {
    assertSameOrigin(request);
    const ctx = await context(request);
    if (!ctx) {
      return Response.json({ error: "Authentication required." }, { status: 401 });
    }
    const body = await objectBody(request);
    if (!body) {
      return Response.json({ error: "Request body must be an object." }, { status: 400 });
    }
    const operation = string(body, "operation");
    const targetUserId = string(body, "identityUserId");
    const currentPassword = string(body, "currentPassword");
    if (operation === "unlink") {
      await unlinkIdentity(ctx, targetUserId, currentPassword);
    } else if (operation === "revoke") {
      await suspendIdentity(ctx, targetUserId, currentPassword);
    } else if (operation === "recover") {
      await recoverIdentity(ctx, targetUserId, currentPassword);
    } else {
      return Response.json({ error: "Unknown operation." }, { status: 400 });
    }
    return new Response(null, { status: 204 });
  } catch (error) {
    return errorResponse(error);
  }
}
