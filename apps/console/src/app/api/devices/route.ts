import { auth } from "@/lib/auth";
import {
  approveNodeRoutes,
  listAllNodes,
  revokeNode,
  updateNodeFriendlyName,
} from "@/lib/coord";
import { can, permissionReason } from "@/lib/roles";
import {
  assertSameOrigin,
  RequestSecurityError,
} from "@/lib/request-security";
import {
  organisationContext,
  resolveSessionContext,
  type PersonSessionContext,
} from "@/lib/session";

async function context(request: Request): Promise<PersonSessionContext | null> {
  const session = await auth.api.getSession({ headers: request.headers });
  return session ? resolveSessionContext(session) : null;
}

function errorResponse(error: unknown): Response {
  if (error instanceof RequestSecurityError) {
    return Response.json({ error: error.message }, { status: error.status });
  }
  return Response.json(
    { error: error instanceof Error ? error.message : "Device request failed." },
    { status: 400 },
  );
}

export async function GET(request: Request): Promise<Response> {
  try {
    const ctx = await context(request);
    if (!ctx) {
      return Response.json({ error: "Authentication required." }, { status: 401 });
    }
    const inventory = await listAllNodes(ctx);
    return Response.json({
      devices: inventory.nodes,
      errors: inventory.errors,
      blockedOrganisations: ctx.blockedOrganisations,
    });
  } catch (error) {
    return errorResponse(error);
  }
}

export async function PATCH(request: Request): Promise<Response> {
  try {
    assertSameOrigin(request);
    const person = await context(request);
    if (!person) {
      return Response.json({ error: "Authentication required." }, { status: 401 });
    }
    const body = (await request.json()) as Record<string, unknown>;
    const organisationId =
      typeof body.organisationId === "string" ? body.organisationId : "";
    const nodeId = typeof body.nodeId === "string" ? body.nodeId : "";
    const operation = typeof body.operation === "string" ? body.operation : "";
    const ctx = organisationContext(person, organisationId);
    if (!can(ctx.role, "manage_peers")) {
      return Response.json(
        { error: permissionReason(ctx.role, "manage_peers") },
        { status: 403 },
      );
    }
    if (operation === "rename") {
      const friendlyName =
        typeof body.friendlyName === "string" ? body.friendlyName.trim() : "";
      if ([...friendlyName].length > 64) {
        return Response.json(
          { error: "Friendly names must be 64 characters or fewer." },
          { status: 400 },
        );
      }
      await updateNodeFriendlyName(ctx, nodeId, friendlyName);
    } else if (operation === "approve-routes") {
      const routesDenied = permissionReason(ctx.role, "manage_networks");
      if (routesDenied) {
        return Response.json({ error: routesDenied }, { status: 403 });
      }
      const routes = Array.isArray(body.approvedRoutes)
        ? body.approvedRoutes.filter(
            (route): route is string => typeof route === "string",
          )
        : [];
      await approveNodeRoutes(ctx, nodeId, routes);
    } else {
      return Response.json({ error: "Unknown operation." }, { status: 400 });
    }
    return new Response(null, { status: 204 });
  } catch (error) {
    return errorResponse(error);
  }
}

export async function DELETE(request: Request): Promise<Response> {
  try {
    assertSameOrigin(request);
    const person = await context(request);
    if (!person) {
      return Response.json({ error: "Authentication required." }, { status: 401 });
    }
    const body = (await request.json()) as Record<string, unknown>;
    const organisationId =
      typeof body.organisationId === "string" ? body.organisationId : "";
    const nodeId = typeof body.nodeId === "string" ? body.nodeId : "";
    const ctx = organisationContext(person, organisationId);
    if (!can(ctx.role, "manage_peers")) {
      return Response.json(
        { error: permissionReason(ctx.role, "manage_peers") },
        { status: 403 },
      );
    }
    await revokeNode(ctx, nodeId);
    return new Response(null, { status: 204 });
  } catch (error) {
    return errorResponse(error);
  }
}
