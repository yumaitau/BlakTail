import { NextResponse } from "next/server";
import {
  approveNodeRoutes,
  revokeNode,
  updateNodeFriendlyName,
} from "@/lib/coord";
import {
  requireConsoleContextFromSession,
  sessionFromBearer,
} from "@/lib/desktop-auth";
import { can, permissionReason } from "@/lib/roles";
import { OrganisationAccessError } from "@/lib/session";

type RouteContext = {
  params: Promise<{ nodeId: string }>;
};

type UpdateBody =
  | { operation: "rename"; friendlyName?: unknown }
  | { operation: "routes"; approvedRoutes?: unknown };

async function mutationContext(request: Request) {
  const session = await sessionFromBearer(request);
  if (!session) return null;
  const organisationId = request.headers
    .get("x-blaktail-organisation")
    ?.trim();
  if (!organisationId) {
    throw new OrganisationAccessError("Choose a network for this device.");
  }
  return requireConsoleContextFromSession(session, organisationId);
}

function errorResponse(error: unknown, fallback: string): Response {
  const message = error instanceof Error ? error.message : fallback;
  const status =
    error instanceof OrganisationAccessError
      ? 403
      : message.toLowerCase().includes("unauthor")
        ? 401
        : 400;
  return NextResponse.json({ error: message }, { status });
}

export async function PATCH(
  request: Request,
  { params }: RouteContext,
): Promise<Response> {
  try {
    const ctx = await mutationContext(request);
    if (!ctx) {
      return NextResponse.json({ error: "Unauthorised" }, { status: 401 });
    }
    if (!can(ctx.role, "manage_peers")) {
      return NextResponse.json(
        { error: permissionReason(ctx.role, "manage_peers") },
        { status: 403 },
      );
    }

    const { nodeId } = await params;
    if (!nodeId) {
      return NextResponse.json({ error: "Choose a device." }, { status: 400 });
    }
    const body = (await request.json().catch(() => null)) as UpdateBody | null;
    if (body?.operation === "rename") {
      if (
        body.friendlyName !== undefined &&
        typeof body.friendlyName !== "string"
      ) {
        return NextResponse.json(
          { error: "Friendly name must be text." },
          { status: 400 },
        );
      }
      const friendlyName = (body.friendlyName ?? "").trim();
      if ([...friendlyName].length > 64) {
        return NextResponse.json(
          { error: "Friendly names must be 64 characters or fewer." },
          { status: 400 },
        );
      }
      if (/[\u0000-\u001f\u007f]/u.test(friendlyName)) {
        return NextResponse.json(
          { error: "Friendly names cannot contain control characters." },
          { status: 400 },
        );
      }
      await updateNodeFriendlyName(ctx, nodeId, friendlyName);
      return new Response(null, { status: 204 });
    }
    if (body?.operation === "routes") {
      if (
        !Array.isArray(body.approvedRoutes) ||
        body.approvedRoutes.some((route) => typeof route !== "string")
      ) {
        return NextResponse.json(
          { error: "Approved routes must be a list of routes." },
          { status: 400 },
        );
      }
      await approveNodeRoutes(ctx, nodeId, body.approvedRoutes);
      return new Response(null, { status: 204 });
    }

    return NextResponse.json(
      { error: "Choose rename or routes." },
      { status: 400 },
    );
  } catch (error) {
    return errorResponse(error, "Could not update device.");
  }
}

export async function DELETE(
  request: Request,
  { params }: RouteContext,
): Promise<Response> {
  try {
    const ctx = await mutationContext(request);
    if (!ctx) {
      return NextResponse.json({ error: "Unauthorised" }, { status: 401 });
    }
    if (!can(ctx.role, "manage_peers")) {
      return NextResponse.json(
        { error: permissionReason(ctx.role, "manage_peers") },
        { status: 403 },
      );
    }

    const { nodeId } = await params;
    if (!nodeId) {
      return NextResponse.json({ error: "Choose a device." }, { status: 400 });
    }
    await revokeNode(ctx, nodeId);
    return new Response(null, { status: 204 });
  } catch (error) {
    return errorResponse(error, "Could not revoke device.");
  }
}
