import { errorText, readJsonBody } from "@/lib/server-errors";
import {
  createWgOnlyPeer,
  listAllWgOnlyPeers,
  rotateWgOnlyPeer,
  revokeWgOnlyPeer,
  type DeviceTag,
} from "@/lib/coord";
import { can, permissionReason } from "@/lib/roles";
import {
  assertSameOrigin,
  RequestSecurityError,
} from "@/lib/request-security";
import { auth } from "@/lib/auth";
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
    {
      error:
        errorText(error, "Unmanaged peer request failed."),
    },
    { status: 400 },
  );
}

function deviceTag(value: unknown): value is DeviceTag {
  return value === "office" || value === "ranger" || value === "store";
}

export async function GET(request: Request): Promise<Response> {
  try {
    const ctx = await context(request);
    if (!ctx) {
      return Response.json({ error: "Authentication required." }, { status: 401 });
    }
    const inventory = await listAllWgOnlyPeers(ctx);
    return Response.json({
      peers: inventory.peers,
      errors: inventory.errors,
    });
  } catch (error) {
    return errorResponse(error);
  }
}

export async function POST(request: Request): Promise<Response> {
  try {
    assertSameOrigin(request);
    const person = await context(request);
    if (!person) {
      return Response.json({ error: "Authentication required." }, { status: 401 });
    }
    const body = (await readJsonBody(request)) as Record<string, unknown>;
    const organisationId =
      typeof body.organisationId === "string" ? body.organisationId : "";
    const ctx = organisationContext(person, organisationId);
    if (!can(ctx.role, "manage_peers")) {
      return Response.json(
        { error: permissionReason(ctx.role, "manage_peers") },
        { status: 403 },
      );
    }
    const name = typeof body.name === "string" ? body.name.trim() : "";
    const wgPublicKey =
      typeof body.wgPublicKey === "string" ? body.wgPublicKey.trim() : "";
    const endpoint =
      typeof body.endpoint === "string" ? body.endpoint.trim() : "";
    const allowedIps = Array.isArray(body.allowedIps)
      ? body.allowedIps.filter(
          (item): item is string => typeof item === "string" && Boolean(item.trim()),
        )
      : [];
    const tags = Array.isArray(body.tags) ? body.tags.filter(deviceTag) : [];
    if (!name || !wgPublicKey || !endpoint || allowedIps.length === 0) {
      return Response.json(
        { error: "Name, public key, endpoint, and AllowedIPs are required." },
        { status: 400 },
      );
    }
    const peer = await createWgOnlyPeer(ctx, {
      name,
      wg_public_key: wgPublicKey,
      endpoint,
      allowed_ips: allowedIps,
      tags,
    });
    return Response.json({
      ...peer,
      organisation_id: ctx.organisationId,
      organisation_name: ctx.organisationName,
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
    const body = (await readJsonBody(request)) as Record<string, unknown>;
    const organisationId =
      typeof body.organisationId === "string" ? body.organisationId : "";
    const peerId = typeof body.peerId === "string" ? body.peerId : "";
    const wgPublicKey =
      typeof body.wgPublicKey === "string" ? body.wgPublicKey.trim() : "";
    const overlapSeconds =
      typeof body.overlapSeconds === "number" ? body.overlapSeconds : 300;
    const ctx = organisationContext(person, organisationId);
    if (!can(ctx.role, "manage_peers")) {
      return Response.json(
        { error: permissionReason(ctx.role, "manage_peers") },
        { status: 403 },
      );
    }
    if (!peerId || !wgPublicKey) {
      return Response.json(
        { error: "Peer and new public key are required." },
        { status: 400 },
      );
    }
    const peer = await rotateWgOnlyPeer(ctx, peerId, {
      wg_public_key: wgPublicKey,
      overlap_seconds: overlapSeconds,
    });
    return Response.json({
      ...peer,
      organisation_id: ctx.organisationId,
      organisation_name: ctx.organisationName,
    });
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
    const body = (await readJsonBody(request)) as Record<string, unknown>;
    const organisationId =
      typeof body.organisationId === "string" ? body.organisationId : "";
    const peerId = typeof body.peerId === "string" ? body.peerId : "";
    const ctx = organisationContext(person, organisationId);
    if (!can(ctx.role, "manage_peers")) {
      return Response.json(
        { error: permissionReason(ctx.role, "manage_peers") },
        { status: 403 },
      );
    }
    await revokeWgOnlyPeer(ctx, peerId);
    return new Response(null, { status: 204 });
  } catch (error) {
    return errorResponse(error);
  }
}
