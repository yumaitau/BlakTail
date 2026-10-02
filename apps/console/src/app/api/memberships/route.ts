import { NextResponse } from "next/server";
import { emitMembershipUpdated } from "@/lib/coord";
import { changeMembership, OidcError } from "@/lib/oidc";
import { AssuranceError, requireSecurityAssurance } from "@/lib/auth-policy";
import { isOrgRole, permissionReason } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

export async function PATCH(request: Request) {
  try {
    const ctx = await requireConsoleContext();
    const body = (await request.json()) as {
      membershipId?: string;
      role?: unknown;
      status?: "active" | "suspended" | "removed";
    };
    if (!body.membershipId) {
      return NextResponse.json({ error: "membershipId is required" }, { status: 400 });
    }
    const role = isOrgRole(body.role) ? body.role : undefined;
    if (body.role !== undefined && !role) {
      return NextResponse.json({ error: "role is not a known role" }, { status: 400 });
    }
    const denied = permissionReason(ctx.role, "manage_security");
    if (denied) {
      return NextResponse.json({ error: denied }, { status: 403 });
    }
    await requireSecurityAssurance(ctx);
    const next = await changeMembership({
      organisationId: ctx.organisationId,
      membershipId: body.membershipId,
      role,
      status: body.status,
      actorUserId: ctx.userId,
      actorEmail: ctx.email,
      actorRole: ctx.role,
    });
    await emitMembershipUpdated(ctx, {
      membership_id: body.membershipId,
      role: next.role,
      status: next.status,
    });
    return NextResponse.json({ ok: true });
  } catch (error) {
    const status =
      error instanceof AssuranceError ? 403 : error instanceof OidcError ? 400 : 500;
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "membership update failed" },
      { status },
    );
  }
}
