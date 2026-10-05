import { errorText, readJsonBodyOr } from "@/lib/server-errors";
import { NextResponse } from "next/server";
import { mintJoinKey, type DeviceTag } from "@/lib/coord";
import {
  requireConsoleContextFromSession,
  sessionFromBearer,
} from "@/lib/desktop-auth";
import { can, permissionReason } from "@/lib/roles";
import {
  activeOrganisationIdFromRequest,
  OrganisationAccessError,
} from "@/lib/session";

function isDeviceTag(value: string): value is DeviceTag {
  return value === "office" || value === "ranger" || value === "store";
}

export async function POST(request: Request) {
  try {
    const session = await sessionFromBearer(request);
    if (!session) {
      return NextResponse.json({ error: "Unauthorised" }, { status: 401 });
    }
    const body = (await readJsonBodyOr(request, ({}))) as {
      organisationId?: string;
      expiresInSeconds?: number;
      singleUse?: boolean;
      tags?: string[];
    };
    const ctx = await requireConsoleContextFromSession(
      session,
      activeOrganisationIdFromRequest(request) ?? body.organisationId,
    );
    if (!can(ctx.role, "manage_join_keys")) {
      return NextResponse.json(
        { error: permissionReason(ctx.role, "manage_join_keys") },
        { status: 403 },
      );
    }
    const tags = (body.tags ?? []).map(String).filter(isDeviceTag);
    const result = await mintJoinKey(ctx, {
      expiresInSeconds: body.expiresInSeconds ?? 600,
      singleUse: body.singleUse ?? true,
      tags,
    });
    const coordinatorUrl = process.env.COORD_BASE_URL?.replace(/\/$/, "");
    if (!coordinatorUrl) {
      return NextResponse.json(
        { error: "COORD_BASE_URL is not configured on the console." },
        { status: 500 },
      );
    }

    return NextResponse.json({
      key: result.key,
      expiresAt: result.expires_at,
      coordinatorUrl,
    });
  } catch (error) {
    const message =
      errorText(error, "Could not mint join key.");
    const status =
      error instanceof OrganisationAccessError
        ? 403
        : message.toLowerCase().includes("unauthor")
          ? 401
          : 400;
    return NextResponse.json({ error: message }, { status });
  }
}
