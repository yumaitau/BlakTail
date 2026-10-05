import { errorText } from "@/lib/server-errors";
import { NextResponse } from "next/server";
import {
  requirePersonContextFromSession,
  sessionFromBearer,
} from "@/lib/desktop-auth";
import { activeOrganisationIdFromRequest } from "@/lib/session";

export async function GET(request: Request) {
  try {
    const session = await sessionFromBearer(request);
    if (!session) {
      return NextResponse.json({ error: "Unauthorised" }, { status: 401 });
    }
    const ctx = await requirePersonContextFromSession(session);
    const requestedOrganisationId = activeOrganisationIdFromRequest(request);
    const primary =
      ctx.organisations.find(
        (organisation) =>
          organisation.organisationId === requestedOrganisationId,
      ) ?? ctx.organisations[0]!;
    return NextResponse.json({
      email: ctx.email,
      organisationId: primary.organisationId,
      organisationName: primary.organisationName,
      role: primary.role,
      organisations: ctx.organisations.map((organisation) => ({
        id: organisation.organisationId,
        name: organisation.organisationName,
        role: organisation.role,
        networkAccounts: organisation.networkAccountIds.map((id, index) => ({
          id,
          name:
            organisation.networkAccountNames[index] ??
            organisation.organisationName,
        })),
      })),
      blockedOrganisations: ctx.blockedOrganisations,
      coordinatorUrl: process.env.COORD_BASE_URL?.replace(/\/$/, "") ?? null,
    });
  } catch (error) {
    const message =
      errorText(error, "Could not load desktop session.");
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
