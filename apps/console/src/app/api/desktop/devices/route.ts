import { errorText } from "@/lib/server-errors";
import { NextResponse } from "next/server";
import { listNodes } from "@/lib/coord";
import {
  requireConsoleContextFromSession,
  sessionFromBearer,
} from "@/lib/desktop-auth";
import { can } from "@/lib/roles";
import { contextForOrganisation } from "@/lib/session";

export async function GET(request: Request): Promise<Response> {
  try {
    const session = await sessionFromBearer(request);
    if (!session) {
      return NextResponse.json({ error: "Unauthorised" }, { status: 401 });
    }

    const ctx = await requireConsoleContextFromSession(session);
    const inventories = await Promise.all(
      ctx.organisations.map(async (organisation) => {
        const organisationContext = contextForOrganisation(
          ctx,
          organisation.organisationId,
        );
        try {
          const devices = await listNodes(organisationContext);
          return {
            devices: devices.map((device) => ({
              ...device,
              organisation_id: organisation.organisationId,
              organisation_name: organisation.organisationName,
              can_mutate: can(organisation.role, "manage_peers"),
            })),
            error: null,
          };
        } catch (error) {
          return {
            devices: [],
            error: `${organisation.organisationName}: ${
              errorText(error, "Could not load devices.")
            }`,
          };
        }
      }),
    );

    return NextResponse.json({
      devices: inventories
        .flatMap((inventory) => inventory.devices)
        .sort(
          (left, right) =>
            left.organisation_name.localeCompare(right.organisation_name) ||
            (left.display_name || left.name).localeCompare(
              right.display_name || right.name,
            ),
        ),
      errors: inventories.flatMap((inventory) =>
        inventory.error ? [inventory.error] : [],
      ),
    });
  } catch (error) {
    const message =
      errorText(error, "Could not load devices.");
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
