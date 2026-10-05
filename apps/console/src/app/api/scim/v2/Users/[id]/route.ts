import { SCIM_BODY_LIMIT, readJsonBody } from "@/lib/server-errors";
import { NextResponse } from "next/server";
import { getScimUser, organisationForToken, ScimError, setScimActive } from "@/lib/scim";
import { patchDeactivates } from "@/lib/scim-core";

function scimError(error: unknown) {
  if (error instanceof ScimError) {
    return NextResponse.json(
      { schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], detail: error.message },
      { status: error.status },
    );
  }
  console.error("SCIM request failed:", error instanceof Error ? error.message : error);
  return NextResponse.json(
    { schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], detail: "SCIM request failed." },
    { status: 500 },
  );
}

export async function GET(
  request: Request,
  context: { params: Promise<{ id: string }> },
) {
  try {
    const organisationId = await organisationForToken(request.headers.get("authorization"));
    const { id } = await context.params;
    return NextResponse.json(await getScimUser(organisationId, id));
  } catch (error) {
    return scimError(error);
  }
}

export async function PATCH(
  request: Request,
  context: { params: Promise<{ id: string }> },
) {
  try {
    const organisationId = await organisationForToken(request.headers.get("authorization"));
    const deactivates = patchDeactivates(await readJsonBody(request, SCIM_BODY_LIMIT));
    if (deactivates === null) {
      return NextResponse.json(
        {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
          detail: "Only a replace of active is supported.",
        },
        { status: 400 },
      );
    }
    const { id } = await context.params;
    return NextResponse.json(await setScimActive(organisationId, id, !deactivates));
  } catch (error) {
    return scimError(error);
  }
}

/** RFC 7644 DELETE: deprovision with the organisation's grace period. */
export async function DELETE(
  request: Request,
  context: { params: Promise<{ id: string }> },
) {
  try {
    const organisationId = await organisationForToken(request.headers.get("authorization"));
    const { id } = await context.params;
    await setScimActive(organisationId, id, false);
    return new NextResponse(null, { status: 204 });
  } catch (error) {
    return scimError(error);
  }
}
