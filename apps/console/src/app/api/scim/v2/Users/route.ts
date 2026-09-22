import { NextResponse } from "next/server";
import { ScimError, listScimUsers, organisationForToken, provisionScimUser } from "@/lib/scim";
import { parseScimUser, userNameFilter } from "@/lib/scim-core";

function scimError(error: unknown) {
  if (error instanceof ScimError) {
    return NextResponse.json(
      { schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], detail: error.message },
      { status: error.status },
    );
  }
  return NextResponse.json(
    { schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], detail: "SCIM request failed." },
    { status: 500 },
  );
}

export async function GET(request: Request) {
  try {
    const organisationId = await organisationForToken(request.headers.get("authorization"));
    const filter = userNameFilter(new URL(request.url).searchParams.get("filter"));
    if (new URL(request.url).searchParams.get("filter") && !filter) {
      return NextResponse.json(
        {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
          detail: 'Only userName eq "email" filters are supported.',
        },
        { status: 400 },
      );
    }
    return NextResponse.json(await listScimUsers(organisationId, filter));
  } catch (error) {
    return scimError(error);
  }
}

export async function POST(request: Request) {
  try {
    const organisationId = await organisationForToken(request.headers.get("authorization"));
    const input = parseScimUser(await request.json());
    if (!input) {
      return NextResponse.json(
        {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
          detail: "userName must be an email address.",
        },
        { status: 400 },
      );
    }
    const created = await provisionScimUser(organisationId, input);
    return NextResponse.json(created, { status: 201 });
  } catch (error) {
    return scimError(error);
  }
}
