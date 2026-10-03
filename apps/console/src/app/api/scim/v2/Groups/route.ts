import { NextResponse } from "next/server";
import { organisationForToken } from "@/lib/scim";
import { createScimGroup, listScimGroups } from "@/lib/scim-groups";
import { scimFailure } from "@/lib/scim-http";
import {
  displayNameFilter,
  pagination,
  parseScimGroup,
  scimErrorBody,
} from "@/lib/scim-groups-core";

export async function GET(request: Request) {
  try {
    const organisationId = await organisationForToken(request.headers.get("authorization"));
    const params = new URL(request.url).searchParams;
    const rawFilter = params.get("filter");
    const filter = displayNameFilter(rawFilter);
    if (rawFilter && !filter) {
      return NextResponse.json(
        scimErrorBody('Only displayName eq "name" filters are supported.', 400, "invalidFilter"),
        { status: 400 },
      );
    }
    return NextResponse.json(await listScimGroups(organisationId, filter, pagination(params)));
  } catch (error) {
    return scimFailure(error);
  }
}

export async function POST(request: Request) {
  try {
    const organisationId = await organisationForToken(request.headers.get("authorization"));
    const input = parseScimGroup(await request.json().catch(() => null));
    if (!input) {
      return NextResponse.json(
        scimErrorBody("displayName is required and members must be [{ value }].", 400, "invalidValue"),
        { status: 400 },
      );
    }
    return NextResponse.json(await createScimGroup(organisationId, input), { status: 201 });
  } catch (error) {
    return scimFailure(error);
  }
}
