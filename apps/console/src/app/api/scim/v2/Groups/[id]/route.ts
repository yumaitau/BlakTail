import { NextResponse } from "next/server";
import { organisationForToken } from "@/lib/scim";
import {
  deleteScimGroup,
  getScimGroup,
  patchScimGroup,
  replaceScimGroup,
} from "@/lib/scim-groups";
import { parseGroupPatch, parseScimGroup, scimErrorBody } from "@/lib/scim-groups-core";
import { scimFailure } from "@/lib/scim-http";

type Context = { params: Promise<{ id: string }> };

export async function GET(request: Request, context: Context) {
  try {
    const organisationId = await organisationForToken(request.headers.get("authorization"));
    const { id } = await context.params;
    return NextResponse.json(await getScimGroup(organisationId, id));
  } catch (error) {
    return scimFailure(error);
  }
}

export async function PATCH(request: Request, context: Context) {
  try {
    const organisationId = await organisationForToken(request.headers.get("authorization"));
    const ops = parseGroupPatch(await request.json().catch(() => null));
    if (!ops) {
      return NextResponse.json(
        scimErrorBody(
          "Supported operations: add/remove/replace members, remove members[value eq \"id\"], replace displayName or externalId.",
          400,
          "invalidPath",
        ),
        { status: 400 },
      );
    }
    const { id } = await context.params;
    return NextResponse.json(await patchScimGroup(organisationId, id, ops));
  } catch (error) {
    return scimFailure(error);
  }
}

export async function PUT(request: Request, context: Context) {
  try {
    const organisationId = await organisationForToken(request.headers.get("authorization"));
    const input = parseScimGroup(await request.json().catch(() => null));
    if (!input) {
      return NextResponse.json(
        scimErrorBody("displayName is required and members must be [{ value }].", 400, "invalidValue"),
        { status: 400 },
      );
    }
    const { id } = await context.params;
    return NextResponse.json(await replaceScimGroup(organisationId, id, input));
  } catch (error) {
    return scimFailure(error);
  }
}

export async function DELETE(request: Request, context: Context) {
  try {
    const organisationId = await organisationForToken(request.headers.get("authorization"));
    const { id } = await context.params;
    await deleteScimGroup(organisationId, id);
    return new NextResponse(null, { status: 204 });
  } catch (error) {
    return scimFailure(error);
  }
}
