import { NextResponse } from "next/server";
import { ScimError } from "./scim";
import { scimErrorBody } from "./scim-groups-core";

export function scimFailure(error: unknown) {
  if (error instanceof ScimError) {
    return NextResponse.json(scimErrorBody(error.message, error.status), { status: error.status });
  }
  console.error("SCIM request failed:", error instanceof Error ? error.message : error);
  return NextResponse.json(scimErrorBody("SCIM request failed.", 500), { status: 500 });
}
