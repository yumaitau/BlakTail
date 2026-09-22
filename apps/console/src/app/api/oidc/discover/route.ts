import { NextResponse } from "next/server";
import { discoverSso } from "@/lib/sso";

export async function GET(request: Request) {
  const email = new URL(request.url).searchParams.get("email") ?? "";
  const match = await discoverSso(email);
  if (!match) {
    return NextResponse.json({ organisationId: null });
  }
  return NextResponse.json(match);
}
