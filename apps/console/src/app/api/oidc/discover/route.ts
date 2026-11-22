import { NextResponse } from "next/server";
import { discoverSso } from "@/lib/sso";
import {
  RequestSecurityError,
  consumeRateLimit,
  requestRateLimitIdentity,
} from "@/lib/request-security";

export async function GET(request: Request) {
  try {
    // Unauthenticated and answers "does this domain use SSO", so bounded.
    await consumeRateLimit(`oidc:discover:${requestRateLimitIdentity(request)}`, 60, 60);
  } catch (error) {
    if (error instanceof RequestSecurityError) {
      return NextResponse.json(
        { error: error.message },
        { status: error.status, headers: { "retry-after": String(error.retryAfter ?? 60) } },
      );
    }
    throw error;
  }
  const email = new URL(request.url).searchParams.get("email") ?? "";
  const match = await discoverSso(email);
  if (!match) {
    return NextResponse.json({ organisationId: null });
  }
  return NextResponse.json(match);
}
