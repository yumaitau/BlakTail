import { NextResponse, type NextRequest } from "next/server";
import { contentSecurityPolicy, securityHeaders } from "@/lib/security-headers";

/**
 * Adds a per-request CSP nonce and the security headers to every response.
 * Next reads the nonce from the request's CSP header and stamps it on its own
 * scripts; the root layout reads headers so every page renders dynamically
 * (a static page can't carry a per-request nonce).
 */
export function proxy(request: NextRequest) {
  const nonce = btoa(crypto.randomUUID());
  const dev = process.env.NODE_ENV === "development";
  const options = {
    nonce,
    dev,
    extraConnectSrc: process.env.BLAKTAIL_CSP_CONNECT_SRC,
  };
  const https =
    request.nextUrl.protocol === "https:" ||
    request.headers.get("x-forwarded-proto")?.split(",")[0]?.trim() === "https";

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", contentSecurityPolicy(options));

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  for (const [name, value] of Object.entries(securityHeaders({ ...options, https }))) {
    response.headers.set(name, value);
  }
  return response;
}

export const config = {
  matcher: [
    // Everything except build assets, which carry their own immutable caching.
    "/((?!_next/static|_next/image|favicon.ico).*)",
  ],
};
