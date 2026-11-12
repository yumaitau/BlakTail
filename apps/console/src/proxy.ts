import { NextResponse, type NextRequest } from "next/server";
import { contentSecurityPolicy, securityHeaders } from "@/lib/security-headers";
import {
  CLIENT_IP_HEADER,
  trustedClientAddress,
  trustedProxyHops,
} from "@/lib/client-ip-core";

/**
 * Adds a per-request CSP nonce and the security headers to every response.
 * Next reads the nonce from the request's CSP header and stamps it on its own
 * scripts; the root layout reads headers so every page renders dynamically
 * (a static page can't carry a per-request nonce).
 */
export function proxy(request: NextRequest) {
  const nonce = btoa(crypto.randomUUID());
  const dev = process.env.NODE_ENV === "development";
  const https =
    request.nextUrl.protocol === "https:" ||
    request.headers.get("x-forwarded-proto")?.split(",")[0]?.trim() === "https";
  const options = {
    nonce,
    dev,
    https,
    extraConnectSrc: process.env.BLAKTAIL_CSP_CONNECT_SRC,
  };

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  // Better Auth rate limits and records sessions by this header only; a
  // client-sent value is always replaced.
  requestHeaders.delete(CLIENT_IP_HEADER);
  const clientAddress = trustedClientAddress(
    request.headers,
    trustedProxyHops(process.env.BLAKTAIL_TRUSTED_PROXY_HOPS),
  );
  if (clientAddress) requestHeaders.set(CLIENT_IP_HEADER, clientAddress);
  requestHeaders.set("Content-Security-Policy", contentSecurityPolicy(options));

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  for (const [name, value] of Object.entries(securityHeaders(options))) {
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
