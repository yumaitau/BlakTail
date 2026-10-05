// Security headers for every console response. Pure so unit tests can check
// the policy without running Next. Applied by src/proxy.ts.

export type CspOptions = {
  nonce: string;
  dev?: boolean;
  /** Extra connect-src sources, space-separated (BLAKTAIL_CSP_CONNECT_SRC). */
  extraConnectSrc?: string;
};

/**
 * Strict CSP. Scripts need the per-request nonce ('strict-dynamic' lets
 * Next's own chunks load). Styles allow 'unsafe-inline' because React style
 * attributes and the Control Center graph set inline styles; that can't run
 * script. Remote terminal and desktop sessions open a WebSocket to the
 * organisation's remote-access gateway, whose address is configured per
 * organisation, so connect-src allows wss: (encrypted WebSockets only).
 */
export function contentSecurityPolicy({ nonce, dev = false, extraConnectSrc }: CspOptions): string {
  const connect = ["'self'", "wss:"];
  if (dev) connect.push("ws:");
  if (extraConnectSrc) {
    for (const source of extraConnectSrc.split(/\s+/u)) {
      // Only plain origins; never let config widen to '*' or schemes like data:.
      if (/^(https|wss):\/\/[a-z0-9.-]+(:\d+)?$/iu.test(source)) connect.push(source);
    }
  }
  const directives = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    `connect-src ${connect.join(" ")}`,
    "worker-src 'self' blob:",
    "media-src 'self'",
    "object-src 'none'",
    "frame-src 'none'",
    "base-uri 'self'",
    // Single sign-on: the GET form to /api/oidc/start redirects to the
    // organisation's identity provider, and browsers apply form-action to
    // that redirect. Providers are configured per organisation (HTTPS only).
    "form-action 'self' https:",
    "frame-ancestors 'none'",
    "manifest-src 'self'",
  ];
  if (!dev) directives.push("upgrade-insecure-requests");
  return directives.join("; ");
}

export const PERMISSIONS_POLICY = [
  "accelerometer=()",
  "autoplay=()",
  "camera=()",
  "display-capture=()",
  "geolocation=()",
  "gyroscope=()",
  "hid=()",
  "magnetometer=()",
  "microphone=()",
  "midi=()",
  "payment=()",
  "publickey-credentials-get=(self)",
  "serial=()",
  "usb=()",
  "browsing-topics=()",
  // Remote desktop sessions use the clipboard.
  "clipboard-read=(self)",
  "clipboard-write=(self)",
].join(", ");

/** Headers set on every response. HSTS only when the request came over HTTPS. */
export function securityHeaders(options: CspOptions & { https: boolean }): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Security-Policy": contentSecurityPolicy(options),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": PERMISSIONS_POLICY,
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Frame-Options": "DENY",
  };
  if (options.https) {
    headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains";
  }
  return headers;
}
