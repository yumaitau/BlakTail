import "server-only";

import { createHash, randomUUID } from "node:crypto";
import { rawSqlClient } from "./db/client";

export class RequestSecurityError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly retryAfter?: number,
  ) {
    super(message);
  }
}

function trustedOrigins(): Set<string> {
  const configured =
    process.env.BETTER_AUTH_TRUSTED_ORIGINS ??
    process.env.BETTER_AUTH_URL ??
    "http://localhost:3000";
  return new Set(
    configured
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean)
      .map((value) => new URL(value).origin),
  );
}

export function assertSameOrigin(request: Request): void {
  assertTrustedOrigin(request);
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    throw new RequestSecurityError("JSON content type is required.", 415);
  }
}

/** Origin check alone, for plain HTML form posts. */
export function assertTrustedOrigin(request: Request): void {
  const origin = request.headers.get("origin");
  if (!origin) {
    throw new RequestSecurityError("Request origin is required.", 403);
  }
  let parsed: string;
  try {
    parsed = new URL(origin).origin;
  } catch {
    throw new RequestSecurityError("Request origin is not allowed.", 403);
  }
  if (!trustedOrigins().has(parsed)) {
    throw new RequestSecurityError("Request origin is not allowed.", 403);
  }
}

export function requestRateLimitIdentity(request: Request): string {
  const forwarded = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  const address = forwarded || request.headers.get("x-real-ip") || "unknown";
  return createHash("sha256").update(address.slice(0, 128)).digest("hex");
}

export async function consumeRateLimit(
  key: string,
  windowSeconds: number,
  maximum: number,
): Promise<void> {
  const now = Date.now();
  const windowMilliseconds = windowSeconds * 1000;
  const sql = rawSqlClient();
  const [row] = await sql`
    INSERT INTO rate_limit (id, key, count, last_request)
    VALUES (${randomUUID()}, ${key}, 1, ${now})
    ON CONFLICT (key) DO UPDATE SET
      count = CASE
        WHEN ${now} - rate_limit.last_request >= ${windowMilliseconds} THEN 1
        ELSE rate_limit.count + 1
      END,
      last_request = CASE
        WHEN ${now} - rate_limit.last_request >= ${windowMilliseconds} THEN ${now}
        ELSE rate_limit.last_request
      END
    RETURNING count, last_request
  `;
  if (row.count > maximum) {
    const retryAfter = Math.max(
      1,
      Math.ceil((row.last_request + windowMilliseconds - now) / 1000),
    );
    throw new RequestSecurityError(
      "Too many requests. Try again later.",
      429,
      retryAfter,
    );
  }
}
