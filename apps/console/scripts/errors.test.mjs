import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import {
  COORD_ERROR_CODES,
  CoordError,
  authErrorMessage,
  describeError,
  parseCoordEnvelope,
  safeDetail,
  shortRef,
  toUserError,
  userErrorText,
} from "../src/lib/errors.ts";
import {
  PERMISSIONS_POLICY,
  contentSecurityPolicy,
  securityHeaders,
} from "../src/lib/security-headers.ts";

const REQUEST_ID = "3f2a9c21-77aa-4b1e-9d0c-1234567890ab";

function envelope(code, error, status = COORD_ERROR_CODES[code]) {
  return parseCoordEnvelope(
    status,
    JSON.stringify({ error, message: error, code, request_id: REQUEST_ID }),
  );
}

function leaks(message) {
  return /[{}[\]]|request_id|sqlx|database|stack|internal_error|precondition_failed|\bcode\b/iu.test(message);
}

describe("coordinator envelope codes", () => {
  test("every ApiError code in blaktail-coord is covered", () => {
    const source = readFileSync(new URL("../../../blaktail-coord/src/lib.rs", import.meta.url), "utf8");
    const block = source.slice(source.indexOf("let code = match self"), source.indexOf("Json(serde_json::json!({", source.indexOf("let code = match self")));
    const codes = [...block.matchAll(/=> "([a-z_]+)"/gu)].map((match) => match[1]);
    expect(codes.length).toBeGreaterThan(5);
    for (const code of codes) {
      expect(Object.keys(COORD_ERROR_CODES)).toContain(code);
    }
  });

  test("each code maps to a short message that hides internals", () => {
    for (const [code, status] of Object.entries(COORD_ERROR_CODES)) {
      const user = describeError(envelope(code, "database error at sqlx::query", status));
      expect(user.message.length).toBeGreaterThan(10);
      expect(user.message.length).toBeLessThan(200);
      expect(leaks(user.message)).toBe(false);
    }
  });

  test("parses the envelope and takes the reference from request_id", () => {
    const descriptor = envelope("conflict", "conflict: name already in use");
    expect(descriptor).toMatchObject({ status: 409, code: "conflict", requestId: REQUEST_ID });
    const user = describeError(descriptor);
    expect(user.ref).toBe("3F2A9C21");
    expect(user.message).toBe("Name already in use. Reload to see the latest version.");
  });

  test("non-JSON bodies fall back to the status", () => {
    const descriptor = parseCoordEnvelope(502, "<html>Bad gateway</html>");
    expect(descriptor.code).toBeUndefined();
    expect(describeError(descriptor).kind).toBe("unavailable");
  });
});

describe("status fallbacks", () => {
  const cases = [
    [401, "sign_in", /sign in again/iu],
    [403, "permission", /role doesn't allow/iu],
    [404, "not_found", /couldn't find/iu],
    [409, "conflict", /someone else changed this/iu],
    [412, "stale", /changed since the page loaded/iu],
    [413, "too_large", /too large/iu],
    [422, "validation", /check the form/iu],
    [400, "validation", /check the form/iu],
    [429, "rate_limited", /too many requests/iu],
    [500, "server", /went wrong on our side/iu],
    [502, "unavailable", /couldn't reach the coordinator/iu],
    [503, "unavailable", /couldn't reach the coordinator/iu],
    [504, "timeout", /took too long/iu],
  ];
  for (const [status, kind, pattern] of cases) {
    test(`${status} -> ${kind}`, () => {
      const user = describeError({ status });
      expect(user.kind).toBe(kind);
      expect(user.message).toMatch(pattern);
    });
  }

  test("403 names the role", () => {
    expect(describeError({ status: 403 }, { role: "Network admin" }).message).toStartWith(
      "Your network admin role doesn't allow this.",
    );
  });

  test("429 uses Retry-After", () => {
    const user = describeError(parseCoordEnvelope(429, "{}", "30"));
    expect(user.retryAfter).toBe(30);
    expect(user.message).toContain("Try again in 30 seconds.");
    expect(describeError({ status: 429, retryAfter: 600 }).message).toContain("about 10 minutes");
  });

  test("server, network and timeout failures carry a reference", () => {
    for (const descriptor of [{ status: 500 }, { transport: "network" }, { transport: "timeout" }]) {
      const user = describeError(descriptor);
      expect(user.ref).toMatch(/^[0-9A-F]{8}$/u);
      expect(user.retryable).toBe(true);
    }
  });

  test("page-specific overrides win", () => {
    expect(
      describeError({ status: 412 }, { messages: { 412: "Someone else changed this posture check." } })
        .message,
    ).toBe("Someone else changed this posture check.");
  });
});

describe("validation detail", () => {
  test("short plain sentences are shown, capitalised", () => {
    expect(describeError(envelope("bad_request", "org name must not be empty")).message).toBe(
      "Org name must not be empty.",
    );
  });

  test("technical detail is replaced", () => {
    for (const detail of [
      "invalid ACL: unknown field `foo`, expected one of [groups, hosts] at line 3",
      'failed to parse {"a":1}',
      "error returned from database: duplicate key value violates unique constraint",
      "SELECT * FROM nodes WHERE id = $1",
      "BLAKTAIL_AUTH_HMAC_SECRET must be set",
      "x".repeat(400),
    ]) {
      expect(describeError(envelope("bad_request", detail)).message).toBe(
        "Some details weren't accepted. Check the form and try again.",
      );
    }
  });

  test("maps detail onto form fields", () => {
    const user = describeError(envelope("bad_request", "friendly name must be 64 characters or fewer"), {
      fields: { friendlyName: ["friendly name"], tags: ["tag"] },
    });
    expect(user.fieldErrors).toEqual({ friendlyName: "Friendly name must be 64 characters or fewer." });
  });

  test("safeDetail rejects ids, URLs and env names", () => {
    expect(safeDetail("node 3f2a9c21-77aa-4b1e-9d0c-1234567890ab not found")).toBeNull();
    expect(safeDetail("could not reach https://coord.internal:8443")).toBeNull();
    expect(safeDetail("COORD_BASE_URL is required")).toBeNull();
    expect(safeDetail("Choose a device to rename")).toBe("Choose a device to rename.");
  });
});

describe("toUserError", () => {
  test("CoordError keeps its mapped message", () => {
    const error = new CoordError(envelope("forbidden", "permission denied"), { role: "Member" });
    expect(error.message).toMatch(/^Your member role/u);
    expect(toUserError(error, "Could not save.").message).toBe(error.message);
  });

  test("console validation and permission sentences pass through", () => {
    expect(toUserError(new Error("Only owners and admins can manage join keys."), "x").message).toBe(
      "Only owners and admins can manage join keys.",
    );
  });

  test("library, driver and programming errors are hidden behind a reference", () => {
    for (const error of [
      new TypeError("Cannot read properties of undefined (reading 'id')"),
      Object.assign(new Error("Failed query: select * from member where id = $1"), { name: "DrizzleQueryError" }),
      new Error("BETTER_AUTH_SECRET must be at least 32 bytes."),
      new Error("Coordinator returned 500"),
      "a string",
      null,
    ]) {
      const user = toUserError(error, "Could not save the policy");
      expect(user.message).toStartWith("Could not save the policy. Try again");
      expect(user.ref).toMatch(/^[0-9A-F]{8}$/u);
    }
  });

  test("fetch failures and timeouts become coordinator messages", () => {
    const network = Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNREFUSED" } });
    expect(toUserError(network, "x").kind).toBe("network");
    const timeout = Object.assign(new Error("The operation timed out."), { name: "TimeoutError" });
    expect(toUserError(timeout, "x").kind).toBe("timeout");
  });

  test("userErrorText appends the reference", () => {
    expect(userErrorText(describeError({ status: 503, }))).toMatch(/Reference [0-9A-F]{8}\.$/u);
    expect(userErrorText({ kind: "validation", message: "Name is required.", retryable: false })).toBe(
      "Name is required.",
    );
  });

  test("shortRef is 8 hex characters", () => {
    expect(shortRef(REQUEST_ID)).toBe("3F2A9C21");
    expect(shortRef()).toMatch(/^[0-9A-F]{8}$/u);
    expect(shortRef("nope")).toMatch(/^[0-9A-F]{8}$/u);
  });
});

describe("authErrorMessage", () => {
  test("wrong current password", () => {
    expect(authErrorMessage({ status: 400, code: "INVALID_PASSWORD", message: "Invalid password" }, "x").message).toBe(
      "Your current password isn't right. Check it and try again.",
    );
  });

  test("rate limits and server errors", () => {
    expect(authErrorMessage({ status: 429 }, "x").kind).toBe("rate_limited");
    expect(authErrorMessage({ status: 500, message: "Internal" }, "x").kind).toBe("server");
  });

  test("unknown codes use the fallback, never the raw message", () => {
    expect(authErrorMessage({ status: 400, code: "SOMETHING_NEW", message: "raw internal text" }, "Your password wasn't changed.").message).toBe(
      "Your password wasn't changed.",
    );
  });
});

describe("security headers", () => {
  const csp = contentSecurityPolicy({ nonce: "abc123" });

  test("CSP is strict", () => {
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self' 'nonce-abc123' 'strict-dynamic'");
    expect(csp).not.toContain("unsafe-eval");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'self'");
    expect(csp).not.toMatch(/script-src[^;]*unsafe-inline/u);
    expect(csp).not.toMatch(/\*/u);
  });

  test("dev allows eval and ws for hot reload only", () => {
    const dev = contentSecurityPolicy({ nonce: "n", dev: true });
    expect(dev).toContain("'unsafe-eval'");
    expect(dev).toContain("ws:");
    expect(csp).not.toMatch(/\bws:/u);
  });

  test("extra connect sources accept only plain origins", () => {
    const extra = contentSecurityPolicy({
      nonce: "n",
      extraConnectSrc: "https://gw.example.org wss://gw.example.org:8443 * data: javascript:alert(1)",
    });
    expect(extra).toContain("connect-src 'self' wss: https://gw.example.org wss://gw.example.org:8443;");
  });

  test("other headers", () => {
    const headers = securityHeaders({ nonce: "n", https: true });
    expect(headers["Strict-Transport-Security"]).toContain("max-age=");
    expect(headers["X-Content-Type-Options"]).toBe("nosniff");
    expect(headers["Referrer-Policy"]).toBe("strict-origin-when-cross-origin");
    expect(headers["Cross-Origin-Opener-Policy"]).toBe("same-origin");
    expect(PERMISSIONS_POLICY).toContain("camera=()");
    expect(PERMISSIONS_POLICY).toContain("microphone=()");
    expect(PERMISSIONS_POLICY).toContain("geolocation=()");
    expect(securityHeaders({ nonce: "n", https: false })["Strict-Transport-Security"]).toBeUndefined();
  });
});
