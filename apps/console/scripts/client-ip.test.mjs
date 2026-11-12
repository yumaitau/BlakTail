import { describe, expect, test } from "bun:test";
import { trustedClientAddress, trustedProxyHops } from "../src/lib/client-ip-core.ts";

const headers = (values) => new Headers(values);

describe("trusted proxy hops", () => {
  test("defaults to none and rejects junk", () => {
    expect(trustedProxyHops(undefined)).toBe(0);
    expect(trustedProxyHops("")).toBe(0);
    expect(trustedProxyHops("one")).toBe(0);
    expect(trustedProxyHops("-1")).toBe(0);
    expect(trustedProxyHops("1.5")).toBe(0);
    expect(trustedProxyHops("99")).toBe(0);
    expect(trustedProxyHops("1")).toBe(1);
    expect(trustedProxyHops(" 2 ")).toBe(2);
  });
});

describe("client address", () => {
  test("ignores every forwarding header when no proxy is trusted", () => {
    const request = headers({ "x-forwarded-for": "198.51.100.7", "x-real-ip": "198.51.100.8" });
    expect(trustedClientAddress(request, 0)).toBeNull();
  });

  test("a spoofed left-most X-Forwarded-For entry does not change the key behind one ALB", () => {
    // The ALB appends the address it saw; the client controls everything before it.
    const honest = headers({ "x-forwarded-for": "203.0.113.9" });
    const spoofed = headers({ "x-forwarded-for": "192.0.2.1, 192.0.2.2, 203.0.113.9" });
    expect(trustedClientAddress(honest, 1)).toBe("203.0.113.9");
    expect(trustedClientAddress(spoofed, 1)).toBe("203.0.113.9");
  });

  test("two trusted hops take the second entry from the right", () => {
    const request = headers({ "x-forwarded-for": "192.0.2.1, 203.0.113.9, 10.0.0.5" });
    expect(trustedClientAddress(request, 2)).toBe("203.0.113.9");
  });

  test("a chain shorter than the trusted hops, or junk, is untrusted", () => {
    expect(trustedClientAddress(headers({ "x-forwarded-for": "203.0.113.9" }), 2)).toBeNull();
    expect(trustedClientAddress(headers({ "x-forwarded-for": "not-an-ip" }), 1)).toBeNull();
    expect(trustedClientAddress(headers({ "x-forwarded-for": "" }), 1)).toBeNull();
  });

  test("X-Real-IP counts only behind a trusted proxy and without a forwarded chain", () => {
    expect(trustedClientAddress(headers({ "x-real-ip": "203.0.113.9" }), 1)).toBe("203.0.113.9");
    expect(trustedClientAddress(headers({ "x-real-ip": "203.0.113.9" }), 0)).toBeNull();
    expect(
      trustedClientAddress(
        headers({ "x-forwarded-for": "198.51.100.1", "x-real-ip": "203.0.113.9" }),
        1,
      ),
    ).toBe("198.51.100.1");
    expect(trustedClientAddress(headers({ "x-real-ip": "2001:DB8::1" }), 1)).toBe("2001:db8::1");
  });
});
