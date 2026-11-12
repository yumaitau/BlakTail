import { describe, expect, test } from "bun:test";
import {
  OIDC_BINDING_COOKIE_PATH,
  bindingCookie,
  bindingMatches,
  hashBindingSecret,
  newBindingSecret,
  oidcLinkDecision,
  safeRedirectPath,
  sameOriginRedirect,
} from "../src/lib/oidc-flow-core.ts";

describe("oidc browser binding", () => {
  test("the browser that started the sign-in can finish it", () => {
    const { secret, hash } = newBindingSecret();
    expect(hash).toBe(hashBindingSecret(secret));
    expect(bindingMatches(hash, secret)).toBe(true);
  });

  test("a missing or foreign binding cookie is rejected", () => {
    const victim = newBindingSecret();
    const attacker = newBindingSecret();
    expect(bindingMatches(victim.hash, null)).toBe(false);
    expect(bindingMatches(victim.hash, undefined)).toBe(false);
    expect(bindingMatches(victim.hash, "")).toBe(false);
    expect(bindingMatches(victim.hash, attacker.secret)).toBe(false);
    // Presenting the stored hash itself is not the secret.
    expect(bindingMatches(victim.hash, victim.hash)).toBe(false);
    expect(bindingMatches("", victim.secret)).toBe(false);
    expect(bindingMatches(null, victim.secret)).toBe(false);
  });

  test("the cookie is HttpOnly, Lax, scoped to the callback and short-lived", () => {
    const cookie = bindingCookie("fake-binding", true);
    expect(cookie).toMatchObject({
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: OIDC_BINDING_COOKIE_PATH,
      maxAge: 600,
    });
    expect(bindingCookie("fake-binding", false).secure).toBe(false);
    expect(bindingCookie("", true).maxAge).toBe(0);
  });
});

describe("oidc linking", () => {
  const owner = { userId: "user-owner", sessionId: "session-owner" };

  test("an ambient session never turns a plain sign-in into a link", () => {
    expect(
      oidcLinkDecision({ linkUserId: null, linkSessionId: null }, owner),
    ).toEqual({ linkingUserId: null });
    expect(
      oidcLinkDecision({ linkUserId: null, linkSessionId: null }, null),
    ).toEqual({ linkingUserId: null });
  });

  test("an explicit link finishes only in the session that started it", () => {
    const pending = { linkUserId: owner.userId, linkSessionId: owner.sessionId };
    expect(oidcLinkDecision(pending, owner)).toEqual({ linkingUserId: owner.userId });
    expect("refusal" in oidcLinkDecision(pending, null)).toBe(true);
    expect(
      "refusal" in
        oidcLinkDecision(pending, { userId: owner.userId, sessionId: "session-other" }),
    ).toBe(true);
    expect(
      "refusal" in
        oidcLinkDecision(pending, { userId: "user-other", sessionId: owner.sessionId }),
    ).toBe(true);
  });

  test("a half-recorded link fails closed", () => {
    expect(
      "refusal" in oidcLinkDecision({ linkUserId: owner.userId, linkSessionId: null }, owner),
    ).toBe(true);
    expect(
      "refusal" in oidcLinkDecision({ linkUserId: null, linkSessionId: owner.sessionId }, owner),
    ).toBe(true);
  });
});

describe("oidc post-sign-in redirect", () => {
  const origin = "https://console.example.org.au";

  test("keeps same-origin paths", () => {
    expect(safeRedirectPath("/control-center")).toBe("/control-center");
    expect(safeRedirectPath("/enroll?code=ABC-123")).toBe("/enroll?code=ABC-123");
    expect(safeRedirectPath("/settings#identities")).toBe("/settings#identities");
    expect(sameOriginRedirect("/devices?x=1", origin).href).toBe(`${origin}/devices?x=1`);
  });

  test("refuses protocol-relative, backslash, control-character and absolute targets", () => {
    for (const hostile of [
      "//evil.example",
      "/\\evil.example",
      "\\\\evil.example",
      "/\t/evil.example",
      "/\n/evil.example",
      "/\r\n/evil.example",
      "/\u0000/evil.example",
      "https://evil.example/",
      "javascript:alert(1)",
      "evil.example",
      "",
      null,
      undefined,
    ]) {
      expect(safeRedirectPath(hostile)).toBe("/control-center");
      expect(sameOriginRedirect(hostile, origin).origin).toBe(origin);
    }
  });
});
