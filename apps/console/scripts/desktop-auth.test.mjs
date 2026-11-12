import { describe, expect, test } from "bun:test";
import {
  DESKTOP_REDIRECT_URI,
  escapeHtml,
  validDesktopRedirectUri,
} from "../src/lib/desktop-auth-core.ts";

describe("desktop redirect_uri", () => {
  test("accepts exactly the app callback", () => {
    expect(validDesktopRedirectUri("blaktail://auth/callback")).toBe(DESKTOP_REDIRECT_URI);
  });

  test("refuses anything else, including script-breaking payloads", () => {
    for (const value of [
      null,
      undefined,
      "",
      "blaktail://",
      "blaktail://evil",
      "blaktail://auth/callback/",
      "blaktail://auth/callback?x=1",
      "blaktail://auth/callback#token=x",
      "blaktail://user@auth/callback",
      "blaktail://auth:1/callback",
      "BLAKTAIL://auth/callback",
      "blaktail://auth/callback</script><script>alert(1)</script>",
      'blaktail://x"onload=alert(1)',
      "https://auth/callback",
      "javascript:alert(1)",
    ]) {
      expect(validDesktopRedirectUri(value)).toBeNull();
    }
  });

  test("escapes markup characters", () => {
    expect(escapeHtml(`</script><a href="x" onclick='y'>&`)).toBe(
      "&lt;/script&gt;&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;",
    );
  });
});
