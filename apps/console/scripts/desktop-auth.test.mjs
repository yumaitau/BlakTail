import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import {
  DESKTOP_CODE_PREFIX,
  DESKTOP_CODE_TTL_SECONDS,
  DESKTOP_CREDENTIAL_PREFIX,
  DESKTOP_REDIRECT_URI,
  codeExpiresAt,
  codeRedeemable,
  credentialUsable,
  desktopBearer,
  desktopCallbackUrl,
  escapeHtml,
  hashDesktopSecret,
  newDesktopSecret,
  parseAuthoriseRequest,
  s256Challenge,
  validDesktopRedirectUri,
  verifyS256,
} from "../src/lib/desktop-auth-core.ts";

const VERIFIER = "fake-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";
// Computed independently with WebCrypto + manual base64url, as the apps do.
const digest = new Uint8Array(
  await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER)),
);
const CHALLENGE = btoa(String.fromCharCode(...digest))
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/, "");
const STATE = "fake-state-0123456789";

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

describe("desktop PKCE", () => {
  test("S256 is base64url(SHA-256(verifier)) without padding", () => {
    expect(s256Challenge(VERIFIER)).toBe(CHALLENGE);
    expect(verifyS256(VERIFIER, CHALLENGE)).toBe(true);
  });

  test("rejects a wrong, short or non-string verifier", () => {
    expect(verifyS256(`${VERIFIER.slice(0, -1)}y`, CHALLENGE)).toBe(false);
    expect(verifyS256("short", s256Challenge("short"))).toBe(false);
    expect(verifyS256(undefined, CHALLENGE)).toBe(false);
    expect(verifyS256(VERIFIER, "not-a-challenge")).toBe(false);
  });

  test("parses a valid authorise request and refuses plain or missing PKCE", () => {
    const good = {
      redirect_uri: DESKTOP_REDIRECT_URI,
      state: STATE,
      code_challenge: CHALLENGE,
      code_challenge_method: "S256",
    };
    expect(parseAuthoriseRequest(good)).toEqual({
      redirectUri: DESKTOP_REDIRECT_URI,
      state: STATE,
      codeChallenge: CHALLENGE,
    });
    expect("error" in parseAuthoriseRequest({ ...good, code_challenge_method: "plain" })).toBe(true);
    expect("error" in parseAuthoriseRequest({ ...good, code_challenge: undefined })).toBe(true);
    expect("error" in parseAuthoriseRequest({ ...good, state: "short" })).toBe(true);
    expect("error" in parseAuthoriseRequest({ ...good, state: "bad state with spaces!" })).toBe(true);
    expect("error" in parseAuthoriseRequest({ ...good, redirect_uri: "blaktail://evil" })).toBe(true);
    expect("error" in parseAuthoriseRequest(null)).toBe(true);
  });

  test("callback URL carries only code and state", () => {
    const url = new URL(desktopCallbackUrl(DESKTOP_REDIRECT_URI, "btc_fake", STATE));
    expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(DESKTOP_REDIRECT_URI);
    expect([...url.searchParams.keys()]).toEqual(["code", "state"]);
    expect(url.searchParams.get("code")).toBe("btc_fake");
    expect(url.hash).toBe("");
  });
});

describe("desktop codes and credentials", () => {
  test("codes last 60 seconds and are single use", () => {
    expect(DESKTOP_CODE_TTL_SECONDS).toBe(60);
    const now = new Date("2026-01-01T00:00:00Z");
    const expiresAt = codeExpiresAt(now);
    expect(expiresAt.getTime() - now.getTime()).toBe(60_000);
    expect(codeRedeemable({ expiresAt, usedAt: null }, now)).toBe(true);
    expect(codeRedeemable({ expiresAt, usedAt: now }, now)).toBe(false);
    expect(codeRedeemable({ expiresAt, usedAt: null }, new Date(now.getTime() + 60_000))).toBe(
      false,
    );
  });

  test("secrets are random, prefixed and stored as hashes", () => {
    const a = newDesktopSecret(DESKTOP_CODE_PREFIX);
    const b = newDesktopSecret(DESKTOP_CODE_PREFIX);
    expect(a.secret.startsWith("btc_")).toBe(true);
    expect(a.secret).not.toBe(b.secret);
    expect(a.hash).toBe(hashDesktopSecret(a.secret));
    expect(a.hash).not.toContain(a.secret);
  });

  test("a credential dies when revoked, expired or its approving session ends", () => {
    const now = new Date("2026-01-01T00:00:00Z");
    const later = new Date(now.getTime() + 1000);
    const live = { revokedAt: null, expiresAt: later, sessionExpiresAt: later };
    expect(credentialUsable(live, now)).toBe(true);
    expect(credentialUsable({ ...live, revokedAt: now }, now)).toBe(false);
    expect(credentialUsable({ ...live, expiresAt: now }, now)).toBe(false);
    expect(credentialUsable({ ...live, sessionExpiresAt: now }, now)).toBe(false);
    expect(credentialUsable({ ...live, sessionExpiresAt: null }, now)).toBe(false);
  });

  test("only desktop credentials are accepted as Bearer, never browser session tokens", () => {
    const { secret } = newDesktopSecret(DESKTOP_CREDENTIAL_PREFIX);
    expect(desktopBearer(`Bearer ${secret}`)).toBe(secret);
    expect(desktopBearer(`bearer ${secret}`)).toBe(secret);
    expect(desktopBearer("Bearer fake-browser-session-token.signature")).toBeNull();
    expect(desktopBearer(`Bearer ${newDesktopSecret(DESKTOP_CODE_PREFIX).secret}`)).toBeNull();
    expect(desktopBearer(null)).toBeNull();
    expect(desktopBearer("Basic abc")).toBeNull();
  });
});

describe("desktop sign-in wiring", () => {
  const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");

  test("no route echoes the browser session token", () => {
    const authorise = read("../src/app/api/desktop/auth/authorize/route.ts");
    const token = read("../src/app/api/desktop/auth/token/route.ts");
    const bridge = read("../src/lib/desktop-auth.ts");
    for (const source of [authorise, token, bridge]) {
      expect(source).not.toContain("session_token");
      expect(source).not.toMatch(/session\.session\.token/);
    }
    expect(authorise).toContain("assertSameOrigin(request)");
  });

  test("the migration stores hashes bound to the approving session", () => {
    const sql = read("../drizzle/0012_desktop_credential.sql");
    expect(sql).toContain("code_hash text NOT NULL UNIQUE");
    expect(sql).toContain("token_hash text NOT NULL UNIQUE");
    expect(sql.match(/REFERENCES session\(id\) ON DELETE CASCADE/g)?.length).toBe(2);
  });
});
