import { describe, expect, test } from "bun:test";
import {
  hashScimToken,
  newScimToken,
  parseScimUser,
  patchDeactivates,
  tokenMatches,
  userNameFilter,
} from "../src/lib/scim-core.ts";

describe("scim", () => {
  test("parses a user and treats a missing active flag as enabled", () => {
    const user = parseScimUser({
      userName: "Ranger@Example.org.au",
      name: { formatted: "Ranger One" },
      externalId: "idp-1",
    });
    expect(user).toEqual({
      userName: "ranger@example.org.au",
      displayName: "Ranger One",
      externalId: "idp-1",
      active: true,
    });
  });

  test("rejects a userName that is not an email", () => {
    expect(parseScimUser({ userName: "ranger" })).toBeNull();
  });

  test("reads a SCIM patch that deactivates a user", () => {
    expect(
      patchDeactivates({
        Operations: [{ op: "Replace", path: "active", value: false }],
      }),
    ).toBe(true);
    expect(patchDeactivates({ Operations: [{ op: "replace", value: { active: true } }] })).toBe(
      false,
    );
  });

  test("matches only the hashed bearer token", () => {
    const minted = newScimToken();
    expect(minted.token.startsWith("bts_")).toBe(true);
    expect(tokenMatches(minted.token, minted.hash)).toBe(true);
    expect(tokenMatches(`${minted.token}x`, hashScimToken("other"))).toBe(false);
  });

  test("reads an exact userName filter", () => {
    expect(userNameFilter('userName eq "a@b.c"')).toBe("a@b.c");
    expect(userNameFilter("userName co \"a\"")).toBeNull();
  });
});
