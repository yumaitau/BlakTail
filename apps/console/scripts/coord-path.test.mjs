import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { idSegment } from "../src/lib/coord-path-core.ts";

describe("coordinator path IDs", () => {
  test("accepts coordinator UUIDs", () => {
    const id = "6f1d0c2e-9b7a-4c3d-8e5f-0a1b2c3d4e5f";
    expect(idSegment(id)).toBe(id);
    expect(idSegment(id.toUpperCase())).toBe(id.toUpperCase());
  });

  test("refuses anything that could reach another route", () => {
    for (const hostile of [
      "../acl",
      "6f1d0c2e-9b7a-4c3d-8e5f-0a1b2c3d4e5f/../../acl",
      "6f1d0c2e-9b7a-4c3d-8e5f-0a1b2c3d4e5f?x=1",
      "6f1d0c2e-9b7a-4c3d-8e5f-0a1b2c3d4e5f#x",
      "%2e%2e",
      "",
      " 6f1d0c2e-9b7a-4c3d-8e5f-0a1b2c3d4e5f",
      null,
      undefined,
      42,
    ]) {
      expect(() => idSegment(hostile)).toThrow("not valid");
    }
  });

  test("coord.ts never interpolates a raw ID into a coordinator path", () => {
    const source = readFileSync(new URL("../src/lib/coord.ts", import.meta.url), "utf8");
    const paths = source.match(/`\/v1\/orgs\/[^`]*`/g) ?? [];
    expect(paths.length).toBeGreaterThan(10);
    for (const path of paths) {
      const raw = [...path.matchAll(/\$\{([^}]+)\}/g)]
        .map((match) => match[1])
        .filter((expr) => expr !== "ctx.coordOrgId" && !/^(idSegment|encodeURIComponent)\(/.test(expr))
        .filter((expr) => !/^(query|suffix|params\.toString\(\))/.test(expr));
      expect({ path, raw }).toEqual({ path, raw: [] });
    }
  });
});
