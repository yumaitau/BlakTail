import { describe, expect, test } from "bun:test";
import {
  auditCsv,
  auditFiltersFromParams,
  coordinatorAuditQuery,
  cursorOf,
  encodeAuditCursor,
  mergeAuditPages,
  parseAuditCursor,
  redactDetails,
} from "../src/lib/audit-view.ts";

function event(id, created_at, extra = {}) {
  return {
    id,
    actor_user_id: "u",
    actor_name: "",
    actor_email: "u@example.test",
    actor_role: "owner",
    action: "node.renamed",
    target_type: "node",
    target_id: null,
    details: {},
    created_at,
    ...extra,
  };
}

// Two stores, each already in timeline order: seconds descending, then the
// store's own id order. Coordinator rows sort before console rows per second.
function timeline(coordinator, consoleRows) {
  return mergeAuditPages(coordinator, consoleRows, coordinator.length + consoleRows.length).events;
}

function pageThrough(coordinator, consoleRows, limit) {
  const seen = [];
  let cursor = null;
  for (let guard = 0; guard < 100; guard += 1) {
    // Mirrors the SQL each store runs for a cursor.
    const before = (rows, src) =>
      rows.filter((row, index) => {
        if (!cursor) return true;
        const t = row.created_at;
        if (t !== cursor.t) return t < cursor.t;
        if (cursor.src !== src) return src === "k";
        return index > rows.findIndex((r) => cursorOf(r).id === cursor.id);
      });
    const page = mergeAuditPages(
      before(coordinator, "c").slice(0, limit),
      before(consoleRows, "k").slice(0, limit),
      limit,
    );
    seen.push(...page.events.map((row) => row.id));
    if (!page.next) break;
    cursor = parseAuditCursor(page.next);
  }
  return seen;
}

describe("merged audit pagination", () => {
  const coordinator = [
    event("c3", 300),
    event("c2b", 200),
    event("c2a", 200),
    event("c1", 100),
  ];
  const consoleRows = [
    event("console:k3", 300),
    event("console:k2", 200),
    event("console:k0", 50),
  ];

  test("orders by second, coordinator first within a second", () => {
    expect(timeline(coordinator, consoleRows).map((row) => row.id)).toEqual([
      "c3",
      "console:k3",
      "c2b",
      "c2a",
      "console:k2",
      "c1",
      "console:k0",
    ]);
  });

  test("every page size returns every row exactly once", () => {
    const all = timeline(coordinator, consoleRows).map((row) => row.id);
    for (const limit of [1, 2, 3, 5, 10]) {
      expect(pageThrough(coordinator, consoleRows, limit)).toEqual(all);
    }
  });

  test("cursor round-trips and rejects junk", () => {
    const cursor = cursorOf(event("console:abc-1", 42));
    expect(cursor).toEqual({ t: 42, src: "k", id: "abc-1" });
    expect(parseAuditCursor(encodeAuditCursor(cursor))).toEqual(cursor);
    expect(parseAuditCursor("42~x~id")).toBeNull();
    expect(parseAuditCursor("42~c~id;drop")).toBeNull();
  });

  test("coordinator query honours the source of the cursor", () => {
    const filters = { action: "node.*", until: 1000 };
    const fromCoordinator = coordinatorAuditQuery(filters, { t: 200, src: "c", id: "c2b" }, 50);
    expect(fromCoordinator.get("before")).toBe("200:c2b");
    expect(fromCoordinator.get("until")).toBe("1000");
    const fromConsole = coordinatorAuditQuery(filters, { t: 200, src: "k", id: "k2" }, 50);
    expect(fromConsole.get("before")).toBeNull();
    expect(fromConsole.get("until")).toBe("200");
    expect(fromConsole.get("action")).toBe("node.*");
  });
});

describe("audit filters and safe rendering", () => {
  test("filters parse UTC days and drop junk", () => {
    const filters = auditFiltersFromParams({
      actor: " alice@example.test ",
      from: "2026-10-01",
      to: "2026-10-01",
      target_id: "x".repeat(500),
    });
    expect(filters.actor).toBe("alice@example.test");
    expect(filters.since).toBe(Date.UTC(2026, 9, 1) / 1000);
    expect(filters.until).toBe(Date.UTC(2026, 9, 2) / 1000);
    expect(filters.target_id).toBeUndefined();
  });

  test("redaction hides secrets by key name and shape", () => {
    const redacted = redactDetails({
      token: "x",
      client_secret: "x",
      token_prefix: "bta_abc",
      nested: [{ password: "p" }, "btk_aaaaaaaaaaaaaaaaaaaaaaaa"],
      name: "laptop",
    });
    expect(redacted).toEqual({
      token: "[redacted]",
      client_secret: "[redacted]",
      token_prefix: "bta_abc",
      nested: [{ password: "[redacted]" }, "[redacted]"],
      name: "laptop",
    });
  });

  test("CSV quotes cells and neutralises formulas", () => {
    const csv = auditCsv([event("c1", 0, { action: "=cmd()", details: { secret: "s" } })]);
    expect(csv).toContain(`"'=cmd()"`);
    expect(csv).not.toContain('"s"');
    expect(csv.split("\r\n")[0]).toStartWith("created_at,id");
  });
});
