import { describe, expect, test } from "bun:test";
import {
  DEFAULT_DIRECTORY_SETTINGS,
  desiredRole,
  graceState,
  mappingRefusal,
  parseGraceDays,
  planDrift,
  planSignature,
  scimActivation,
} from "../src/lib/directory-mapping-core.ts";
import {
  applyMemberOps,
  displayNameFilter,
  pagination,
  parseGroupPatch,
  parseScimGroup,
  scimGroupResource,
  scimListResponse,
} from "../src/lib/scim-groups-core.ts";

const settings = DEFAULT_DIRECTORY_SETTINGS;
const mappings = [
  { source: "scim", groupName: "BlakTail Admins", role: "admin" },
  { source: "scim", groupName: "Rangers", role: "member" },
  { source: "oidc", groupName: "net-ops", role: "network_admin" },
  { source: "scim", groupName: "Auditors", role: "auditor" },
];

function member(overrides) {
  return {
    membershipId: overrides.email,
    role: "member",
    status: "active",
    roleSource: "manual",
    hasPassword: false,
    scimGroups: [],
    oidcGroups: [],
    ...overrides,
  };
}

describe("group -> role precedence", () => {
  test("the highest mapped role wins across SCIM groups and the OIDC claim", () => {
    const result = desiredRole(
      member({ email: "a@x", scimGroups: ["rangers", "Auditors"], oidcGroups: ["net-ops"] }),
      mappings,
      settings,
    );
    expect(result.role).toBe("network_admin");
    expect(result.groups).toEqual(["oidc:net-ops"]);
    expect(
      desiredRole(member({ email: "b@x", scimGroups: ["BlakTail Admins", "Rangers"] }), mappings, settings)
        .role,
    ).toBe("admin");
  });

  test("group names match case-insensitively but sources stay separate", () => {
    expect(desiredRole(member({ email: "c@x", scimGroups: ["BLAKTAIL ADMINS"] }), mappings, settings).role).toBe(
      "admin",
    );
    // net-ops is mapped from the OIDC claim only.
    expect(desiredRole(member({ email: "d@x", scimGroups: ["net-ops"] }), mappings, settings).role).toBeNull();
  });

  test("no matching group leaves a hand-set role alone but drops a mapped role to member", () => {
    expect(desiredRole(member({ email: "e@x", role: "admin" }), mappings, settings).role).toBeNull();
    expect(
      desiredRole(member({ email: "f@x", role: "admin", roleSource: "directory" }), mappings, settings).role,
    ).toBe("member");
  });

  test("owner mappings are ignored and refused unless an owner allows them", () => {
    const withOwner = [...mappings, { source: "scim", groupName: "Owners", role: "owner" }];
    const someone = member({ email: "g@x", scimGroups: ["Owners", "Rangers"] });
    expect(desiredRole(someone, withOwner, settings).role).toBe("member");
    expect(mappingRefusal({ role: "owner" }, settings)).toContain("cannot grant owner");
    const allowed = { ...settings, allowOwnerMapping: true };
    expect(mappingRefusal({ role: "owner" }, allowed)).toBeNull();
    expect(desiredRole(someone, withOwner, allowed).role).toBe("owner");
  });
});

describe("drift preview", () => {
  const members = [
    member({ email: "owner@x", role: "owner", hasPassword: true }),
    member({ email: "admin-to-be@x", scimGroups: ["BlakTail Admins"] }),
    member({ email: "same@x", role: "auditor", scimGroups: ["Auditors"] }),
    member({ email: "gone@x", role: "admin", roleSource: "directory" }),
    member({ email: "removed@x", status: "removed", scimGroups: ["BlakTail Admins"] }),
    member({ email: "invited@x", status: "invited", scimGroups: ["BlakTail Admins"] }),
  ];

  test("lists who changes, how and why, skipping owners and inactive rows", () => {
    const changes = planDrift(members, mappings, settings);
    expect(changes).toEqual([
      {
        membershipId: "admin-to-be@x",
        email: "admin-to-be@x",
        from: "member",
        to: "admin",
        groups: ["scim:BlakTail Admins"],
        blocked: null,
      },
      {
        membershipId: "gone@x",
        email: "gone@x",
        from: "admin",
        to: "member",
        groups: [],
        blocked: null,
      },
    ]);
  });

  test("the signature changes when the plan changes", () => {
    const before = planSignature(planDrift(members, mappings, settings));
    const after = planSignature(
      planDrift(members, [...mappings, { source: "scim", groupName: "Auditors", role: "admin" }], settings),
    );
    expect(before).toBe("admin-to-be@x:member>admin|gone@x:admin>member");
    expect(after).not.toBe(before);
  });

  test("never demotes the last password owner, even when owner mapping is allowed", () => {
    const allowed = { ...settings, allowOwnerMapping: true };
    const owners = [
      member({ email: "pw-owner@x", role: "owner", hasPassword: true, roleSource: "directory" }),
      member({ email: "sso-owner@x", role: "owner", hasPassword: false, roleSource: "directory" }),
    ];
    const changes = planDrift(owners, [{ source: "scim", groupName: "Owners", role: "owner" }], allowed);
    const pw = changes.find((change) => change.email === "pw-owner@x");
    const sso = changes.find((change) => change.email === "sso-owner@x");
    expect(pw.blocked).toContain("password");
    expect(sso.blocked).toBeNull();
    expect(planSignature(changes)).toBe("sso-owner@x:owner>member");
  });

  test("never removes the last active owner", () => {
    const allowed = { ...settings, allowOwnerMapping: true };
    const changes = planDrift(
      [member({ email: "only@x", role: "owner", roleSource: "directory" })],
      [],
      allowed,
    );
    expect(changes[0].blocked).toContain("last active owner");
    expect(planSignature(changes)).toBe("");
  });
});

describe("deprovision grace period", () => {
  const now = new Date("2026-10-03T00:00:00Z");

  test("deactivation suspends now and tombstones after the default seven days", () => {
    const next = scimActivation(
      { role: "admin", status: "active", deprovisionAt: null, tombstonedAt: null },
      false,
      settings,
      now,
    );
    expect(next.status).toBe("suspended");
    expect(next.role).toBe("admin");
    expect(next.deprovisionAt.toISOString()).toBe("2026-10-10T00:00:00.000Z");
    expect(
      graceState({ status: next.status, deprovisionAt: next.deprovisionAt, tombstonedAt: null }, now),
    ).toBe("in_grace");
    expect(
      graceState(
        { status: next.status, deprovisionAt: next.deprovisionAt, tombstonedAt: null },
        new Date("2026-10-10T00:00:00Z"),
      ),
    ).toBe("expired");
  });

  test("a repeated deactivation keeps the original deadline", () => {
    const deadline = new Date("2026-10-05T00:00:00Z");
    const next = scimActivation(
      { role: "member", status: "suspended", deprovisionAt: deadline, tombstonedAt: null },
      false,
      settings,
      now,
    );
    expect(next.deprovisionAt).toEqual(deadline);
  });

  test("reactivation in grace keeps the role; after the tombstone it starts as member", () => {
    const inGrace = scimActivation(
      { role: "admin", status: "suspended", deprovisionAt: new Date("2026-10-05T00:00:00Z"), tombstonedAt: null },
      true,
      settings,
      now,
    );
    expect(inGrace).toEqual({ status: "active", role: "admin", deprovisionAt: null, tombstonedAt: null });
    const revived = scimActivation(
      { role: "admin", status: "removed", deprovisionAt: now, tombstonedAt: now },
      true,
      settings,
      now,
    );
    expect(revived.role).toBe("member");
    expect(revived.roleSource).toBe("manual");
    expect(revived.tombstonedAt).toBeNull();
  });

  test("zero days tombstones at once; grace days are bounded", () => {
    const next = scimActivation(
      { role: "member", status: "active", deprovisionAt: null, tombstonedAt: null },
      false,
      { ...settings, deprovisionGraceDays: 0 },
      now,
    );
    expect(next.status).toBe("removed");
    expect(next.tombstonedAt).toEqual(now);
    expect(parseGraceDays("7")).toBe(7);
    expect(parseGraceDays(91)).toBeNull();
    expect(parseGraceDays("-1")).toBeNull();
    expect(parseGraceDays("1.5")).toBeNull();
  });
});

describe("SCIM Groups resource", () => {
  test("parses a create body and renders RFC 7643 shape", () => {
    expect(
      parseScimGroup({
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        displayName: " BlakTail Admins ",
        externalId: "aad-123",
        members: [{ value: "u1" }, { value: "u2" }, { value: "u1" }],
      }),
    ).toEqual({ displayName: "BlakTail Admins", externalId: "aad-123", memberIds: ["u1", "u2"] });
    expect(parseScimGroup({ displayName: "" })).toBeNull();
    expect(parseScimGroup({ displayName: "x", members: [{ display: "no value" }] })).toBeNull();
    const created = new Date("2026-10-03T00:00:00Z");
    const resource = scimGroupResource({
      id: "g1",
      displayName: "BlakTail Admins",
      externalId: null,
      members: [{ value: "u1", display: "a@x" }],
      created,
      lastModified: created,
    });
    expect(resource.schemas).toEqual(["urn:ietf:params:scim:schemas:core:2.0:Group"]);
    expect(resource.members[0]).toEqual({ value: "u1", display: "a@x", $ref: "../Users/u1", type: "User" });
    expect(resource.meta.resourceType).toBe("Group");
    expect("externalId" in resource).toBe(false);
    const list = scimListResponse([resource], 1, 3);
    expect(list.schemas).toEqual(["urn:ietf:params:scim:api:messages:2.0:ListResponse"]);
    expect(list.totalResults).toBe(3);
    expect(list.itemsPerPage).toBe(1);
  });

  test("reads Entra ID and Okta PATCH member operations", () => {
    const entra = parseGroupPatch({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [
        { op: "Add", path: "members", value: [{ value: "u3" }] },
        { op: "Remove", path: "members", value: [{ value: "u1" }] },
      ],
    });
    expect(applyMemberOps(["u1", "u2"], entra)).toEqual(["u2", "u3"]);
    const okta = parseGroupPatch({
      Operations: [
        { op: "remove", path: 'members[value eq "u2"]' },
        { op: "replace", value: { id: "g1", displayName: "Renamed" } },
      ],
    });
    expect(okta).toEqual([
      { kind: "remove", memberIds: ["u2"] },
      { kind: "rename", displayName: "Renamed" },
    ]);
    expect(applyMemberOps(["u1", "u2"], [{ kind: "replace", memberIds: ["u9"] }])).toEqual(["u9"]);
    expect(applyMemberOps(["u1"], parseGroupPatch({ Operations: [{ op: "remove", path: "members" }] }))).toEqual(
      [],
    );
  });

  test("rejects unsupported PATCH operations and filters", () => {
    expect(parseGroupPatch({ Operations: [] })).toBeNull();
    expect(parseGroupPatch({ Operations: [{ op: "move", path: "members", value: [] }] })).toBeNull();
    expect(parseGroupPatch({ Operations: [{ op: "add", path: 'members[value eq "u1"]' }] })).toBeNull();
    expect(parseGroupPatch({ Operations: [{ op: "replace", path: "owner", value: "x" }] })).toBeNull();
    expect(displayNameFilter('displayName eq "Rangers"')).toBe("Rangers");
    expect(displayNameFilter('displayName co "R"')).toBeNull();
    expect(pagination(new URLSearchParams("startIndex=0&count=900"))).toEqual({ startIndex: 1, count: 200 });
  });
});
