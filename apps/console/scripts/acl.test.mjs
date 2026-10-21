import { test } from "node:test";
import assert from "node:assert/strict";
import {
  expandGroupMembers,
  parseAclPolicy,
  serializeAclPolicy,
  validGroupName,
} from "../src/lib/acl.ts";
import { folderBrowserUrl } from "../src/lib/drive.ts";

test("ACL drafts keep groups and compact empty selectors", () => {
  const policy = parseAclPolicy({
    groups: { rangers: ["alice@example.test", "alice-user"] },
    rules: [
      {
        action: "allow",
        src_groups: ["rangers"],
        dst_tags: ["store"],
        src_roles: [],
      },
    ],
  });
  assert.deepEqual(policy.groups, [
    { name: "rangers", members: ["alice@example.test", "alice-user"] },
  ]);
  assert.equal(validGroupName("rangers"), true);
  assert.equal(validGroupName("Rangers"), false);
  const people = [
    {
      userId: "alice-user",
      email: "alice@example.test",
      name: "Alice",
    },
  ];
  assert.deepEqual(
    expandGroupMembers(["alice@example.test"], people).sort(),
    ["alice-user", "alice@example.test"].sort(),
  );
  assert.equal(policy.defaults, "same_tag");
  assert.deepEqual(serializeAclPolicy(policy), {
    version: 1,
    defaults: "same_tag",
    groups: { rangers: ["alice@example.test", "alice-user"] },
    rules: [{ action: "allow", src_groups: ["rangers"], dst_tags: ["store"] }],
  });
});

test("ACL drafts keep hosts, ports, and protocols across a round trip", () => {
  const policy = parseAclPolicy({
    hosts: { wiki: "10.0.0.10" },
    rules: [
      {
        action: "allow",
        src_groups: ["rangers"],
        dst_hosts: ["wiki"],
        dst_ports: ["443"],
        protocols: ["tcp"],
      },
    ],
  });
  assert.deepEqual(policy.hosts, [{ name: "wiki", target: "10.0.0.10" }]);
  assert.deepEqual(serializeAclPolicy(policy), {
    version: 1,
    defaults: "same_tag",
    groups: {},
    hosts: { wiki: "10.0.0.10" },
    rules: [
      {
        action: "allow",
        src_groups: ["rangers"],
        dst_hosts: ["wiki"],
        dst_ports: ["443"],
        protocols: ["tcp"],
      },
    ],
  });
});

test("ACL drafts keep policy tests and tag owners across a round trip", () => {
  const policy = parseAclPolicy({
    version: 1,
    tag_owners: { office: ["owner-1"] },
    tests: [{ name: "office isolated", src_tags: ["office"], dst_tags: ["store"], allow: false }],
    rules: [],
  });
  assert.equal(policy.version, 1);
  assert.deepEqual(policy.tag_owners, [{ tag: "office", owners: ["owner-1"] }]);
  assert.equal(policy.tests.length, 1);
  assert.deepEqual(serializeAclPolicy(policy), {
    version: 1,
    defaults: "same_tag",
    groups: {},
    tag_owners: { office: ["owner-1"] },
    tests: [{ name: "office isolated", src_tags: ["office"], dst_tags: ["store"], allow: false }],
    rules: [],
  });
});

test("ACL drafts keep SSH rules across a round trip", () => {
  const policy = parseAclPolicy({
    ssh: [
      {
        action: "check",
        src_groups: ["rangers"],
        dst_tags: ["store"],
        users: ["ubuntu", "deploy"],
        check_period_secs: 3600,
      },
    ],
    rules: [],
  });
  assert.deepEqual(policy.ssh, [
    {
      action: "check",
      src_roles: [],
      src_tags: [],
      src_groups: ["rangers"],
      dst_roles: [],
      dst_tags: ["store"],
      dst_groups: [],
      users: ["ubuntu", "deploy"],
      check_period_secs: "3600",
      posture: [],
    },
  ]);
  assert.deepEqual(serializeAclPolicy(policy), {
    version: 1,
    defaults: "same_tag",
    groups: {},
    ssh: [
      {
        action: "check",
        src_groups: ["rangers"],
        dst_tags: ["store"],
        users: ["ubuntu", "deploy"],
        check_period_secs: 3600,
      },
    ],
    rules: [],
  });
});

test("ACL drafts keep deny defaults and generated legacy rules", () => {
  const policy = parseAclPolicy({
    defaults: "deny",
    etag: "abc",
    revision: 2,
    has_previous: true,
    generated: [
      {
        kind: "legacy_same_tag",
        action: "allow",
        applies: ["same_tag", "untagged"],
        note: "legacy",
      },
    ],
    rules: [],
  });
  assert.equal(policy.defaults, "deny");
  assert.equal(policy.etag, "abc");
  assert.equal(policy.has_previous, true);
  assert.equal(policy.generated[0]?.kind, "legacy_same_tag");
  assert.deepEqual(serializeAclPolicy(policy), {
    version: 1,
    defaults: "deny",
    groups: {},
    rules: [],
  });
});

test("ACL drafts keep posture on allow rules and drop it from denies", () => {
  const policy = parseAclPolicy({
    defaults: "deny",
    rules: [
      { action: "allow", src_tags: ["ranger"], posture: ["baseline"] },
      { action: "deny", src_tags: ["office"], posture: ["baseline"] },
    ],
    ssh: [
      { action: "check", src_tags: ["ranger"], users: ["deploy"], posture: ["baseline"] },
      { action: "deny", src_tags: ["office"], users: ["root"], posture: ["baseline"] },
    ],
  });
  const serialized = serializeAclPolicy(policy);
  assert.deepEqual(serialized.rules, [
    { action: "allow", src_tags: ["ranger"], posture: ["baseline"] },
    { action: "deny", src_tags: ["office"] },
  ]);
  assert.deepEqual(serialized.ssh, [
    { action: "check", src_tags: ["ranger"], users: ["deploy"], posture: ["baseline"] },
    { action: "deny", src_tags: ["office"], users: ["root"] },
  ]);
});

test("ACL drafts keep a drive section through a round trip", () => {
  const drive = {
    share: ["*"],
    access: ["member"],
    grants: [
      {
        src_roles: ["member"],
        dst_tags: ["store"],
        shares: ["company-docs"],
        access: "ro",
      },
    ],
  };
  const policy = parseAclPolicy({ version: 1, defaults: "deny", drive, rules: [] });
  assert.deepEqual(policy.drive, drive);
  assert.deepEqual(serializeAclPolicy(policy).drive, drive);
  assert.equal(serializeAclPolicy(parseAclPolicy({ defaults: "deny" })).drive, undefined);
});

test("folder browser URL uses the MagicDNS domain and host label", () => {
  assert.equal(
    folderBrowserUrl("Store.abcdef12.blaktail.", "files"),
    "http://127.0.0.1:8080/abcdef12.blaktail/store/files/",
  );
  assert.equal(
    folderBrowserUrl("not-a-tailnet", "files"),
    "http://127.0.0.1:8080/blaktail/not-a-tailnet/files/",
  );
});
