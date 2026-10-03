#!/usr/bin/env python3
"""Coordinator driver for prove-upgrade.sh.

Signs short-lived console assertions with BLAKTAIL_AUTH_HMAC_SECRET (read
from the environment, never argv) and calls the coordinator over TLS. Only
endpoints that already existed in the round-1 release (schema 28) are used,
so the same driver seeds the old coordinator and checks the new one.

  upgrade-lab bootstrap <org>            organisation with a representative policy
  upgrade-lab join-key <org> <tag>       print a fresh one-use join key
  upgrade-lab seed <org>                 friendly name, route approval, reusable and
                                         revoked join keys, API client, open draft
  upgrade-lab snapshot <org>             print the org state as JSON
  upgrade-lab compare <before> <after>   every field of <before> must be unchanged
"""
import base64
import hashlib
import hmac
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid

BASE = os.environ.get("UPGRADELAB_COORD", "https://labs-upgrade-coord:8443")
CTX = ssl.create_default_context(cafile=os.environ.get("UPGRADELAB_CA", "/certs/ca.crt"))

ACL = {
    "version": 1,
    "defaults": "deny",
    "groups": {
        "field": ["aunty.lab@example.org", "uncle.lab@example.org"],
        "admins": ["upgrade-lab@example.org"],
    },
    "tag_owners": {"office": ["upgrade-lab@example.org"], "store": ["upgrade-lab@example.org"]},
    "hosts": {"store-lan": "10.77.0.0/24"},
    "rules": [
        {"action": "allow", "src_tags": ["office"], "dst_tags": ["store"],
         "dst_ports": ["8080", "22"], "protocols": ["tcp"]},
        {"action": "allow", "src_tags": ["office"], "dst_tags": ["store"], "protocols": ["icmp"]},
        {"action": "allow", "src_tags": ["store"], "dst_tags": ["office"], "protocols": ["icmp"]},
        {"action": "allow", "src_tags": ["office"], "dst_hosts": ["store-lan"],
         "dst_ports": ["443"], "protocols": ["tcp"]},
        {"action": "allow", "src_groups": ["field"], "dst_hosts": ["store-lan"],
         "dst_ports": ["443"], "protocols": ["tcp"]},
        {"action": "deny", "src_tags": ["store"], "dst_tags": ["office"],
         "dst_ports": ["9000"], "protocols": ["tcp"]},
    ],
    "ssh": [
        {"action": "allow", "src_tags": ["office"], "dst_tags": ["store"], "users": ["kooricare"]},
    ],
}

# Fields that legitimately move between two reads (liveness, clocks, counters
# that the running agents advance) and are therefore not compared.
VOLATILE = {
    "last_seen", "last_seen_at", "online", "status", "connection", "endpoint",
    "endpoints", "control_revision", "transport", "last_handshake", "rx_bytes",
    "tx_bytes", "applied_dns_revision", "last_poll_at", "credential_expires_at",
    "key_expires_at", "relay", "last_used_at", "expires_in_seconds", "age_seconds", "server_time",
}


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def assertion(org_id: str, role: str, action=None) -> str:
    now = int(time.time())
    claims = {
        "sub": "upgrade-lab-owner", "org_id": org_id, "role": role,
        "name": "Upgrade lab", "email": "upgrade-lab@example.org",
        "iss": "blaktail-console", "aud": "blaktail-coord",
        "iat": now, "exp": now + 50, "jti": str(uuid.uuid4()),
    }
    if action:
        claims["action"] = action
    payload = b64(json.dumps(claims).encode())
    secret = os.environ["BLAKTAIL_AUTH_HMAC_SECRET"].encode()
    mac = hmac.new(secret, payload.encode(), hashlib.sha256).digest()
    return f"{payload}.{b64(mac)}"


def call(method, path, org_id, body=None, role="owner", action=None, allow=()):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(BASE + path, data=data, method=method)
    request.add_header("Authorization", f"Bearer {assertion(org_id, role, action)}")
    request.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(request, context=CTX, timeout=30) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as error:
        if error.code in allow:
            return error.code, None
        sys.exit(f"{method} {path} -> {error.code}: {error.read().decode()}")


def nodes(org_id):
    _, listing = call("GET", f"/v1/orgs/{org_id}/nodes", org_id)
    return listing["nodes"] if isinstance(listing, dict) and "nodes" in listing else listing


def by_name(org_id, name):
    for node in nodes(org_id):
        if node.get("name") == name:
            return node
    sys.exit(f"node {name} not found")


def seed(org_id):
    office = by_name(org_id, "upgrade-a")
    store = by_name(org_id, "upgrade-b")
    call("PUT", f"/v1/orgs/{org_id}/nodes/{office['id']}/friendly-name", org_id,
         {"friendly_name": "Office front desk"})
    call("PUT", f"/v1/orgs/{org_id}/nodes/{store['id']}/routes", org_id,
         {"approved_routes": ["10.77.0.0/24"]})
    # Round 1 did not bump the control revision on route approval, so its
    # clients never learnt the route; republishing the policy bumps it.
    _, acl = call("GET", f"/v1/orgs/{org_id}/acl", org_id)
    call("PUT", f"/v1/orgs/{org_id}/acl", org_id, ACL)
    _, after = call("GET", f"/v1/orgs/{org_id}/acl", org_id)
    print(f"policy republished: revision {acl['revision']} -> {after['revision']}")
    call("POST", f"/v1/orgs/{org_id}/join-keys", org_id,
         {"expires_in_seconds": 86400, "single_use": False, "max_uses": 5,
          "tags": ["office"], "name": "office rollout", "description": "reusable, unused"})
    _, revoked = call("POST", f"/v1/orgs/{org_id}/join-keys", org_id,
                      {"expires_in_seconds": 86400, "tags": ["store"], "name": "revoked key"})
    call("DELETE", f"/v1/orgs/{org_id}/join-keys/{revoked['id']}", org_id)
    call("POST", f"/v1/orgs/{org_id}/api-clients", org_id,
         {"name": "upgrade-ci", "scopes": ["devices:read", "policy:write"]})
    call("POST", f"/v1/orgs/{org_id}/changes", org_id,
         {"title": "Open draft from round 1", "surfaces": ["policy"]})
    print("seeded")


def snapshot(org_id):
    out = {}
    out["nodes"] = sorted(nodes(org_id), key=lambda n: n["id"])
    for node in out["nodes"]:
        _, detail = call("GET", f"/v1/orgs/{org_id}/nodes/{node['id']}", org_id)
        node["detail"] = detail
    _, out["acl"] = call("GET", f"/v1/orgs/{org_id}/acl", org_id)
    _, out["dns"] = call("GET", f"/v1/orgs/{org_id}/dns", org_id)
    _, out["join_keys"] = call("GET", f"/v1/orgs/{org_id}/join-keys", org_id)
    _, out["api_clients"] = call("GET", f"/v1/orgs/{org_id}/api-clients", org_id)
    _, out["changes"] = call("GET", f"/v1/orgs/{org_id}/changes", org_id)
    print(json.dumps(out, sort_keys=True))


def unchanged(before, after, path, problems):
    if isinstance(before, dict):
        if not isinstance(after, dict):
            problems.append(f"{path}: object became {type(after).__name__}")
            return
        for key, value in before.items():
            if key in VOLATILE:
                continue
            if key not in after:
                problems.append(f"{path}.{key}: missing after upgrade")
                continue
            unchanged(value, after[key], f"{path}.{key}", problems)
    elif isinstance(before, list):
        if not isinstance(after, list) or len(before) != len(after):
            problems.append(f"{path}: list length {len(before)} -> "
                            f"{len(after) if isinstance(after, list) else after!r}")
            return
        for index, (old, new) in enumerate(zip(before, after)):
            unchanged(old, new, f"{path}[{index}]", problems)
    elif before != after:
        problems.append(f"{path}: {before!r} -> {after!r}")


def compare(before_path, after_path, extra=()):
    with open(before_path) as handle:
        before = json.load(handle)
    with open(after_path) as handle:
        after = json.load(handle)
    problems = []
    VOLATILE.update(extra)
    unchanged(before, after, "$", problems)
    nodes_before = before["nodes"]
    def count(value):
        if isinstance(value, dict):
            lists = [v for v in value.values() if isinstance(v, list)]
            return len(lists[0]) if lists else len(value)
        return len(value)

    print(f"compared {len(nodes_before)} devices, {len(before['acl'].get('rules', []))} policy rules,"
          f" {len(before['acl'].get('ssh', []))} SSH rules,"
          f" {len(before['acl'].get('groups', {}))} groups,"
          f" {count(before['join_keys'])} join keys, {count(before['api_clients'])} API clients,"
          f" {count(before['changes'])} drafts, ACL revision {before['acl'].get('revision')}")
    if problems:
        print("\n".join(problems))
        sys.exit(1)
    print("all pre-upgrade fields unchanged (volatile liveness fields ignored: "
          + ", ".join(sorted(VOLATILE)) + ")")


def main():
    command = sys.argv[1]
    if command == "compare":
        compare(sys.argv[2], sys.argv[3], sys.argv[4:])
        return
    org_id = sys.argv[2]
    if command == "bootstrap":
        call("POST", "/v1/orgs", org_id, {"id": org_id, "name": "upgrade-lab", "acl": ACL},
             role="service", action="bootstrap.prepare")
        call("POST", f"/v1/orgs/{org_id}/bootstrap-commit", org_id, {},
             role="service", action="bootstrap.commit")
        print("org ready")
    elif command == "join-key":
        _, key = call("POST", f"/v1/orgs/{org_id}/join-keys", org_id,
                      {"expires_in_seconds": 600, "tags": [sys.argv[3]]})
        print(key["key"])
    elif command == "approve":
        store = by_name(org_id, "upgrade-b")
        call("PUT", f"/v1/orgs/{org_id}/nodes/{store['id']}/routes", org_id,
             {"approved_routes": sys.argv[3:]})
        print(f"approved {sys.argv[3:]}")
    elif command == "seed":
        seed(org_id)
    elif command == "snapshot":
        snapshot(org_id)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
