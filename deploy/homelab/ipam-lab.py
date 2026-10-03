#!/usr/bin/env python3
"""Coordinator driver for prove-ipv6-renumber.sh.

Signs short-lived console assertions with BLAKTAIL_AUTH_HMAC_SECRET (read
from the environment, never argv) and calls the coordinator over TLS.

  ipam-lab bootstrap <org_id>                    create the lab organisation
  ipam-lab join-key <org_id>                     print a fresh join key
  ipam-lab approve <org_id> <name> <route>...    approve a device's advertised routes
  ipam-lab routes <org_id> <name>                print a device's approved routes
  ipam-lab pool <org_id>                         print the IPv4 pool and staged plan
  ipam-lab renumber-pool <org_id> <cidr> <secs>  stage (or apply) a pool change
  ipam-lab renumber-device <org_id> <name> <secs>  stage a move of one device
  ipam-lab finish <org_id> complete|rollback     finish the staged plan
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

BASE = os.environ.get("IPAMLAB_COORD", "https://ipamlab-coord:8443")
CTX = ssl.create_default_context(cafile=os.environ.get("IPAMLAB_CA", "/certs/ca.crt"))


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def assertion(org_id: str, role: str, action=None) -> str:
    now = int(time.time())
    claims = {
        "sub": "ipam-lab-operator",
        "org_id": org_id,
        "role": role,
        "name": "IPAM lab",
        "email": "ipam-lab@example.org",
        "iss": "blaktail-console",
        "aud": "blaktail-coord",
        "iat": now,
        "exp": now + 50,
        "jti": str(uuid.uuid4()),
    }
    if action:
        claims["action"] = action
    payload = b64(json.dumps(claims).encode())
    secret = os.environ["BLAKTAIL_AUTH_HMAC_SECRET"].encode()
    mac = hmac.new(secret, payload.encode(), hashlib.sha256).digest()
    return f"{payload}.{b64(mac)}"


def call(method: str, path: str, token: str, body=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(BASE + path, data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("content-type", "application/json")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, context=CTX, timeout=30) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as error:
        sys.exit(f"{method} {path} -> {error.code}: {error.read().decode()}")


# Assertion IDs are single-use, so every call signs a fresh one.
def node(org_id: str, name: str) -> dict:
    _, nodes = call("GET", f"/v1/orgs/{org_id}/nodes", assertion(org_id, "owner"))
    for row in nodes:
        if row["name"] == name:
            return row
    sys.exit(f"no device named {name}")


def main() -> None:
    command, org_id = sys.argv[1], sys.argv[2]
    if command == "bootstrap":
        acl = {"version": 1, "defaults": "same_tag", "rules": []}
        call("POST", "/v1/orgs", assertion(org_id, "service", "bootstrap.prepare"),
             {"id": org_id, "name": "ipam-lab", "acl": acl})
        call("POST", f"/v1/orgs/{org_id}/bootstrap-commit",
             assertion(org_id, "service", "bootstrap.commit"), {})
        print("org ready")
    elif command == "join-key":
        _, key = call("POST", f"/v1/orgs/{org_id}/join-keys", assertion(org_id, "owner"), {"expires_in_seconds": 600})
        print(key["key"])
    elif command == "approve":
        target = node(org_id, sys.argv[3])
        call("PUT", f"/v1/orgs/{org_id}/nodes/{target['id']}/routes", assertion(org_id, "owner"),
             {"approved_routes": sys.argv[4:]})
        print(f"approved {' '.join(sys.argv[4:])} on {sys.argv[3]}")
    elif command == "routes":
        print(" ".join(node(org_id, sys.argv[3])["approved_routes"]))
    elif command == "pool":
        _, view = call("GET", f"/v1/orgs/{org_id}/ipam", assertion(org_id, "owner"))
        staged = view["renumber"]["staged"]
        print(json.dumps({
            "pools": [pool["cidr"] for pool in view["pools"]],
            "staged": None if staged is None else {
                "id": staged["id"], "moves": staged["moves"], "etag": staged["etag"],
            },
            "history": [plan["state"] for plan in view["renumber"]["history"]],
        }, sort_keys=True))
    elif command == "renumber-pool":
        _, plan = call("POST", f"/v1/orgs/{org_id}/ipam/renumber", assertion(org_id, "owner"), {
            "pool": sys.argv[3], "window_seconds": int(sys.argv[4]), "reason": "ipam lab",
        })
        print(json.dumps({"state": plan["state"], "moves": plan["moves"]}, sort_keys=True))
    elif command == "renumber-device":
        target = node(org_id, sys.argv[3])
        _, plan = call("POST", f"/v1/orgs/{org_id}/ipam/renumber", assertion(org_id, "owner"), {
            "devices": [{"node_id": target["id"]}],
            "window_seconds": int(sys.argv[4]),
            "reason": "ipam lab rollback drill",
        })
        print(json.dumps({"state": plan["state"], "moves": plan["moves"]}, sort_keys=True))
    elif command == "finish":
        _, view = call("GET", f"/v1/orgs/{org_id}/ipam", assertion(org_id, "owner"))
        staged = view["renumber"]["staged"] or sys.exit("no staged plan")
        _, plan = call("POST", f"/v1/orgs/{org_id}/ipam/renumber/{staged['id']}/{sys.argv[3]}",
                       assertion(org_id, "owner"), headers={"if-match": f"\"{staged['etag']}\""})
        print(f"plan {plan['state']}")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
