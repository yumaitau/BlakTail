#!/usr/bin/env python3
"""Coordinator driver for prove-routing.sh.

Signs short-lived console assertions with BLAKTAIL_AUTH_HMAC_SECRET (read
from the environment, never argv) and calls the coordinator over TLS.

  routing-lab bootstrap <org>                     organisation and tag policy
  routing-lab join-key <org> <tag>                print a fresh join key
  routing-lab node-id <org> <name>                print a node's id
  routing-lab approve <org> <node_id> <cidr,...>  approve device routes
  routing-lab resource <org> <name> <cidr> <port> <tag> <id:metric,...>
                                                  create a TCP-port resource
  routing-lab set-port <org> <resource_id> <p,...> replace the resource ports
  routing-lab detail <org> <resource_id>          print resource detail JSON
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

BASE = os.environ.get("ROUTINGLAB_COORD", "https://labs-routing-coord:8443")
CTX = ssl.create_default_context(cafile=os.environ.get("ROUTINGLAB_CA", "/certs/ca.crt"))

# Device tags are a fixed set: clients are office (staff) and ranger
# (guest); routers and the exit node are store. Clients pair with every router
# in both directions; what they may reach *behind* a router is decided by
# resources, device approvals and the router's forward filter, not by policy.
ACL = {
    "version": 1,
    "defaults": "deny",
    "rules": [
        {"action": "allow", "src_tags": ["office", "ranger"], "dst_tags": ["store"]},
        {"action": "allow", "src_tags": ["store"], "dst_tags": ["office", "ranger"]},
        {"action": "allow", "src_tags": ["store"], "dst_tags": ["store"]},
    ],
}


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def assertion(org_id: str, role: str, action=None) -> str:
    now = int(time.time())
    claims = {
        "sub": "routing-lab-owner",
        "org_id": org_id,
        "role": role,
        "name": "Routing lab",
        "email": "routing-lab@example.org",
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


def call(method: str, path: str, token: str, body=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(BASE + path, data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(request, context=CTX, timeout=30) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as error:
        sys.exit(f"{method} {path} -> {error.code}: {error.read().decode()}")


def owner(org_id: str) -> str:
    return assertion(org_id, "owner")


def main() -> None:
    command, org_id = sys.argv[1], sys.argv[2]
    if command == "bootstrap":
        call("POST", "/v1/orgs", assertion(org_id, "service", "bootstrap.prepare"),
             {"id": org_id, "name": "routing-lab", "acl": ACL})
        call("POST", f"/v1/orgs/{org_id}/bootstrap-commit",
             assertion(org_id, "service", "bootstrap.commit"), {})
        print("org ready")
    elif command == "join-key":
        _, key = call("POST", f"/v1/orgs/{org_id}/join-keys", owner(org_id),
                      {"expires_in_seconds": 600, "tags": [sys.argv[3]]})
        print(key["key"])
    elif command == "node-id":
        _, nodes = call("GET", f"/v1/orgs/{org_id}/nodes", owner(org_id))
        print(next(n["id"] for n in nodes if n["name"] == sys.argv[3]))
    elif command == "approve":
        call("PUT", f"/v1/orgs/{org_id}/nodes/{sys.argv[3]}/routes", owner(org_id),
             {"approved_routes": sys.argv[4].split(",")})
        print("approved")
    elif command == "resource":
        name, cidr, port, tag, peers = sys.argv[3:8]
        routing_peers = [
            {"node_id": node, "metric": int(metric)}
            for node, metric in (p.split(":") for p in peers.split(","))
        ]
        _, resource = call("POST", f"/v1/orgs/{org_id}/networks", owner(org_id), {
            "name": name, "cidr": cidr, "ports": [port], "protocols": ["tcp"],
            "routing_peers": routing_peers, "access": {"tags": tag.split(",")},
        })
        print(resource["id"])
    elif command == "set-port":
        resource_id, port = sys.argv[3], sys.argv[4]
        _, current = call("GET", f"/v1/orgs/{org_id}/networks/{resource_id}", owner(org_id))
        current = current.get("resource", current)
        body = {
            "name": current["name"], "cidr": current["cidr"], "ports": port.split(","),
            "protocols": current["protocols"], "routing_peers": current["routing_peers"],
            "access": current["access"], "etag": current["etag"],
        }
        call("PUT", f"/v1/orgs/{org_id}/networks/{resource_id}", owner(org_id), body)
        print("updated")
    elif command == "detail":
        _, detail = call("GET", f"/v1/orgs/{org_id}/networks/{sys.argv[3]}", owner(org_id))
        print(json.dumps(detail, sort_keys=True))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
