#!/usr/bin/env python3
"""Coordinator driver for prove-traffic-events.sh.

Signs short-lived console assertions with BLAKTAIL_AUTH_HMAC_SECRET (read
from the environment, never argv) as the organisation owner the console
bootstrap created (TE_OWNER) and calls the coordinator over TLS.

  traffic-events-lab policy <org>                    publish the lab policy
  traffic-events-lab join-key <org> <tag>            print a fresh join key
  traffic-events-lab node-id <org> <name>            print a device id
  traffic-events-lab resource <org> <cidr> <port> <router_id>
                                                     create "Billing DB"
  traffic-events-lab traffic <org> on|off            owner opt-in / opt-out
  traffic-events-lab flows <org> [query]             GET /traffic/flows JSON
  traffic-events-lab export <org>                    CSV export (auditor)
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

BASE = os.environ.get("TE_COORD", "https://traffic-events-coord:8443")
CTX = ssl.create_default_context(cafile=os.environ.get("TE_CA", "/certs/ca.crt"))

# office (alice) may reach store devices on TCP 22, 443, 8080 and ping them;
# RDP is explicitly denied; store devices may ping office devices so the
# pair is mutual. Everything else falls to the default deny.
ACL = {
    "version": 1,
    "defaults": "deny",
    "rules": [
        {"action": "allow", "src_tags": ["office"], "dst_tags": ["store"],
         "dst_ports": ["22", "443", "8080"], "protocols": ["tcp"]},
        {"action": "allow", "src_tags": ["office"], "dst_tags": ["store"],
         "protocols": ["icmp"]},
        {"action": "deny", "src_tags": ["office"], "dst_tags": ["store"],
         "dst_ports": ["3389"], "protocols": ["tcp"]},
        {"action": "allow", "src_tags": ["store"], "dst_tags": ["office", "store"],
         "protocols": ["icmp"]},
    ],
}


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def assertion(org_id: str, role: str) -> str:
    now = int(time.time())
    claims = {
        "sub": os.environ.get("TE_OWNER", "traffic-events-owner"),
        "org_id": org_id,
        "role": role,
        "name": "Jen Walker",
        "email": "owner@warrang.org.au",
        "iss": "blaktail-console",
        "aud": "blaktail-coord",
        "iat": now,
        "exp": now + 50,
        "jti": str(uuid.uuid4()),
    }
    payload = b64(json.dumps(claims).encode())
    secret = os.environ["BLAKTAIL_AUTH_HMAC_SECRET"].encode()
    mac = hmac.new(secret, payload.encode(), hashlib.sha256).digest()
    return f"{payload}.{b64(mac)}"


def call(method: str, path: str, token: str, body=None, raw=False):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(BASE + path, data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(request, context=CTX, timeout=30) as response:
            content = response.read()
            if raw:
                return response.status, content.decode()
            return response.status, (json.loads(content) if content else None)
    except urllib.error.HTTPError as error:
        sys.exit(f"{method} {path} -> {error.code}: {error.read().decode()}")


def main() -> None:
    command, org_id = sys.argv[1], sys.argv[2]
    owner = assertion(org_id, "owner")
    if command == "policy":
        call("PUT", f"/v1/orgs/{org_id}/acl", owner, ACL)
        print("policy published")
    elif command == "join-key":
        _, key = call("POST", f"/v1/orgs/{org_id}/join-keys", owner,
                      {"expires_in_seconds": 600, "tags": [sys.argv[3]]})
        print(key["key"])
    elif command == "node-id":
        _, nodes = call("GET", f"/v1/orgs/{org_id}/nodes", owner)
        print(next(n["id"] for n in nodes if n["name"] == sys.argv[3]))
    elif command == "resource":
        cidr, port, router = sys.argv[3:6]
        _, resource = call("POST", f"/v1/orgs/{org_id}/networks", owner, {
            "name": "Billing DB", "description": "Finance database behind router-1",
            "cidr": cidr, "ports": [port], "protocols": ["tcp"],
            "routing_peers": [{"node_id": router, "metric": 10}],
            "access": {"tags": ["office"]},
        })
        print(resource["id"])
    elif command == "traffic":
        enabled = sys.argv[3] == "on"
        _, settings = call("PUT", f"/v1/orgs/{org_id}/traffic/settings", owner,
                           {"enabled": enabled, "sampling_rate": 1.0, "retention_days": 7})
        print(f"traffic enabled={settings['enabled']}")
    elif command == "flows":
        query = sys.argv[3] if len(sys.argv) > 3 else "limit=200"
        _, page = call("GET", f"/v1/orgs/{org_id}/traffic/flows?{query}",
                       assertion(org_id, "auditor"))
        print(json.dumps(page, sort_keys=True))
    elif command == "export":
        _, text = call("GET", f"/v1/orgs/{org_id}/traffic/events/export?format=csv",
                       assertion(org_id, "auditor"), raw=True)
        print(text, end="")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
