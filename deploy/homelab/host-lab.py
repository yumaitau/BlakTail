#!/usr/bin/env python3
"""Coordinator driver for prove-sshd-limits.sh and prove-clean-install.sh.

Signs short-lived console assertions with BLAKTAIL_AUTH_HMAC_SECRET (read
from the environment, never argv) and calls the coordinator over TLS.

  host-lab bootstrap <org_id> ssh|install   organisation with the lab policy
  host-lab join-key <org_id> <tag>          print a fresh one-use join key
  host-lab nodes <org_id>                   print the node list as JSON
  host-lab revoke <org_id> <node_id>        owner revokes a node
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

BASE = os.environ.get("HOSTLAB_COORD", "https://labs-host-coord:8443")
CTX = ssl.create_default_context(cafile=os.environ.get("HOSTLAB_CA", "/certs/ca.crt"))

ICMP = {"protocols": ["icmp"]}
POLICIES = {
    # store runs sshd. office may log in as deploy only; ranger (guest) may reach
    # store on TCP 8080 (so the pair is wired) but has no SSH grant.
    "ssh": {
        "version": 1,
        "defaults": "deny",
        "rules": [
            {"action": "allow", "src_tags": ["ranger"], "dst_tags": ["store"],
             "dst_ports": ["8080"], "protocols": ["tcp"]},
            {"action": "allow", "src_tags": ["office", "ranger"], "dst_tags": ["store"], **ICMP},
            {"action": "allow", "src_tags": ["store"], "dst_tags": ["office", "ranger"], **ICMP},
        ],
        "ssh": [
            {"action": "allow", "src_tags": ["office"], "dst_tags": ["store"],
             "users": ["deploy"]},
        ],
    },
    # Freshly installed hosts may ping each other.
    "install": {
        "version": 1,
        "defaults": "deny",
        "rules": [
            {"action": "allow", "src_tags": ["office"], "dst_tags": ["store"], **ICMP},
            {"action": "allow", "src_tags": ["store"], "dst_tags": ["office"], **ICMP},
        ],
    },
}


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def assertion(org_id: str, role: str, action=None) -> str:
    now = int(time.time())
    claims = {
        "sub": "host-lab-owner",
        "org_id": org_id,
        "role": role,
        "name": "Host lab",
        "email": "host-lab@example.org",
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


def main() -> None:
    command, org_id = sys.argv[1], sys.argv[2]
    if command == "bootstrap":
        call("POST", "/v1/orgs", assertion(org_id, "service", "bootstrap.prepare"),
             {"id": org_id, "name": "host-lab", "acl": POLICIES[sys.argv[3]]})
        call("POST", f"/v1/orgs/{org_id}/bootstrap-commit",
             assertion(org_id, "service", "bootstrap.commit"), {})
        print("org ready")
    elif command == "join-key":
        _, key = call("POST", f"/v1/orgs/{org_id}/join-keys", assertion(org_id, "owner"),
                      {"expires_in_seconds": 600, "tags": [sys.argv[3]]})
        print(key["key"])
    elif command == "nodes":
        _, nodes = call("GET", f"/v1/orgs/{org_id}/nodes", assertion(org_id, "owner"))
        print(json.dumps(nodes))
    elif command == "revoke":
        status, _ = call("DELETE", f"/v1/orgs/{org_id}/nodes/{sys.argv[3]}",
                         assertion(org_id, "owner"))
        print(f"revoked ({status})")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
