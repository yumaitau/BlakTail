#!/usr/bin/env python3
"""Coordinator driver for prove-traffic.sh.

Signs short-lived console assertions with BLAKTAIL_AUTH_HMAC_SECRET (read
from the environment, never argv) and calls the coordinator over TLS.

  traffic-lab bootstrap <org_id>        organisation with a port-scoped policy
  traffic-lab join-key <org_id> <tag>   print a fresh join key for a tag
  traffic-lab traffic <org_id> on|off   owner opt-in / opt-out (100 % sampling)
  traffic-lab summary <org_id>          print the /traffic summary as JSON
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

BASE = os.environ.get("TRAFFICLAB_COORD", "https://trafficlab-coord:8443")
CTX = ssl.create_default_context(cafile=os.environ.get("TRAFFICLAB_CA", "/certs/ca.crt"))

# office may reach store on TCP 8080 and ICMP; store may ping office (pairing
# needs a grant in each direction). Everything else is denied.
ACL = {
    "version": 1,
    "defaults": "deny",
    "rules": [
        {"action": "allow", "src_tags": ["office"], "dst_tags": ["store"],
         "dst_ports": ["8080"], "protocols": ["tcp"]},
        {"action": "allow", "src_tags": ["office"], "dst_tags": ["store"],
         "protocols": ["icmp"]},
        {"action": "allow", "src_tags": ["store"], "dst_tags": ["office"],
         "protocols": ["icmp"]},
    ],
}


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def assertion(org_id: str, role: str, action=None) -> str:
    now = int(time.time())
    claims = {
        "sub": "traffic-lab-owner",
        "org_id": org_id,
        "role": role,
        "name": "Traffic lab",
        "email": "traffic-lab@example.org",
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
             {"id": org_id, "name": "traffic-lab", "acl": ACL})
        call("POST", f"/v1/orgs/{org_id}/bootstrap-commit",
             assertion(org_id, "service", "bootstrap.commit"), {})
        print("org ready")
    elif command == "join-key":
        _, key = call("POST", f"/v1/orgs/{org_id}/join-keys", assertion(org_id, "owner"),
                      {"expires_in_seconds": 600, "tags": [sys.argv[3]]})
        print(key["key"])
    elif command == "traffic":
        enabled = sys.argv[3] == "on"
        _, settings = call("PUT", f"/v1/orgs/{org_id}/traffic/settings",
                           assertion(org_id, "owner"),
                           {"enabled": enabled, "sampling_rate": 1.0, "retention_days": 1})
        print(f"traffic enabled={settings['enabled']}")
    elif command == "summary":
        _, summary = call("GET", f"/v1/orgs/{org_id}/traffic/summary?hours=1",
                          assertion(org_id, "auditor"))
        print(json.dumps(summary, sort_keys=True))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
