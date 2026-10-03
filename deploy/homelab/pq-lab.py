#!/usr/bin/env python3
"""Coordinator driver for prove-post-quantum.sh.

Signs short-lived console assertions with BLAKTAIL_AUTH_HMAC_SECRET (read
from the environment, never argv) and calls the coordinator over TLS.

  pq-lab bootstrap <org_id>         create the lab organisation
  pq-lab join-key <org_id>          print a fresh join key
  pq-lab policy <org_id> <mode>     set off|prefer|require (blocking on)
  pq-lab overview <org_id>          print per-peer rows as JSON lines
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

BASE = os.environ.get("PQLAB_COORD", "https://pqlab-coord:8443")
CTX = ssl.create_default_context(cafile=os.environ.get("PQLAB_CA", "/certs/ca.crt"))


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def assertion(org_id: str, role: str, action=None) -> str:
    now = int(time.time())
    claims = {
        "sub": "pq-lab-operator",
        "org_id": org_id,
        "role": role,
        "name": "PQ lab",
        "email": "pq-lab@example.org",
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
        acl = {"version": 1, "defaults": "same_tag", "rules": []}
        call("POST", "/v1/orgs", assertion(org_id, "service", "bootstrap.prepare"),
             {"id": org_id, "name": "pq-lab", "acl": acl})
        call("POST", f"/v1/orgs/{org_id}/bootstrap-commit",
             assertion(org_id, "service", "bootstrap.commit"), {})
        print("org ready")
    elif command == "join-key":
        _, key = call("POST", f"/v1/orgs/{org_id}/join-keys", assertion(org_id, "owner"),
                      {"expires_in_seconds": 600})
        print(key["key"])
    elif command == "policy":
        _, policy = call("PUT", f"/v1/orgs/{org_id}/post-quantum", assertion(org_id, "owner"),
                         {"mode": sys.argv[3], "block_unestablished": True})
        print(f"policy mode={policy['mode']} revision={policy['revision']}")
    elif command == "overview":
        _, view = call("GET", f"/v1/orgs/{org_id}/post-quantum", assertion(org_id, "auditor"))
        names = {device["id"]: device["name"] for device in view["devices"]}
        capable = {device["name"]: device["capable"] for device in view["devices"]}
        print(json.dumps({"capable": capable}))
        for row in view["peers"]:
            print(json.dumps({
                "device": names.get(row["node_id"]),
                "peer": row["peer_name"],
                "state": row["state"],
                "mode": row["mode"],
                "algorithm": row["algorithm"],
                "epoch": row["epoch"],
                "rotated_seconds_ago": row["rotated_seconds_ago"],
                "blocked": row["blocked"],
                "reason": row["reason"],
            }, sort_keys=True))
        lowered = json.dumps(view).lower()
        for needle in ("psk", "preshared", "private"):
            if needle in lowered:
                sys.exit(f"coordinator overview mentions {needle}")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
