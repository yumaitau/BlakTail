#!/usr/bin/env python3
"""Relay lab helper: creates a throwaway organisation on a lab coordinator and
mints join keys, signing console assertions with the lab's HMAC secret (the
same format the console uses). Never use against a real deployment.

  relay-lab bootstrap            -> prints the new organisation id
  relay-lab mint ORG_ID TAG      -> prints a single-use join key
"""

import base64
import hashlib
import hmac
import json
import os
import ssl
import sys
import time
import urllib.request
import uuid

COORD = os.environ.get("COORD_BASE_URL", "https://coord:8443").rstrip("/")
SECRET = os.environ["BLAKTAIL_AUTH_HMAC_SECRET"].encode()
CONTEXT = ssl.create_default_context(cafile=os.environ.get("COORD_CA", "/certs/ca.crt"))


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def assertion(org_id: str, role: str, user: str, action: str | None = None) -> str:
    now = int(time.time())
    claims = {
        "sub": user,
        "org_id": org_id,
        "role": role,
        "name": user,
        "email": "" if role == "service" else f"{user}@lab.example.au",
        "iss": "blaktail-console",
        "aud": "blaktail-coord",
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
    }
    if action:
        claims["action"] = action
    payload = b64(json.dumps(claims).encode())
    signature = b64(hmac.new(SECRET, payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{signature}"


def call(method: str, path: str, token: str, body: dict) -> dict:
    request = urllib.request.Request(
        COORD + path,
        method=method,
        data=json.dumps(body).encode(),
        headers={"authorization": f"Bearer {token}", "content-type": "application/json"},
    )
    with urllib.request.urlopen(request, context=CONTEXT, timeout=15) as response:
        text = response.read()
        return json.loads(text) if text else {}


def main() -> None:
    command = sys.argv[1]
    if command == "bootstrap":
        org_id = str(uuid.uuid4())
        acl = {"version": 1, "defaults": "same_tag", "rules": []}
        call(
            "POST",
            "/v1/orgs",
            assertion(org_id, "service", "operator-cli", "bootstrap.prepare"),
            {"id": org_id, "name": "Relay lab", "acl": acl},
        )
        call(
            "POST",
            f"/v1/orgs/{org_id}/bootstrap-commit",
            assertion(org_id, "service", "operator-cli", "bootstrap.commit"),
            {},
        )
        print(org_id)
    elif command == "mint":
        org_id, tag = sys.argv[2], sys.argv[3]
        minted = call(
            "POST",
            f"/v1/orgs/{org_id}/join-keys",
            assertion(org_id, "owner", "lab-owner"),
            {"expires_in_seconds": 900, "single_use": True, "tags": [tag]},
        )
        print(minted["key"])
    else:
        raise SystemExit(f"unknown command {command}")


if __name__ == "__main__":
    main()
