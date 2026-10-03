#!/usr/bin/env python3
"""Coordinator driver for prove-private-services.sh.

Signs short-lived console assertions with BLAKTAIL_AUTH_HMAC_SECRET (read
from the environment, never argv) and calls the coordinator over TLS.

  svc-lab bootstrap <org_id>                         create the lab organisation
  svc-lab join-key <org_id> <tags>                   print a join key (tags comma separated)
  svc-lab create <org_id> <name> <node> <port> <tags> create a service, print id and fqdn
  svc-lab status <org_id>                            print one JSON line per service
  svc-lab disable <org_id> <service_id>              disable a service
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

BASE = os.environ.get("SVCLAB_COORD", "https://svclab-coord:8443")
CTX = ssl.create_default_context(cafile=os.environ.get("SVCLAB_CA", "/certs/ca.crt"))


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def assertion(org_id: str, role: str, action=None) -> str:
    now = int(time.time())
    claims = {
        "sub": "svc-lab-operator",
        "org_id": org_id,
        "role": role,
        "name": "Service lab",
        "email": "svc-lab@example.org",
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


def services(org_id: str):
    return call("GET", f"/v1/orgs/{org_id}/services", assertion(org_id, "auditor"))[1]


def main() -> None:
    command, org_id = sys.argv[1], sys.argv[2]
    if command == "bootstrap":
        acl = {"version": 1, "defaults": "same_tag", "rules": []}
        call("POST", "/v1/orgs", assertion(org_id, "service", "bootstrap.prepare"),
             {"id": org_id, "name": "svc-lab", "acl": acl})
        call("POST", f"/v1/orgs/{org_id}/bootstrap-commit",
             assertion(org_id, "service", "bootstrap.commit"), {})
        print("org ready")
    elif command == "join-key":
        _, key = call("POST", f"/v1/orgs/{org_id}/join-keys", assertion(org_id, "owner"),
                      {"expires_in_seconds": 600, "tags": sys.argv[3].split(",")})
        print(key["key"])
    elif command == "create":
        name, node, port, tags = sys.argv[3:7]
        _, service = call("POST", f"/v1/orgs/{org_id}/services", assertion(org_id, "owner"),
                          {"name": name, "target_node_id": node, "port": int(port),
                           "protocol": "http", "access_tags": tags.split(",")})
        print(json.dumps({"id": service["id"], "fqdn": service["fqdn"]}))
    elif command == "status":
        view = services(org_id)
        for service in view["services"]:
            print(json.dumps({
                "name": service["name"],
                "status": service["status"],
                "reachable": service["reachable"],
                "detail": service["status_detail"],
            }, sort_keys=True))
        lowered = json.dumps(view).lower()
        if "private key" in lowered or "begin ec" in lowered:
            sys.exit("service view mentions private key material")
    elif command == "disable":
        service_id = sys.argv[3]
        current = next(s for s in services(org_id)["services"] if s["id"] == service_id)
        call("PATCH", f"/v1/orgs/{org_id}/services/{service_id}", assertion(org_id, "owner"),
             {"revision": current["revision"], "enabled": False})
        print("disabled")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
