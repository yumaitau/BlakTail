#!/usr/bin/env python3
"""Coordinator driver for prove-public-ingress.sh.

Signs short-lived console assertions with the lab's HMAC secret (exactly
what the console does) so the proof needs no browser. Lab use only.
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

COORD = os.environ.get("COORD", "https://pubingress-coord:8443")
SECRET = os.environ["BLAKTAIL_AUTH_HMAC_SECRET"].encode()
CTX = ssl.create_default_context(cafile=os.environ.get("COORD_CA", "/certs/ca.crt"))
STATE = os.environ.get("LAB_STATE", "/lab/org.json")


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def assertion(org_id: str, role: str, action=None) -> str:
    now = int(time.time())
    claims = {
        "sub": f"lab-{role}",
        "org_id": org_id,
        "role": role,
        "name": f"Lab {role}",
        "email": f"{role}@example.org.au",
        "iss": "blaktail-console",
        "aud": "blaktail-coord",
        "iat": now,
        "exp": now + 60,
        "jti": uuid.uuid4().hex + uuid.uuid4().hex,
    }
    if action:
        claims["action"] = action
    payload = b64(json.dumps(claims).encode())
    signature = b64(hmac.new(SECRET, payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{signature}"


def call(method: str, path: str, org_id: str, role="owner", body=None, action=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(COORD + path, data=data, method=method)
    request.add_header("Authorization", "Bearer " + assertion(org_id, role, action))
    request.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(request, context=CTX, timeout=30) as response:
            text = response.read().decode()
            return response.status, (json.loads(text) if text else None)
    except urllib.error.HTTPError as error:
        text = error.read().decode()
        try:
            return error.code, json.loads(text)
        except ValueError:
            return error.code, text


def org() -> str:
    with open(STATE) as handle:
        return json.load(handle)["org_id"]


def expect(status, body, *ok):
    if status not in ok:
        print(json.dumps({"status": status, "body": body}), file=sys.stderr)
        sys.exit(1)
    return body


def main(argv):
    command = argv[0]
    if command == "bootstrap":
        org_id = str(uuid.uuid4())
        acl = {"version": 1, "defaults": "same_tag", "rules": []}
        expect(*call("POST", "/v1/orgs", org_id, "service", {"id": org_id, "name": "Ingress lab", "acl": acl}, "bootstrap.prepare"), 202)
        expect(*call("POST", f"/v1/orgs/{org_id}/bootstrap-commit", org_id, "service", {}, "bootstrap.commit"), 201)
        with open(STATE, "w") as handle:
            json.dump({"org_id": org_id}, handle)
        print(org_id)
    elif command == "join-key":
        body = expect(*call("POST", f"/v1/orgs/{org()}/join-keys", org(), body={"expires_in_seconds": 600, "tags": [argv[1]]}), 201)
        print(body["key"])
    elif command == "node-id":
        body = expect(*call("GET", f"/v1/orgs/{org()}/nodes", org()), 200)
        nodes = body if isinstance(body, list) else body.get("nodes", [])
        print(next(n["id"] for n in nodes if n["name"] == argv[1]))
    elif command == "enable":
        expect(*call("PUT", f"/v1/orgs/{org()}/public-ingress/settings", org(), body={"enabled": True, "abuse_contact": "abuse@example.org.au", "confirm": "PUBLIC"}), 200)
        print("enabled")
    elif command == "create-route":
        fqdn, node_id, port = argv[1], argv[2], int(argv[3])
        tls_mode = argv[4] if len(argv) > 4 else "operator_files"
        route = {"fqdn": fqdn, "confirm_fqdn": fqdn, "target_node_id": node_id, "target_port": port, "tls_mode": tls_mode}
        body = expect(*call("POST", f"/v1/orgs/{org()}/public-ingress/routes", org(), body=route), 201)
        print(body["id"])
    elif command == "as-role":
        # as-role <role> <METHOD> <path> [json]: prints the HTTP status only.
        status, _ = call(argv[2], argv[3].replace("{org}", org()), org(), argv[1], json.loads(argv[4]) if len(argv) > 4 else None)
        print(status)
    elif command == "emergency":
        status, body = call("POST", f"/v1/orgs/{org()}/public-ingress/routes/{argv[1]}/emergency-disable", org(), "admin", {"reason": "lab emergency drill"})
        expect(status, body, 200)
        print(body["status"])
    elif command == "reenable":
        route = next(r for r in expect(*call("GET", f"/v1/orgs/{org()}/public-ingress", org()), 200)["routes"] if r["id"] == argv[1])
        body = {"revision": route["revision"], "enabled": True, "confirm_fqdn": route["fqdn"]}
        print(expect(*call("PATCH", f"/v1/orgs/{org()}/public-ingress/routes/{argv[1]}", org(), body=body), 200)["status"])
    elif command == "workspace":
        print(json.dumps(expect(*call("GET", f"/v1/orgs/{org()}/public-ingress", org(), "member"), 200), indent=2))
    elif command == "set-acl":
        expect(*call("PUT", f"/v1/orgs/{org()}/acl", org(), body=json.loads(argv[1])), 200, 204)
        print("acl updated")
    else:
        raise SystemExit(f"unknown command {command}")


if __name__ == "__main__":
    main(sys.argv[1:])
