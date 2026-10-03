#!/usr/bin/env python3
"""Coordinator driver and lab DNS server for prove-app-connector.sh.

Signs short-lived console assertions with BLAKTAIL_AUTH_HMAC_SECRET (read
from the environment, never argv) and calls the coordinator over TLS.

  connector-lab bootstrap <org_id>               organisation and policy
  connector-lab join-key <org_id> <tag>          print a fresh join key
  connector-lab create <org_id> <json>           create a network resource, print its id
  connector-lab detail <org_id> <resource_id>    print resource detail as JSON
  connector-lab dns-serve <zone_file>            authoritative UDP DNS on :53

The DNS server answers A queries from <zone_file> (lines `name address ttl`),
re-read on every query so the lab can change answers; anything else is
NXDOMAIN (or an empty NOERROR answer for AAAA of a known name).
"""
import base64
import hashlib
import hmac
import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.request
import uuid

BASE = os.environ.get("CONNECTORLAB_COORD", "https://labs-connector-coord:8443")

# office (laptop) and store (connector) may ping each other, so they pair;
# resource access (tag office, TCP 8080) lets the laptop through the connector.
ACL = {
    "version": 1,
    "defaults": "deny",
    "rules": [
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
        "sub": "connector-lab-owner",
        "org_id": org_id,
        "role": role,
        "name": "Connector lab",
        "email": "connector-lab@example.org",
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
    ctx = ssl.create_default_context(cafile=os.environ.get("CONNECTORLAB_CA", "/certs/ca.crt"))
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(BASE + path, data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(request, context=ctx, timeout=30) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as error:
        sys.exit(f"{method} {path} -> {error.code}: {error.read().decode()}")


def zone(path: str):
    records = {}
    with open(path) as handle:
        for line in handle:
            parts = line.split()
            if len(parts) == 3:
                records.setdefault(parts[0].lower().rstrip("."), []).append(
                    (socket.inet_aton(parts[1]), int(parts[2])))
    return records


def dns_serve(path: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))
    while True:
        packet, peer = sock.recvfrom(512)
        if len(packet) < 12:
            continue
        ident = packet[:2]
        offset, labels = 12, []
        while offset < len(packet) and packet[offset]:
            length = packet[offset]
            labels.append(packet[offset + 1:offset + 1 + length].decode(errors="replace"))
            offset += 1 + length
        question = packet[12:offset + 5]
        qtype = struct.unpack("!H", packet[offset + 1:offset + 3])[0]
        name = ".".join(labels).lower()
        records = zone(path).get(name)
        answers = b""
        rcode = 0 if records is not None else 3
        if records and qtype == 1:
            for address, ttl in records:
                answers += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + address
        count = len(records) if records and qtype == 1 else 0
        header = ident + struct.pack("!BBHHHH", 0x84, rcode, 1, count, 0, 0)
        sock.sendto(header + question + answers, peer)


def main() -> None:
    command = sys.argv[1]
    if command == "dns-serve":
        dns_serve(sys.argv[2])
        return
    org_id = sys.argv[2]
    owner = assertion(org_id, "owner")
    if command == "bootstrap":
        call("POST", "/v1/orgs", assertion(org_id, "service", "bootstrap.prepare"),
             {"id": org_id, "name": "connector-lab", "acl": ACL})
        call("POST", f"/v1/orgs/{org_id}/bootstrap-commit",
             assertion(org_id, "service", "bootstrap.commit"), {})
        print("org ready")
    elif command == "join-key":
        _, key = call("POST", f"/v1/orgs/{org_id}/join-keys", owner,
                      {"expires_in_seconds": 600, "tags": [sys.argv[3]]})
        print(key["key"])
    elif command == "create":
        _, resource = call("POST", f"/v1/orgs/{org_id}/networks", owner, json.loads(sys.argv[3]))
        print(resource["id"])
    elif command == "detail":
        _, detail = call("GET", f"/v1/orgs/{org_id}/networks/{sys.argv[3]}",
                         assertion(org_id, "auditor"))
        print(json.dumps(detail, sort_keys=True))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
