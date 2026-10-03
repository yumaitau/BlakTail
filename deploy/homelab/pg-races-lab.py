#!/usr/bin/env python3
"""Race driver for prove-pg-races.sh.

Two coordinator replicas share one PostgreSQL database. Each round releases
several writers at once (a threading barrier), alternating replicas, and then
checks that exactly one write won and that the stored state is the winner's.

  pg-races-lab bootstrap <org>
  pg-races-lab policy-put <org> <rounds> <writers>
      policy PUT with the same If-Match etag; expect one 204, the rest 412
  pg-races-lab publish-same <org> <rounds> <writers>
      the same draft version published concurrently; expect one 200
  pg-races-lab publish-rival <org> <rounds> <writers>
      different drafts based on the same live policy published concurrently;
      expect one 200, the rest 409 (rebase required) or 412

The HMAC secret is read from BLAKTAIL_AUTH_HMAC_SECRET, never argv.
"""
import base64
import collections
import hashlib
import hmac
import json
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid

REPLICAS = os.environ.get(
    "PGRACES_COORDS", "https://labs-upgrade-races-coord1:8443,https://labs-upgrade-races-coord2:8443"
).split(",")
CTX = ssl.create_default_context(cafile=os.environ.get("PGRACES_CA", "/certs/ca.crt"))


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def assertion(org_id, role="owner", action=None, sub="race-owner"):
    now = int(time.time())
    claims = {
        "sub": sub, "org_id": org_id, "role": role, "name": "Race lab",
        "email": "race-lab@example.org", "iss": "blaktail-console",
        "aud": "blaktail-coord", "iat": now, "exp": now + 50, "jti": str(uuid.uuid4()),
    }
    if action:
        claims["action"] = action
    payload = b64(json.dumps(claims).encode())
    mac = hmac.new(os.environ["BLAKTAIL_AUTH_HMAC_SECRET"].encode(), payload.encode(),
                   hashlib.sha256).digest()
    return f"{payload}.{b64(mac)}"


def call(method, path, org_id, body=None, replica=0, headers=None, **claims):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(REPLICAS[replica % len(REPLICAS)] + path, data=data,
                                     method=method)
    request.add_header("Authorization", f"Bearer {assertion(org_id, **claims)}")
    request.add_header("content-type", "application/json")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, context=CTX, timeout=60) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()[:200]


def must(result, *ok):
    status, body = result
    if status not in ok:
        sys.exit(f"unexpected {status}: {body}")
    return body


def policy(marker):
    return {
        "version": 1, "defaults": "deny",
        "groups": {"race": [f"{marker}@example.org"]},
        "rules": [{"action": "allow", "src_groups": ["race"], "dst_tags": ["store"],
                   "dst_ports": ["8080"], "protocols": ["tcp"]}],
    }


def marker_of(acl):
    members = acl.get("groups", {}).get("race", [])
    return members[0].split("@")[0] if members else None


def live(org_id):
    return must(call("GET", f"/v1/orgs/{org_id}/acl", org_id), 200)


def race(jobs):
    """Run every job at once; return their (status, body) in job order."""
    barrier = threading.Barrier(len(jobs))
    results = [None] * len(jobs)

    def run(index, job):
        barrier.wait()
        results[index] = job()

    threads = [threading.Thread(target=run, args=(i, job)) for i, job in enumerate(jobs)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results


def report(name, rounds, tally, lost, problems):
    print(f"{name}: {rounds} rounds, statuses {dict(sorted(tally.items()))}, "
          f"lost updates {lost}, problems {len(problems)}")
    for problem in problems[:10]:
        print("  " + problem)
    if lost or problems:
        sys.exit(1)


def policy_put(org_id, rounds, writers):
    tally, lost, problems = collections.Counter(), 0, []
    for round_no in range(rounds):
        before = live(org_id)
        etag, revision = before["etag"], before["revision"]
        markers = [f"r{round_no}w{w}-{uuid.uuid4().hex[:6]}" for w in range(writers)]
        results = race([
            (lambda w=w: call("PUT", f"/v1/orgs/{org_id}/acl", org_id, policy(markers[w]),
                              replica=w, headers={"If-Match": f'"{etag}"'}))
            for w in range(writers)
        ])
        statuses = [status for status, _ in results]
        tally.update(statuses)
        winners = [w for w, status in enumerate(statuses) if status == 204]
        if len(winners) != 1 or any(s not in (204, 412) for s in statuses):
            problems.append(f"round {round_no}: statuses {statuses}")
            continue
        after = live(org_id)
        if marker_of(after) != markers[winners[0]] or after["revision"] != revision + 1:
            lost += 1
            problems.append(f"round {round_no}: stored {marker_of(after)} rev {after['revision']}, "
                            f"winner {markers[winners[0]]} expected rev {revision + 1}")
    report("policy PUT, same If-Match", rounds, tally, lost, problems)


def new_draft(org_id, marker, replica):
    draft = must(call("POST", f"/v1/orgs/{org_id}/changes", org_id,
                      {"title": f"race {marker}", "surfaces": ["policy"]}, replica=replica), 201)
    draft = must(call("PUT", f"/v1/orgs/{org_id}/changes/{draft['id']}", org_id,
                      {"version": draft["version"], "payload": {"policy": policy(marker)}},
                      replica=replica), 200)
    preview = must(call("POST", f"/v1/orgs/{org_id}/changes/{draft['id']}/preview", org_id, {},
                        replica=replica), 200)
    draft["risks"] = [risk["code"] for risk in preview.get("risks", [])]
    return draft


def publish(org_id, draft, replica):
    return call("POST", f"/v1/orgs/{org_id}/changes/{draft['id']}/publish", org_id,
                {"version": draft["version"], "confirm_risks": draft["risks"]}, replica=replica)


def drafts_status(org_id, draft):
    return must(call("GET", f"/v1/orgs/{org_id}/changes/{draft['id']}", org_id), 200)["status"]


def publish_same(org_id, rounds, writers):
    tally, lost, problems = collections.Counter(), 0, []
    for round_no in range(rounds):
        revision = live(org_id)["revision"]
        marker = f"same{round_no}-{uuid.uuid4().hex[:6]}"
        draft = new_draft(org_id, marker, round_no)
        results = race([(lambda w=w: publish(org_id, draft, w)) for w in range(writers)])
        statuses = [status for status, _ in results]
        tally.update(statuses)
        if statuses.count(200) != 1 or any(s not in (200, 409, 412) for s in statuses):
            problems.append(f"round {round_no}: statuses {statuses}")
            continue
        after = live(org_id)
        if marker_of(after) != marker or after["revision"] != revision + 1:
            lost += 1
            problems.append(f"round {round_no}: stored {marker_of(after)} rev {after['revision']}")
        if drafts_status(org_id, draft) != "published":
            problems.append(f"round {round_no}: draft not published")
    report("draft publish, same draft", rounds, tally, lost, problems)


def publish_rival(org_id, rounds, writers):
    tally, lost, problems = collections.Counter(), 0, []
    for round_no in range(rounds):
        revision = live(org_id)["revision"]
        markers = [f"rival{round_no}w{w}-{uuid.uuid4().hex[:6]}" for w in range(writers)]
        drafts = [new_draft(org_id, markers[w], w) for w in range(writers)]
        results = race([(lambda w=w: publish(org_id, drafts[w], w)) for w in range(writers)])
        statuses = [status for status, _ in results]
        tally.update(statuses)
        winners = [w for w, status in enumerate(statuses) if status == 200]
        if len(winners) != 1 or any(s not in (200, 409, 412) for s in statuses):
            problems.append(f"round {round_no}: statuses {statuses}")
            continue
        after = live(org_id)
        if marker_of(after) != markers[winners[0]] or after["revision"] != revision + 1:
            lost += 1
            problems.append(f"round {round_no}: stored {marker_of(after)} rev {after['revision']}, "
                            f"winner {markers[winners[0]]}")
        for w, draft in enumerate(drafts):
            state = drafts_status(org_id, draft)
            if state != ("published" if w == winners[0] else "open"):
                problems.append(f"round {round_no}: draft {w} {state}")
            if w != winners[0]:
                call("POST", f"/v1/orgs/{org_id}/changes/{draft['id']}/discard", org_id,
                     {"version": draft["version"]})
    report("draft publish, rival drafts on one base", rounds, tally, lost, problems)


def main():
    command, org_id = sys.argv[1], sys.argv[2]
    if command == "bootstrap":
        must(call("POST", "/v1/orgs", org_id, {"id": org_id, "name": "race-lab", "acl": policy("seed")},
                  role="service", action="bootstrap.prepare"), 200, 201, 202)
        must(call("POST", f"/v1/orgs/{org_id}/bootstrap-commit", org_id, {},
                  role="service", action="bootstrap.commit", replica=1), 200, 201, 202, 204)
        print("org ready")
        return
    rounds, writers = int(sys.argv[3]), int(sys.argv[4])
    {"policy-put": policy_put, "publish-same": publish_same,
     "publish-rival": publish_rival}[command](org_id, rounds, writers)


if __name__ == "__main__":
    main()
