#!/usr/bin/env bash
# Live lab for per-flow traffic events (draft 17, docs/audit-and-traffic.md).
# One Docker host (default context m3-max), everything named
# traffic-events-*: PostgreSQL, a coordinator on PostgreSQL, three Linux
# agents on kernel WireGuard and a host behind a routing peer.
#
#   wan   10.242.0.0/24  coordinator, alice-laptop (office), server (store),
#                        router-1 (store, routing peer)
#   site  10.242.1.0/24  router-1 and the "Billing DB" host 10.242.1.10
#                        (TCP 5432 granted to office as a network resource,
#                        TCP 8080 not granted)
#
# Proves, with traffic diagnostics on:
#   1. allowed TCP (alice -> server 8080) arrives as start/end events from
#      both ends with device identities, ports and rule 1
#   2. allowed ICMP (ping) arrives with ICMP type Echo and rule 2
#   3. denied ports arrive as drop events from server: 3389 (deny rule 3,
#      hint acl:deny-rule) and 9000 (default deny, hint acl:default)
#   4. routed traffic to the resource arrives from alice (router named) and
#      router-1 (connection type routed, destination Billing DB); a port the
#      resource does not grant is a drop on router-1 (fwd:default)
#   5. turning diagnostics off stops events: nothing new is stored for 90 s
#      and every agent logs the stop
#
# KEEP=1 leaves the lab running (for console screenshots). With TE_ORG and
# TE_OWNER set (a console-bootstrapped organisation and its owner's user id)
# the lab uses that organisation instead of creating one; TE_INFRA_ONLY=1
# stops after PostgreSQL and the coordinator are up, TE_REUSE=1 starts from
# that running infrastructure.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
CTX="${DOCKER_CONTEXT:-m3-max}"
D=(docker --context "$CTX")
P=traffic-events
IMG="${LABS_IMAGE:-$P-lab:latest}"
COORD_URL=https://$P-coord:8443
PUBLISH_HOST="${TE_PUBLISH_HOST:-100.89.92.86}"
STATE="${TE_STATE:-${TMPDIR:-/tmp}/$P-state}"
mkdir -p "$STATE"
DB=10.242.1.10
AGENTS=(alice server router)

cleanup() {
  for c in coord pg db "${AGENTS[@]}"; do "${D[@]}" rm -f "$P-$c" >/dev/null 2>&1 || true; done
  for n in wan site; do "${D[@]}" network rm "$P-$n" >/dev/null 2>&1 || true; done
  "${D[@]}" volume rm "$P-certs" >/dev/null 2>&1 || true
}
[[ -n "${KEEP:-}" || -n "${TE_INFRA_ONLY:-}" ]] || trap cleanup EXIT
fail() { echo "FAIL $*" >&2; exit 1; }
x() { local c="$1"; shift; "${D[@]}" exec "$P-$c" "$@"; }
psql_q() { x pg psql -U blaktail -d blaktail -tAc "$1"; }

if [[ -z "${TE_REUSE:-}" ]]; then
  if [[ -z "${LABS_IMAGE:-}" ]]; then
    echo "== build lab image on $CTX"
    git ls-files -co --exclude-standard -z -- . ':!apps' \
      | tar --null -T - -czf - \
      | "${D[@]}" build -q -f deploy/homelab/labs.Dockerfile -t "$IMG" - >/dev/null
  fi
  cleanup
  "${D[@]}" network create --subnet 10.242.0.0/24 "$P-wan" >/dev/null
  "${D[@]}" network create --internal --subnet 10.242.1.0/24 "$P-site" >/dev/null
  "${D[@]}" volume create "$P-certs" >/dev/null
  printf '%s' "$(openssl rand -hex 32)" >"$STATE/hmac"
  printf '%s' "$(openssl rand -hex 32)" >"$STATE/relay"

  echo "== PostgreSQL (coordinator and console databases)"
  "${D[@]}" run -d --name "$P-pg" --network "$P-wan" -p 55492:5432 \
    -e POSTGRES_USER=blaktail -e POSTGRES_PASSWORD=blaktail -e POSTGRES_DB=blaktail \
    postgres:16-alpine >/dev/null
  for i in $(seq 1 61); do
    (( i <= 60 )) || fail "postgres not ready"
    x pg pg_isready -U blaktail -d blaktail >/dev/null 2>&1 && break
    sleep 1
  done
  sleep 2
  x pg psql -U blaktail -d blaktail -qc "CREATE DATABASE console" >/dev/null

  echo "== coordinator on PostgreSQL"
  "${D[@]}" run -d --name "$P-coord" --network "$P-wan" -p 18492:8443 -v "$P-certs:/certs" \
    -e BLAKTAIL_AUTH_HMAC_SECRET="$(cat "$STATE/hmac")" \
    -e BLAKTAIL_RELAY_AUTH_SECRET="$(cat "$STATE/relay")" \
    -e BLAKTAIL_REGION=ap-southeast-2 -e BLAKTAIL_BIND=0.0.0.0:8443 \
    -e BLAKTAIL_DATABASE_BACKEND=postgres -e BLAKTAIL_DATABASE_STORAGE=network \
    -e BLAKTAIL_DATABASE_URL=postgres://blaktail:blaktail@$P-pg:5432/blaktail \
    -e BLAKTAIL_TLS_CERT=/certs/coord.crt -e BLAKTAIL_TLS_KEY=/certs/coord.key \
    -e BLAKTAIL_CONSOLE_URL=http://127.0.0.1:3492 \
    "$IMG" >/dev/null
  "${D[@]}" cp deploy/homelab/traffic-events-lab.py "$P-coord:/usr/local/bin/traffic-events-lab"
  x coord chmod 0755 /usr/local/bin/traffic-events-lab
  "${D[@]}" exec -e P="$P" -e PUBLISH_HOST="$PUBLISH_HOST" "$P-coord" sh -c '
    set -e; cd /certs
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
      -subj "/CN=traffic-events CA" -keyout ca.key -out ca.crt 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -subj "/CN=$P-coord" -keyout coord.key -out coord.csr 2>/dev/null
    printf "subjectAltName=DNS:%s,IP:%s,IP:127.0.0.1\n" "$P-coord" "$PUBLISH_HOST" > san.ext
    openssl x509 -req -in coord.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
      -days 2 -extfile san.ext -out coord.crt 2>/dev/null
    chmod 644 coord.key ca.crt coord.crt; rm -f ca.key'
  "${D[@]}" cp "$P-coord:/certs/ca.crt" "$STATE/ca.crt"
  "${D[@]}" exec -d "$P-coord" sh -c '(blaktail-coord migrate && blaktail-coord serve) >/var/log/coord.log 2>&1'
  for i in $(seq 1 61); do
    (( i <= 60 )) || { x coord tail -5 /var/log/coord.log; fail "coordinator not ready"; }
    x coord python3 -c "import ssl,urllib.request; urllib.request.urlopen('$COORD_URL/readyz', context=ssl.create_default_context(cafile='/certs/ca.crt'))" >/dev/null 2>&1 && break
    sleep 1
  done
  version="$(psql_q "SELECT MAX(version) FROM coordinator_schema_migrations")"
  [[ "$version" == 41 ]] || fail "schema version $version, want 41"
  echo "ok coordinator on PostgreSQL at schema $version"
  if [[ -n "${TE_INFRA_ONLY:-}" ]]; then
    echo "infrastructure up; CA at $STATE/ca.crt, HMAC secret at $STATE/hmac"
    exit 0
  fi
fi

export BLAKTAIL_AUTH_HMAC_SECRET="$(cat "$STATE/hmac")"
ORG="${TE_ORG:-}"
OWNER="${TE_OWNER:-traffic-events-owner}"
lab() { "${D[@]}" exec -e BLAKTAIL_AUTH_HMAC_SECRET -e TE_OWNER="$OWNER" -e TE_COORD="$COORD_URL" "$P-coord" traffic-events-lab "$@"; }
if [[ -z "$ORG" ]]; then
  ORG="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  "${D[@]}" exec -i -e BLAKTAIL_AUTH_HMAC_SECRET -e ORG="$ORG" "$P-coord" python3 - <<'PY'
import base64, hashlib, hmac, json, os, ssl, time, urllib.request, uuid
ctx = ssl.create_default_context(cafile="/certs/ca.crt")
org = os.environ["ORG"]
def token(action):
    now = int(time.time())
    claims = {"sub": "traffic-events-service", "org_id": org, "role": "service", "name": "lab",
              "email": "lab@example.org", "iss": "blaktail-console", "aud": "blaktail-coord",
              "iat": now, "exp": now + 50, "jti": str(uuid.uuid4()), "action": action}
    p = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    m = hmac.new(os.environ["BLAKTAIL_AUTH_HMAC_SECRET"].encode(), p.encode(), hashlib.sha256).digest()
    return p + "." + base64.urlsafe_b64encode(m).rstrip(b"=").decode()
for path, action, body in [("/v1/orgs", "bootstrap.prepare", {"id": org, "name": "Warrang Health", "acl": {"version": 1, "defaults": "deny", "rules": []}}),
                           (f"/v1/orgs/{org}/bootstrap-commit", "bootstrap.commit", {})]:
    r = urllib.request.Request("https://traffic-events-coord:8443" + path, data=json.dumps(body).encode(), method="POST")
    r.add_header("Authorization", "Bearer " + token(action)); r.add_header("content-type", "application/json")
    urllib.request.urlopen(r, context=ctx, timeout=30).read()
print("org ready")
PY
fi
lab policy "$ORG"

echo "== the Billing DB host behind router-1"
"${D[@]}" run -d --name "$P-db" --network "$P-site" --ip "$DB" "$IMG" >/dev/null
"${D[@]}" exec -d "$P-db" sh -c 'nc -lk -p 5432 >/dev/null'
"${D[@]}" exec -d "$P-db" python3 -m http.server 8080

echo "== agents: alice-laptop (office), server (store), router-1 (store, routing peer)"
for name in "${AGENTS[@]}"; do
  "${D[@]}" run -d --name "$P-$name" --hostname "$name" --network "$P-wan" --privileged \
    -v "$P-certs:/certs:ro" "$IMG" >/dev/null
done
"${D[@]}" network connect "$P-site" "$P-router"
wan_ip() { "${D[@]}" inspect -f "{{(index .NetworkSettings.Networks \"$P-wan\").IPAddress}}" "$P-$1"; }
start_agent() { # container device-name tag extra...
  local name="$1" device="$2" tag="$3"; shift 3
  BLAKTAIL_JOIN_KEY="$(lab join-key "$ORG" "$tag")" "${D[@]}" exec -d -e BLAKTAIL_JOIN_KEY "$P-$name" sh -c \
    "blaktaild --coord-ca /certs/ca.crt up --coord $COORD_URL --name $device --endpoint $(wan_ip "$name"):51820 $* >>/var/log/agent.log 2>&1"
}
pin_port() {
  for _ in $(seq 1 30); do
    x "$1" wg set blaktail0 listen-port 51820 2>/dev/null && return 0
    sleep 1
  done
  fail "agent $1 never created blaktail0"
}
overlay() { x "$1" blaktaild status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["address"].split("/")[0])'; }
wait_for() { # seconds description command...
  local limit="$1" what="$2" start=$SECONDS; shift 2
  until "$@" >/dev/null 2>&1; do
    (( SECONDS - start < limit )) || fail "$what (after ${limit}s)"
    sleep 2
  done
  echo "ok $what after $((SECONDS - start))s"
}
start_agent alice alice-laptop office
start_agent server server store
start_agent router router-1 store --advertise-routes 10.242.1.0/24
for name in "${AGENTS[@]}"; do pin_port "$name"; done
for name in "${AGENTS[@]}"; do wait_for 60 "$name enrolled" overlay "$name"; done
ALICE="$(overlay alice)"; SERVER="$(overlay server)"; ROUTER="$(overlay router)"
ROUTER_ID="$(lab node-id "$ORG" router-1)"
RESOURCE="$(lab resource "$ORG" "$DB/32" 5432 "$ROUTER_ID")"
echo "alice $ALICE, server $SERVER, router-1 $ROUTER; resource $RESOURCE"
x server sh -c 'nohup python3 -m http.server 8080 >/dev/null 2>&1 &'
for port in 9000 3389; do "${D[@]}" exec -d "$P-server" sh -c "nc -lk -p $port >/dev/null"; done
wait_for 90 "alice reaches server 8080" x alice nc -z -w 3 "$SERVER" 8080
wait_for 90 "alice reaches Billing DB 5432 through router-1" x alice nc -z -w 3 "$DB" 5432
x alice nc -z -w 3 "$SERVER" 9000 && fail "9000 should be rejected"
x alice nc -z -w 3 "$DB" 8080 && fail "Billing DB 8080 is not granted"
echo "ok policy enforced before reporting"

stored() { psql_q "SELECT COUNT(*) FROM flow_events WHERE org_id='$ORG'"; }
[[ "$(stored)" == 0 ]] || fail "events stored while off"

echo "== traffic diagnostics on"
lab traffic "$ORG" on
sleep 8
generate() {
  x alice sh -c "curl -s -o /dev/null --max-time 3 http://$SERVER:8080/" || true
  x alice ping -c 3 -i 0.3 -W 2 "$SERVER" >/dev/null 2>&1 || true
  x alice nc -z -w 2 "$SERVER" 3389 >/dev/null 2>&1 || true
  x alice nc -z -w 2 "$SERVER" 9000 >/dev/null 2>&1 || true
  x alice sh -c "printf 'SELECT 1;' | nc -w 2 -q 1 $DB 5432" >/dev/null 2>&1 || true
  x alice nc -z -w 2 "$DB" 8080 >/dev/null 2>&1 || true
}
flows() { lab flows "$ORG" "${1:-limit=200}"; }
check() {
  flows | python3 -c '
import json, sys
page = json.load(sys.stdin)
alice, server, db = sys.argv[1:4]
events = [e for f in page["flows"] for e in f["events"]]
def find(**want):
    out = []
    for e in events:
        ok = True
        for k, v in want.items():
            cur = e
            for part in k.split("__"):
                cur = cur.get(part) if isinstance(cur, dict) else None
            if cur != v:
                ok = False
        if ok:
            out.append(e)
    return out
checks = {
  "tcp 8080 start from alice": find(event_type="start", reporter__name="alice-laptop", destination__port=8080, rule__index=0),
  "tcp 8080 end with bytes": [e for e in find(event_type="end", destination__name="server", destination__port=8080) if e["rx_bytes"] > 0 and e["tx_bytes"] > 0],
  "icmp end with packets": [e for e in find(event_type="end", protocol="icmp") if e["rx_packets"] > 0 and e["tx_packets"] > 0],
  "routed 8080 not granted": find(reporter__name="alice-laptop", destination__port=8080, destination__name="Billing DB", rule__basis="default_deny"),
  "tcp 8080 start seen by server": find(event_type="start", reporter__name="server", direction="inbound", destination__port=8080),
  "icmp echo": find(protocol="icmp", icmp_name="Echo", rule__index=1),
  "drop 3389 deny rule": find(event_type="drop", reporter__name="server", destination__port=3389, rule__basis="deny_rule", rule__hint="acl:deny-rule"),
  "drop 9000 default deny": find(event_type="drop", reporter__name="server", destination__port=9000, rule__basis="default_deny", rule__hint="acl:default"),
  "routed request from alice": find(reporter__name="alice-laptop", destination__name="Billing DB", destination__port=5432, connection_type="routed", router__name="router-1"),
  "routed on router-1": find(reporter__name="router-1", destination__name="Billing DB", destination__port=5432, connection_type="routed", source__name="alice-laptop"),
  "routed drop on router-1": find(event_type="drop", reporter__name="router-1", destination__port=8080, rule__hint="fwd:default"),
}
missing = [k for k, v in checks.items() if not v]
for k, v in checks.items():
    if v:
        e = v[0]
        s, d = e["source"], e["destination"]
        print("  %s: %s %s:%s -> %s %s:%s %s rule=%r type=%s" % (
            k, s["name"], s["ip"], s["port"], d["name"] or "unknown", d["ip"], d["port"],
            e["protocol"], e["rule"]["label"], e["connection_type"]))
if missing:
    print("missing:", ", ".join(missing))
    sys.exit(1)
' "$ALICE" "$SERVER" "$DB"
}
started=$SECONDS
until check >"$STATE/check.txt" 2>&1; do
  if (( SECONDS - started > 240 )); then
    cat "$STATE/check.txt"
    for name in "${AGENTS[@]}"; do echo "--- $name"; x "$name" tail -15 /var/log/agent.log; done
    fail "expected events did not all arrive"
  fi
  generate
  sleep 15
done
cat "$STATE/check.txt"
echo "ok every expected event arrived after $((SECONDS - started))s ($(stored) stored)"
psql_q "SELECT reporter_id IS NOT NULL, COUNT(*) FROM flow_events WHERE org_id='$ORG' GROUP BY 1" >/dev/null
psql_q "SELECT COUNT(*) FROM flow_events WHERE org_id='$ORG' AND (src_ip LIKE '172.%' OR dst_ip LIKE '172.%')" | grep -qx 0 \
  || fail "non-overlay (Docker bridge) traffic was reported"
echo "ok no underlay (Docker bridge) addresses stored"
lab export "$ORG" >"$STATE/export.csv"
echo "ok CSV export: $(($(wc -l <"$STATE/export.csv") - 1)) rows"

if [[ -n "${KEEP:-}" ]]; then
  echo "KEEP=1: leaving the lab running with diagnostics on (org $ORG)"
  exit 0
fi

echo "== traffic diagnostics off"
lab traffic "$ORG" off
sleep 10
before="$(stored)"
for _ in 1 2 3; do generate; sleep 20; done
sleep 30
after="$(stored)"
[[ "$after" == "$before" ]] || fail "events arrived after opt-out ($before -> $after)"
for name in "${AGENTS[@]}"; do
  x "$name" grep -q "flow events discarded" /var/log/agent.log || fail "$name did not log the stop"
  x "$name" sh -c '! pgrep -x conntrack' >/dev/null || fail "$name still runs conntrack"
done
echo "ok off: events stayed at $before for 90 s, agents stopped conntrack and logged the stop"
echo "traffic events lab passed"
