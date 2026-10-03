#!/usr/bin/env bash
# Live lab for agent traffic reporting (draft 17, docs/audit-and-traffic.md).
# One coordinator and two privileged Linux agents on kernel WireGuard, on one
# Docker host (default context m3-max). Policy: office may reach store on TCP
# 8080 and ICMP only.
#
#   1. traffic diagnostics off: no records are stored
#   2. on: allowed (8080, ping) and denied (8081, 9000) flows appear in the
#      /traffic summary within ~2 minutes, with allow/deny, buckets and
#      directions; stored rows carry no addresses
#   3. off again: agents stop and no further rows arrive
#
# It proves the Linux counter path end to end on one host, not macOS, iOS,
# Windows or Android reporting, nor throughput impact.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
CTX="${DOCKER_CONTEXT:-m3-max}"
D=(docker --context "$CTX")
P=trafficlab
IMG=trafficlab-image:latest
COORD_URL=https://trafficlab-coord:8443
ORG="$(python3 -c 'import uuid; print(uuid.uuid4())')"
export BLAKTAIL_AUTH_HMAC_SECRET="$(openssl rand -hex 32)"
export BLAKTAIL_RELAY_AUTH_SECRET="$(openssl rand -hex 32)"

cleanup() {
  "${D[@]}" rm -f "$P-coord" "$P-a" "$P-b" >/dev/null 2>&1 || true
  "${D[@]}" network rm "$P-net" >/dev/null 2>&1 || true
  "${D[@]}" volume rm "$P-certs" >/dev/null 2>&1 || true
}
trap cleanup EXIT
fail() { echo "FAIL $*" >&2; exit 1; }

echo "== build lab image on $CTX"
git ls-files -co --exclude-standard -z \
  | tar --null -T - -czf - \
  | "${D[@]}" build -q -f deploy/homelab/traffic-lab.Dockerfile -t "$IMG" - >/dev/null

cleanup
"${D[@]}" network create "$P-net" >/dev/null
"${D[@]}" volume create "$P-certs" >/dev/null

echo "== coordinator (self-signed lab CA, SQLite)"
"${D[@]}" run -d --name "$P-coord" --network "$P-net" -v "$P-certs:/certs" \
  -e BLAKTAIL_AUTH_HMAC_SECRET -e BLAKTAIL_RELAY_AUTH_SECRET \
  -e BLAKTAIL_REGION=ap-southeast-2 -e BLAKTAIL_BIND=0.0.0.0:8443 \
  -e BLAKTAIL_DATABASE=/data/coord.sqlite3 -e BLAKTAIL_DATABASE_STORAGE=local \
  -e BLAKTAIL_TLS_CERT=/certs/coord.crt -e BLAKTAIL_TLS_KEY=/certs/coord.key \
  -e BLAKTAIL_CONSOLE_URL=https://console.trafficlab.example \
  "$IMG" >/dev/null
"${D[@]}" exec "$P-coord" sh -c '
  set -e; cd /certs
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj "/CN=trafficlab CA" -keyout ca.key -out ca.crt 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=trafficlab-coord" -keyout coord.key -out coord.csr 2>/dev/null
  printf "subjectAltName=DNS:trafficlab-coord\n" > san.ext
  openssl x509 -req -in coord.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 1 -extfile san.ext -out coord.crt 2>/dev/null
  chmod 644 coord.key ca.crt coord.crt; rm -f ca.key'
"${D[@]}" exec -d "$P-coord" sh -c '(blaktail-coord migrate && blaktail-coord serve) >/var/log/coord.log 2>&1'
for i in $(seq 1 61); do
  (( i <= 60 )) || { "${D[@]}" exec "$P-coord" tail -5 /var/log/coord.log; fail "coordinator not ready"; }
  "${D[@]}" exec "$P-coord" python3 -c "import ssl,urllib.request; urllib.request.urlopen('$COORD_URL/readyz', context=ssl.create_default_context(cafile='/certs/ca.crt'))" >/dev/null 2>&1 && break
  sleep 1
done
lab() { "${D[@]}" exec -e BLAKTAIL_AUTH_HMAC_SECRET "$P-coord" traffic-lab "$@"; }
lab bootstrap "$ORG"
stored() {
  "${D[@]}" exec "$P-coord" python3 -c \
    'import sqlite3; print(sqlite3.connect("/data/coord.sqlite3").execute("SELECT COUNT(*) FROM flow_records").fetchone()[0])'
}
summary_field() { lab summary "$ORG" | python3 -c "import json,sys; s=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }

agent_ip() { "${D[@]}" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$P-$1"; }
start_agent() { # name tag
  BLAKTAIL_JOIN_KEY="$(lab join-key "$ORG" "$2")" "${D[@]}" exec -d -e BLAKTAIL_JOIN_KEY "$P-$1" sh -c \
    "blaktaild --coord-ca /certs/ca.crt up --coord $COORD_URL --name traffic-$1 --endpoint $(agent_ip "$1"):51820 >/var/log/agent.log 2>&1"
}
pin_port() {
  for _ in $(seq 1 30); do
    "${D[@]}" exec "$P-$1" wg set blaktail0 listen-port 51820 2>/dev/null && return 0
    sleep 1
  done
  fail "agent $1 never created blaktail0"
}
overlay() {
  "${D[@]}" exec "$P-$1" blaktaild status --json \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["address"].split("/")[0])'
}
connects() { "${D[@]}" exec "$P-$1" sh -c "printf x | nc -w 2 -q 1 $2 $3" >/dev/null 2>&1; }

for name in a b; do
  "${D[@]}" run -d --name "$P-$name" --hostname "traffic-$name" --network "$P-net" --privileged \
    -v "$P-certs:/certs:ro" "$IMG" >/dev/null
done
echo "== enrol office (a) and store (b)"
start_agent a office
start_agent b store
pin_port a
pin_port b
for _ in $(seq 1 60); do
  ip_a="$(overlay a 2>/dev/null || true)"; ip_b="$(overlay b 2>/dev/null || true)"
  [[ -n "$ip_a" && -n "$ip_b" ]] && "${D[@]}" exec "$P-a" ping -c 1 -W 2 "$ip_b" >/dev/null 2>&1 && break
  sleep 2
done
"${D[@]}" exec "$P-a" ping -c 1 -W 2 "$ip_b" >/dev/null 2>&1 || fail "baseline ping a -> b"
"${D[@]}" exec -d "$P-b" sh -c 'nc -lk -p 8080 >/dev/null'
"${D[@]}" exec -d "$P-a" sh -c 'nc -lk -p 9000 >/dev/null'
sleep 1
connects a "$ip_b" 8080 || fail "allowed 8080 a -> b"
connects a "$ip_b" 8081 && fail "8081 should be rejected"
connects b "$ip_a" 9000 && fail "9000 should be rejected on a"
echo "ok policy enforced: 8080 allowed, 8081 and 9000 rejected ($ip_a <-> $ip_b)"

echo "== diagnostics off: nothing stored"
sleep 70
[[ "$(stored)" == 0 ]] || fail "records stored while off"
[[ "$(summary_field 's["state"]')" == disabled ]] || fail "summary not disabled"
echo "ok off: 0 records, state disabled"

echo "== diagnostics on"
lab traffic "$ORG" on
sleep 5
started=$SECONDS
until [[ "$(summary_field 's["allowed"]["records"] > 0 and s["denied"]["records"] > 0')" == True ]]; do
  (( SECONDS - started < 180 )) || { lab summary "$ORG"; "${D[@]}" exec "$P-b" tail -20 /var/log/agent.log; fail "no allowed+denied records"; }
  for _ in 1 2 3; do
    connects a "$ip_b" 8080 || true
    connects a "$ip_b" 8081 || true
    connects b "$ip_a" 9000 || true
  done
  "${D[@]}" exec "$P-a" ping -c 3 -i 0.2 -W 2 "$ip_b" >/dev/null 2>&1 || true
  sleep 10
done
echo "ok records after $((SECONDS - started))s"
lab summary "$ORG" | python3 -c '
import json, sys
s = json.load(sys.stdin)
print("state:", s["state"], "| allowed:", s["allowed"], "| denied:", s["denied"])
print("buckets:", [(b["start"], b["allowed"]["records"], b["denied"]["records"]) for b in s["buckets"]])
print("by_service:", {k: v["records"] for k, v in s["by_service"].items()})
print("by_direction:", {k: v["records"] for k, v in s["by_direction"].items()})
print("confidence:", s["confidence"]["level"], s["confidence"]["reporting_devices"], "of", s["confidence"]["active_devices"])
assert s["state"] == "current" and s["buckets"], "no buckets"
'
"${D[@]}" exec "$P-coord" python3 -c '
import sqlite3, json, re
db = sqlite3.connect("/data/coord.sqlite3")
cur = db.execute("SELECT * FROM flow_records")
cols = [c[0] for c in cur.description]
rows = [dict(zip(cols, r)) for r in cur.fetchall()]
text = json.dumps(rows)
assert not re.search(r"\b(100\.64|172\.\d+\.\d+\.\d+|fd7a)", text), "address stored"
denied = [r for r in rows if r["decision"] == "denied" and r["peer_id"]]
assert denied, "denials not attributed to a peer"
print("stored rows:", len(rows), "| columns:", ",".join(cols))
print("sample denied:", {k: denied[0][k] for k in ("service","proto","port","decision","direction","transport","packets")})
'
echo "ok stored rows carry ids, classes and counters only"

echo "== diagnostics off again"
lab traffic "$ORG" off
sleep 5
before="$(stored)"
for _ in 1 2 3; do connects a "$ip_b" 8080 || true; connects a "$ip_b" 8081 || true; done
sleep 90
[[ "$(stored)" == "$before" ]] || fail "records arrived after opt-out"
"${D[@]}" exec "$P-b" grep -q "traffic diagnostics off" /var/log/agent.log || fail "agent b did not stop"
echo "ok off: rows stayed at $before for 90s and agents logged the stop"
echo "traffic lab passed"
