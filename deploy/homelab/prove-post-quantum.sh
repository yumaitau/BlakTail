#!/usr/bin/env bash
# Live lab for opt-in hybrid post-quantum WireGuard PSKs (draft 25,
# docs/post-quantum.md). One coordinator and two privileged Linux agents on
# kernel WireGuard, on one Docker host (default context m3-max):
#
#   1. baseline: classical tunnel, ping works, no PSK on either side
#   2. policy require: both agents report the hybrid key established, `wg`
#      shows a PSK on both sides (fingerprints compared, never printed), and
#      ping works
#   3. rotation: the PSK fingerprint and epoch change within ~2.5 minutes
#   4. downgrade: agent b restarts with BLAKTAIL_DISABLE_PQ_PSK=1; agent a
#      reports "required_not_established", installs the raw-table block, the
#      PSK is cleared and ping fails
#
# It proves agent and coordinator behaviour on one host, not independent
# networks, mobile platforms or an external cryptographic review.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
CTX="${DOCKER_CONTEXT:-m3-max}"
D=(docker --context "$CTX")
P=pqlab
IMG=pqlab-image:latest
COORD_URL=https://pqlab-coord:8443
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
  | "${D[@]}" build -q -f deploy/homelab/pq-lab.Dockerfile -t "$IMG" - >/dev/null

cleanup
"${D[@]}" network create "$P-net" >/dev/null
"${D[@]}" volume create "$P-certs" >/dev/null

echo "== coordinator (self-signed lab CA, SQLite)"
"${D[@]}" run -d --name "$P-coord" --network "$P-net" -v "$P-certs:/certs" \
  -e BLAKTAIL_AUTH_HMAC_SECRET -e BLAKTAIL_RELAY_AUTH_SECRET \
  -e BLAKTAIL_REGION=ap-southeast-2 -e BLAKTAIL_BIND=0.0.0.0:8443 \
  -e BLAKTAIL_DATABASE=/data/coord.sqlite3 -e BLAKTAIL_DATABASE_STORAGE=local \
  -e BLAKTAIL_TLS_CERT=/certs/coord.crt -e BLAKTAIL_TLS_KEY=/certs/coord.key \
  -e BLAKTAIL_CONSOLE_URL=https://console.pqlab.example \
  "$IMG" >/dev/null
"${D[@]}" exec "$P-coord" sh -c '
  set -e; cd /certs
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj "/CN=pqlab CA" -keyout ca.key -out ca.crt 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=pqlab-coord" -keyout coord.key -out coord.csr 2>/dev/null
  printf "subjectAltName=DNS:pqlab-coord\n" > san.ext
  openssl x509 -req -in coord.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 1 -extfile san.ext -out coord.crt 2>/dev/null
  chmod 644 coord.key ca.crt coord.crt; rm -f ca.key'
"${D[@]}" exec -d "$P-coord" sh -c '(blaktail-coord migrate && blaktail-coord serve) >/var/log/coord.log 2>&1'
for i in $(seq 1 61); do
  (( i <= 60 )) || { "${D[@]}" exec "$P-coord" tail -5 /var/log/coord.log; fail "coordinator not ready"; }
  "${D[@]}" exec "$P-coord" python3 -c "import ssl,urllib.request; urllib.request.urlopen('$COORD_URL/readyz', context=ssl.create_default_context(cafile='/certs/ca.crt'))" >/dev/null 2>&1 && break
  sleep 1
done
lab() { "${D[@]}" exec -e BLAKTAIL_AUTH_HMAC_SECRET "$P-coord" pq-lab "$@"; }
lab bootstrap "$ORG"

agent_ip() { "${D[@]}" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$P-$1"; }
start_agent() { # name, then extra docker exec flags
  local name="$1"; shift
  BLAKTAIL_JOIN_KEY="$(lab join-key "$ORG")" "${D[@]}" exec -d -e BLAKTAIL_JOIN_KEY "$@" "$P-$name" sh -c \
    "blaktaild --coord-ca /certs/ca.crt up --coord $COORD_URL --name pq-$name --endpoint $(agent_ip "$name"):51820 >/var/log/agent.log 2>&1"
}
pin_port() { # kernel WireGuard picks a random port; the lab advertises 51820
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
psk_fingerprint() { # sha256 of the PSK column, or "none"; the key itself never leaves the container
  "${D[@]}" exec "$P-$1" sh -c \
    'k="$(wg show blaktail0 preshared-keys | cut -f2)"; if [ -z "$k" ] || [ "$k" = "(none)" ]; then echo none; else printf %s "$k" | sha256sum | cut -d" " -f1; fi'
}
ping_ok() { "${D[@]}" exec "$P-$1" ping -c 2 -W 2 "$2" >/dev/null 2>&1; }
row() { lab overview "$ORG" | python3 -c '
import json, sys
device, peer = sys.argv[1], sys.argv[2]
for line in sys.stdin:
    row = json.loads(line)
    if row.get("device") == device and row.get("peer") == peer:
        print(row[sys.argv[3]])' "pq-$1" "pq-$2" "$3"; }

for name in a b; do
  "${D[@]}" run -d --name "$P-$name" --hostname "pq-$name" --network "$P-net" --privileged \
    -v "$P-certs:/certs:ro" "$IMG" >/dev/null
done
echo "== enrol two agents (kernel WireGuard)"
start_agent a
start_agent b
pin_port a
pin_port b
for _ in $(seq 1 60); do
  ip_a="$(overlay a 2>/dev/null || true)"; ip_b="$(overlay b 2>/dev/null || true)"
  [[ -n "$ip_a" && -n "$ip_b" ]] && ping_ok a "$ip_b" && break
  sleep 2
done
ping_ok a "$ip_b" || fail "baseline overlay ping a -> b"
[[ "$(psk_fingerprint a)" == none ]] || fail "PSK present before policy"
echo "ok baseline classical tunnel ($ip_a <-> $ip_b), no PSK"

echo "== policy require"
lab policy "$ORG" require
started=$SECONDS
until [[ "$(row a b state)" == established && "$(row b a state)" == established ]]; do
  (( SECONDS - started < 120 )) || { lab overview "$ORG"; fail "hybrid key not established"; }
  sleep 3
done
echo "ok both agents report established after $((SECONDS - started))s"
fp_a="$(psk_fingerprint a)"; fp_b="$(psk_fingerprint b)"
[[ "$fp_a" != none ]] || fail "no PSK on a"
[[ "$fp_a" == "$fp_b" ]] || fail "PSKs differ between a and b"
[[ "$fp_a" != "$(printf %s AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= | sha256sum | cut -d' ' -f1)" ]] || fail "PSK is all-zero"
echo "ok wg shows the same non-zero PSK on both sides (fingerprint compared, not printed)"
ping_ok a "$ip_b" || fail "ping under hybrid PSK"
echo "ok ping a -> b with the hybrid PSK installed"
epoch1="$(row a b epoch)"
lab overview "$ORG"

echo "== rotation (every 120s)"
started=$SECONDS
until [[ "$(psk_fingerprint a)" != "$fp_a" && "$(row a b epoch)" -gt "$epoch1" ]]; do
  (( SECONDS - started < 200 )) || fail "PSK did not rotate"
  sleep 5
done
[[ "$(psk_fingerprint a)" == "$(psk_fingerprint b)" ]] || fail "rotated PSKs differ"
ping_ok a "$ip_b" || fail "ping after rotation"
echo "ok PSK rotated after $((SECONDS - started))s (epoch $epoch1 -> $(row a b epoch)), both sides agree, ping works"

echo "== downgrade: b restarts without the pq-psk capability"
"${D[@]}" exec "$P-b" pkill -x blaktaild || true
sleep 2
"${D[@]}" exec -d -e BLAKTAIL_DISABLE_PQ_PSK=1 "$P-b" sh -c \
  'blaktaild --coord-ca /certs/ca.crt run >/var/log/agent-downgraded.log 2>&1'
pin_port b
started=$SECONDS
until [[ "$(row a b state)" == required_not_established && "$(row a b blocked)" == True ]]; do
  (( SECONDS - started < 120 )) || { lab overview "$ORG"; fail "downgrade not reported"; }
  sleep 3
done
echo "ok a reports b: required_not_established, reason $(row a b reason), blocked"
[[ "$(psk_fingerprint a)" == none ]] || fail "a kept a PSK for a non-capable peer"
"${D[@]}" exec "$P-a" iptables -t raw -S BLAKTAIL-PQ | grep -q -- "-j DROP" || fail "no raw-table block on a"
ping_ok a "$ip_b" && fail "traffic still flows to a required-but-unestablished peer"
echo "ok PSK cleared, raw-table block installed, ping a -> b blocked"
lab overview "$ORG"
echo "post_quantum lab passed"
