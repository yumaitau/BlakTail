#!/usr/bin/env bash
# Live lab for IPv6 subnet routes and staged renumbering (drafts 05 and 26,
# docs/ipam.md, docs/network-resources.md). One coordinator, a client and a
# Linux router on kernel WireGuard, and an IPv6-only LAN host behind the
# router, on one Docker host (default context m3-max):
#
#   1. IPv6 subnet route: the router advertises a ULA /64, an owner approves
#      it, and the client pings the LAN host over IPv6 through the overlay
#   2. pool renumber: every device moves to a new /24 in a 10-minute
#      dual-address window while a continuous ping runs; old and new
#      addresses (IPv4 and IPv6) both answer during the window, then the plan
#      completes and only the new ones do
#   3. rollback: one device is staged onto a new address and rolled back; its
#      original address keeps working
#   4. IPv6-only underlay (attempt, reported, never fails the run): the same
#      coordinator and agents on a network without IPv4
#
# It proves agent and coordinator behaviour on one host, not independent
# networks, real routers or ISP IPv6.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
CTX="${DOCKER_CONTEXT:-m3-max}"
D=(docker --context "$CTX")
P=ipamlab
IMG=ipamlab-image:latest
LAN6=fd42:b1a:c0de:1
V6ONLY=fd42:b1a:c0de:2
ORG="$(python3 -c 'import uuid; print(uuid.uuid4())')"
export BLAKTAIL_AUTH_HMAC_SECRET="$(openssl rand -hex 32)"
export BLAKTAIL_RELAY_AUTH_SECRET="$(openssl rand -hex 32)"
SYSCTL=(--sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.default.disable_ipv6=0)

cleanup() {
  "${D[@]}" rm -f "$P-coord" "$P-client" "$P-router" "$P-lanhost" "$P-6coord" "$P-6a" "$P-6b" >/dev/null 2>&1 || true
  for net in net lan v6only; do "${D[@]}" network rm "$P-$net" >/dev/null 2>&1 || true; done
  "${D[@]}" volume rm "$P-certs" "$P-6certs" >/dev/null 2>&1 || true
}
trap cleanup EXIT
fail() { echo "FAIL $*" >&2; exit 1; }

echo "== build lab image on $CTX"
git ls-files -co --exclude-standard -z \
  | tar --null -T - -czf - \
  | "${D[@]}" build -q -f deploy/homelab/ipam-lab.Dockerfile -t "$IMG" - >/dev/null

cleanup
"${D[@]}" network create "$P-net" >/dev/null
"${D[@]}" network create --ipv4=false --ipv6 --subnet "$LAN6::/64" "$P-lan" >/dev/null
"${D[@]}" volume create "$P-certs" >/dev/null

start_coord() { # container, certs volume, network, bind
  local name="$1" certs="$2" net="$3" bind="$4"
  "${D[@]}" run -d --name "$name" --network "$net" -v "$certs:/certs" "${SYSCTL[@]}" \
    -e BLAKTAIL_AUTH_HMAC_SECRET -e BLAKTAIL_RELAY_AUTH_SECRET \
    -e BLAKTAIL_REGION=ap-southeast-2 -e BLAKTAIL_BIND="$bind" \
    -e BLAKTAIL_DATABASE=/data/coord.sqlite3 -e BLAKTAIL_DATABASE_STORAGE=local \
    -e BLAKTAIL_TLS_CERT=/certs/coord.crt -e BLAKTAIL_TLS_KEY=/certs/coord.key \
    -e BLAKTAIL_CONSOLE_URL=https://console.ipamlab.example \
    "$IMG" >/dev/null
  "${D[@]}" exec -e NAME="$name" "$name" sh -c '
    set -e; cd /certs
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
      -subj "/CN=ipamlab CA" -keyout ca.key -out ca.crt 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -subj "/CN=$NAME" -keyout coord.key -out coord.csr 2>/dev/null
    printf "subjectAltName=DNS:%s\n" "$NAME" > san.ext
    openssl x509 -req -in coord.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
      -days 1 -extfile san.ext -out coord.crt 2>/dev/null
    chmod 644 coord.key ca.crt coord.crt; rm -f ca.key'
  "${D[@]}" exec -d "$name" sh -c '(blaktail-coord migrate && blaktail-coord serve) >/var/log/coord.log 2>&1'
  for i in $(seq 1 61); do
    (( i <= 60 )) || { "${D[@]}" exec "$name" tail -5 /var/log/coord.log; return 1; }
    "${D[@]}" exec "$name" python3 -c "import ssl,urllib.request; urllib.request.urlopen('https://$name:8443/readyz', context=ssl.create_default_context(cafile='/certs/ca.crt'))" >/dev/null 2>&1 && return 0
    sleep 1
  done
}

echo "== coordinator (self-signed lab CA, SQLite)"
start_coord "$P-coord" "$P-certs" "$P-net" 0.0.0.0:8443 || fail "coordinator not ready"
COORD="$P-coord"
lab() { "${D[@]}" exec -e BLAKTAIL_AUTH_HMAC_SECRET -e IPAMLAB_COORD="https://$COORD:8443" "$COORD" ipam-lab "$@"; }
lab bootstrap "$ORG"

agent_ip() { "${D[@]}" inspect -f "{{(index .NetworkSettings.Networks \"$2\").$3}}" "$P-$1"; }
start_agent() { # name, endpoint, extra agent flags
  local name="$1" endpoint="$2"; shift 2
  BLAKTAIL_JOIN_KEY="$(lab join-key "$ORG")" "${D[@]}" exec -d -e BLAKTAIL_JOIN_KEY "$P-$name" sh -c \
    "blaktaild --coord-ca /certs/ca.crt up --coord https://$COORD:8443 --name ipam-$name --endpoint $endpoint $* >/var/log/agent.log 2>&1"
}
pin_port() { # kernel WireGuard picks a random port; the lab advertises 51820
  for _ in $(seq 1 30); do
    "${D[@]}" exec "$P-$1" wg set blaktail0 listen-port 51820 2>/dev/null && return 0
    sleep 1
  done
  "${D[@]}" exec "$P-$1" tail -5 /var/log/agent.log >&2 || true
  return 1
}
overlay4() {
  "${D[@]}" exec "$P-$1" blaktaild status --json \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["address"].split("/")[0])'
}
iface_addrs() { "${D[@]}" exec "$P-$1" ip -o addr show dev blaktail0 | awk '{print $4}' | cut -d/ -f1 | tr '\n' ' '; }
ping_ok() { "${D[@]}" exec "$P-$1" ping -c 2 -W 2 "$2" >/dev/null 2>&1; }
wait_ping() { # container, target, seconds
  local started=$SECONDS
  until ping_ok "$1" "$2"; do (( SECONDS - started < $3 )) || return 1; sleep 2; done
}

"${D[@]}" run -d --name "$P-client" --hostname ipam-client --network "$P-net" --privileged "${SYSCTL[@]}" \
  -v "$P-certs:/certs:ro" "$IMG" >/dev/null
"${D[@]}" run -d --name "$P-router" --hostname ipam-router --network "$P-net" --privileged "${SYSCTL[@]}" \
  -v "$P-certs:/certs:ro" "$IMG" >/dev/null
"${D[@]}" network connect --ip6 "$LAN6::2" "$P-lan" "$P-router"
"${D[@]}" run -d --name "$P-lanhost" --network "$P-lan" --ip6 "$LAN6::10" "$IMG" >/dev/null

echo "== enrol client and IPv6 router (kernel WireGuard)"
start_agent client "$(agent_ip client "$P-net" IPAddress):51820"
start_agent router "$(agent_ip router "$P-net" IPAddress):51820" --advertise-routes "$LAN6::/64"
pin_port client || fail "client never created blaktail0"
pin_port router || fail "router never created blaktail0"
for _ in $(seq 1 60); do
  c4="$(overlay4 client 2>/dev/null || true)"; r4="$(overlay4 router 2>/dev/null || true)"
  [[ -n "$c4" && -n "$r4" ]] && ping_ok client "$r4" && break
  sleep 2
done
ping_ok client "$r4" || fail "baseline overlay ping client -> router"
echo "ok baseline overlay: client $(iface_addrs client)<-> router $(iface_addrs router)"

echo "== 1. IPv6 ULA subnet route $LAN6::/64 through the router"
ping_ok client "$LAN6::10" && fail "LAN host reachable before the route was approved"
echo "ok unapproved: client cannot reach $LAN6::10"
lab approve "$ORG" ipam-router "$LAN6::/64"
wait_ping client "$LAN6::10" 90 || {
  "${D[@]}" exec "$P-client" ip -6 route; "${D[@]}" exec "$P-router" ip6tables -S; fail "client -> $LAN6::10 over IPv6"
}
echo "ok client pings $LAN6::10 over IPv6 via the router ($( "${D[@]}" exec "$P-client" ip -6 route get "$LAN6::10" | head -1))"
"${D[@]}" exec "$P-router" sysctl -n net.ipv6.conf.all.forwarding | grep -qx 1 || fail "router IPv6 forwarding off"
echo "ok router enabled net.ipv6.conf.all.forwarding"

echo "== 2. pool renumber with a continuous ping"
c6_old="$("${D[@]}" exec "$P-client" ip -6 -o addr show dev blaktail0 scope global | awk '{print $4}' | cut -d/ -f1 | head -1)"
r6_old="$("${D[@]}" exec "$P-router" ip -6 -o addr show dev blaktail0 scope global | awk '{print $4}' | cut -d/ -f1 | head -1)"
"${D[@]}" exec -d "$P-client" sh -c "ping -i 0.2 -W 1 $r4 > /tmp/renumber-ping.log 2>&1"
sleep 3
lab renumber-pool "$ORG" 100.64.8.0/24 600
started=$SECONDS
until [[ "$(iface_addrs client)" == *100.64.8.* && "$(iface_addrs router)" == *100.64.8.* ]]; do
  (( SECONDS - started < 90 )) || { iface_addrs client; iface_addrs router; fail "agents did not add the new addresses"; }
  sleep 2
done
echo "ok staged after $((SECONDS - started))s: client $(iface_addrs client)| router $(iface_addrs router)"
r4_new="$(iface_addrs router | tr ' ' '\n' | grep '^100\.64\.8\.' | head -1)"
r6_new="$("${D[@]}" exec "$P-router" ip -6 -o addr show dev blaktail0 scope global | awk '{print $4}' | cut -d/ -f1 | grep -vx "$r6_old" | head -1)"
[[ -n "$r6_new" ]] || fail "router has no new IPv6 address"
wait_ping client "$r4_new" 60 || fail "new IPv4 $r4_new unreachable in the window"
ping_ok client "$r4" || fail "old IPv4 $r4 stopped answering in the window"
wait_ping client "$r6_new" 60 || fail "new IPv6 $r6_new unreachable in the window"
ping_ok client "$r6_old" || fail "old IPv6 $r6_old stopped answering in the window"
ping_ok client "$LAN6::10" || fail "IPv6 subnet route broke in the window"
echo "ok in the window both old ($r4, $r6_old) and new ($r4_new, $r6_new) answer; subnet route still works"
"${D[@]}" exec "$P-client" pkill -INT -x ping || true
sleep 1
summary="$("${D[@]}" exec "$P-client" grep -E 'packets transmitted' /tmp/renumber-ping.log)"
echo "ok continuous ping to the old address across staging: $summary"
lab finish "$ORG" complete
started=$SECONDS
until [[ "$(iface_addrs router)" != *"$r4 "* ]]; do
  (( SECONDS - started < 90 )) || fail "router kept the old address after completion"
  sleep 2
done
wait_ping client "$r4_new" 30 || fail "new IPv4 unreachable after completion"
wait_ping client "$r6_new" 30 || fail "new IPv6 unreachable after completion"
ping_ok client "$LAN6::10" || fail "IPv6 subnet route broke after completion"
ping_ok client "$r4" && fail "old IPv4 still answers after completion"
echo "ok completed: new addresses answer, old $r4 is withdrawn, subnet route intact"
lab pool "$ORG"

echo "== 3. stage one device and roll back"
lab renumber-device "$ORG" ipam-router 600
started=$SECONDS
until [[ "$(iface_addrs router | wc -w)" -ge 4 ]]; do
  (( SECONDS - started < 90 )) || fail "router did not add the staged address"
  sleep 2
done
lab finish "$ORG" rollback
started=$SECONDS
until [[ "$(iface_addrs router | wc -w)" -le 3 ]]; do
  (( SECONDS - started < 90 )) || fail "router kept the rolled-back address"
  sleep 2
done
wait_ping client "$r4_new" 30 || fail "original address broke after rollback"
echo "ok rollback: router back on $r4_new only ($(iface_addrs router))"
lab pool "$ORG"
echo "ipv6 subnet route and renumber lab passed"

echo "== 4. IPv6-only underlay (attempt)"
"${D[@]}" rm -f "$P-client" "$P-router" "$P-lanhost" >/dev/null
v6only() {
  "${D[@]}" network create --ipv4=false --ipv6 --subnet "$V6ONLY::/64" "$P-v6only" >/dev/null
  "${D[@]}" volume create "$P-6certs" >/dev/null
  start_coord "$P-6coord" "$P-6certs" "$P-v6only" "[::]:8443" || { echo "coordinator not ready on IPv6-only"; return 1; }
  COORD="$P-6coord"
  lab bootstrap "$ORG" || return 1
  for name in 6a 6b; do
    "${D[@]}" run -d --name "$P-$name" --network "$P-v6only" --privileged "${SYSCTL[@]}" \
      -v "$P-6certs:/certs:ro" "$IMG" >/dev/null
    start_agent "$name" "[$(agent_ip "$name" "$P-v6only" GlobalIPv6Address)]:51820"
  done
  pin_port 6a || return 1
  pin_port 6b || return 1
  for _ in $(seq 1 45); do
    b4="$(overlay4 6b 2>/dev/null || true)"
    [[ -n "$b4" ]] && ping_ok 6a "$b4" && break
    sleep 2
  done
  [[ -n "${b4:-}" ]] && ping_ok 6a "$b4" || { "${D[@]}" exec "$P-6a" wg show; return 1; }
  echo "ok IPv6-only underlay: 6a pings 6b at $b4 ($("${D[@]}" exec "$P-6a" wg show blaktail0 endpoints | cut -f2))"
}
if v6only; then echo "ipv6-only attempt passed"; else
  echo "ipv6-only attempt FAILED (recorded, not fatal)"
  "${D[@]}" exec "$P-6a" tail -5 /var/log/agent.log 2>/dev/null || true
fi
