#!/usr/bin/env bash
# Live lab for two-site IPv4 routing with the router forward filter (drafts
# 04, 05 and 07; docs/network-resources.md). One Docker host (default context
# m3-max), everything named labs-routing-*:
#
#   wan   10.231.0.0/24  coordinator, routers, exit node, clients
#   siteA 10.231.1.0/24  routers ra1 (metric 10, iptables-nft) and ra2
#                        (metric 20, iptables-legacy), host ha (8080, 8081)
#   siteB 10.231.2.0/24  router rb (iptables-legacy), host hb (9090, 9091)
#   inet  10.231.9.0/24  exit node ex (iptables-nft), "Internet" host with
#                        TCP 80 and DNS on UDP 53; only ex is attached
#
# Clients c1 (tag office, the authorised client) and c2 (tag ranger, the
# guest) default-route to a home gateway on wan that forwards nothing.
# Resources: site A TCP 8080 and site B TCP 9090, both for tags office and
# store (routers). Proves:
#
#   1. authorised client reaches the allowed port behind each router; the
#      adjacent port, and a guest that forces the route into WireGuard, are
#      rejected by BLAKTAIL-FWD (counters checked on nft and legacy routers)
#   2. routers reach each other's site (bidirectional, router-originated)
#   3. repeated BLAKTAIL-FWD-NEW -> BLAKTAIL-FWD swaps with a live jump on both
#      iptables backends while a client keeps connecting: no failed connect,
#      exactly one jump and no staging chain left
#   4. exit node: only the selecting client reaches the Internet host; a
#      guest forcing 0.0.0.0/0 is rejected; captures show no DNS or plaintext
#      leak on the exit client's uplink and no traffic from non-exit clients
#      on the exit node's Internet uplink
#   5. primary router killed: time until the client reaches site A via ra2
#
# KEEP=1 leaves the lab running for inspection; LABS_IMAGE=<tag> skips the
# image build.
#
# Host-originated site-to-site (ha -> hb without NAT) is not supported and
# not tested: routers forward overlay sources only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
CTX="${DOCKER_CONTEXT:-m3-max}"
D=(docker --context "$CTX")
P=labs-routing
IMG="${LABS_IMAGE:-labs-routing:latest}"
COORD_URL=https://$P-coord:8443
ORG="$(python3 -c 'import uuid; print(uuid.uuid4())')"
export BLAKTAIL_AUTH_HMAC_SECRET="$(openssl rand -hex 32)"
export BLAKTAIL_RELAY_AUTH_SECRET="$(openssl rand -hex 32)"
HA=10.231.1.10
HB=10.231.2.10
NET=10.231.9.10
AGENTS=(ra1 ra2 rb ex c1 c2)

cleanup() {
  for c in coord "${AGENTS[@]}" ha hb inet gw; do "${D[@]}" rm -f "$P-$c" >/dev/null 2>&1 || true; done
  for n in wan sitea siteb inet; do "${D[@]}" network rm "$P-$n" >/dev/null 2>&1 || true; done
  "${D[@]}" volume rm "$P-certs" >/dev/null 2>&1 || true
}
[[ -n "${KEEP:-}" ]] || trap cleanup EXIT
fail() { echo "FAIL $*" >&2; exit 1; }
x() { local c="$1"; shift; "${D[@]}" exec "$P-$c" "$@"; }

if [[ -z "${LABS_IMAGE:-}" ]]; then
  echo "== build lab image on $CTX"
  git ls-files -co --exclude-standard -z \
    | tar --null -T - -czf - \
    | "${D[@]}" build -q -f deploy/homelab/labs.Dockerfile -t "$IMG" - >/dev/null
fi

cleanup
# Every lab network is internal: Docker would otherwise route between its
# bridges through the engine host and hand clients a path around the routers.
"${D[@]}" network create --internal --subnet 10.231.0.0/24 "$P-wan" >/dev/null
"${D[@]}" network create --internal --subnet 10.231.1.0/24 "$P-sitea" >/dev/null
"${D[@]}" network create --internal --subnet 10.231.2.0/24 "$P-siteb" >/dev/null
"${D[@]}" network create --internal --subnet 10.231.9.0/24 "$P-inet" >/dev/null
"${D[@]}" volume create "$P-certs" >/dev/null

echo "== coordinator (self-signed lab CA, SQLite)"
"${D[@]}" run -d --name "$P-coord" --network "$P-wan" -v "$P-certs:/certs" \
  -e BLAKTAIL_AUTH_HMAC_SECRET -e BLAKTAIL_RELAY_AUTH_SECRET \
  -e BLAKTAIL_REGION=ap-southeast-2 -e BLAKTAIL_BIND=0.0.0.0:8443 \
  -e BLAKTAIL_DATABASE=/data/coord.sqlite3 -e BLAKTAIL_DATABASE_STORAGE=local \
  -e BLAKTAIL_TLS_CERT=/certs/coord.crt -e BLAKTAIL_TLS_KEY=/certs/coord.key \
  -e BLAKTAIL_CONSOLE_URL=https://console.routinglab.example \
  "$IMG" >/dev/null
"${D[@]}" cp deploy/homelab/routing-lab.py "$P-coord:/usr/local/bin/routing-lab"
x coord chmod 0755 /usr/local/bin/routing-lab
x coord sh -c '
  set -e; cd /certs
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj "/CN=labs-routing CA" -keyout ca.key -out ca.crt 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=labs-routing-coord" -keyout coord.key -out coord.csr 2>/dev/null
  printf "subjectAltName=DNS:labs-routing-coord\n" > san.ext
  openssl x509 -req -in coord.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 1 -extfile san.ext -out coord.crt 2>/dev/null
  chmod 644 coord.key ca.crt coord.crt; rm -f ca.key'
"${D[@]}" exec -d "$P-coord" sh -c '(blaktail-coord migrate && blaktail-coord serve) >/var/log/coord.log 2>&1'
for i in $(seq 1 61); do
  (( i <= 60 )) || { x coord tail -5 /var/log/coord.log; fail "coordinator not ready"; }
  x coord python3 -c "import ssl,urllib.request; urllib.request.urlopen('$COORD_URL/readyz', context=ssl.create_default_context(cafile='/certs/ca.crt'))" >/dev/null 2>&1 && break
  sleep 1
done
lab() { "${D[@]}" exec -e BLAKTAIL_AUTH_HMAC_SECRET "$P-coord" routing-lab "$@"; }
lab bootstrap "$ORG"

echo "== hosts behind the sites and the Internet host"
"${D[@]}" run -d --name "$P-ha" --network "$P-sitea" --ip "$HA" "$IMG" >/dev/null
"${D[@]}" run -d --name "$P-hb" --network "$P-siteb" --ip "$HB" "$IMG" >/dev/null
"${D[@]}" run -d --name "$P-inet" --network "$P-inet" --ip "$NET" "$IMG" >/dev/null
for port in 8080 8081; do "${D[@]}" exec -d "$P-ha" python3 -m http.server "$port"; done
for port in 9090 9091; do "${D[@]}" exec -d "$P-hb" python3 -m http.server "$port"; done
"${D[@]}" exec -d "$P-inet" python3 -m http.server 80
# Clients' ordinary default route: a home gateway on wan that forwards
# nothing, so anything that bypasses the tunnel shows up on the client uplink.
"${D[@]}" run -d --name "$P-gw" --network "$P-wan" --ip 10.231.0.254 "$IMG" >/dev/null
# Minimal DNS answer (A 10.231.9.10) for `dig +noedns`, so leak captures
# see a complete query/response exchange.
"${D[@]}" exec -d "$P-inet" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", 53))
while True:
    q, a = s.recvfrom(512)
    s.sendto(q[:2] + b"\x81\x80" + q[4:6] + b"\x00\x01\x00\x00\x00\x00" + q[12:]
             + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([10, 231, 9, 10]), a)'

echo "== routers, exit node and clients"
# name extra-network iptables-backend
for spec in "ra1 sitea nft" "ra2 sitea legacy" "rb siteb legacy" "ex inet nft" "c1 - nft" "c2 - nft"; do
  read -r name extra backend <<<"$spec"
  "${D[@]}" run -d --name "$P-$name" --hostname "routing-$name" --network "$P-wan" --privileged \
    -v "$P-certs:/certs:ro" "$IMG" >/dev/null
  if [[ "$extra" == - ]]; then
    x "$name" ip route add default via 10.231.0.254
  else
    "${D[@]}" network connect "$P-$extra" "$P-$name"
  fi
  if [[ "$backend" == legacy ]]; then
    x "$name" sh -c 'update-alternatives --set iptables /usr/sbin/iptables-legacy >/dev/null &&
      update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy >/dev/null'
  fi
done
for name in "${AGENTS[@]}"; do echo "$name: $(x "$name" iptables -V)"; done
wan_ip() { "${D[@]}" inspect -f "{{(index .NetworkSettings.Networks \"$P-wan\").IPAddress}}" "$P-$1"; }
start_agent() { # name tag extra-args...
  local name="$1" tag="$2"; shift 2
  BLAKTAIL_JOIN_KEY="$(lab join-key "$ORG" "$tag")" "${D[@]}" exec -d -e BLAKTAIL_JOIN_KEY "$P-$name" sh -c \
    "blaktaild --coord-ca /certs/ca.crt up --coord $COORD_URL --name routing-$name --endpoint $(wan_ip "$name"):51820 $* >>/var/log/agent.log 2>&1"
}
resume_agent() { # name extra-args...
  local name="$1"; shift
  "${D[@]}" exec -d "$P-$name" sh -c \
    "blaktaild --coord-ca /certs/ca.crt up --coord $COORD_URL --endpoint $(wan_ip "$name"):51820 $* >>/var/log/agent.log 2>&1"
}
pin_port() {
  for _ in $(seq 1 30); do
    x "$1" wg set blaktail0 listen-port 51820 2>/dev/null && return 0
    sleep 1
  done
  fail "agent $1 never created blaktail0"
}
overlay() { x "$1" blaktaild status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["address"].split("/")[0])'; }
connects() { x "$1" nc -z -w 3 "$2" "$3" >/dev/null 2>&1; }
wait_for() { # seconds description command...
  local limit="$1" what="$2" start=$SECONDS; shift 2
  until "$@"; do
    (( SECONDS - start < limit )) || fail "$what (after ${limit}s)"
    sleep 2
  done
  echo "ok $what after $((SECONDS - start))s"
}
# Packet counters of BLAKTAIL-FWD rules matching a pattern.
fwd_pkts() { # router pattern
  x "$1" iptables -L BLAKTAIL-FWD -v -n -x | awk -v pat="$2" '$0 ~ pat {s += $1} END {print s + 0}'
}
# Runs a command and succeeds when the matching counters rose across it.
# Agents rebuild the chain (resetting counters) on every peer map, so a
# reading that straddles a rebuild is retried.
rises() { # router pattern command...
  local router="$1" pattern="$2" before after; shift 2
  for _ in 1 2 3; do
    before="$(fwd_pkts "$router" "$pattern")"
    "$@" || true
    after="$(fwd_pkts "$router" "$pattern")"
    if (( after > before )); then RISE="$before -> $after packets"; return 0; fi
  done
  return 1
}

start_agent ra1 store --advertise-routes 10.231.1.0/24
start_agent ra2 store --advertise-routes 10.231.1.0/24
start_agent rb store --advertise-routes 10.231.2.0/24
start_agent ex store --advertise-exit-node
start_agent c1 office
start_agent c2 ranger
for name in "${AGENTS[@]}"; do pin_port "$name"; done
for name in "${AGENTS[@]}"; do wait_for 60 "$name enrolled" overlay "$name" >/dev/null; done
# Overlay address and node id per agent (bash 3 has no associative arrays).
for name in "${AGENTS[@]}"; do
  printf -v "OV_$name" '%s' "$(overlay "$name")"
  printf -v "ID_$name" '%s' "$(lab node-id "$ORG" "routing-$name")"
done
ov() { local v="OV_$1"; echo "${!v}"; }
id() { local v="ID_$1"; echo "${!v}"; }
echo "overlay: $(for n in "${AGENTS[@]}"; do printf '%s=%s ' "$n" "$(ov "$n")"; done)"
wait_for 60 "c1 paired with ra1" x c1 ping -c 1 -W 2 "$(ov ra1)"

echo "== baseline: nothing behind the routers or the exit node is reachable yet"
connects c1 "$HA" 8080 && fail "c1 reached site A before any resource"
connects c1 "$NET" 80 && fail "c1 reached the Internet host directly"
echo "ok baseline closed"

echo "== resources: site A (ra1 metric 10, ra2 metric 20) TCP 8080; site B (rb) TCP 9090"
RES_A="$(lab resource "$ORG" site-a 10.231.1.0/24 8080 office,store "$(id ra1):10,$(id ra2):20")"
RES_B="$(lab resource "$ORG" site-b 10.231.2.0/24 9090 office,store "$(id rb):10")"
started=$SECONDS
wait_for 90 "c1 -> site A host :8080" connects c1 "$HA" 8080
wait_for 60 "c1 -> site B host :9090" connects c1 "$HB" 9090
echo "route distribution took $((SECONDS - started))s"
lab detail "$ORG" "$RES_A" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("site-a port_enforcement:", d["port_enforcement"],
      "| peers:", [(p["name"], p["state"], p["forwarding"]) for p in d["status"]["routing_peers"]])
assert d["port_enforcement"] == "enforced"'

echo "== 1. adjacent ports and the guest are rejected by BLAKTAIL-FWD"
REJ='REJECT .*0\.0\.0\.0/0 +0\.0\.0\.0/0'
for _ in 1 2 3; do
  connects c1 "$HA" 8080 || fail "allowed 8080 flapped"
  connects c1 "$HA" 8081 && fail "c1 reached site A :8081"
  connects c1 "$HB" 9091 && fail "c1 reached site B :9091"
done
x c2 ip route get "$HA" | grep -q blaktail0 && fail "guest c2 was given a route to site A"
rises ra1 "$(ov c1) .*dpt:8080" connects c1 "$HA" 8080 || fail "ra1 (nft) accept counter for c1 :8080 did not move"
echo "ra1 (nft) c1 :8080 accept $RISE"
rises ra1 "$REJ" connects c1 "$HA" 8081 || fail "ra1 (nft) default reject did not count c1 :8081"
echo "ra1 (nft) default reject for c1 :8081 $RISE"
rises rb "$REJ" connects c1 "$HB" 9091 || fail "rb (legacy) default reject did not count c1 :9091"
echo "rb (legacy) default reject for c1 :9091 $RISE"
# A modified guest client: force site A into ra1's allowed IPs and route it.
ra1_key="$(x ra1 wg show blaktail0 public-key)"
force_c2() { # peer-key peer-overlay prefix
  x c2 sh -c "wg set blaktail0 peer $1 allowed-ips $2/32,$3 && ip route replace $3 dev blaktail0"
}
guest_site_a() {
  force_c2 "$ra1_key" "$(ov ra1)" 10.231.1.0/24
  ! connects c2 "$HA" 8080 || fail "guest c2 reached site A through a forced route"
}
rises ra1 "$REJ" guest_site_a || fail "guest packets were not rejected by ra1 BLAKTAIL-FWD"
echo "ra1 (nft) default reject for forced guest c2 :8080 $RISE"
x c2 ip route del 10.231.1.0/24 dev blaktail0 || true
echo "-- ra1 iptables -L BLAKTAIL-FWD -v -n:"; x ra1 iptables -L BLAKTAIL-FWD -v -n | sed 's/^/   /'
echo "-- rb iptables -L BLAKTAIL-FWD -v -n:"; x rb iptables -L BLAKTAIL-FWD -v -n | sed 's/^/   /'

echo "== 2. routers reach each other's site"
wait_for 60 "rb -> site A host :8080 via ra1" connects rb "$HA" 8080
wait_for 60 "ra1 -> site B host :9090 via rb" connects ra1 "$HB" 9090
connects rb "$HA" 8081 && fail "rb reached site A :8081"
echo "ok router-originated traffic both ways, port limits hold"

echo "== 3. live chain swaps on nft (ra1) and legacy (rb) while c1 connects"
x c1 sh -c "rm -f /tmp/probe; for i in \$(seq 1 150); do
  if nc -z -w 2 $HA 8080 && nc -z -w 2 $HB 9090; then echo ok; else echo bad; fi >>/tmp/probe; sleep 0.2; done" &
probe=$!
# Each edit bumps the control revision, so every router receives a new peer
# map and rebuilds its chain through BLAKTAIL-FWD-NEW.
for ports in 8080,8082 8080 8080,8082 8080 8080,8082 8080; do
  lab set-port "$ORG" "$RES_A" "$ports" >/dev/null
  sleep 4
done
wait "$probe"
ok="$(x c1 grep -c ok /tmp/probe || true)"; bad="$(x c1 grep -c bad /tmp/probe || true)"
echo "connects (site A :8080 and site B :9090) during 6 policy edits: ok=$ok bad=$bad"
[[ "$bad" == 0 ]] || fail "a connect failed during chain swaps"
for r in ra1 ra2 rb ex; do
  jumps="$(x "$r" iptables -S FORWARD | grep -c -- '-j BLAKTAIL-FWD$' || true)"
  staged="$(x "$r" iptables -S 2>/dev/null | grep -c 'BLAKTAIL-FWD-NEW' || true)"
  echo "$r ($(x "$r" iptables -V | grep -o '(.*)')): jumps to BLAKTAIL-FWD=$jumps, staging references=$staged"
  [[ "$jumps" == 1 && "$staged" == 0 ]] || fail "$r chain state after swaps"
done
connects c1 "$HA" 8082 && fail "8082 still open after the last edit"
echo "ok swaps clean; :8082 closed again after the final edit"

echo "== 4. exit node: approve 0.0.0.0/0 on ex; c1 selects it, c2 does not"
lab approve "$ORG" "$(id ex)" 0.0.0.0/0 >/dev/null
x c1 pkill -INT -f 'blaktaild.*up' || true
sleep 2
resume_agent c1 --exit-node routing-ex
wait_for 90 "c1 -> Internet host via exit node" connects c1 "$NET" 80
connects c2 "$NET" 80 && fail "c2 reached the Internet host without selecting the exit node"
x c2 ip route get 1.1.1.1 | grep -q "via 10.231.0.254" || fail "c2 default route does not stay on its own gateway"
connects c1 "$HA" 8080 || fail "c1 lost site A while using the exit node"
connects c1 "$HA" 8081 && fail "exit node widened site A to :8081"
echo "ok exit only for the selecting client; site A port limit still holds"
ex_if="$(x ex sh -c "ip -o -4 addr show | awk '/10\\.231\\.9\\./{print \$2}'")"
c1_if="$(x c1 sh -c "ip -o -4 addr show | awk '/10\\.231\\.0\\./{print \$2}'")"
x ex sh -c "timeout 25 tcpdump -i $ex_if -nn -U -w /tmp/inet.pcap 'ip and host $NET' >/dev/null 2>&1" &
cap_ex=$!
x c1 sh -c "timeout 25 tcpdump -i $c1_if -nn -U -w /tmp/up.pcap 'not (udp port 51820) and not (tcp port 8443) and not arp' >/dev/null 2>&1" &
cap_c1=$!
sleep 3
echo "-- c2 (no exit) tries the Internet host and its DNS"
ex_key="$(x ex wg show blaktail0 public-key)"
x c2 sh -c "dig +noedns +time=1 +tries=1 @$NET lab.example >/dev/null 2>&1; nc -z -w 2 $NET 80" && fail "c2 reached $NET"
sleep 2
# Forced default route on c2 (modified client): ex must reject it.
x c2 sh -c "wg set blaktail0 peer $ex_key allowed-ips $(ov ex)/32,10.231.9.0/24 && ip route replace 10.231.9.0/24 dev blaktail0"
guest_exit() {
  ! connects c2 "$NET" 80 || fail "guest c2 used the exit node through a forced route"
  ! x c2 dig +noedns +time=1 +tries=1 @"$NET" lab.example >/dev/null 2>&1 || fail "guest c2 resolved through the exit node"
}
rises ex "$REJ" guest_exit || fail "forced exit traffic not rejected by ex BLAKTAIL-FWD"
ex_rise="$RISE"
x c2 ip route del 10.231.9.0/24 dev blaktail0 || true
sleep 2
c2_window="$(x ex sh -c "tcpdump -r /tmp/inet.pcap -nn 2>/dev/null | wc -l")"
echo "-- c1 (exit) uses DNS and HTTP on the Internet host"
c1_dns="$(x c1 dig +noedns +short +time=2 +tries=1 @"$NET" lab.example)"
connects c1 "$NET" 80 || fail "c1 lost the exit path"
wait "$cap_ex" || true; wait "$cap_c1" || true
inet_pkts="$(x ex sh -c "tcpdump -r /tmp/inet.pcap -nn 2>/dev/null | wc -l")"
inet_dns="$(x ex sh -c "tcpdump -r /tmp/inet.pcap -nn 'udp port 53' 2>/dev/null | wc -l")"
inet_src="$(x ex sh -c "tcpdump -r /tmp/inet.pcap -nn 'dst host $NET' 2>/dev/null | awk '{print \$3}' | cut -d. -f1-4 | sort -u | tr '\n' ' '")"
up_pkts="$(x c1 sh -c "tcpdump -r /tmp/up.pcap -nn 2>/dev/null | wc -l")"
echo "ex (nft) BLAKTAIL-FWD default reject during forced c2 exit: $ex_rise"
echo "ex Internet uplink: $c2_window packets during c2's attempts; $inet_pkts in total, $inet_dns DNS, sources: $inet_src"
echo "c1 uplink outside WireGuard/coordinator: $up_pkts packets while using DNS and HTTP via the exit node (answer: $c1_dns)"
[[ "$c2_window" == 0 ]] || { x ex tcpdump -r /tmp/inet.pcap -nn; fail "non-exit client traffic reached the Internet uplink"; }
(( inet_dns > 0 )) || fail "exit client's DNS did not leave through the exit node"
[[ "$c1_dns" == "$NET" ]] || fail "exit client DNS answer"
[[ "$up_pkts" == 0 ]] || { x c1 tcpdump -r /tmp/up.pcap -nn | head; fail "exit client leaked outside the tunnel"; }
echo "-- ex iptables -L BLAKTAIL-FWD -v -n:"; x ex iptables -L BLAKTAIL-FWD -v -n | sed 's/^/   /'

echo "== 5. primary router loss: kill ra1, measure failover to ra2"
connects c1 "$HA" 8080 || fail "site A before failover"
"${D[@]}" kill "$P-ra1" >/dev/null
killed=$SECONDS
until connects c1 "$HA" 8080; do
  (( SECONDS - killed < 240 )) || fail "no failover within 240s"
  sleep 2
done
failover=$((SECONDS - killed))
echo "ok c1 reached site A via ra2 ${failover}s after ra1 was killed"
connects c1 "$HA" 8081 && fail "ra2 forwarded :8081"
x ra2 iptables -L BLAKTAIL-FWD -v -n -x | grep -q "$(ov c1) .*dpt:8080" || fail "ra2 has no c1 entry"
wait_for 120 "rb -> site A via ra2" connects rb "$HA" 8080
lab detail "$ORG" "$RES_A" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("site-a peers after loss:", [(p["name"], p["state"]) for p in d["status"]["routing_peers"]])'
echo "-- ra2 (legacy) iptables -L BLAKTAIL-FWD -v -n:"; x ra2 iptables -L BLAKTAIL-FWD -v -n | sed 's/^/   /'
echo "routing lab passed (failover ${failover}s)"
