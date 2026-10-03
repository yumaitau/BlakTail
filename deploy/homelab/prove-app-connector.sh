#!/usr/bin/env bash
# Live lab for DNS network resources through an app connector (draft 06,
# docs/app-connectors.md). One coordinator, a Linux app connector
# (`blaktaild up --app-connector`) on a "WAN" and a private site network, a
# Linux client on the WAN only, a lab authoritative DNS server on the site,
# and three site hosts each serving HTTP on TCP 8080 and 8081:
#
#   app1 10.77.1.10, app2 10.77.1.20, protected 10.77.2.10 (inside a CIDR
#   resource the client may not use)
#
# The DNS resource app.connector-lab.example (TCP 8080, tag laptop) is routed
# through the connector. The lab proves:
#
#   1. answer app1: the client reaches app1:8080; app1:8081 and app2:8080 fail
#   2. answer changes to app2: the app1 host route is withdrawn, app2:8080 works
#   3. answer moves into the protected CIDR: the report is blocked, every
#      lease withdrawn, the reason shown in resource detail, nothing reachable
#   4. answer back to app1: routing resumes
#   5. connector outage (container restart, agent down): leases expire and the
#      client route is withdrawn; restarting the agent recovers app1:8080 and
#      8081 stays blocked
#
# Timings are printed for each transition. It proves one Linux connector on
# one Docker host, not IPv6 answers, connector failover between two
# connectors, or clients on other operating systems.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
CTX="${DOCKER_CONTEXT:-m3-max}"
D=(docker --context "$CTX")
P=labs-connector
IMG="${LABS_IMAGE:-labs-base:latest}"
COORD_URL=https://$P-coord:8443
FQDN=app.connector-lab.example
ORG="$(python3 -c 'import uuid; print(uuid.uuid4())')"
export BLAKTAIL_AUTH_HMAC_SECRET="$(openssl rand -hex 32)"
export BLAKTAIL_RELAY_AUTH_SECRET="$(openssl rand -hex 32)"

cleanup() {
  "${D[@]}" rm -f "$P-coord" "$P-conn" "$P-client" "$P-dns" "$P-app1" "$P-app2" "$P-protected" >/dev/null 2>&1 || true
  "${D[@]}" network rm "$P-wan" "$P-site" >/dev/null 2>&1 || true
  "${D[@]}" volume rm "$P-certs" >/dev/null 2>&1 || true
}
trap '[[ -n "${LABS_KEEP:-}" ]] || cleanup' EXIT
fail() { echo "FAIL $*" >&2; exit 1; }

if [[ -z "${LABS_IMAGE:-}" ]]; then
  echo "== build lab image on $CTX"
  git ls-files -co --exclude-standard -z \
    | tar --null -T - -czf - \
    | "${D[@]}" build -q -f deploy/homelab/labs.Dockerfile -t "$IMG" - >/dev/null
fi

cleanup
"${D[@]}" network create "$P-wan" >/dev/null
"${D[@]}" network create --subnet 10.77.0.0/16 "$P-site" >/dev/null
"${D[@]}" volume create "$P-certs" >/dev/null

run() { # name network [extra docker args...]
  local name=$1 net=$2; shift 2
  "${D[@]}" run -d --name "$P-$name" --hostname "$name" --network "$net" "$@" "$IMG" >/dev/null
  "${D[@]}" cp deploy/homelab/connector-lab.py "$P-$name:/usr/local/bin/connector-lab" >/dev/null
}

echo "== coordinator (self-signed lab CA, SQLite)"
run coord "$P-wan" -v "$P-certs:/certs" \
  -e BLAKTAIL_AUTH_HMAC_SECRET -e BLAKTAIL_RELAY_AUTH_SECRET \
  -e BLAKTAIL_REGION=ap-southeast-2 -e BLAKTAIL_BIND=0.0.0.0:8443 \
  -e BLAKTAIL_DATABASE=/data/coord.sqlite3 -e BLAKTAIL_DATABASE_STORAGE=local \
  -e BLAKTAIL_TLS_CERT=/certs/coord.crt -e BLAKTAIL_TLS_KEY=/certs/coord.key \
  -e BLAKTAIL_CONSOLE_URL=https://console.connector-lab.example
"${D[@]}" exec "$P-coord" sh -c "
  set -e; cd /certs
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj '/CN=connector lab CA' -keyout ca.key -out ca.crt 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj '/CN=$P-coord' -keyout coord.key -out coord.csr 2>/dev/null
  printf 'subjectAltName=DNS:$P-coord\n' > san.ext
  openssl x509 -req -in coord.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 1 -extfile san.ext -out coord.crt 2>/dev/null
  chmod 644 coord.key ca.crt coord.crt; rm -f ca.key"
"${D[@]}" exec -d "$P-coord" sh -c '(blaktail-coord migrate && blaktail-coord serve) >/var/log/coord.log 2>&1'
for i in $(seq 1 61); do
  (( i <= 60 )) || { "${D[@]}" exec "$P-coord" tail -5 /var/log/coord.log; fail "coordinator not ready"; }
  "${D[@]}" exec "$P-coord" python3 -c "import ssl,urllib.request; urllib.request.urlopen('$COORD_URL/readyz', context=ssl.create_default_context(cafile='/certs/ca.crt'))" >/dev/null 2>&1 && break
  sleep 1
done
lab() { "${D[@]}" exec -e BLAKTAIL_AUTH_HMAC_SECRET "$P-coord" connector-lab "$@"; }
lab bootstrap "$ORG"

echo "== site: DNS server and three HTTP hosts"
run dns "$P-site" --ip 10.77.1.53
"${D[@]}" exec "$P-dns" sh -c "echo '$FQDN 10.77.1.10 5' > /data/zone"
"${D[@]}" exec -d "$P-dns" sh -c 'connector-lab dns-serve /data/zone >/var/log/dns.log 2>&1'
for host in app1:10.77.1.10 app2:10.77.1.20 protected:10.77.2.10; do
  name=${host%%:*}
  run "$name" "$P-site" --ip "${host#*:}"
  "${D[@]}" exec "$P-$name" sh -c "mkdir -p /srv && echo $name > /srv/name"
  for port in 8080 8081; do
    "${D[@]}" exec -d "$P-$name" sh -c "python3 -m http.server $port --directory /srv >/dev/null 2>&1"
  done
done
set_answer() { "${D[@]}" exec "$P-dns" sh -c "echo '$FQDN $1 5' > /data/zone"; }

echo "== connector (WAN + site) and client (WAN only)"
run conn "$P-wan" --privileged -v "$P-certs:/certs:ro"
"${D[@]}" network connect --ip 10.77.0.5 "$P-site" "$P-conn"
run client "$P-wan" --privileged -v "$P-certs:/certs:ro"
# The Docker host routes between bridges; make the site unreachable from the
# client except through more specific routes on blaktail0.
"${D[@]}" exec "$P-client" ip route add unreachable 10.77.0.0/16
# The connector resolves only from the site DNS; the coordinator name stays
# reachable through /etc/hosts.
coord_ip="$("${D[@]}" inspect -f "{{(index .NetworkSettings.Networks \"$P-wan\").IPAddress}}" "$P-coord")"
site_dns() { "${D[@]}" exec "$P-conn" sh -c "echo 'nameserver 10.77.1.53' > /etc/resolv.conf; grep -q $P-coord /etc/hosts || echo '$coord_ip $P-coord' >> /etc/hosts"; }
site_dns
"${D[@]}" exec "$P-conn" dig +short "$FQDN" | grep -qx 10.77.1.10 || fail "connector cannot resolve $FQDN from the lab DNS"
wan_ip() { "${D[@]}" inspect -f "{{(index .NetworkSettings.Networks \"$P-wan\").IPAddress}}" "$P-$1"; }
start_agent() { # name tag [extra flags]
  local name=$1 tag=$2; shift 2
  BLAKTAIL_JOIN_KEY="$(lab join-key "$ORG" "$tag")" "${D[@]}" exec -d -e BLAKTAIL_JOIN_KEY "$P-$name" sh -c \
    "blaktaild --coord-ca /certs/ca.crt up --coord $COORD_URL --name connector-$name --endpoint $(wan_ip "$name"):51820 $* >/var/log/agent.log 2>&1"
}
pin_port() {
  for _ in $(seq 1 30); do
    "${D[@]}" exec "$P-$1" wg set blaktail0 listen-port 51820 2>/dev/null && return 0
    sleep 1
  done
  "${D[@]}" exec "$P-$1" tail -20 /var/log/agent.log
  fail "agent $1 never created blaktail0"
}
status_field() {
  "${D[@]}" exec "$P-$1" blaktaild status --json | python3 -c "import json,sys; print(json.load(sys.stdin)[sys.argv[1]])" "$2"
}
start_agent conn store --app-connector
start_agent client office
pin_port conn
pin_port client
conn_id="$(status_field conn node_id)"
conn_overlay="$(status_field conn address | cut -d/ -f1)"
for _ in $(seq 1 60); do
  "${D[@]}" exec "$P-client" ping -c 1 -W 2 "$conn_overlay" >/dev/null 2>&1 && break
  sleep 2
done
"${D[@]}" exec "$P-client" ping -c 1 -W 2 "$conn_overlay" >/dev/null 2>&1 || fail "baseline ping client -> connector"

reach() { # host port -> prints the serving host name or nothing
  "${D[@]}" exec "$P-client" curl -s -m 3 "http://$1:$2/name" 2>/dev/null || true
}
client_route() { "${D[@]}" exec "$P-client" ip -4 route show "$1/32" | grep -c blaktail0 || true; }
detail() { lab detail "$ORG" "$res_id"; }
serves() { [[ "$(reach "$1" "$2")" == "$3" ]]; }
route_gone() { [[ "$(client_route "$1")" == 0 ]]; }
detail_field() { detail | python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
wait_for() { # description timeout command...
  local what=$1 limit=$2; shift 2
  local started=$SECONDS
  until "$@"; do
    (( SECONDS - started < limit )) || { detail || true; "${D[@]}" exec "$P-client" ip -4 route; "${D[@]}" exec "$P-conn" iptables -S BLAKTAIL-FWD || true; "${D[@]}" exec "$P-conn" tail -15 /var/log/agent.log; fail "$what not reached in ${limit}s"; }
    sleep 1
  done
  echo "ok $what after $((SECONDS - started))s"
}
[[ -z "$(reach 10.77.1.10 8080)" ]] || fail "client reached the site before any resource existed"
echo "ok baseline: client paired with connector ($conn_overlay) and cannot reach the site"

echo "== resources: protected CIDR (nobody) and DNS $FQDN (office, TCP 8080)"
lab create "$ORG" '{"name":"protected","cidr":"10.77.2.0/24","routing_peers":[{"node_id":"'"$conn_id"'"}],"access":{"tags":["ranger"]}}' >/dev/null
res_id="$(lab create "$ORG" '{"name":"app","dns_target":"'"$FQDN"'","ports":["8080"],"protocols":["tcp"],"routing_peers":[{"node_id":"'"$conn_id"'"}],"access":{"tags":["office"]}}')"

echo "== 1. answer app1"
wait_for "client reaches app1:8080 through the connector" 120 serves 10.77.1.10 8080 app1
[[ -z "$(reach 10.77.1.10 8081)" ]] || fail "adjacent port app1:8081 reachable"
[[ -z "$(reach 10.77.1.20 8080)" ]] || fail "unresolved host app2:8080 reachable"
detail | python3 -c '
import json, sys
d = json.load(sys.stdin)
c = d["connector"]
print("state:", d["status"]["state"], "| forwarding:", d["status"]["forwarding"], "| ports:", d["port_enforcement"])
print("answers:", [(a["route"], a["ttl"], a["expires_at"]) for a in c["answers"]])
assert d["status"]["state"] == "distributing", d["status"]
assert d["port_enforcement"] == "enforced", d["port_enforcement"]
'
"${D[@]}" exec "$P-conn" iptables -S BLAKTAIL-FWD | grep -E '10\.77\.1\.10' || fail "no BLAKTAIL-FWD rule for app1"
echo "ok app1:8081 and app2:8080 blocked; BLAKTAIL-FWD scoped to app1 TCP 8080"

echo "== 2. answer changes to app2"
set_answer 10.77.1.20
wait_for "app2:8080 reachable after the answer changed" 120 serves 10.77.1.20 8080 app2
wait_for "app1 host route withdrawn from the client" 60 route_gone 10.77.1.10
[[ -z "$(reach 10.77.1.10 8080)" ]] || fail "old answer app1:8080 still reachable"
[[ -z "$(reach 10.77.1.20 8081)" ]] || fail "adjacent port app2:8081 reachable"
echo "ok old address unreachable, adjacent port still blocked"

echo "== 3. answer moves into the protected CIDR"
set_answer 10.77.2.10
blocked() { [[ "$(detail_field 'd["status"]["state"]')" == dns_blocked ]]; }
wait_for "resource blocked" 120 blocked
echo "blocked reason: $(detail_field 'd["connector"]["blocked_reason"]')"
wait_for "app2 host route withdrawn" 60 route_gone 10.77.1.20
[[ "$(client_route 10.77.2.10)" == 0 ]] || fail "client received a route into the protected CIDR"
[[ -z "$(reach 10.77.2.10 8080)" ]] || fail "protected host reachable"
[[ -z "$(reach 10.77.1.20 8080)" ]] || fail "app2 still reachable after block"
echo "ok fail closed: nothing routed, protected host unreachable"

echo "== 4. answer back to app1"
set_answer 10.77.1.10
wait_for "app1:8080 reachable again" 120 serves 10.77.1.10 8080 app1

echo "== 5. connector outage and restart"
"${D[@]}" restart -t 2 "$P-conn" >/dev/null
outage=$SECONDS
wait_for "app1 host route withdrawn while the connector is down" 420 route_gone 10.77.1.10
echo "detail during outage: $(detail_field '(d["status"]["state"], [a["route"] for a in d["connector"]["answers"]])')"
[[ -z "$(reach 10.77.1.10 8080)" ]] || fail "app1 reachable with the connector down"
site_dns
restarted=$SECONDS
"${D[@]}" exec -d "$P-conn" sh -c 'blaktaild --coord-ca /certs/ca.crt run >>/var/log/agent.log 2>&1'
pin_port conn
wait_for "app1:8080 reachable after the connector restarted" 180 serves 10.77.1.10 8080 app1
[[ -z "$(reach 10.77.1.10 8081)" ]] || fail "adjacent port reachable after restart"
echo "ok recovered $((SECONDS - restarted))s after the agent restarted; outage lasted $((SECONDS - outage))s; 8081 still blocked"
echo "app connector lab passed"
