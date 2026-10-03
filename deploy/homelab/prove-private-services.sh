#!/usr/bin/env bash
# Live lab for private service serving (draft 10, docs/private-services.md).
# One coordinator and three privileged Linux agents on kernel WireGuard, on
# one Docker host (default context m3-max):
#
#   server   tags office,ranger; `blaktaild up --serve-services
#            --serve-services-ports 8080`; a loopback
#            HTTP target on 127.0.0.1:8080
#   ally     tag office (the service's access tag)
#   outsider tag ranger (a policy peer of the server without the access tag)
#
#   1. the server generates its key, gets a certificate, reports healthy and
#      the console status becomes "serving"
#   2. ally: `curl --cacert <org CA> https://<name>` via MagicDNS succeeds
#   3. outsider: the name does not resolve; forcing the name to the server's
#      overlay IP and using the raw overlay IP both fail
#   4. target outage: status "target_unhealthy" and ally's name is withdrawn;
#      recovery republishes it
#   5. disable: the server drops its listener and ally can no longer connect
#
# It proves agent and coordinator behaviour on one host, not independent
# networks, macOS serving nodes or browser trust stores.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
CTX="${DOCKER_CONTEXT:-m3-max}"
D=(docker --context "$CTX")
P=svclab
IMG=svclab-image:latest
COORD_URL=https://svclab-coord:8443
ORG="$(python3 -c 'import uuid; print(uuid.uuid4())')"
export BLAKTAIL_AUTH_HMAC_SECRET="$(openssl rand -hex 32)"
export BLAKTAIL_RELAY_AUTH_SECRET="$(openssl rand -hex 32)"

cleanup() {
  [[ -n "${SVCLAB_KEEP:-}" ]] && return 0
  "${D[@]}" rm -f "$P-coord" "$P-server" "$P-ally" "$P-outsider" >/dev/null 2>&1 || true
  "${D[@]}" network rm "$P-net" >/dev/null 2>&1 || true
  "${D[@]}" volume rm "$P-certs" >/dev/null 2>&1 || true
}
trap cleanup EXIT
fail() { echo "FAIL $*" >&2; exit 1; }

echo "== build lab image on $CTX"
git ls-files -co --exclude-standard -z \
  | tar --null -T - -czf - \
  | "${D[@]}" build -q -f deploy/homelab/svc-lab.Dockerfile -t "$IMG" - >/dev/null

cleanup
"${D[@]}" network create "$P-net" >/dev/null
"${D[@]}" volume create "$P-certs" >/dev/null

echo "== coordinator (self-signed lab CA, SQLite)"
"${D[@]}" run -d --name "$P-coord" --network "$P-net" -v "$P-certs:/certs" \
  -e BLAKTAIL_AUTH_HMAC_SECRET -e BLAKTAIL_RELAY_AUTH_SECRET \
  -e BLAKTAIL_REGION=ap-southeast-2 -e BLAKTAIL_BIND=0.0.0.0:8443 \
  -e BLAKTAIL_DATABASE=/data/coord.sqlite3 -e BLAKTAIL_DATABASE_STORAGE=local \
  -e BLAKTAIL_TLS_CERT=/certs/coord.crt -e BLAKTAIL_TLS_KEY=/certs/coord.key \
  -e BLAKTAIL_CONSOLE_URL=https://console.svclab.example \
  "$IMG" >/dev/null
"${D[@]}" exec "$P-coord" sh -c '
  set -e; cd /certs
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj "/CN=svclab CA" -keyout ca.key -out ca.crt 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=svclab-coord" -keyout coord.key -out coord.csr 2>/dev/null
  printf "subjectAltName=DNS:svclab-coord\n" > san.ext
  openssl x509 -req -in coord.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 1 -extfile san.ext -out coord.crt 2>/dev/null
  chmod 644 coord.key ca.crt coord.crt; rm -f ca.key'
"${D[@]}" exec -d "$P-coord" sh -c '(blaktail-coord migrate && blaktail-coord serve) >/var/log/coord.log 2>&1'
for i in $(seq 1 61); do
  (( i <= 60 )) || { "${D[@]}" exec "$P-coord" tail -5 /var/log/coord.log; fail "coordinator not ready"; }
  "${D[@]}" exec "$P-coord" python3 -c "import ssl,urllib.request; urllib.request.urlopen('$COORD_URL/readyz', context=ssl.create_default_context(cafile='/certs/ca.crt'))" >/dev/null 2>&1 && break
  sleep 1
done
lab() { "${D[@]}" exec -e BLAKTAIL_AUTH_HMAC_SECRET "$P-coord" svc-lab "$@"; }
lab bootstrap "$ORG"

agent_ip() { "${D[@]}" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$P-$1"; }
start_agent() { # name, tags, extra blaktaild up flags
  local name="$1" tags="$2"; shift 2
  BLAKTAIL_JOIN_KEY="$(lab join-key "$ORG" "$tags")" "${D[@]}" exec -d -e BLAKTAIL_JOIN_KEY "$P-$name" sh -c \
    "blaktaild --coord-ca /certs/ca.crt up --coord $COORD_URL --name svc-$name --endpoint $(agent_ip "$name"):51820 $* >/var/log/agent.log 2>&1"
}
pin_port() {
  for _ in $(seq 1 30); do
    "${D[@]}" exec "$P-$1" wg set blaktail0 listen-port 51820 2>/dev/null && return 0
    sleep 1
  done
  fail "agent $1 never created blaktail0"
}
status_field() {
  "${D[@]}" exec "$P-$1" blaktaild status --json \
    | python3 -c "import json,sys; print(json.load(sys.stdin)[sys.argv[1]].split('/')[0])" "$2"
}
service_status() { lab status "$ORG" | python3 -c 'import json,sys; print(json.loads(sys.stdin.readline())["status"])'; }
wait_status() {
  local want="$1" started=$SECONDS
  until [[ "$(service_status)" == "$want" ]]; do
    (( SECONDS - started < 150 )) || { lab status "$ORG"; "${D[@]}" exec "$P-server" tail -20 /var/log/agent.log; fail "status never became $want"; }
    sleep 3
  done
  echo "ok status $want after $((SECONDS - started))s"
}
resolves() { "${D[@]}" exec "$P-$1" getent hosts "$2" >/dev/null 2>&1; }
wait_resolution() { # agent, name, yes|no
  local started=$SECONDS
  while :; do
    if resolves "$1" "$2"; then [[ "$3" == yes ]] && return 0; else [[ "$3" == no ]] && return 0; fi
    (( SECONDS - started < 120 )) || fail "$1 resolution of $2 never became $3"
    sleep 3
  done
}
start_target() {
  "${D[@]}" exec -d "$P-server" sh -c 'mkdir -p /srv/wiki && echo "hello from the private wiki" > /srv/wiki/index.html && cd /srv/wiki && exec python3 -m http.server 8080 --bind 127.0.0.1 >/var/log/target.log 2>&1'
}

for name in server ally outsider; do
  "${D[@]}" run -d --name "$P-$name" --hostname "svc-$name" --network "$P-net" --privileged \
    -v "$P-certs:/certs:ro" "$IMG" >/dev/null
done
echo "== enrol server (office,ranger; --serve-services), ally (office), outsider (ranger)"
start_target
start_agent server office,ranger --serve-services --serve-services-ports 8080
start_agent ally office
start_agent outsider ranger
for name in server ally outsider; do pin_port "$name"; done
for _ in $(seq 1 60); do
  server_ip="$(status_field server address 2>/dev/null || true)"
  [[ -n "$server_ip" ]] && "${D[@]}" exec "$P-ally" ping -c 1 -W 2 "$server_ip" >/dev/null 2>&1 \
    && "${D[@]}" exec "$P-outsider" ping -c 1 -W 2 "$server_ip" >/dev/null 2>&1 && break
  sleep 2
done
server_node="$(status_field server node_id)"
# Docker rewrites a container's resolv.conf, which makes the agent fall back
# to "listener-only" DNS. Point each client's system resolver at its own
# MagicDNS listener, as the agent's resolver routing does on a host. The stub
# never forwards public names, so the coordinator goes in /etc/hosts.
coord_ip="$(agent_ip coord)"
for name in ally outsider; do
  "${D[@]}" exec "$P-$name" sh -c "echo '$coord_ip $P-coord' >> /etc/hosts; echo nameserver $(status_field "$name" address) > /etc/resolv.conf"
done
echo "ok overlay up; server $server_ip ($server_node); ally and outsider both reach it by ping"

echo "== create service wiki -> server 127.0.0.1:8080, access tag office"
created="$(lab create "$ORG" wiki "$server_node" 8080 office)"
service_id="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["id"])' "$created")"
fqdn="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["fqdn"])' "$created")"
echo "ok $fqdn ($service_id)"
wait_status serving
lab status "$ORG"

echo "== server: key generated on the node, 0600, never logged; listener on overlay only"
mode="$("${D[@]}" exec "$P-server" sh -c "stat -c %a /var/lib/blaktail/services/$service_id.key")"
[[ "$mode" == 600 ]] || fail "service key mode $mode"
"${D[@]}" exec "$P-server" grep -q "PRIVATE KEY" /var/lib/blaktail/services/$service_id.key || fail "no key on server"
"${D[@]}" exec "$P-server" grep -q "PRIVATE KEY" /var/log/agent.log && fail "agent log contains key material"
listeners="$("${D[@]}" exec "$P-server" ss -Htln 'sport = :443' | awk '{print $4}' | sort -u | tr '\n' ' ')"
server_ip6="$(status_field server ipv6_address)"
want="$(printf '%s\n' "[$server_ip6]:443" "$server_ip:443" | sort -u | tr '\n' ' ')"
[[ "$listeners" == "$want" ]] || fail "listener bound to '$listeners', want only the overlay addresses '$want'"
"${D[@]}" exec "$P-server" iptables -S BLAKTAIL-ACL | grep -- "--dport 443" | grep -q REJECT \
  || fail "no port-level reject for non-members on the server"
echo "ok key mode 600, not in the agent log; listener only on $want; acl_filter rejects non-members at tcp/443"

echo "== ally (office): trust the CA explicitly, curl by MagicDNS name"
"${D[@]}" exec "$P-ally" blaktaild --coord-ca /certs/ca.crt trust-service-ca --output /tmp/svc-ca.pem
wait_resolution ally "$fqdn" yes
body="$("${D[@]}" exec "$P-ally" curl -sS --max-time 10 --cacert /tmp/svc-ca.pem "https://$fqdn/")"
[[ "$body" == "hello from the private wiki" ]] || fail "ally got '$body'"
echo "ok ally: curl --cacert <org CA> https://$fqdn/ -> '$body'"
"${D[@]}" exec "$P-ally" curl -sS --max-time 5 -o /dev/null -k "https://$server_ip/" >/dev/null 2>&1 \
  && fail "raw-IP request without SNI was served"
echo "ok ally: raw overlay IP without the service name is refused (no SNI, no route)"

echo "== outsider (ranger): no name, no raw-IP access"
resolves outsider "$fqdn" && fail "outsider resolves $fqdn"
"${D[@]}" exec "$P-outsider" blaktaild --coord-ca /certs/ca.crt trust-service-ca --output /tmp/svc-ca.pem >/dev/null
"${D[@]}" exec "$P-outsider" curl -sS --max-time 8 --cacert /tmp/svc-ca.pem "https://$fqdn/" >/dev/null 2>&1 \
  && fail "outsider reached the service by name"
"${D[@]}" exec "$P-outsider" curl -sS --max-time 8 --cacert /tmp/svc-ca.pem --resolve "$fqdn:443:$server_ip" "https://$fqdn/" >/dev/null 2>&1 \
  && fail "outsider reached the service by forcing the name to the raw IP"
"${D[@]}" exec "$P-outsider" curl -sS --max-time 8 -k "https://$server_ip/" >/dev/null 2>&1 \
  && fail "outsider reached the raw overlay IP"
"${D[@]}" exec "$P-outsider" ping -c 1 -W 2 "$server_ip" >/dev/null 2>&1 || fail "outsider lost ordinary policy access"
echo "ok outsider: name NXDOMAIN; forced name and raw IP both refused; ordinary policy access (ping) unchanged"

echo "== target outage withdraws the name; recovery republishes it"
"${D[@]}" exec "$P-server" pkill -f "http.server 8080"
wait_status target_unhealthy
wait_resolution ally "$fqdn" no
echo "ok ally no longer resolves $fqdn while the target is down"
start_target
wait_status serving
wait_resolution ally "$fqdn" yes
"${D[@]}" exec "$P-ally" curl -sS --max-time 10 --cacert /tmp/svc-ca.pem "https://$fqdn/" >/dev/null || fail "not served after recovery"
echo "ok republished and served after recovery"

echo "== disable: the listener goes within one control update"
lab disable "$ORG" "$service_id"
started=$SECONDS
until [[ -z "$("${D[@]}" exec "$P-server" ss -Htln 'sport = :443')" ]]; do
  (( SECONDS - started < 60 )) || fail "listener still up after disable"
  sleep 1
done
echo "ok server dropped its listener $((SECONDS - started))s after disable"
"${D[@]}" exec "$P-ally" curl -sS --max-time 8 --cacert /tmp/svc-ca.pem --resolve "$fqdn:443:$server_ip" "https://$fqdn/" >/dev/null 2>&1 \
  && fail "ally still reached the disabled service"
wait_resolution ally "$fqdn" no
"${D[@]}" exec "$P-server" test -e "/var/lib/blaktail/services/$service_id.key" && fail "key kept after disable"
lab status "$ORG"
echo "ok disabled: no listener, no name, key deleted"
echo "private services lab passed"
