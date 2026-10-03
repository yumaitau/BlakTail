#!/usr/bin/env bash
# Live proof for public ingress (draft 11 / ADR 0007): a coordinator, an
# ingress host (blaktaild --public-ingress + blaktail-ingress) and a target
# agent serving HTTP only on its overlay address, plus an "Internet" client.
#
#   DOCKER_CONTEXT=m3-max deploy/homelab/prove-public-ingress.sh
#
# Everything it starts is named pubingress-* and removed on exit.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
P="${LAB_PREFIX:-pubingress}"
IMG="${P}-lab:latest"
NET="${P}-net"
FQDN=app.example.org.au
ACME_FQDN=auto.example.org.au
PEBBLE_IMAGE="${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:latest}"
WRONG=wrong.example.org.au
COORD="https://${P}-coord:8443"
BOUND=30
WORK="$(mktemp -d)"

cleanup() {
  if [[ "${KEEP_LAB:-0}" == 1 ]]; then rm -rf "$WORK"; return; fi
  docker rm -f "${P}-coord" "${P}-edge" "${P}-app" "${P}-client" "${P}-pebble" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker volume rm -f "${P}-certs" "${P}-pebble" >/dev/null 2>&1 || true
  if [[ "${KEEP_IMAGE:-0}" != 1 ]]; then docker image rm -f "$IMG" >/dev/null 2>&1 || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

pass() { printf 'ok   %s\n' "$*"; }
fail() {
  printf 'FAIL %s\n' "$*" >&2
  docker logs --tail 30 "${P}-coord" >&2 2>&1 || true
  docker exec "${P}-edge" tail -n 30 /var/log/blaktail-ingress.log >&2 2>&1 || true
  exit 1
}

echo "== build lab image from tracked sources"
git ls-files -z | tar --null -T - -czf "$WORK/src.tgz"
docker build -q -t "$IMG" -f deploy/homelab/public-ingress.Dockerfile - <"$WORK/src.tgz" >/dev/null

cleanup_soft() {
  docker rm -f "${P}-coord" "${P}-edge" "${P}-app" "${P}-client" "${P}-pebble" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker volume rm -f "${P}-certs" "${P}-pebble" >/dev/null 2>&1 || true
}
cleanup_soft
docker network create "$NET" >/dev/null
docker volume create "${P}-certs" >/dev/null

echo "== lab certificates (coordinator and the public test name)"
docker run --rm -v "${P}-certs:/certs" -e P="$P" --entrypoint sh "$IMG" -ceu '
  cd /certs
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.crt \
    -days 2 -subj "/CN=pubingress lab CA" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
  gen() {
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$1" 2>/dev/null
    printf "subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n" "$2" >"$1.ext"
    openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -out "$1.crt" -days 2 -extfile "$1.ext" 2>/dev/null
  }
  gen coord "DNS:$P-coord"
  gen public DNS:app.example.org.au
  chmod 644 ./*.crt && chmod 600 ./*.key'

umask 077
{
  echo "BLAKTAIL_AUTH_HMAC_SECRET=$(openssl rand -hex 32)"
  echo "BLAKTAIL_RELAY_AUTH_SECRET=$(openssl rand -hex 32)"
  echo "BLAKTAIL_COORD_DIAGNOSTICS_TOKEN=$(openssl rand -hex 24)"
} >"$WORK/secrets.env"

echo "== coordinator"
docker run -d --name "${P}-coord" --network "$NET" -v "${P}-certs:/certs:ro" \
  --env-file "$WORK/secrets.env" \
  -e BLAKTAIL_REGION=ap-southeast-2 -e BLAKTAIL_BIND=0.0.0.0:8443 \
  -e BLAKTAIL_COORD_METRICS_BIND=127.0.0.1:9701 \
  -e BLAKTAIL_DATABASE=/data/coord.sqlite3 -e BLAKTAIL_DATABASE_STORAGE=local \
  -e BLAKTAIL_TLS_CERT=/certs/coord.crt -e BLAKTAIL_TLS_KEY=/certs/coord.key \
  -e BLAKTAIL_CONSOLE_URL=https://console.example.org.au \
  --entrypoint sh "$IMG" -c 'mkdir -p /data && blaktail-coord migrate && exec blaktail-coord serve' >/dev/null

docker run -d --name "${P}-client" --network "$NET" -v "${P}-certs:/certs:ro" \
  --env-file "$WORK/secrets.env" -e COORD="$COORD" "$IMG" >/dev/null
docker exec "${P}-client" mkdir -p /lab
docker cp deploy/homelab/public-ingress-lab.py "${P}-client:/lab/lab.py"
lab() { docker exec "${P}-client" python3 /lab/lab.py "$@"; }

for _ in $(seq 1 60); do
  docker exec "${P}-client" curl -fsS --cacert /certs/ca.crt "$COORD/health" >/dev/null 2>&1 && break
  sleep 1
done
docker exec "${P}-client" curl -fsS --cacert /certs/ca.crt "$COORD/health" >/dev/null || fail "coordinator did not start"
org="$(lab bootstrap)"
pass "organisation ${org} created"

echo "== agents"
for node in edge app; do
  alias=()
  [[ "$node" == edge ]] && alias=(--network-alias "$ACME_FQDN")
  docker run -d --name "${P}-${node}" --hostname "${P}-${node}" --network "$NET" ${alias[@]+"${alias[@]}"} \
    --privileged --cap-add NET_ADMIN --device /dev/net/tun \
    --security-opt apparmor=unconfined --security-opt seccomp=unconfined \
    -v "${P}-certs:/certs:ro" "$IMG" >/dev/null
done
ip_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"; }
enrol() {
  local node="$1"; shift
  local key; key="$(lab join-key office)"
  printf '%s' "$key" | docker exec -i "${P}-${node}" blaktaild --coord-ca /certs/ca.crt up \
    --coord "$COORD" --name "$node" --endpoint "$(ip_of "${P}-${node}"):51820" \
    --poll-seconds 5 --exit-after-join "$@" >/dev/null
  docker exec -d "${P}-${node}" blaktaild --coord-ca /certs/ca.crt run --poll-seconds 5
}
enrol edge --public-ingress
enrol app
for node in edge app; do
  for _ in $(seq 1 20); do docker exec "${P}-${node}" wg show blaktail0 >/dev/null 2>&1 && break; sleep 1; done
  docker exec "${P}-${node}" wg set blaktail0 listen-port 51820
done
app_overlay="$(docker exec "${P}-app" sh -c "ip -4 -o addr show blaktail0 | awk '{print \$4}' | cut -d/ -f1")"
docker exec -d "${P}-app" sh -c "mkdir -p /srv && echo 'hello from the private app' >/srv/index.html && cd /srv && exec python3 -m http.server 8080 --bind ${app_overlay}"
for _ in $(seq 1 45); do
  docker exec "${P}-edge" curl -fsS -m 2 "http://${app_overlay}:8080/" >/dev/null 2>&1 && break
  sleep 1
done
docker exec "${P}-edge" curl -fsS -m 2 "http://${app_overlay}:8080/" >/dev/null || fail "edge cannot reach app over the overlay"
pass "edge reaches app at ${app_overlay}:8080 over WireGuard"
if docker exec "${P}-client" curl -fsS -m 3 "http://${app_overlay}:8080/" >/dev/null 2>&1; then
  fail "client reached the app without the overlay"
fi
pass "Internet client cannot reach the private app directly"

echo "== ingress"
docker exec "${P}-edge" sh -ceu "
  d=/etc/blaktail-ingress/certs/${FQDN}; mkdir -p \$d
  cp /certs/public.crt \$d/fullchain.pem; cp /certs/public.key \$d/privkey.pem; chmod 600 \$d/privkey.pem"
echo "== Pebble test ACME server (HTTP-01 against the ingress on port 80)"
docker volume create "${P}-pebble" >/dev/null
docker run --rm -i -v "${P}-pebble:/cfg" --entrypoint sh "$IMG" -c 'cat >/cfg/pebble.json' <<'JSON'
{"pebble": {"listenAddress": "0.0.0.0:14000", "managementListenAddress": "0.0.0.0:15000",
  "certificate": "/test/certs/localhost/cert.pem", "privateKey": "/test/certs/localhost/key.pem",
  "httpPort": 80, "tlsPort": 443, "ocspResponderURL": "", "externalAccountBindingRequired": false}}
JSON
docker run -d --name "${P}-pebble" --network "$NET" --network-alias pebble -e PEBBLE_VA_NOSLEEP=1 \
  -v "${P}-pebble:/cfg:ro" "$PEBBLE_IMAGE" -config /cfg/pebble.json >/dev/null
for _ in $(seq 1 30); do
  docker exec "${P}-client" curl -fsS -k -m 3 https://pebble:14000/dir >/dev/null 2>&1 && break
  sleep 1
done
docker cp "${P}-pebble:/test/certs/pebble.minica.pem" "$WORK/pebble.minica.pem"
docker cp "$WORK/pebble.minica.pem" "${P}-edge:/etc/pebble.minica.pem"
docker exec -d "${P}-edge" sh -c 'blaktail-ingress --coord-ca /certs/ca.crt --acme-directory https://pebble:14000/dir --acme-root /etc/pebble.minica.pem >/var/log/blaktail-ingress.log 2>&1'

app_id="$(lab node-id app)"
for role in member admin network_admin; do
  status="$(lab as-role "$role" POST "/v1/orgs/{org}/public-ingress/routes" \
    "{\"fqdn\":\"${FQDN}\",\"confirm_fqdn\":\"${FQDN}\",\"target_node_id\":\"${app_id}\",\"target_port\":8080}")"
  [[ "$status" == 403 ]] || fail "${role} create answered ${status}"
done
pass "member, admin and network admin cannot create a public route (403)"
status="$(lab as-role owner POST "/v1/orgs/{org}/public-ingress/routes" \
  "{\"fqdn\":\"${FQDN}\",\"confirm_fqdn\":\"${FQDN}\",\"target_node_id\":\"${app_id}\",\"target_port\":8080}")"
[[ "$status" == 409 ]] || fail "create while organisation off answered ${status}"
pass "owner cannot publish while the organisation setting is off (409)"
lab enable >/dev/null
route_id="$(lab create-route "$FQDN" "$app_id" 8080)"
pass "owner published ${FQDN} -> app:8080 (route ${route_id})"

edge_ip="$(ip_of "${P}-edge")"
public() { docker exec "${P}-client" curl -sS -m 5 --cacert /certs/ca.crt --resolve "${FQDN}:443:${edge_ip}" "$@"; }

echo "== designation: the capability alone gets no routes"
sleep 15 # three ingress polls
if public "https://${FQDN}/" >/dev/null 2>&1; then fail "undesignated ingress served the route"; fi
edge_id="$(lab node-id edge)"
for role in admin network_admin member; do
  status="$(lab designate "$edge_id" true "$role")"
  [[ "$status" == 403 ]] || fail "${role} designation answered ${status}"
done
pass "undesignated edge serves nothing; admin, network admin and member cannot designate it (403)"
status="$(lab designate "$edge_id" true)"
[[ "$status" == 200 ]] || fail "owner designation answered ${status}"
pass "owner designated edge as the public ingress"
for _ in $(seq 1 60); do
  [[ "$(public "https://${FQDN}/" 2>/dev/null || true)" == "hello from the private app" ]] && break
  sleep 1
done
[[ "$(public "https://${FQDN}/")" == "hello from the private app" ]] || fail "public request did not reach the app"
pass "https://${FQDN}/ via the ingress returns the private app (certificate verified)"

head="$(public -D - -o /dev/null "https://${FQDN}/")"
for leaked in "server:" "100.64." "100.65." ".blaktail" "simplehttp" "${app_overlay}"; do
  if grep -qi -- "$leaked" <<<"$head"; then fail "response header leaked ${leaked}: ${head}"; fi
done
pass "response headers carry no Server banner, overlay address or internal name"

code="$(public -o /dev/null -w '%{http_code}' -H "Host: ${WRONG}" "https://${FQDN}/")"
[[ "$code" == 421 ]] || fail "wrong Host answered ${code}"
pass "wrong Host header on the published connection -> 421"
code="$(public -o /dev/null -w '%{http_code}' --request-target "http://169.254.169.254/latest/meta-data/" "https://${FQDN}/")"
[[ "$code" == 421 ]] || fail "absolute-form metadata request answered ${code}"
pass "absolute-form request for 169.254.169.254 -> 421, never forwarded"
if docker exec "${P}-client" curl -sS -m 5 --cacert /certs/ca.crt --resolve "${WRONG}:443:${edge_ip}" "https://${WRONG}/" >/dev/null 2>&1; then
  fail "unknown server name completed a TLS handshake"
fi
pass "unpublished server name ${WRONG} fails the TLS handshake"
if docker exec "${P}-client" curl -sS -m 5 -k "https://${edge_ip}/" >/dev/null 2>&1; then
  fail "connecting by IP (no SNI) was served"
fi
pass "connecting by IP without a server name fails the TLS handshake"

echo "== policy still applies"
lab set-acl '{"version":1,"defaults":"deny","rules":[]}' >/dev/null
for _ in $(seq 1 30); do
  [[ "$(public -o /dev/null -w '%{http_code}' "https://${FQDN}/" 2>/dev/null || true)" != 200 ]] && break
  sleep 1
done
[[ "$(public -o /dev/null -w '%{http_code}' "https://${FQDN}/" 2>/dev/null || true)" != 200 ]] || fail "route still served after policy denied the ingress"
lab workspace | grep -q '"status": "blocked_by_policy"' || fail "workspace did not report blocked_by_policy"
pass "deny-by-default policy withdraws the route; console reports blocked_by_policy"
lab set-acl '{"version":1,"defaults":"same_tag","rules":[]}' >/dev/null
for _ in $(seq 1 60); do
  [[ "$(public "https://${FQDN}/" 2>/dev/null || true)" == "hello from the private app" ]] && break
  sleep 1
done
[[ "$(public "https://${FQDN}/")" == "hello from the private app" ]] || fail "route did not return after policy restore"
pass "restoring the policy serves the route again"

echo "== ACME HTTP-01 route"
lab create-route "$ACME_FQDN" "$app_id" 8080 acme_http01 >/dev/null
for _ in $(seq 1 90); do
  docker exec "${P}-client" curl -fsS -k -m 5 https://pebble:15000/roots/0 >"$WORK/pebble-root.pem" 2>/dev/null || true
  docker cp "$WORK/pebble-root.pem" "${P}-client:/lab/pebble-root.pem" >/dev/null 2>&1 || true
  body="$(docker exec "${P}-client" curl -sS -m 5 --cacert /lab/pebble-root.pem --resolve "${ACME_FQDN}:443:${edge_ip}" "https://${ACME_FQDN}/" 2>/dev/null || true)"
  [[ "$body" == "hello from the private app" ]] && break
  sleep 2
done
[[ "$body" == "hello from the private app" ]] || fail "ACME route was not served with a Pebble-issued certificate"
pass "ingress obtained a certificate for ${ACME_FQDN} over ACME HTTP-01 (Pebble) and serves it"

echo "== console status"
sleep 2
workspace="$(lab workspace)"
grep -q '"online": true' <<<"$workspace" || fail "ingress not reported online"
grep -q '"certificate_not_after": [0-9]' <<<"$workspace" || fail "certificate expiry not reported"
pass "workspace shows the ingress online and the certificate expiry"

echo "== emergency disable"
start_ms="$(docker exec "${P}-client" python3 -c 'import time;print(int(time.time()*1000))')"
lab emergency "$route_id" >/dev/null
stop_ms=""
for _ in $(seq 1 $((BOUND * 10))); do
  code="$(public -o /dev/null -w '%{http_code}' "https://${FQDN}/" 2>/dev/null || true)"
  if [[ "$code" != 200 ]]; then
    stop_ms="$(docker exec "${P}-client" python3 -c 'import time;print(int(time.time()*1000))')"
    break
  fi
  sleep 0.1
done
[[ -n "$stop_ms" ]] || fail "route still served ${BOUND}s after emergency disable"
elapsed=$((stop_ms - start_ms))
(( elapsed <= BOUND * 1000 )) || fail "emergency disable took ${elapsed} ms"
pass "emergency disable removed public access in ${elapsed} ms (bound ${BOUND} s; first failing status ${code})"

echo "== access log"
log="$(docker exec "${P}-edge" sh -c "cat /var/lib/blaktail-ingress/access-logs/${FQDN}/*.jsonl")"
grep -q '"outcome":"proxied"' <<<"$log" || fail "no proxied entries in the access log"
if grep -q -- "${app_overlay}" <<<"$log"; then fail "access log contains the target address"; fi
pass "access log on the ingress host records requests without the target address ($(wc -l <<<"$log" | tr -d ' ') entries)"

echo "== coordinator loss fails closed"
lab reenable "$route_id" >/dev/null
for _ in $(seq 1 30); do
  [[ "$(public "https://${FQDN}/" 2>/dev/null || true)" == "hello from the private app" ]] && break
  sleep 1
done
[[ "$(public "https://${FQDN}/")" == "hello from the private app" ]] || fail "owner re-enable did not restore the route"
pass "owner re-enable (typed hostname) restores the route"
start_ms="$(docker exec "${P}-client" python3 -c 'import time;print(int(time.time()*1000))')"
docker stop "${P}-coord" >/dev/null
stop_ms=""
for _ in $(seq 1 $(((BOUND + 10) * 2))); do
  code="$(public -o /dev/null -w '%{http_code}' "https://${FQDN}/" 2>/dev/null || true)"
  if [[ "$code" != 200 ]]; then
    stop_ms="$(docker exec "${P}-client" python3 -c 'import time;print(int(time.time()*1000))')"
    break
  fi
  sleep 0.5
done
[[ -n "$stop_ms" ]] || fail "route still served after the coordinator stopped"
elapsed=$((stop_ms - start_ms))
(( elapsed <= (BOUND + 1) * 1000 )) || fail "stale bound exceeded: ${elapsed} ms"
pass "with the coordinator stopped the ingress stopped serving after ${elapsed} ms (status ${code})"

echo "public_ingress_proof passed"
