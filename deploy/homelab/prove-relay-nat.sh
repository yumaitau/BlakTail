#!/usr/bin/env bash
# Two agents on one Docker host, with direct UDP between them dropped.
# Overlay ping must succeed through the relay forwarder (127.0.0.1), which is
# the same failure mode as two sites that can only meet at the relay.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
export COMPOSE_HTTP_TIMEOUT="${COMPOSE_HTTP_TIMEOUT:-300}"
export DOCKER_CLIENT_TIMEOUT="${DOCKER_CLIENT_TIMEOUT:-300}"
export BLAKTAIL_COORD_PUBLISH="${BLAKTAIL_COORD_PUBLISH:-192.168.1.19:8443}"
export BLAKTAIL_CADDYFILE="${BLAKTAIL_CADDYFILE:-/home/justinmiddler/apps/BlakTail/deploy/homelab/Caddyfile}"
ENV_FILE="${BLAKTAIL_ENV_FILE:-}"
if [[ -z "$ENV_FILE" ]]; then
  ENV_FILE="$(mktemp /tmp/blaktail-env.XXXXXX)"
  scp -o BatchMode=yes -q homelab:/home/justinmiddler/apps/BlakTail/.env "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  trap 'rm -f "$ENV_FILE"' EXIT
fi
COMPOSE=(docker --context "${DOCKER_CONTEXT:-homelab}" compose --env-file "$ENV_FILE" -p blaktail -f compose.yaml -f compose.homelab.yml --profile acl-prove)
WORKDIR="/home/justinmiddler/blaktail-relay-nat"
ssh -o BatchMode=yes homelab "rm -rf '$WORKDIR' && mkdir -p '$WORKDIR' && chmod 777 '$WORKDIR'"
scp -o BatchMode=yes -q deploy/homelab/acl-prove.mjs "homelab:$WORKDIR/acl-prove.mjs"
COORD="https://coord:8443"
LISTEN_PORT=51820
suffix="$(openssl rand -hex 2)"
office_name="office-nat-${suffix}"
store_name="store-nat-${suffix}"

status_of() {
  "${COMPOSE[@]}" exec -T "$1" blaktaild --coord-ca /certs/ca.crt status
}

overlay_ip() {
  local text
  text="$(status_of "$1")" || return 1
  awk '$1 == "address:" { sub("/32","",$2); print $2; exit }' <<<"$text"
}

container_ip() {
  "${COMPOSE[@]}" exec -T "$1" sh -c "ip -4 -o addr show eth0 | awk '{print \$4}' | cut -d/ -f1 | head -n1"
}

console_bun() {
  "${COMPOSE[@]}" run --rm \
    -e ACL_PROVE_KEY_DIR=/bootstrap \
    -v "${WORKDIR}:/bootstrap" \
    console bun /bootstrap/acl-prove.mjs "$@"
}

drop_direct_udp() {
  local from="$1" to_ip="$2"
  "${COMPOSE[@]}" exec -T "$from" iptables -C OUTPUT -d "$to_ip" -p udp -j DROP 2>/dev/null \
    || "${COMPOSE[@]}" exec -T "$from" iptables -I OUTPUT -d "$to_ip" -p udp -j DROP
  "${COMPOSE[@]}" exec -T "$from" iptables -C INPUT -s "$to_ip" -p udp -j DROP 2>/dev/null \
    || "${COMPOSE[@]}" exec -T "$from" iptables -I INPUT -s "$to_ip" -p udp -j DROP
}

# Docker does not hairpin the host's published relay port back into the relay
# container. Rewrite only that destination to the relay's compose address.
# Peer UDP stays dropped, so the overlay still has to cross the relay.
redirect_relay() {
  local from="$1" advertised_ip="$2" advertised_port="$3" relay_ip="$4"
  "${COMPOSE[@]}" exec -T "$from" iptables -t nat -C OUTPUT -d "$advertised_ip" -p udp --dport "$advertised_port" -j DNAT --to-destination "${relay_ip}:${advertised_port}" 2>/dev/null \
    || "${COMPOSE[@]}" exec -T "$from" iptables -t nat -A OUTPUT -d "$advertised_ip" -p udp --dport "$advertised_port" -j DNAT --to-destination "${relay_ip}:${advertised_port}"
}

ssh -o BatchMode=yes homelab "chmod 644 '$WORKDIR/acl-prove.mjs'"

coord_secret="$("${COMPOSE[@]}" exec -T coord sh -c 'printf %s "$BLAKTAIL_RELAY_AUTH_SECRET" | sha256sum')"
relay_secret="$("${COMPOSE[@]}" exec -T relay sh -c 'printf %s "$BLAKTAIL_RELAY_AUTH_SECRET" | sha256sum')"
if [[ "$coord_secret" != "$relay_secret" ]]; then
  echo "== relay auth secret drifted from the coordinator; recreating relay"
  "${COMPOSE[@]}" up -d --force-recreate --no-deps relay
fi

echo "== purge leftover prove nodes"
console_bun purge-nodes

echo "== build and start agents"
"${COMPOSE[@]}" rm -sf agent-office agent-store >/dev/null 2>&1 || true
docker --context "${DOCKER_CONTEXT:-homelab}" volume rm -f blaktail_agent-office-data blaktail_agent-store-data >/dev/null 2>&1 || true
"${COMPOSE[@]}" build agent-office
"${COMPOSE[@]}" up -d --force-recreate agent-office agent-store

echo "== mint join keys"
console_bun mint
docker --context "${DOCKER_CONTEXT:-homelab}" run --rm -v "$WORKDIR:/w" alpine chmod 644 /w/office /w/store
office_id="$("${COMPOSE[@]}" ps -q agent-office)"
store_id="$("${COMPOSE[@]}" ps -q agent-store)"
ssh -o BatchMode=yes homelab "docker cp '$WORKDIR/office' '${office_id}:/tmp/office.key' && docker cp '$WORKDIR/store' '${store_id}:/tmp/store.key' && rm -f '$WORKDIR/office' '$WORKDIR/store'"

office_lan="$(container_ip agent-office)"
store_lan="$(container_ip agent-store)"
echo "== drop direct UDP ${office_lan} <-> ${store_lan}"
drop_direct_udp agent-office "$store_lan"
drop_direct_udp agent-store "$office_lan"

relay_advertise="$(awk -F= '$1=="BLAKTAIL_RELAY_ENDPOINT" { print substr($0, index($0, "=")+1) }' "$ENV_FILE")"
relay_advertise="${relay_advertise//\"/}"
relay_advertise="${relay_advertise//$'\r'/}"
relay_host="${relay_advertise%%:*}"
relay_port="${relay_advertise##*:}"
relay_id="$("${COMPOSE[@]}" ps -q relay)"
relay_ip="$(docker --context "${DOCKER_CONTEXT:-homelab}" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$relay_id")"
if [[ -z "$relay_host" || -z "$relay_port" || -z "$relay_ip" || "$relay_host" == "$relay_advertise" ]]; then
  echo "FAIL could not resolve relay ${relay_advertise} -> ${relay_ip}" >&2
  exit 1
fi
echo "== relay ${relay_host}:${relay_port} -> ${relay_ip}:${relay_port}"
redirect_relay agent-office "$relay_host" "$relay_port" "$relay_ip"
redirect_relay agent-store "$relay_host" "$relay_port" "$relay_ip"

echo "== enrol ${office_name}"
"${COMPOSE[@]}" exec -T agent-office sh -ceu '
  chmod 600 /tmp/office.key
  printf "%s" "$(tr -d "\n" < /tmp/office.key)" | blaktaild --coord-ca /certs/ca.crt up \
    --coord "'"$COORD"'" --name "'"$office_name"'" \
    --endpoint "'"${office_lan}:${LISTEN_PORT}"'" --poll-seconds 5 --exit-after-join
  shred -u /tmp/office.key || rm -f /tmp/office.key
'
echo "== enrol ${store_name}"
"${COMPOSE[@]}" exec -T agent-store sh -ceu '
  chmod 600 /tmp/store.key
  printf "%s" "$(tr -d "\n" < /tmp/store.key)" | blaktaild --coord-ca /certs/ca.crt up \
    --coord "'"$COORD"'" --name "'"$store_name"'" \
    --endpoint "'"${store_lan}:${LISTEN_PORT}"'" --poll-seconds 5 --exit-after-join
  shred -u /tmp/store.key || rm -f /tmp/store.key
'

"${COMPOSE[@]}" exec -d agent-office sh -c 'blaktaild --coord-ca /certs/ca.crt run --poll-seconds 5 > /tmp/blaktaild.log 2>&1'
"${COMPOSE[@]}" exec -d agent-store sh -c 'blaktaild --coord-ca /certs/ca.crt run --poll-seconds 5 > /tmp/blaktaild.log 2>&1'

echo "== allow the two agents to reach each other on the overlay"
console_bun put-acl '{"defaults":"deny","groups":{},"rules":[{"action":"allow","src_tags":["office","store"],"dst_tags":["office","store"]}]}'

deadline=$((SECONDS + 150))
store_ip=""
office_ip=""
while (( SECONDS < deadline )); do
  store_ip="$(overlay_ip agent-store || true)"
  office_ip="$(overlay_ip agent-office || true)"
  office_eps="$("${COMPOSE[@]}" exec -T agent-office wg show blaktail0 endpoints 2>/dev/null || true)"
  store_eps="$("${COMPOSE[@]}" exec -T agent-store wg show blaktail0 endpoints 2>/dev/null || true)"
  if [[ -n "$store_ip" && -n "$office_ip" && "$office_eps" == *127.0.0.1* && "$store_eps" == *127.0.0.1* ]]; then
    if "${COMPOSE[@]}" exec -T agent-office iptables -C OUTPUT -d "$store_lan" -p udp -j DROP \
      && "${COMPOSE[@]}" exec -T agent-store iptables -C OUTPUT -d "$office_lan" -p udp -j DROP \
      && "${COMPOSE[@]}" exec -T agent-office ping -c 2 -W 3 "$store_ip" >/dev/null \
      && "${COMPOSE[@]}" exec -T agent-store ping -c 2 -W 3 "$office_ip" >/dev/null; then
      echo "ok relay path ${office_ip} <-> ${store_ip} with direct UDP dropped"
      echo "relay_nat passed"
      exit 0
    fi
  fi
  sleep 5
done

echo "FAIL overlay did not converge through the relay" >&2
status_of agent-office >&2 || true
status_of agent-store >&2 || true
"${COMPOSE[@]}" exec -T agent-office wg show blaktail0 >&2 || true
"${COMPOSE[@]}" exec -T agent-store wg show blaktail0 >&2 || true
echo "== office log" >&2
"${COMPOSE[@]}" exec -T agent-office tail -n 40 /tmp/blaktaild.log >&2 || true
echo "== store log" >&2
"${COMPOSE[@]}" exec -T agent-store tail -n 40 /tmp/blaktaild.log >&2 || true
exit 1
