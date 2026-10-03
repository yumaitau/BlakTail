# Shared harness for the self-contained relay labs (sourced, not executed).
#
# Builds one image from the committed tree (git ls-files), then runs a
# coordinator, one or two Australian relays (UDP 3478 + WSS 443) and two
# Linux agents on a private Docker network. Nothing depends on a long-lived
# stack, a console or SSH access to the Docker host. Every container, network
# and volume is named with $LAB_PREFIX and removed on exit.
#
# Requires: docker (any context; default m3-max), git, openssl, python3.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CTX="${DOCKER_CONTEXT:-m3-max}"
LAB_PREFIX="${LAB_PREFIX:-ops-clients-relaylab}"
IMAGE="${LAB_PREFIX}:latest"
NET="${LAB_PREFIX}-net"
CERTS="${LAB_PREFIX}-certs"
D=(docker --context "$CTX")
RELAY_HOST="relay.lab.example.au"
RELAY2_HOST="relay2.lab.example.au"
LAB_ENV="$(mktemp "${TMPDIR:-/tmp}/relay-lab-env.XXXXXX")"
chmod 600 "$LAB_ENV"

lab_cleanup() {
  local status=$?
  if [[ $status -ne 0 && -z "${LAB_QUIET_FAILURE:-}" ]]; then
    for agent in a b; do
      echo "== agent ${agent} log (tail)" >&2
      "${D[@]}" exec "${LAB_PREFIX}-${agent}" tail -n 30 /tmp/blaktaild.log >&2 2>/dev/null || true
    done
  fi
  "${D[@]}" rm -f "${LAB_PREFIX}-coord" "${LAB_PREFIX}-relay" "${LAB_PREFIX}-relay2" \
    "${LAB_PREFIX}-a" "${LAB_PREFIX}-b" "${LAB_PREFIX}-certgen" >/dev/null 2>&1 || true
  "${D[@]}" network rm "$NET" >/dev/null 2>&1 || true
  "${D[@]}" volume rm "$CERTS" >/dev/null 2>&1 || true
  if [[ -z "${LAB_KEEP_IMAGE:-}" ]]; then
    "${D[@]}" image rm "$IMAGE" >/dev/null 2>&1 || true
  fi
  rm -f "$LAB_ENV"
  return $status
}

lab_build() {
  echo "== build ${IMAGE} on ${CTX} from the committed tree ($(git -C "$ROOT" rev-parse --short HEAD))"
  (cd "$ROOT" && git ls-files -z | tar --null -T - -cf -) \
    | "${D[@]}" build -q -t "$IMAGE" -f deploy/homelab/relay-lab.Dockerfile - >/dev/null
}

lab_secrets() {
  {
    printf 'BLAKTAIL_AUTH_HMAC_SECRET=%s\n' "$(openssl rand -hex 32)"
    printf 'BLAKTAIL_RELAY_AUTH_SECRET=%s\n' "$(openssl rand -hex 32)"
  } >"$LAB_ENV"
}

lab_network() {
  "${D[@]}" network create "$NET" >/dev/null
  "${D[@]}" volume create "$CERTS" >/dev/null
  # Throwaway CA plus leaves for the coordinator and both relays.
  "${D[@]}" run --rm --name "${LAB_PREFIX}-certgen" -v "$CERTS:/certs" "$IMAGE" sh -ceu '
    cd /certs
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
      -keyout ca.key -out ca.crt -subj "/CN=relay lab CA" 2>/dev/null
    leaf() {
      openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$1.key" -out "$1.csr" -subj "/CN=$2" 2>/dev/null
      printf "subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n" "$2" >"$1.ext"
      openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out "$1.crt" -days 2 -extfile "$1.ext" 2>/dev/null
      rm -f "$1.csr" "$1.ext"
    }
    leaf coord coord
    leaf relay '"$RELAY_HOST"'
    leaf relay2 '"$RELAY2_HOST"'
    chmod 644 ./*.crt ./*.key
  '
}

# lab_relay NAME HOST: a relay with UDP 3478 and a TLS WebSocket listener on 443.
lab_relay() {
  local name="$1" host="$2" cert="$3"
  "${D[@]}" run -d --name "${LAB_PREFIX}-${name}" --network "$NET" --network-alias "$host" \
    -v "$CERTS:/certs:ro" --env-file "$LAB_ENV" \
    -e BLAKTAIL_REGION=ap-southeast-2 \
    -e BLAKTAIL_RELAY_WSS_BIND=0.0.0.0:443 \
    -e BLAKTAIL_RELAY_WSS_CERT_FILE="/certs/${cert}.crt" \
    -e BLAKTAIL_RELAY_WSS_KEY_FILE="/certs/${cert}.key" \
    "$IMAGE" blaktail-relay >/dev/null
}

# lab_coord RELAYS: coordinator advertising the given BLAKTAIL_RELAYS list.
lab_coord() {
  "${D[@]}" run -d --name "${LAB_PREFIX}-coord" --network "$NET" --network-alias coord \
    -v "$CERTS:/certs:ro" --env-file "$LAB_ENV" --tmpfs /data \
    -e BLAKTAIL_REGION=ap-southeast-2 \
    -e BLAKTAIL_BIND=0.0.0.0:8443 \
    -e BLAKTAIL_DATABASE=/data/coord.sqlite3 \
    -e BLAKTAIL_DATABASE_STORAGE=local \
    -e BLAKTAIL_TLS_CERT=/certs/coord.crt \
    -e BLAKTAIL_TLS_KEY=/certs/coord.key \
    -e BLAKTAIL_CONSOLE_URL=https://console.lab.example.au \
    -e BLAKTAIL_RELAYS="$1" \
    "$IMAGE" sh -c 'blaktail-coord migrate && exec blaktail-coord serve' >/dev/null
  local deadline=$((SECONDS + 60))
  until "${D[@]}" exec "${LAB_PREFIX}-coord" curl -fsS --cacert /certs/ca.crt https://coord:8443/readyz >/dev/null 2>&1; do
    (( SECONDS < deadline )) || { echo "FAIL coordinator did not become ready" >&2; "${D[@]}" logs "${LAB_PREFIX}-coord" >&2; return 1; }
    sleep 1
  done
}

lab_agent_start() {
  local agent="$1"
  "${D[@]}" run -d --name "${LAB_PREFIX}-${agent}" --hostname "lab-${agent}" --network "$NET" \
    --privileged --device /dev/net/tun -v "$CERTS:/certs:ro" \
    -e BLAKTAIL_RELAY_WSS_CA_FILE=/certs/ca.crt \
    "$IMAGE" sleep infinity >/dev/null
}

# lab_enrol ORG AGENT: joins with a single-use key passed on stdin, then runs.
lab_enrol() {
  local org="$1" agent="$2" key ip
  key="$("${D[@]}" exec --env-file "$LAB_ENV" "${LAB_PREFIX}-coord" relay-lab mint "$org" office)"
  ip="$(lab_eth0 "$agent")"
  printf '%s' "$key" | "${D[@]}" exec -i "${LAB_PREFIX}-${agent}" sh -ceu "
    blaktaild --coord-ca /certs/ca.crt up --coord https://coord:8443 --name lab-${agent} \
      --endpoint ${ip}:51820 --poll-seconds 5 --exit-after-join >/tmp/join.log 2>&1
  "
  "${D[@]}" exec -d "${LAB_PREFIX}-${agent}" sh -c \
    'blaktaild --coord-ca /certs/ca.crt run --poll-seconds 5 > /tmp/blaktaild.log 2>&1'
}

lab_eth0() {
  "${D[@]}" exec "${LAB_PREFIX}-$1" sh -c "ip -4 -o addr show eth0 | awk '{print \$4}' | cut -d/ -f1"
}

lab_status() {
  "${D[@]}" exec "${LAB_PREFIX}-$1" blaktaild --coord-ca /certs/ca.crt status --json 2>/dev/null
}

lab_field() {
  python3 -c 'import json,sys
try:
    v = json.load(sys.stdin).get(sys.argv[1])
except Exception:
    v = None
print("" if v is None else v)' "$1"
}

lab_overlay_ip() { lab_status "$1" | lab_field address | cut -d/ -f1; }

lab_ping() {
  "${D[@]}" exec "${LAB_PREFIX}-$1" ping -c 1 -W 2 "$2" >/dev/null 2>&1
}

lab_relay_metric() {
  local relay="$1" name="$2"
  "${D[@]}" exec "${LAB_PREFIX}-${relay}" curl -fsS http://127.0.0.1:9702/metrics 2>/dev/null \
    | awk -v n="$name" '$1 == n { print $2 }'
}

lab_bootstrap() {
  "${D[@]}" exec --env-file "$LAB_ENV" "${LAB_PREFIX}-coord" relay-lab bootstrap
}
