#!/usr/bin/env bash
# Upgrade drill (draft 23, docs/upgrades.md): a coordinator database created
# by the round-1 release (main at cab5fe4, schema 28) is upgraded in place to
# this tree's coordinator (schema 40), on SQLite and on PostgreSQL 16.
#
# For each backend:
#   1. old coordinator + two old (cab5fe4) Linux agents on kernel WireGuard;
#      seed a policy with groups, tag owners, hosts, rules and SSH rules, a
#      friendly name, an approved subnet route, reusable and revoked join
#      keys, an API client and an open change draft; snapshot via the API
#   2. stop the old coordinator, run the new `blaktail-coord migrate` on the
#      same database, start the new coordinator
#   3. every field of the old snapshot reads back unchanged (liveness fields
#      excepted); the old agents still reach each other over the overlay, and
#      the approved route is still distributed
#   4. the agents are upgraded to this tree's blaktaild (`run`, persisted
#      enrolment) and still reach each other
#
# Needs: images built from cab5fe4 and from this tree (built below).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
CTX="${DOCKER_CONTEXT:-m3-max}"
D=(docker --context "$CTX")
P=labs-upgrade
OLD_REV="${OLD_REV:-cab5fe4}"
OLD_IMG="$P-old:$OLD_REV"
NEW_IMG="$P-new:latest"
COORD_URL=https://$P-coord:8443
BACKENDS="${BACKENDS:-sqlite postgres}"
export BLAKTAIL_AUTH_HMAC_SECRET="$(openssl rand -hex 32)"
export BLAKTAIL_RELAY_AUTH_SECRET="$(openssl rand -hex 32)"
PGPASS="$(openssl rand -hex 16)"
WORK="$(mktemp -d)"

cleanup() {
  "${D[@]}" rm -f "$P-coord" "$P-a" "$P-b" "$P-pg" "$P-driver" >/dev/null 2>&1 || true
  "${D[@]}" network rm "$P-net" >/dev/null 2>&1 || true
  "${D[@]}" volume rm "$P-certs" "$P-data" >/dev/null 2>&1 || true
}
trap '[[ -n "${KEEP:-}" ]] || cleanup; rm -rf "$WORK"' EXIT
fail() { echo "FAIL $*" >&2; exit 1; }

echo "== build $OLD_IMG (git archive $OLD_REV) and $NEW_IMG on $CTX"
mkdir -p "$WORK/old"
git archive "$OLD_REV" | tar -x -C "$WORK/old"
sed 's/id=labs-target/id=labs-upgrade-old-target/' deploy/homelab/labs.Dockerfile \
  > "$WORK/old/deploy/homelab/labs.Dockerfile"
tar -czf - -C "$WORK/old" . | "${D[@]}" build -q -f deploy/homelab/labs.Dockerfile -t "$OLD_IMG" - >/dev/null
git ls-files -co --exclude-standard -z | tar --null -T - -czf - \
  | "${D[@]}" build -q -f deploy/homelab/labs.Dockerfile -t "$NEW_IMG" - >/dev/null

coord_env() { # backend
  echo -e "-e BLAKTAIL_AUTH_HMAC_SECRET -e BLAKTAIL_RELAY_AUTH_SECRET -e BLAKTAIL_REGION=ap-southeast-2"
  echo -e "-e BLAKTAIL_BIND=0.0.0.0:8443 -e BLAKTAIL_TLS_CERT=/certs/coord.crt -e BLAKTAIL_TLS_KEY=/certs/coord.key"
  echo -e "-e BLAKTAIL_CONSOLE_URL=https://console.upgradelab.example"
  if [[ "$1" == postgres ]]; then
    echo -e "-e BLAKTAIL_DATABASE_BACKEND=postgres -e BLAKTAIL_DATABASE_STORAGE=network -e BLAKTAIL_DATABASE_URL"
  else
    echo -e "-e BLAKTAIL_DATABASE=/data/coord.sqlite3 -e BLAKTAIL_DATABASE_STORAGE=local"
  fi
}
start_coord() { # image backend
  # shellcheck disable=SC2046
  "${D[@]}" run -d --name "$P-coord" --network "$P-net" -v "$P-certs:/certs" -v "$P-data:/data" \
    $(coord_env "$2") "$1" >/dev/null
  "${D[@]}" exec -d "$P-coord" sh -c '(blaktail-coord migrate && blaktail-coord serve) >/var/log/coord.log 2>&1'
  for i in $(seq 1 91); do
    (( i <= 90 )) || { "${D[@]}" exec "$P-coord" tail -20 /var/log/coord.log; fail "coordinator not ready"; }
    "${D[@]}" exec "$P-coord" python3 -c "import ssl,urllib.request; urllib.request.urlopen('$COORD_URL/readyz', context=ssl.create_default_context(cafile='/certs/ca.crt'))" >/dev/null 2>&1 && break
    sleep 1
  done
}
lab() { "${D[@]}" exec -e BLAKTAIL_AUTH_HMAC_SECRET "$P-driver" upgrade-lab "$@"; }
agent_ip() { "${D[@]}" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$P-$1"; }
overlay() {
  "${D[@]}" exec "$P-$1" blaktaild status --json \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["address"].split("/")[0])'
}
reach() { # from to_ip ; ping plus TCP 8080 (allowed by policy)
  "${D[@]}" exec "$P-$1" ping -c 1 -W 2 "$2" >/dev/null 2>&1 \
    && "${D[@]}" exec "$P-$1" sh -c "printf x | nc -w 2 -q 1 $2 8080" >/dev/null 2>&1
}
wait_reach() { # from to_ip label
  local started=$SECONDS
  until reach "$1" "$2"; do
    (( SECONDS - started < 120 )) || { "${D[@]}" exec "$P-$1" tail -20 /var/log/agent.log; fail "$3: $1 cannot reach $2"; }
    sleep 2
  done
  echo "ok $3: $1 -> $2 ping + tcp/8080 after $((SECONDS - started))s"
}
route_distributed() { # a's WireGuard peer for b carries the approved 10.77.0.0/24
  "${D[@]}" exec "$P-a" wg show blaktail0 allowed-ips | grep -q '10\.77\.0\.0/24'
}
schema_version() { # backend label
  local v
  if [[ "$1" == postgres ]]; then
    v="$("${D[@]}" exec "$P-pg" psql -U coord -d blaktail -tAc 'SELECT MAX(version) FROM coordinator_schema_migrations')"
  else
    v="$("${D[@]}" exec "$P-coord" python3 -c 'import sqlite3; print(sqlite3.connect("/data/coord.sqlite3").execute("PRAGMA user_version").fetchone()[0])')"
  fi
  echo "schema $2 upgrade: $v"
}
pin_ports() { # the advertised endpoint is :51820; the lab agents pick a random port
  for name in a b; do
    for _ in $(seq 1 30); do
      "${D[@]}" exec "$P-$name" wg set blaktail0 listen-port 51820 2>/dev/null && break
      sleep 1
    done
  done
}
version_of() { "${D[@]}" exec "$P-$1" sh -c 'echo "$(blaktaild --version) sha256:$(sha256sum /usr/local/bin/blaktaild | cut -c1-12)"'; }

drill() { # backend
  local backend="$1" org t0
  org="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  echo
  echo "################ backend: $backend"
  cleanup
  "${D[@]}" network create "$P-net" >/dev/null
  "${D[@]}" volume create "$P-certs" >/dev/null
  "${D[@]}" volume create "$P-data" >/dev/null
  export BLAKTAIL_DATABASE_URL=""
  if [[ "$backend" == postgres ]]; then
    "${D[@]}" run -d --name "$P-pg" --network "$P-net" -e POSTGRES_USER=coord \
      -e POSTGRES_PASSWORD="$PGPASS" -e POSTGRES_DB=blaktail postgres:16 >/dev/null
    for _ in $(seq 1 60); do
      "${D[@]}" exec "$P-pg" pg_isready -U coord -d blaktail >/dev/null 2>&1 && break
      sleep 1
    done
    export BLAKTAIL_DATABASE_URL="postgres://coord:$PGPASS@$P-pg:5432/blaktail"
  fi
  "${D[@]}" run -d --name "$P-driver" --network "$P-net" -v "$P-certs:/certs" "$NEW_IMG" >/dev/null
  "${D[@]}" cp deploy/homelab/upgrade-lab.py "$P-driver:/usr/local/bin/upgrade-lab"
  "${D[@]}" exec "$P-driver" sh -c '
    set -e; cd /certs
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
      -subj "/CN=labs-upgrade CA" -keyout ca.key -out ca.crt 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -subj "/CN=labs-upgrade-coord" -keyout coord.key -out coord.csr 2>/dev/null
    printf "subjectAltName=DNS:labs-upgrade-coord\n" > san.ext
    openssl x509 -req -in coord.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
      -days 1 -extfile san.ext -out coord.crt 2>/dev/null
    chmod 644 coord.key ca.crt coord.crt; rm -f ca.key'

  echo "== round-1 coordinator ($OLD_REV) on $backend"
  start_coord "$OLD_IMG" "$backend"
  lab bootstrap "$org"
  for name in a b; do
    "${D[@]}" run -d --name "$P-$name" --hostname "upgrade-$name" --network "$P-net" --privileged \
      -v "$P-certs:/certs:ro" "$OLD_IMG" >/dev/null
  done
  local tag routes
  for name in a b; do
    tag=office; routes=""
    [[ "$name" == b ]] && { tag=store; routes="--advertise-routes 10.77.0.0/24"; }
    BLAKTAIL_JOIN_KEY="$(lab join-key "$org" "$tag")" "${D[@]}" exec -d -e BLAKTAIL_JOIN_KEY "$P-$name" sh -c \
      "blaktaild --coord-ca /certs/ca.crt up --coord $COORD_URL --name upgrade-$name --endpoint $(agent_ip "$name"):51820 $routes >/var/log/agent.log 2>&1"
  done
  pin_ports
  local ip_a="" ip_b=""
  for _ in $(seq 1 60); do
    ip_a="$(overlay a 2>/dev/null || true)"; ip_b="$(overlay b 2>/dev/null || true)"
    [[ -n "$ip_a" && -n "$ip_b" ]] && break
    sleep 2
  done
  "${D[@]}" exec -d "$P-b" sh -c 'nc -lk -p 8080 >/dev/null'
  wait_reach a "$ip_b" "baseline on $OLD_REV"
  lab seed "$org"
  local started=$SECONDS
  until route_distributed; do
    (( SECONDS - started < 90 )) || fail "approved route never reached a on $OLD_REV"
    sleep 2
  done
  echo "ok approved 10.77.0.0/24 distributed to a before upgrade"
  lab snapshot "$org" > "$WORK/before-$backend.json"
  schema_version "$backend" before
  echo "agents: $(version_of a) / $(version_of b)"

  echo "== upgrade: stop old coordinator, migrate + serve this tree on the same $backend database"
  t0=$SECONDS
  "${D[@]}" rm -f "$P-coord" >/dev/null
  start_coord "$NEW_IMG" "$backend"
  echo "ok downtime (stop -> /readyz) $((SECONDS - t0))s"
  "${D[@]}" exec "$P-coord" grep -E 'migration|schema_version' /var/log/coord.log | tail -2 || true
  schema_version "$backend" after
  lab snapshot "$org" > "$WORK/after-$backend.json"
  "${D[@]}" cp "$WORK/before-$backend.json" "$P-driver:/tmp/before.json"
  "${D[@]}" cp "$WORK/after-$backend.json" "$P-driver:/tmp/after.json"
  lab compare /tmp/before.json /tmp/after.json || fail "state changed across the upgrade on $backend"
  wait_reach a "$ip_b" "old agents after upgrade ($backend)"
  route_distributed || fail "approved route lost after upgrade"
  echo "ok approved route still distributed"

  echo "== agents upgraded to this tree's blaktaild (persisted enrolment, blaktaild run)"
  local cid
  cid="$("${D[@]}" create "$NEW_IMG")"
  "${D[@]}" cp "$cid:/usr/local/bin/blaktaild" "$WORK/blaktaild"
  "${D[@]}" rm "$cid" >/dev/null
  for name in a b; do
    "${D[@]}" exec "$P-$name" pkill -x blaktaild || true
    sleep 1
    "${D[@]}" cp "$WORK/blaktaild" "$P-$name:/usr/local/bin/blaktaild"
    "${D[@]}" exec -d "$P-$name" sh -c \
      "blaktaild --coord-ca /certs/ca.crt run >>/var/log/agent.log 2>&1"
  done
  sleep 3
  pin_ports
  echo "agents: $(version_of a) / $(version_of b)"
  wait_reach a "$ip_b" "new agents after upgrade ($backend)"
  "${D[@]}" exec "$P-b" ping -c 2 -W 2 "$ip_a" >/dev/null || fail "reverse ping b -> a"
  echo "ok reverse ping b -> a"
  lab snapshot "$org" > "$WORK/final-$backend.json"
  "${D[@]}" cp "$WORK/final-$backend.json" "$P-driver:/tmp/final.json"
  echo "== route approval changes reach clients without any other change (fixed after round 1)"
  lab approve "$org" >/dev/null
  started=$SECONDS
  while route_distributed; do
    (( SECONDS - started < 60 )) || fail "withdrawn route still on a after 60s"
    sleep 1
  done
  echo "ok withdrawal reached a in $((SECONDS - started))s"
  lab approve "$org" 10.77.0.0/24 >/dev/null
  started=$SECONDS
  until route_distributed; do
    (( SECONDS - started < 60 )) || fail "re-approved route not on a after 60s"
    sleep 1
  done
  echo "ok re-approval reached a in $((SECONDS - started))s"

  # The upgraded agents report more capabilities; nothing else may move.
  lab compare /tmp/before.json /tmp/final.json capabilities || fail "state changed after agent upgrade on $backend"
  python3 -c 'import json,sys; [print("capabilities", n["name"], n["capabilities"]) for n in json.load(open(sys.argv[1]))["nodes"]]' \
    "$WORK/final-$backend.json"
  echo "PASS $backend"
}

for backend in $BACKENDS; do drill "$backend"; done
echo
echo "upgrade lab passed: $BACKENDS"
