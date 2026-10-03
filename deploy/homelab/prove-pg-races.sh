#!/usr/bin/env bash
# PostgreSQL write races across two coordinator replicas (drafts 03 and 07,
# docs/upgrades.md). Two coordinators built from this tree share one
# PostgreSQL 16 database; a driver releases concurrent writers at once,
# alternating replicas, and checks after every round that exactly one write
# won and that the stored policy is the winner's (no lost update):
#
#   1. policy PUT with the same If-Match etag             -> one 204, rest 412
#   2. the same change draft version published at once    -> one 200
#   3. rival drafts on the same base published at once    -> one 200, rest 409/412
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
CTX="${DOCKER_CONTEXT:-m3-max}"
D=(docker --context "$CTX")
P=labs-upgrade-races
IMG=labs-upgrade-new:latest
ROUNDS="${ROUNDS:-20}"
WRITERS="${WRITERS:-4}"
ORG="$(python3 -c 'import uuid; print(uuid.uuid4())')"
export BLAKTAIL_AUTH_HMAC_SECRET="$(openssl rand -hex 32)"
export BLAKTAIL_RELAY_AUTH_SECRET="$(openssl rand -hex 32)"
PGPASS="$(openssl rand -hex 16)"
export BLAKTAIL_DATABASE_URL="postgres://coord:$PGPASS@$P-pg:5432/blaktail"

cleanup() {
  "${D[@]}" rm -f "$P-coord1" "$P-coord2" "$P-pg" "$P-driver" >/dev/null 2>&1 || true
  "${D[@]}" network rm "$P-net" >/dev/null 2>&1 || true
  "${D[@]}" volume rm "$P-certs" >/dev/null 2>&1 || true
}
trap cleanup EXIT
fail() { echo "FAIL $*" >&2; exit 1; }

echo "== build $IMG on $CTX"
git ls-files -co --exclude-standard -z | tar --null -T - -czf - \
  | "${D[@]}" build -q -f deploy/homelab/labs.Dockerfile -t "$IMG" - >/dev/null

cleanup
"${D[@]}" network create "$P-net" >/dev/null
"${D[@]}" volume create "$P-certs" >/dev/null
"${D[@]}" run -d --name "$P-pg" --network "$P-net" -e POSTGRES_USER=coord \
  -e POSTGRES_PASSWORD="$PGPASS" -e POSTGRES_DB=blaktail postgres:16 >/dev/null
for _ in $(seq 1 60); do
  "${D[@]}" exec "$P-pg" pg_isready -U coord -d blaktail >/dev/null 2>&1 && break
  sleep 1
done
"${D[@]}" run -d --name "$P-driver" --network "$P-net" -v "$P-certs:/certs" "$IMG" >/dev/null
"${D[@]}" cp deploy/homelab/pg-races-lab.py "$P-driver:/usr/local/bin/pg-races-lab"
"${D[@]}" exec "$P-driver" sh -c '
  set -e; cd /certs
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj "/CN=labs-upgrade-races CA" -keyout ca.key -out ca.crt 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=labs-upgrade-races-coord" -keyout coord.key -out coord.csr 2>/dev/null
  printf "subjectAltName=DNS:labs-upgrade-races-coord1,DNS:labs-upgrade-races-coord2\n" > san.ext
  openssl x509 -req -in coord.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 1 -extfile san.ext -out coord.crt 2>/dev/null
  chmod 644 coord.key ca.crt coord.crt; rm -f ca.key'

echo "== two coordinator replicas on one PostgreSQL"
for n in 1 2; do
  "${D[@]}" run -d --name "$P-coord$n" --network "$P-net" -v "$P-certs:/certs" \
    -e BLAKTAIL_AUTH_HMAC_SECRET -e BLAKTAIL_RELAY_AUTH_SECRET -e BLAKTAIL_REGION=ap-southeast-2 \
    -e BLAKTAIL_BIND=0.0.0.0:8443 -e BLAKTAIL_TLS_CERT=/certs/coord.crt -e BLAKTAIL_TLS_KEY=/certs/coord.key \
    -e BLAKTAIL_CONSOLE_URL=https://console.raceslab.example \
    -e BLAKTAIL_DATABASE_BACKEND=postgres -e BLAKTAIL_DATABASE_STORAGE=network -e BLAKTAIL_DATABASE_URL \
    "$IMG" >/dev/null
  # Migrate from the first replica only, then serve from both.
  if [[ $n == 1 ]]; then
    "${D[@]}" exec "$P-coord1" blaktail-coord migrate >/dev/null 2>&1 || fail "migrate"
  fi
  "${D[@]}" exec -d "$P-coord$n" sh -c 'blaktail-coord serve >/var/log/coord.log 2>&1'
done
for n in 1 2; do
  for i in $(seq 1 61); do
    (( i <= 60 )) || { "${D[@]}" exec "$P-coord$n" tail -10 /var/log/coord.log; fail "replica $n not ready"; }
    "${D[@]}" exec "$P-driver" python3 -c "import ssl,urllib.request; urllib.request.urlopen('https://$P-coord$n:8443/readyz', context=ssl.create_default_context(cafile='/certs/ca.crt'))" >/dev/null 2>&1 && break
    sleep 1
  done
done
lab() { "${D[@]}" exec -e BLAKTAIL_AUTH_HMAC_SECRET "$P-driver" pg-races-lab "$@"; }
lab bootstrap "$ORG"

for race in policy-put publish-same publish-rival; do
  started=$SECONDS
  lab "$race" "$ORG" "$ROUNDS" "$WRITERS" || fail "$race"
  echo "   ($((SECONDS - started))s)"
done
"${D[@]}" exec "$P-pg" psql -U coord -d blaktail -tAc \
  "SELECT 'audit acl.updated rows: ' || COUNT(*) FROM audit_events WHERE org_id='$ORG' AND action='acl.updated'" || true
echo "postgres race lab passed: $ROUNDS rounds x $WRITERS writers per race"
