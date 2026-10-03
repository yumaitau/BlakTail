#!/usr/bin/env bash
# Live proof for email notification channels: a TLS coordinator sends alerts
# through Mailpit acting as the operator's SMTP relay, with STARTTLS required,
# SMTP AUTH and a private CA. Run with DOCKER_CONTEXT pointing at a lab Docker
# host. Everything this starts is named notify-lab-* and removed on exit.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
P=notify-lab
RUST_IMAGE="${NOTIFY_LAB_RUST_IMAGE:-rust:1-bookworm}"
MAILPIT_IMAGE="${NOTIFY_LAB_MAILPIT_IMAGE:-axllent/mailpit:v1.31.0}"
RUN_IMAGE=debian:bookworm-slim
WORK="$(mktemp -d)"

cleanup() {
  docker rm -f "$P-coord" "$P-mailpit" "$P-driver" >/dev/null 2>&1 || true
  docker network rm "$P-net" >/dev/null 2>&1 || true
  docker volume rm -f "$P-bin" "$P-lab" >/dev/null 2>&1 || true
  if [[ -z "${NOTIFY_LAB_KEEP_CACHE:-}" ]]; then
    docker volume rm -f "$P-cargo" "$P-target" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

docker network create "$P-net" >/dev/null
for volume in bin lab cargo target; do docker volume create "$P-$volume" >/dev/null; done

echo "== build blaktail-coord (release, Linux)"
(cd "$ROOT" && git ls-files -z --cached --others --exclude-standard -- Cargo.toml Cargo.lock 'blaktail-*' blaktaild \
  | COPYFILE_DISABLE=1 tar --no-xattrs --null -T - -czf "$WORK/src.tgz")
docker run --rm -i -v "$P-bin:/out" -v "$P-cargo:/usr/local/cargo/registry" -v "$P-target:/target" "$RUST_IMAGE" \
  bash -ceu 'mkdir /src && cd /src && tar xz && CARGO_TARGET_DIR=/target cargo build --quiet --release -p blaktail-coord && cp /target/release/blaktail-coord /out/' \
  < "$WORK/src.tgz"

echo "== lab CA, coordinator and relay certificates, secrets"
docker run -d --name "$P-driver" --network "$P-net" -v "$P-lab:/lab" "$RUST_IMAGE" sleep infinity >/dev/null
docker exec "$P-driver" bash -ceu '
  apt-get -qq update >/dev/null && apt-get -qq install -y jq >/dev/null
  cd /lab && umask 077
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.crt -days 1 -subj /CN=notify-lab-ca 2>/dev/null
  for host in coord mailpit; do
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout $host.key -out $host.csr -subj /CN=notify-lab-$host 2>/dev/null
    printf "subjectAltName=DNS:notify-lab-$host\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n" > ext
    openssl x509 -req -in $host.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 -extfile ext -out $host.crt 2>/dev/null
  done
  openssl rand -hex 32 | tr -d "\n" > hmac
  openssl rand -hex 32 | tr -d "\n" > relay
  openssl rand -hex 24 | tr -d "\n" > smtp-password
  chmod 644 ca.crt coord.crt mailpit.crt mailpit.key smtp-password && chmod 600 ca.key coord.key hmac relay
'
docker cp "$ROOT/deploy/homelab/notifications-driver.sh" "$P-driver:/driver.sh"
SMTP_PASSWORD="$(docker exec "$P-driver" cat /lab/smtp-password)"

echo "== start Mailpit as the SMTP relay (STARTTLS required, AUTH required)"
docker run -d --name "$P-mailpit" --network "$P-net" -v "$P-lab:/lab:ro" \
  -e MP_SMTP_TLS_CERT=/lab/mailpit.crt -e MP_SMTP_TLS_KEY=/lab/mailpit.key \
  -e MP_SMTP_REQUIRE_STARTTLS=true -e "MP_SMTP_AUTH=alerts:$SMTP_PASSWORD" \
  "$MAILPIT_IMAGE" >/dev/null

COORD_ENV=(
  -e BLAKTAIL_REGION=ap-southeast-2 -e BLAKTAIL_BIND=0.0.0.0:8443
  -e BLAKTAIL_DATABASE=/lab/coord.sqlite3 -e BLAKTAIL_DATABASE_STORAGE=local
  -e BLAKTAIL_TLS_CERT=/lab/coord.crt -e BLAKTAIL_TLS_KEY=/lab/coord.key
  -e BLAKTAIL_AUTH_HMAC_SECRET_FILE=/lab/hmac -e BLAKTAIL_RELAY_AUTH_SECRET_FILE=/lab/relay
  -e BLAKTAIL_CONSOLE_URL=https://console.notify-lab.test
  -e BLAKTAIL_SMTP_HOST=notify-lab-mailpit -e BLAKTAIL_SMTP_PORT=1025 -e BLAKTAIL_SMTP_TLS=starttls
  -e BLAKTAIL_SMTP_USERNAME=alerts -e BLAKTAIL_SMTP_PASSWORD_FILE=/lab/smtp-password
  -e BLAKTAIL_SMTP_CA_FILE=/lab/ca.crt
  -e "BLAKTAIL_SMTP_FROM=BlakTail Alerts <alerts@notify-lab.test>"
)
echo "== migrate and start the coordinator"
docker run --rm -v "$P-bin:/opt/bt:ro" -v "$P-lab:/lab" "${COORD_ENV[@]}" "$RUN_IMAGE" /opt/bt/blaktail-coord migrate >/dev/null
docker run -d --name "$P-coord" --network "$P-net" -v "$P-bin:/opt/bt:ro" -v "$P-lab:/lab" "${COORD_ENV[@]}" "$RUN_IMAGE" /opt/bt/blaktail-coord serve >/dev/null
for _ in $(seq 1 30); do
  docker exec "$P-driver" curl -fsS --cacert /lab/ca.crt https://notify-lab-coord:8443/readyz >/dev/null 2>&1 && break
  sleep 1
done

echo "== channels, test send and a real alert"
docker exec "$P-driver" bash /driver.sh

echo "== secret checks"
for file in alert.eml test.eml; do
  for secret in "$SMTP_PASSWORD" "$(docker exec "$P-driver" cat /lab/hmac)" "$(docker exec "$P-driver" cat /lab/node-token)"; do
    if docker exec "$P-driver" grep -qF "$secret" "/lab/$file"; then echo "FAIL a secret reached $file" >&2; exit 1; fi
  done
done
echo "ok emails hold no SMTP password, HMAC secret or node token"
logs="$(docker logs "$P-coord" 2>&1)"
if grep -qF "$SMTP_PASSWORD" <<<"$logs"; then echo "FAIL SMTP password in coordinator log" >&2; exit 1; fi
echo "ok coordinator log ($(wc -l <<<"$logs") lines) holds no SMTP password"
if docker logs "$P-mailpit" 2>&1 | grep -qi "starttls\|tls"; then
  echo "ok Mailpit log mentions TLS: $(docker logs "$P-mailpit" 2>&1 | grep -i tls | head -1)"
fi
