#!/usr/bin/env bash
# Live proof of browser SSH and remote jobs (draft 13, ADR 0006).
#
# Builds the coordinator and gateway images from tracked sources, starts a
# coordinator, a gateway node (blaktaild + blaktail-gateway) and a Linux
# target (blaktaild + sshd with the opt-in drop-in and SSH user CA), then:
#   - opens a browser-style WebSocket session through the gateway and runs `id`;
#   - shows a reused ticket, a member and an unlisted OS user are refused;
#   - ends live sessions by revoke and by suspending the device;
#   - swaps sshd's host key behind the agent's back: the gateway refuses it;
#   - lets the agent report the new key: new sessions are blocked;
#   - runs approved jobs as an unprivileged user with timeout and cancel;
#   - opens an RDP desktop on xrdp through guacd (set LAB_RDP=0 to skip).
#
# Usage: DOCKER_CONTEXT=m3-max deploy/homelab/prove-remote-access.sh
# Everything it creates is named ${LAB_PREFIX:-rax}-* and removed on exit.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
P="${LAB_PREFIX:-rax}"
NET="${P}-net"
WORK="$(mktemp -d)"
HMAC="$(openssl rand -hex 32)"
RELAY_SECRET="$(openssl rand -hex 32)"
DIAG="$(openssl rand -hex 16)"
LISTEN_PORT=51820
DROPIN=/var/lib/blaktail/sshd_policy.conf
USER_CA=/var/lib/blaktail/ssh_user_ca.pub
REPORTED_KEY=/var/lib/blaktail/reported_host_key.pub

cleanup() {
  if [[ -n "${KEEP_LAB:-}" ]]; then
    echo "KEEP_LAB set: leaving ${P}-* running" >&2
    return
  fi
  docker rm -f -v "${P}-guacd" "${P}-coord" "${P}-gw" "${P}-target" "${P}-driver" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  if [[ -z "${KEEP_IMAGES:-}" ]]; then
    docker rmi -f "${P}-coord:lab" "${P}-gateway:lab" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
on_exit() {
  local status=$?
  if (( status != 0 )); then
    echo "== target sshd log (last 30 lines)" >&2
    docker exec "${P}-target" tail -n 30 /var/log/sshd.log >&2 2>/dev/null || true
    echo "== gateway log (last 20 lines)" >&2
    docker logs --tail 20 "${P}-gw" >&2 2>/dev/null || true
  fi
  cleanup
}
trap on_exit EXIT

step() { printf '\n== %s\n' "$*"; }

step "build images from tracked sources"
(cd "$ROOT" && git ls-files -z | tar --null -T - -czf "$WORK/context.tgz")
docker build -q -t "${P}-coord:lab" -f deploy/docker/coord.Dockerfile - <"$WORK/context.tgz"
docker build -q -t "${P}-gateway:lab" -f deploy/docker/gateway.Dockerfile - <"$WORK/context.tgz"

step "lab certificates"
docker run --rm -i debian:bookworm-slim bash -ceu '
  apt-get update -qq >/dev/null && apt-get install -y -qq openssl >/dev/null
  mkdir /certs && cd /certs
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj "/CN=remote-access lab CA" -keyout ca.key -out ca.crt 2>/dev/null
  for name in coord gateway; do
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -subj "/CN=$name" -keyout $name.key -out $name.csr 2>/dev/null
    printf "subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n" "$name" > $name.ext
    openssl x509 -req -in $name.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 \
      -extfile $name.ext -out $name.crt 2>/dev/null
  done
  chmod 644 *.crt *.key
  tar -cz -C /certs ca.crt coord.crt coord.key gateway.crt gateway.key
' >"$WORK/certs.tgz"
mkdir -p "$WORK/certs"
tar -xzf "$WORK/certs.tgz" -C "$WORK/certs"

step "start coordinator, gateway node, target and driver"
docker network create "$NET" >/dev/null
docker create --name "${P}-coord" --network "$NET" --network-alias coord \
  --tmpfs /data:uid=10001,gid=10001,mode=0700 --tmpfs /tmp \
  -e BLAKTAIL_REGION=ap-southeast-2 -e BLAKTAIL_BIND=0.0.0.0:8443 \
  -e BLAKTAIL_COORD_METRICS_BIND=127.0.0.1:9701 -e BLAKTAIL_COORD_DIAGNOSTICS_TOKEN="$DIAG" \
  -e BLAKTAIL_DATABASE=/data/coord.sqlite3 -e BLAKTAIL_DATABASE_STORAGE=local \
  -e BLAKTAIL_TLS_CERT=/certs/coord.crt -e BLAKTAIL_TLS_KEY=/certs/coord.key \
  -e BLAKTAIL_AUTH_HMAC_SECRET="$HMAC" -e BLAKTAIL_RELAY_AUTH_SECRET="$RELAY_SECRET" \
  -e BLAKTAIL_RELAYS=coord:3478 -e BLAKTAIL_CONSOLE_URL=https://console.invalid \
  --entrypoint sh "${P}-coord:lab" -c 'coord-entrypoint migrate && exec coord-entrypoint serve' >/dev/null
for name in gw target; do
  docker create --name "${P}-${name}" --network "$NET" \
    --network-alias "$([[ $name == gw ]] && echo gateway || echo target)" \
    --privileged --cap-add NET_ADMIN --device /dev/net/tun \
    --security-opt apparmor=unconfined --security-opt seccomp=unconfined \
    --tmpfs /var/lib/blaktail:mode=0700 "${P}-gateway:lab" >/dev/null
done
docker create --name "${P}-driver" --network "$NET" \
  -e LAB_HMAC_SECRET="$HMAC" -e NODE_EXTRA_CA_CERTS=/certs/ca.crt \
  node:22-bookworm-slim sleep infinity >/dev/null
for container in coord gw target driver; do
  docker cp "$WORK/certs" "${P}-${container}:/certs"
done
docker cp "$ROOT/deploy/homelab/remote-access-prove.mjs" "${P}-driver:/prove.mjs"
docker start "${P}-coord" "${P}-gw" "${P}-target" "${P}-driver" >/dev/null

drive() { docker exec "${P}-driver" node /prove.mjs "$@"; }

for _ in $(seq 1 30); do
  if docker exec "${P}-driver" node -e 'fetch("https://coord:8443/readyz").then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))'; then
    break
  fi
  sleep 1
done

step "bootstrap organisation"
boot="$(drive bootstrap)"
org="$(sed -n 's/^org=//p' <<<"$boot")"
gateway_key="$(sed -n 's/^gateway_key=//p' <<<"$boot")"
target_key="$(sed -n 's/^target_key=//p' <<<"$boot")"
echo "org ${org}"

container_ip() {
  docker exec "${P}-$1" sh -c "ip -4 -o addr show eth0 | awk '{print \$4}' | cut -d/ -f1"
}

enrol() {
  local container="$1" name="$2" key="$3" ip
  ip="$(container_ip "$container")"
  printf '%s' "$key" | docker exec -i "${P}-${container}" blaktaild --coord-ca /certs/ca.crt up \
    --coord https://coord:8443 --name "$name" --endpoint "${ip}:${LISTEN_PORT}" \
    --poll-seconds 5 --exit-after-join >/dev/null
  echo "ok ${name} enrolled from ${ip}"
}

step "prepare sshd on the target (opt-in drop-in, no passwords)"
docker exec "${P}-target" sh -ceu '
  apt-get update -qq >/dev/null
  apt-get install -y -qq --no-install-recommends openssh-server procps >/dev/null
  useradd -m -s /bin/bash deploy && usermod -p "*" deploy
  useradd -m -s /usr/sbin/nologin jobrunner
  mkdir -p /run/sshd
  ssh-keygen -A >/dev/null
  printf "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\nLogLevel VERBOSE\n" \
    > /etc/ssh/sshd_config.d/zz-lab.conf
  touch '"$DROPIN"'
  echo "Include '"$DROPIN"'" >> /etc/ssh/sshd_config
  cp /etc/ssh/ssh_host_ed25519_key.pub '"$REPORTED_KEY"'
  sshd -t && /usr/sbin/sshd -E /var/log/sshd.log
'
echo "ok sshd running with host key $(docker exec "${P}-target" ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}')"

step "enrol gateway and target"
enrol gw lab-gateway "$gateway_key"
enrol target lab-target "$target_key"
docker exec -d "${P}-gw" blaktaild --coord-ca /certs/ca.crt run --poll-seconds 5
# The target reports the copy of its host key, so the lab can later swap
# sshd's real key without the agent noticing.
docker exec -d \
  -e BLAKTAIL_SSHD_DROPIN="$DROPIN" -e BLAKTAIL_SSH_USER_CA="$USER_CA" \
  -e BLAKTAIL_SSH_HOST_KEY="$REPORTED_KEY" \
  "${P}-target" blaktaild --coord-ca /certs/ca.crt --allow-remote-jobs \
  --remote-jobs-user jobrunner run --poll-seconds 5
sleep 3
docker exec "${P}-gw" wg set blaktail0 listen-port "$LISTEN_PORT"
docker exec "${P}-target" wg set blaktail0 listen-port "$LISTEN_PORT"
docker exec -d "${P}-gw" blaktail-gateway --coord https://coord:8443 --coord-ca /certs/ca.crt \
  --state-dir /var/lib/blaktail --listen 0.0.0.0:8443 --allowed-origin https://console.invalid \
  --tls-cert /certs/gateway.crt --tls-key /certs/gateway.key --guacd 127.0.0.1:4822

step "policy, gateway and readiness"
drive configure "$org"
drive wait-ready "$org"
docker exec "${P}-target" sh -c "grep -A3 'Match Address' $DROPIN | tail -n +1"

step "browser SSH session"
drive session-id "$org"
drive forbidden "$org"
drive revoke-live "$org"
drive suspend-live "$org"

step "remote jobs"
drive jobs "$org"

if [[ "${LAB_RDP:-1}" != 0 ]]; then
  step "RDP through guacd to xrdp"
  docker exec "${P}-target" sh -ceu '
    apt-get install -y -qq --no-install-recommends xrdp xorgxrdp xterm dbus-x11 >/dev/null
    printf "deploy:lab-rdp-pass\n" | chpasswd
    printf "exec xterm\n" > /home/deploy/.xsession && chown deploy /home/deploy/.xsession
    mkdir -p /run/xrdp && chown xrdp /run/xrdp 2>/dev/null || true
    /usr/sbin/xrdp-sesman && /usr/sbin/xrdp
  '
  # guacd shares the gateway node's network namespace, so it dials over the overlay.
  docker run -d --name "${P}-guacd" --network "container:${P}-gw" guacamole/guacd:1.5.5 >/dev/null
  sleep 3
  drive rdp "$org"
fi

step "host key swapped behind the agent's back"
docker exec "${P}-target" sh -ceu '
  rm -f /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key.pub
  ssh-keygen -q -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key
  kill -HUP "$(cat /run/sshd.pid)"
'
sleep 2
drive expect-mismatch "$org"

step "agent reports the new key"
docker exec "${P}-target" cp /etc/ssh/ssh_host_ed25519_key.pub "$REPORTED_KEY"
drive expect-pending "$org"

step "gateway logs carry no terminal content"
if docker logs "${P}-gw" 2>&1 | grep -q "uid=1000"; then
  echo "FAIL gateway logged terminal output" >&2
  exit 1
fi
echo "ok gateway log has session ids and reasons only"

echo
echo "remote_access_proof passed"
