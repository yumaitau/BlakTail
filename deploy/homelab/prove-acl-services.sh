#!/usr/bin/env bash
# Enrol two Linux agents and prove a port-scoped allow, an adjacent denied
# port, and an unauthorised SSH user. The store agent manages a verified
# sshd drop-in (BLAKTAIL_SSHD_DROPIN); until it proves that drop-in active,
# the coordinator and agent keep TCP 22 closed to user-limited sources.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
export COMPOSE_HTTP_TIMEOUT="${COMPOSE_HTTP_TIMEOUT:-300}"
export DOCKER_CLIENT_TIMEOUT="${DOCKER_CLIENT_TIMEOUT:-300}"
COMPOSE=(docker compose -p blaktail -f compose.yaml -f compose.homelab.yml --profile acl-prove)
WORKDIR="/tmp/blaktail-acl-services-prove"
COORD="https://coord:8443"
LISTEN_PORT=51820
SSH_PASS="prove-ssh"
SSHD_DROPIN="/var/lib/blaktail/sshd_policy.conf"
suffix="$(openssl rand -hex 2)"
office_name="office-svc-${suffix}"
store_name="store-svc-${suffix}"

status_of() {
  "${COMPOSE[@]}" exec -T "$1" blaktaild --coord-ca /certs/ca.crt status
}

wait_for() {
  local label="$1"
  local want="$2"
  local deadline=$((SECONDS + 45))
  while (( SECONDS < deadline )); do
    local text
    text="$(status_of agent-office || true)"
    if [[ "$want" == "present" && "$text" == *"${store_name}"* ]]; then
      echo "ok ${label}"
      return 0
    fi
    if [[ "$want" == "absent" && "$text" != *"${store_name}"* ]]; then
      echo "ok ${label}"
      return 0
    fi
    sleep 3
  done
  echo "FAIL ${label}" >&2
  status_of agent-office >&2 || true
  return 1
}

store_ip() {
  local text
  text="$(status_of agent-store)" || return 1
  awk '$1 == "address:" { sub("/32","",$2); print $2; exit }' <<<"$text"
}

container_ip() {
  "${COMPOSE[@]}" exec -T "$1" sh -c "ip -4 -o addr show eth0 | awk '{print \$4}' | cut -d/ -f1 | head -n1"
}

pin_listen_port() {
  "${COMPOSE[@]}" exec -T "$1" wg set blaktail0 listen-port "$LISTEN_PORT"
}

console_bun() {
  "${COMPOSE[@]}" run --rm \
    -e ACL_PROVE_KEY_DIR=/bootstrap \
    -v "${WORKDIR}:/bootstrap" \
    console bun /bootstrap/acl-prove.mjs "$@"
}

acl() {
  console_bun put-acl "$1"
}

install_tools() {
  echo "== install prove tools"
  "${COMPOSE[@]}" exec -T agent-office sh -ceu '
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends netcat-openbsd openssh-client sshpass >/dev/null
  '
  "${COMPOSE[@]}" exec -T agent-store sh -ceu '
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends netcat-openbsd openssh-server >/dev/null
  '
}

start_listeners() {
  "${COMPOSE[@]}" exec -d agent-store sh -ceu 'while true; do printf allowed | nc -l -p 8080 -q 1 || true; done'
  "${COMPOSE[@]}" exec -d agent-store sh -ceu 'while true; do printf denied | nc -l -p 8081 -q 1 || true; done'
}

wait_connect() {
  local label="$1"
  local port="$2"
  local deadline=$((SECONDS + 45))
  local ip
  while (( SECONDS < deadline )); do
    ip="$(store_ip)"
    if [[ -n "$ip" ]] && "${COMPOSE[@]}" exec -T agent-office nc -w 2 -q 1 "$ip" "$port" >/tmp/blaktail-svc-allow.log 2>&1; then
      echo "ok ${label}"
      return 0
    fi
    sleep 3
  done
  echo "FAIL ${label}" >&2
  cat /tmp/blaktail-svc-allow.log >&2 || true
  status_of agent-office >&2 || true
  status_of agent-store >&2 || true
  "${COMPOSE[@]}" exec -T agent-store iptables -S BLAKTAIL-ACL >&2 || true
  return 1
}

expect_refused() {
  local label="$1"
  local port="$2"
  local ip
  ip="$(store_ip)"
  [[ -n "$ip" ]]
  if "${COMPOSE[@]}" exec -T agent-office nc -w 2 -q 1 "$ip" "$port" >/tmp/blaktail-svc-deny.log 2>&1; then
    echo "FAIL ${label}: connect succeeded" >&2
    cat /tmp/blaktail-svc-deny.log >&2 || true
    return 1
  fi
  echo "ok ${label}"
}

wait_ssh_policy() {
  local deadline=$((SECONDS + 45))
  while (( SECONDS < deadline )); do
    if "${COMPOSE[@]}" exec -T agent-store sh -c "grep -q 'AllowUsers blaktail' ${SSHD_DROPIN}"; then
      echo "ok store ssh policy written and verified"
      return 0
    fi
    sleep 3
  done
  echo "FAIL store ssh policy missing" >&2
  "${COMPOSE[@]}" exec -T agent-store sh -c "cat ${SSHD_DROPIN} /var/lib/blaktail/sshd_blaktail.conf" >&2 || true
  status_of agent-store >&2 || true
  return 1
}

# Users, host keys and auth settings exist before the agent writes and
# verifies its drop-in with sshd -t / sshd -T.
prepare_sshd() {
  "${COMPOSE[@]}" exec -T agent-store sh -ceu '
    useradd -m blaktail 2>/dev/null || true
    useradd -m intruder 2>/dev/null || true
    printf "blaktail:'"$SSH_PASS"'\n" | chpasswd
    printf "intruder:'"$SSH_PASS"'\n" | chpasswd
    mkdir -p /run/sshd /etc/ssh/sshd_config.d
    ssh-keygen -A
    cat > /etc/ssh/sshd_config.d/zz-blaktail.conf <<EOF
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication no
PermitRootLogin no
UsePAM yes
EOF
    # As documented: one Include at the end of sshd_config, file owned by the agent.
    touch /var/lib/blaktail/sshd_policy.conf
    grep -qx "Include /var/lib/blaktail/sshd_policy.conf" /etc/ssh/sshd_config \
      || echo "Include /var/lib/blaktail/sshd_policy.conf" >> /etc/ssh/sshd_config
    sshd -t
  '
}

start_sshd() {
  "${COMPOSE[@]}" exec -T agent-store sh -ceu '
    sshd -t
    if ! pgrep -x sshd >/dev/null; then
      /usr/sbin/sshd
    fi
  '
}

wait_ssh_allowed() {
  local deadline=$((SECONDS + 45))
  while (( SECONDS < deadline )); do
    if ssh_as blaktail >/tmp/blaktail-svc-ssh-allow.log 2>&1; then
      return 0
    fi
    sleep 3
  done
  return 1
}

ssh_as() {
  local user="$1"
  local ip
  ip="$(store_ip)"
  "${COMPOSE[@]}" exec -T agent-office sshpass -p "$SSH_PASS" ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o ConnectTimeout=5 \
    "${user}@${ip}" true
}

sudo rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"
chmod 700 "$WORKDIR"
cp deploy/homelab/acl-prove.mjs "$WORKDIR/acl-prove.mjs"
sudo chown -R 999:999 "$WORKDIR"

echo "== purge leftover prove nodes"
console_bun purge-nodes

echo "== build and start agents"
"${COMPOSE[@]}" rm -sf agent-office agent-store >/dev/null 2>&1 || true
docker volume rm -f blaktail_agent-office-data blaktail_agent-store-data >/dev/null 2>&1 || true
"${COMPOSE[@]}" build agent-office
"${COMPOSE[@]}" up -d --force-recreate agent-office agent-store

echo "== reset ACL to default same-tag only"
acl '{"groups":{},"rules":[]}'

echo "== mint join keys"
console_bun mint
sudo chmod 755 "$WORKDIR"
sudo chmod 644 "$WORKDIR/acl-prove.mjs" "$WORKDIR/office" "$WORKDIR/store"

office_id="$("${COMPOSE[@]}" ps -q agent-office)"
store_id="$("${COMPOSE[@]}" ps -q agent-store)"
docker cp "$WORKDIR/office" "${office_id}:/tmp/office.key"
docker cp "$WORKDIR/store" "${store_id}:/tmp/store.key"
sudo rm -f "$WORKDIR/office" "$WORKDIR/store"

office_ip="$(container_ip agent-office)"
store_ip_lan="$(container_ip agent-store)"
echo "== enrol ${office_name} at ${office_ip}:${LISTEN_PORT}"
"${COMPOSE[@]}" exec -T agent-office sh -ceu '
  chmod 600 /tmp/office.key
  printf "%s" "$(tr -d "\n" < /tmp/office.key)" | blaktaild --coord-ca /certs/ca.crt up \
    --coord "'"$COORD"'" --name "'"$office_name"'" \
    --endpoint "'"${office_ip}:${LISTEN_PORT}"'" --poll-seconds 5 --exit-after-join
  shred -u /tmp/office.key || rm -f /tmp/office.key
'
echo "== enrol ${store_name} at ${store_ip_lan}:${LISTEN_PORT}"
"${COMPOSE[@]}" exec -T agent-store sh -ceu '
  chmod 600 /tmp/store.key
  printf "%s" "$(tr -d "\n" < /tmp/store.key)" | blaktaild --coord-ca /certs/ca.crt up \
    --coord "'"$COORD"'" --name "'"$store_name"'" \
    --endpoint "'"${store_ip_lan}:${LISTEN_PORT}"'" --poll-seconds 5 --exit-after-join
  shred -u /tmp/store.key || rm -f /tmp/store.key
'

install_tools
prepare_sshd
"${COMPOSE[@]}" exec -d agent-office blaktaild --coord-ca /certs/ca.crt run --poll-seconds 5
"${COMPOSE[@]}" exec -d -e "BLAKTAIL_SSHD_DROPIN=${SSHD_DROPIN}" agent-store \
  blaktaild --coord-ca /certs/ca.crt run --poll-seconds 5
for _ in $(seq 1 15); do
  if "${COMPOSE[@]}" exec -T agent-office wg show blaktail0 >/dev/null 2>&1 \
    && "${COMPOSE[@]}" exec -T agent-store wg show blaktail0 >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
pin_listen_port agent-office
pin_listen_port agent-store

identity="$(console_bun identity | grep '^{')"
user_id="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["userId"])' "$identity")"
email="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["email"])' "$identity")"

echo "== allow testers TCP 8080 and SSH user blaktail"
acl "$(python3 -c "import json; print(json.dumps({
  'defaults':'deny',
  'groups': {'testers': ['''$email''', '''$user_id''']},
  'rules': [{
    'action':'allow',
    'src_groups':['testers'],
    'dst_groups':['testers'],
    'dst_ports':['8080'],
    'protocols':['tcp']
  }],
  'ssh': [{
    'action':'allow',
    'src_groups':['testers'],
    'dst_groups':['testers'],
    'users':['blaktail']
  }]
}))")"
wait_for "service policy lists ${store_name}" present
wait_ssh_policy

start_listeners
start_sshd
wait_connect "TCP 8080 allowed under testers service rule" 8080
expect_refused "TCP 8081 denied next to the allowed service" 8081

if ! wait_ssh_allowed; then
  echo "FAIL authorised SSH user blaktail" >&2
  cat /tmp/blaktail-svc-ssh-allow.log >&2 || true
  "${COMPOSE[@]}" exec -T agent-store sh -c "cat ${SSHD_DROPIN}" >&2 || true
  "${COMPOSE[@]}" exec -T agent-store iptables -S BLAKTAIL-ACL >&2 || true
  exit 1
fi
echo "ok SSH user blaktail allowed"

if ssh_as intruder >/tmp/blaktail-svc-ssh-deny.log 2>&1; then
  echo "FAIL unauthorised SSH user intruder succeeded" >&2
  cat /tmp/blaktail-svc-ssh-deny.log >&2 || true
  exit 1
fi
echo "ok SSH user intruder denied"

echo "== reset ACL to default same-tag only"
acl '{"groups":{},"rules":[]}'

echo "acl_service_port_ssh passed"
