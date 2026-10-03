#!/usr/bin/env bash
# Live lab for per-user SSH limits on a real OpenSSH server (draft 07,
# docs/linux-agent.md "SSH user policy"). One coordinator and three Linux
# agents on kernel WireGuard, on one Docker host (default context m3-max):
#
#   store   runs Debian OpenSSH with `Include /var/lib/blaktail/sshd_policy.conf`
#           at the end of sshd_config and BLAKTAIL_SSHD_DROPIN set
#   office  SSH rule: may log in to store as `deploy` only
#   guest   (tag ranger) may reach store on TCP 8080 but has no SSH grant
#
# Both users exist on store and both accept the office and guest keys, so
# every refusal below comes from BlakTail policy, not from missing keys.
#
#   1. office logs in as deploy with key auth
#   2. office as intruder: TCP 22 connects, sshd refuses the user
#   3. guest: TCP 8080 connects, TCP 22 is rejected by BLAKTAIL-ACL
#   4. the agent is restarted (`blaktaild run`): 1-3 still hold
#
# Not proven here: custom SSH ports, systemd reload path (sshd is HUPed via
# /run/sshd.pid), non-Debian OpenSSH builds.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
CTX="${DOCKER_CONTEXT:-m3-max}"
D=(docker --context "$CTX")
P=labs-host-ssh
IMG="${LABS_IMAGE:-labs-base:fc6ec9c}"
COORD_URL=https://labs-host-coord:8443
DROPIN=/var/lib/blaktail/sshd_policy.conf
ORG="$(python3 -c 'import uuid; print(uuid.uuid4())')"
export BLAKTAIL_AUTH_HMAC_SECRET="$(openssl rand -hex 32)"
export BLAKTAIL_RELAY_AUTH_SECRET="$(openssl rand -hex 32)"
T0=$SECONDS

cleanup() {
  "${D[@]}" rm -f labs-host-coord "$P-store" "$P-office" "$P-guest" >/dev/null 2>&1 || true
  "${D[@]}" network rm "$P-net" >/dev/null 2>&1 || true
  "${D[@]}" volume rm "$P-certs" >/dev/null 2>&1 || true
}
finish() {
  cleanup
  [[ "${LABS_BUILD:-0}" != 1 ]] || "${D[@]}" image rm labs-host-image:latest >/dev/null 2>&1 || true
}
trap finish EXIT
fail() { echo "FAIL $*" >&2; exit 1; }
ex() { "${D[@]}" exec "$P-$1" "${@:2}"; }

if [[ "${LABS_BUILD:-0}" == 1 ]]; then
  IMG=labs-host-image:latest
  echo "== build lab image from the working tree on $CTX"
  git ls-files -co --exclude-standard -z | tar --null -T - -czf - \
    | "${D[@]}" build -q -f deploy/homelab/labs.Dockerfile -t "$IMG" - >/dev/null
fi

cleanup
"${D[@]}" network create "$P-net" >/dev/null
"${D[@]}" volume create "$P-certs" >/dev/null

echo "== coordinator (self-signed lab CA, SQLite) from $IMG"
"${D[@]}" run -d --name labs-host-coord --network "$P-net" -v "$P-certs:/certs" \
  -e BLAKTAIL_AUTH_HMAC_SECRET -e BLAKTAIL_RELAY_AUTH_SECRET \
  -e BLAKTAIL_REGION=ap-southeast-2 -e BLAKTAIL_BIND=0.0.0.0:8443 \
  -e BLAKTAIL_DATABASE=/data/coord.sqlite3 -e BLAKTAIL_DATABASE_STORAGE=local \
  -e BLAKTAIL_TLS_CERT=/certs/coord.crt -e BLAKTAIL_TLS_KEY=/certs/coord.key \
  -e BLAKTAIL_CONSOLE_URL=https://console.labs-host.example \
  "$IMG" >/dev/null
"${D[@]}" cp deploy/homelab/host-lab.py labs-host-coord:/usr/local/bin/host-lab
"${D[@]}" exec labs-host-coord sh -c '
  set -e; cd /certs
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj "/CN=labs-host CA" -keyout ca.key -out ca.crt 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=labs-host-coord" -keyout coord.key -out coord.csr 2>/dev/null
  printf "subjectAltName=DNS:labs-host-coord\n" > san.ext
  openssl x509 -req -in coord.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 1 -extfile san.ext -out coord.crt 2>/dev/null
  chmod 644 coord.key ca.crt coord.crt; rm -f ca.key'
"${D[@]}" exec -d labs-host-coord sh -c '(blaktail-coord migrate && blaktail-coord serve) >/var/log/coord.log 2>&1'
for i in $(seq 1 61); do
  (( i <= 60 )) || { "${D[@]}" exec labs-host-coord tail -5 /var/log/coord.log; fail "coordinator not ready"; }
  "${D[@]}" exec labs-host-coord python3 -c "import ssl,urllib.request; urllib.request.urlopen('$COORD_URL/readyz', context=ssl.create_default_context(cafile='/certs/ca.crt'))" >/dev/null 2>&1 && break
  sleep 1
done
lab() { "${D[@]}" exec -e BLAKTAIL_AUTH_HMAC_SECRET labs-host-coord host-lab "$@"; }
lab bootstrap "$ORG" ssh

for name in store office guest; do
  "${D[@]}" run -d --name "$P-$name" --hostname "ssh-$name" --network "$P-net" --privileged \
    -v "$P-certs:/certs:ro" "$IMG" >/dev/null
done
agent_ip() { "${D[@]}" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$P-$1"; }

echo "== OpenSSH on store: users deploy and intruder, key auth only, Include at the end"
for name in office guest; do
  ex "$name" sh -c 'install -d -m 0700 /root/.ssh && ssh-keygen -q -t ed25519 -N "" -f /root/.ssh/id_ed25519'
done
keys="$(ex office cat /root/.ssh/id_ed25519.pub; ex guest cat /root/.ssh/id_ed25519.pub)"
ex store sh -ceu '
  for u in deploy intruder; do
    useradd -m -s /bin/sh "$u"
    install -d -m 0700 -o "$u" -g "$u" "/home/$u/.ssh"
    printf "%s\n" "$1" > "/home/$u/.ssh/authorized_keys"
    chown "$u:$u" "/home/$u/.ssh/authorized_keys"; chmod 0600 "/home/$u/.ssh/authorized_keys"
  done
  ssh-keygen -A >/dev/null
  printf "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n" \
    > /etc/ssh/sshd_config.d/10-lab.conf
  touch '"$DROPIN"'
  echo "Include '"$DROPIN"'" >> /etc/ssh/sshd_config
  sshd -t && /usr/sbin/sshd -E /var/log/sshd.log' _ "$keys"

start_agent() { # name tag [env...]
  local name="$1" tag="$2"; shift 2
  BLAKTAIL_JOIN_KEY="$(lab join-key "$ORG" "$tag")" "${D[@]}" exec -d -e BLAKTAIL_JOIN_KEY "$@" "$P-$name" sh -c \
    "blaktaild --coord-ca /certs/ca.crt up --coord $COORD_URL --name ssh-$name --endpoint $(agent_ip "$name"):51820 --poll-seconds 5 >/var/log/agent.log 2>&1"
}
pin_port() {
  for _ in $(seq 1 30); do
    ex "$1" wg set blaktail0 listen-port 51820 2>/dev/null && return 0
    sleep 1
  done
  fail "agent $1 never created blaktail0"
}
overlay() { ex "$1" blaktaild status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["address"].split("/")[0])'; }

echo "== enrol store (BLAKTAIL_SSHD_DROPIN set), office and guest"
start_agent store store -e "BLAKTAIL_SSHD_DROPIN=$DROPIN"
start_agent office office
start_agent guest ranger
for n in store office guest; do pin_port "$n"; done
for _ in $(seq 1 60); do
  ip_s="$(overlay store 2>/dev/null || true)"; ip_o="$(overlay office 2>/dev/null || true)"; ip_g="$(overlay guest 2>/dev/null || true)"
  [[ -n "$ip_s" && -n "$ip_o" && -n "$ip_g" ]] \
    && ex office ping -c 1 -W 2 "$ip_s" >/dev/null 2>&1 && ex guest ping -c 1 -W 2 "$ip_s" >/dev/null 2>&1 && break
  sleep 2
done
ex office ping -c 1 -W 2 "$ip_s" >/dev/null 2>&1 || fail "office cannot ping store"
ex guest ping -c 1 -W 2 "$ip_s" >/dev/null 2>&1 || fail "guest cannot ping store"
"${D[@]}" exec -d "$P-store" sh -c 'nc -lk -p 8080 >/dev/null'
echo "ok overlay up after $((SECONDS - T0))s: store $ip_s, office $ip_o, guest $ip_g"

ssh_as() { # from user
  ex "$1" ssh -i /root/.ssh/id_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR "$2@$ip_s" id -un
}
tcp() { ex "$1" sh -c "nc -z -w 3 $ip_s $2" >/dev/null 2>&1; }

wait_limits() {
  local started=$SECONDS
  until ex store grep -q "AllowUsers deploy" "$DROPIN" 2>/dev/null && [[ "$(ssh_as office deploy 2>/dev/null)" == deploy ]]; do
    (( SECONDS - started < 90 )) || {
      ex store sh -c "cat $DROPIN; iptables -S BLAKTAIL-ACL; tail -20 /var/log/agent.log" >&2 || true
      fail "deploy login never allowed ($1)"
    }
    sleep 2
  done
  echo "ok $1: drop-in verified and deploy login allowed after $((SECONDS - started))s"
}

check_limits() { # label
  local out
  out="$(ssh_as office deploy 2>&1)" || fail "$1: office as deploy: $out"
  [[ "$out" == deploy ]] || fail "$1: unexpected login output $out"
  echo "ok $1: office -> deploy@store logged in (id -un = $out)"
  tcp office 22 || fail "$1: office TCP 22 should connect"
  if out="$(ssh_as office intruder 2>&1)"; then fail "$1: office as intruder logged in"; fi
  [[ "$out" == *"Permission denied"* ]] || fail "$1: intruder refused for the wrong reason: $out"
  echo "ok $1: office -> intruder@store refused by sshd ($(tr -d '\r' <<<"$out" | tail -1))"
  ex store grep -q "User intruder from $ip_o not allowed because not listed in AllowUsers" /var/log/sshd.log \
    || fail "$1: sshd log does not attribute the refusal to AllowUsers"
  echo "   sshd log: $(ex store grep -m1 "User intruder from $ip_o not allowed" /var/log/sshd.log | sed 's/^.*sshd\[[0-9]*\]: //')"
  tcp guest 8080 || fail "$1: guest TCP 8080 should connect"
  if tcp guest 22; then fail "$1: guest reached TCP 22"; fi
  if out="$(ssh_as guest deploy 2>&1)"; then fail "$1: guest logged in as deploy"; fi
  echo "ok $1: guest TCP 8080 connects, TCP 22 rejected (ssh: $(tr -d '\r' <<<"$out" | tail -1))"
  ex store sshd -T -C "user=x,host=x,addr=$ip_o" | grep -E '^(allowusers|denyusers)' | sed "s/^/   sshd -T for office: /"
  [[ -z "$(ex store sshd -T -C "user=x,host=x,addr=$ip_g" | grep -E '^allowusers' || true)" ]] \
    && echo "   sshd -T for guest: no allowusers (TCP 22 closed by filter instead)"
  ex store iptables -L BLAKTAIL-ACL -v -n | grep -E 'dpt:22|reject' | head -4 | sed 's/^/   /'
}

wait_limits "first apply"
echo "   drop-in:"; ex store cat "$DROPIN" | sed 's/^/     /'
caps="$(lab nodes "$ORG" | python3 -c '
import json,sys
for n in json.load(sys.stdin):
    if n.get("name") == "ssh-store": print(",".join(sorted(n.get("capabilities") or [])))')"
echo "   store capabilities reported: ${caps:-<not in node list>}"
check_limits "before restart"

echo "== restart the store agent"
ex store pkill -x blaktaild || true
for _ in $(seq 1 20); do ex store pgrep -x blaktaild >/dev/null || break; sleep 0.5; done
restart=$SECONDS
"${D[@]}" exec -d -e "BLAKTAIL_SSHD_DROPIN=$DROPIN" "$P-store" sh -c \
  "blaktaild --coord-ca /certs/ca.crt run --poll-seconds 5 >>/var/log/agent.log 2>&1"
ex store grep -q "AllowUsers deploy" "$DROPIN" || fail "drop-in lost across restart"
if ex store sh -c "nc -z -w 3 127.0.0.1 22"; then :; else fail "sshd stopped"; fi
sleep 8
ex store pgrep -x blaktaild >/dev/null || { ex store tail -20 /var/log/agent.log; fail "agent did not stay up after restart"; }
check_limits "after restart ($((SECONDS - restart))s)"
echo "sshd limits lab passed in $((SECONDS - T0))s"
