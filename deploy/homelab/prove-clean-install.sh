#!/usr/bin/env bash
# Clean-host install drill (drafts 16, 19, 23; docs/releases.md). On one
# Docker host (default context m3-max):
#
#   - builds the release packages with deploy/docker/agent-package.Dockerfile
#     (the same build the release workflow runs) and serves them, with
#     SHA256SUMS, from a lab HTTPS "release" server;
#   - boots fresh systemd containers from debian:bookworm and ubuntu:24.04
#     (only systemd, curl and CA certificates added; no agent dependencies);
#   - runs scripts/install-agent.sh unchanged except for
#     BLAKTAIL_RELEASE_BASE_URL/BLAKTAIL_VERSION: tampered asset, missing
#     cosign with BLAKTAIL_REQUIRE_SIGNATURE=1, and (when cosign can be
#     fetched) a bundle that does not verify must all refuse to install;
#     the genuine asset installs via the checksum path;
#   - enrols Debian with the join key on stdin and Ubuntu with
#     BLAKTAIL_JOIN_KEY, scanning every /proc/*/cmdline during enrolment;
#   - enables blaktaild.service, proves ping both ways over the overlay,
#     restarts the service, revokes Ubuntu as owner and proves it is no
#     longer admitted, then uninstalls both and checks nothing is left.
#
# Not proven: a Sigstore bundle that verifies (needs a tagged GitHub release),
# RPM hosts, macOS packages, a reboot of a real VM.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
CTX="${DOCKER_CONTEXT:-m3-max}"
D=(docker --context "$CTX")
P=labs-host-inst
IMG="${LABS_IMAGE:-labs-base:fc6ec9c}"
COORD_URL=https://labs-host-coord:8443
VERSION=0.1.0
ORG="$(python3 -c 'import uuid; print(uuid.uuid4())')"
export BLAKTAIL_AUTH_HMAC_SECRET="$(openssl rand -hex 32)"
export BLAKTAIL_RELAY_AUTH_SECRET="$(openssl rand -hex 32)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/labs-host-inst.XXXXXX")"
T0=$SECONDS

cleanup() {
  [[ "${LABS_KEEP:-0}" == 1 ]] && { echo "LABS_KEEP=1: leaving $P-* for debugging"; return; }
  "${D[@]}" rm -f labs-host-coord "$P-rel" "$P-debian" "$P-ubuntu" >/dev/null 2>&1 || true
  "${D[@]}" network rm "$P-net" >/dev/null 2>&1 || true
  "${D[@]}" volume rm "$P-certs" >/dev/null 2>&1 || true
  "${D[@]}" image rm "$P-debian:fresh" "$P-ubuntu:fresh" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "FAIL $*" >&2; exit 1; }
ex() { "${D[@]}" exec "$P-$1" "${@:2}"; }

echo "== build release packages (agent-package.Dockerfile) on $CTX"
git ls-files -co --exclude-standard -z | tar --null -T - -czf "$WORK/src.tgz"
"${D[@]}" build -q --target export -f deploy/docker/agent-package.Dockerfile \
  --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
  -o "type=local,dest=$WORK/pkg" - < "$WORK/src.tgz" >/dev/null
ls "$WORK/pkg"/*.deb >/dev/null || fail "no deb built"
(cd "$WORK/pkg" && shasum -a 256 -c SHA256SUMS >/dev/null) || fail "built SHA256SUMS does not match"
echo "ok packages: $(cd "$WORK/pkg" && ls | tr '\n' ' ')"

echo "== fresh systemd images"
for distro in debian:bookworm ubuntu:24.04; do
  name="${distro%%:*}"
  "${D[@]}" build -q -t "$P-$name:fresh" - >/dev/null <<EOF
FROM $distro
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      systemd systemd-sysv curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
done

cleanup_lab() { "${D[@]}" rm -f labs-host-coord "$P-rel" "$P-debian" "$P-ubuntu" >/dev/null 2>&1 || true; }
cleanup_lab
"${D[@]}" network rm "$P-net" >/dev/null 2>&1 || true
"${D[@]}" volume rm "$P-certs" >/dev/null 2>&1 || true
"${D[@]}" network create "$P-net" >/dev/null
"${D[@]}" volume create "$P-certs" >/dev/null

echo "== coordinator and lab release server (one lab CA)"
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
  for host in labs-host-coord labs-host-inst-rel; do
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -subj "/CN=$host" -keyout $host.key -out $host.csr 2>/dev/null
    printf "subjectAltName=DNS:$host\n" > san.ext
    openssl x509 -req -in $host.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
      -days 1 -extfile san.ext -out $host.crt 2>/dev/null
  done
  mv labs-host-coord.crt coord.crt; mv labs-host-coord.key coord.key
  chmod 644 *.key *.crt; rm -f ca.key'
"${D[@]}" exec -d labs-host-coord sh -c '(blaktail-coord migrate && blaktail-coord serve) >/var/log/coord.log 2>&1'

"${D[@]}" run -d --name "$P-rel" --network "$P-net" -v "$P-certs:/certs:ro" "$IMG" >/dev/null
good=/srv/good/download/v$VERSION
bad=/srv/bad/download/v$VERSION
ex rel mkdir -p "$good" "$bad"
for f in "$WORK/pkg"/*; do "${D[@]}" cp "$f" "$P-rel:$good/"; done
ex rel sh -ceu "
  cp $good/* $bad/
  deb=\$(ls $bad/*.deb); printf tamper >> \"\$deb\"
  printf 'not a sigstore bundle' > $good/SHA256SUMS.sigstore.json"
"${D[@]}" exec -d "$P-rel" python3 -c '
import http.server, ssl, functools
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory="/srv")
server = http.server.ThreadingHTTPServer(("0.0.0.0", 443), handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/certs/labs-host-inst-rel.crt", "/certs/labs-host-inst-rel.key")
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()'
for i in $(seq 1 61); do
  (( i <= 60 )) || { "${D[@]}" exec labs-host-coord tail -5 /var/log/coord.log; fail "coordinator not ready"; }
  "${D[@]}" exec labs-host-coord python3 -c "import ssl,urllib.request; urllib.request.urlopen('$COORD_URL/readyz', context=ssl.create_default_context(cafile='/certs/ca.crt'))" >/dev/null 2>&1 && break
  sleep 1
done
lab() { "${D[@]}" exec -e BLAKTAIL_AUTH_HMAC_SECRET labs-host-coord host-lab "$@"; }
lab bootstrap "$ORG" install

for name in debian ubuntu; do
  "${D[@]}" run -d --name "$P-$name" --hostname "fresh-$name" --network "$P-net" --privileged \
    --cgroupns=private --tmpfs /run --tmpfs /run/lock "$P-$name:fresh" >/dev/null
done
for name in debian ubuntu; do
  for _ in $(seq 1 30); do
    state="$(ex "$name" systemctl is-system-running 2>/dev/null || true)"
    [[ "$state" == running || "$state" == degraded ]] && break
    sleep 1
  done
  [[ "$state" == running || "$state" == degraded ]] || fail "$name systemd not up ($state)"
  ex "$name" sh -c '! command -v blaktaild && ! command -v wg && ! command -v iptables' >/dev/null \
    || fail "$name is not a clean host"
  "${D[@]}" exec -i "$P-$name" sh -c 'cat > /usr/local/share/ca-certificates/labs-host.crt && update-ca-certificates >/dev/null' \
    < <("${D[@]}" exec labs-host-coord cat /certs/ca.crt)
  "${D[@]}" cp scripts/install-agent.sh "$P-$name:/root/install-agent.sh"
  echo "ok $name: systemd $state, no blaktaild/wg/iptables, lab CA trusted"
done

install() { # name base [env...]
  local name="$1" base="$2"; shift 2
  "${D[@]}" exec -e BLAKTAIL_RELEASE_BASE_URL="https://labs-host-inst-rel/$base" -e BLAKTAIL_VERSION="$VERSION" \
    "$@" "$P-$name" sh /root/install-agent.sh
}

for name in debian ubuntu; do
  echo "== $name: install-agent.sh refusals"
  out="$(install "$name" bad 2>&1)" && fail "$name installed a tampered package"
  [[ "$out" == *"SHA-256 mismatch"* ]] || fail "$name tampered: $out"
  echo "ok tampered asset refused: $(tail -1 <<<"$out")"
  out="$(install "$name" good -e BLAKTAIL_REQUIRE_SIGNATURE=1 2>&1)" && fail "$name installed without cosign"
  [[ "$out" == *"needs cosign"* ]] || fail "$name require-signature: $out"
  echo "ok BLAKTAIL_REQUIRE_SIGNATURE=1 without cosign refused: $(tail -1 <<<"$out")"
  ex "$name" sh -c '! command -v blaktaild' >/dev/null || fail "$name has blaktaild after refusals"
done

cosign_url="https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-linux-$(ex debian dpkg --print-architecture)"
if ex debian curl -fsSL -o /usr/local/bin/cosign "$cosign_url" 2>/dev/null && ex debian chmod 0755 /usr/local/bin/cosign; then
  echo "== debian: cosign $(ex debian cosign version 2>/dev/null | awk '/GitVersion/ {print $2}') present, bundle does not verify"
  out="$(install debian good 2>&1)" && fail "debian installed with a bad signature bundle"
  [[ "$out" == *"did not verify"* ]] || fail "debian bad bundle: $out"
  echo "ok bad Sigstore bundle refused: $(tail -1 <<<"$out")"
  ex debian rm -f /usr/local/bin/cosign
  COSIGN="refused a non-verifying bundle"
else
  COSIGN="not fetched (no egress); signature path not exercised"
  echo "-- cosign not available: $COSIGN"
fi

for name in debian ubuntu; do
  echo "== $name: install genuine package (checksum path)"
  started=$SECONDS
  out="$(install "$name" good 2>&1)" || { echo "$out" | tail -20; fail "$name install failed"; }
  ex "$name" sh -c 'dpkg -s blaktaild | grep -q "Status: install ok installed"' || fail "$name package not configured"
  echo "ok $name installed $(ex "$name" blaktaild --version) in $((SECONDS - started))s; deps: $(ex "$name" sh -c 'for c in wg iptables ip; do command -v $c; done | tr "\n" " "')"
  ex "$name" sh -ceu 'install -d -m 0755 /etc/blaktail && cp /usr/local/share/ca-certificates/labs-host.crt /etc/blaktail/ca.crt
    printf "BLAKTAIL_COORD_CA=/etc/blaktail/ca.crt\n" > /etc/blaktail/agent.env'
  ex "$name" blaktail-config check-config --service agent >/dev/null || fail "$name check-config"
  # Lab tooling only (not an agent dependency): ping for the overlay checks.
  ex "$name" sh -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends iputils-ping >/dev/null 2>&1' \
    || fail "$name could not install ping"
done

host_ip() { "${D[@]}" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$P-$1"; }
argv_scan_start() {
  "${D[@]}" exec -d "$P-$1" sh -c 'i=0; while [ $i -lt 400 ]; do for f in /proc/[0-9]*/cmdline; do tr "\0" " " < "$f" 2>/dev/null; echo; done; i=$((i+1)); sleep 0.05; done > /run/argv-scan; touch /run/argv-scan.done'
  sleep 0.5
}
argv_scan_check() { # name key
  for _ in $(seq 1 60); do ex "$1" test -e /run/argv-scan.done && break; sleep 1; done
  local lines; lines="$(ex "$1" sh -c 'wc -l < /run/argv-scan')"
  ex "$1" grep -q 'blaktaild .* up --coord' /run/argv-scan || fail "$1 argv scan never saw blaktaild up"
  if printf '%s' "$2" | "${D[@]}" exec -i "$P-$1" grep -qF -f - /run/argv-scan; then fail "$1 join key seen in argv"; fi
  echo "ok $1: join key absent from $(tr -d ' \n' <<<"$lines") /proc/*/cmdline reads taken every 50 ms during enrolment"
}

echo "== enrol debian (join key on stdin) and ubuntu (BLAKTAIL_JOIN_KEY)"
key="$(lab join-key "$ORG" office)"
argv_scan_start debian
printf '%s' "$key" | "${D[@]}" exec -i "$P-debian" blaktaild --coord-ca /etc/blaktail/ca.crt up \
  --coord "$COORD_URL" --name fresh-debian --endpoint "$(host_ip debian):51820" --exit-after-join >/dev/null
argv_scan_check debian "$key"
BLAKTAIL_JOIN_KEY="$(lab join-key "$ORG" store)"
export BLAKTAIL_JOIN_KEY
argv_scan_start ubuntu
"${D[@]}" exec -e BLAKTAIL_JOIN_KEY "$P-ubuntu" blaktaild --coord-ca /etc/blaktail/ca.crt up \
  --coord "$COORD_URL" --name fresh-ubuntu --endpoint "$(host_ip ubuntu):51820" --exit-after-join >/dev/null
argv_scan_check ubuntu "$BLAKTAIL_JOIN_KEY"
unset BLAKTAIL_JOIN_KEY key

overlay() { ex "$1" blaktaild status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["address"].split("/")[0])'; }
start_service() {
  ex "$1" systemctl enable --now blaktaild >/dev/null 2>&1 || { ex "$1" journalctl -u blaktaild --no-pager | tail -20; fail "$1 service start"; }
  # The agent picks a random WireGuard port; pin the one advertised with --endpoint.
  for _ in $(seq 1 30); do ex "$1" wg set blaktail0 listen-port 51820 2>/dev/null && return 0; sleep 1; done
  ex "$1" journalctl -u blaktaild --no-pager | tail -20; fail "$1 never created blaktail0"
}
ping_both() {
  local started=$SECONDS
  until ex debian ping -c 1 -W 2 "$ip_u" >/dev/null 2>&1 && ex ubuntu ping -c 1 -W 2 "$ip_d" >/dev/null 2>&1; do
    (( SECONDS - started < 90 )) || fail "no overlay ping both ways ($1)"
    sleep 2
  done
  echo "ok $1: debian $ip_d <-> ubuntu $ip_u ping both ways after $((SECONDS - started))s"
}

start_service debian
start_service ubuntu
ip_d="$(overlay debian)"; ip_u="$(overlay ubuntu)"
ping_both "systemd service"
for name in debian ubuntu; do
  echo "   $name unit: $(ex "$name" systemctl show blaktaild -p ActiveState -p SubState -p ExecMainPID --value | tr '\n' ' ')"
done

echo "== restart blaktaild.service on both"
for name in debian ubuntu; do
  ex "$name" systemctl restart blaktaild
  for _ in $(seq 1 30); do ex "$name" wg set blaktail0 listen-port 51820 2>/dev/null && break; sleep 1; done
done
ping_both "after systemctl restart"
[[ "$(overlay debian)" == "$ip_d" && "$(overlay ubuntu)" == "$ip_u" ]] || fail "addresses changed across restart"
echo "ok addresses kept across restart"

echo "== owner revokes ubuntu"
node_u="$(lab nodes "$ORG" | python3 -c 'import json,sys; print(next(n["id"] for n in json.load(sys.stdin) if n["name"]=="fresh-ubuntu"))')"
lab revoke "$ORG" "$node_u"
revoked=$SECONDS
until ! ex debian wg show blaktail0 peers | grep -q .; do
  (( SECONDS - revoked < 90 )) || fail "debian still has ubuntu as a peer"
  sleep 2
done
echo "ok debian dropped ubuntu's peer $((SECONDS - revoked))s after revoke"
ex debian ping -c 2 -W 2 "$ip_u" >/dev/null 2>&1 && fail "debian still reaches revoked ubuntu"
ex ubuntu ping -c 2 -W 2 "$ip_d" >/dev/null 2>&1 && fail "revoked ubuntu still reaches debian"
ex ubuntu systemctl restart blaktaild || true
sleep 8
echo "ok revoked ubuntu cannot reach debian; after restart its service log says:"
ex ubuntu journalctl -u blaktaild --no-pager -n 40 | grep -iE "revok|401|403|unauthor|rejected|error" | tail -3 | sed 's/^/   /'

echo "== uninstall"
ex debian sh -ceu 'systemctl disable --now blaktaild; blaktaild --coord-ca /etc/blaktail/ca.crt down'
# Ubuntu is already revoked: `down` must still tear the tunnel down locally.
ex ubuntu sh -ceu 'systemctl disable --now blaktaild; blaktaild --coord-ca /etc/blaktail/ca.crt down'
for name in debian ubuntu; do
  ex "$name" sh -ceu 'DEBIAN_FRONTEND=noninteractive apt-get purge -y blaktaild >/dev/null 2>&1; rm -rf /etc/blaktail /var/lib/blaktail'
  leftovers="$(ex "$name" sh -c '
    for c in blaktaild blaktail-config; do command -v $c; done
    ls /usr/lib/systemd/system/blaktaild.service /var/lib/blaktail /etc/resolv.conf.blaktail.tmp 2>/dev/null
    grep -l "Managed by blaktaild" /etc/resolv.conf
    ip link show blaktail0 2>/dev/null | head -1
    iptables-save 2>/dev/null | grep -i blaktail | head -3
    ip rule 2>/dev/null | grep -v -E "^(0|32766|32767):"
    true')"
  [[ -z "$leftovers" ]] || fail "$name leftovers after uninstall: $leftovers"
  echo "ok $name uninstalled: no binary, unit, state, interface, iptables chain or policy rule left"
done
state_d="$(lab nodes "$ORG" | python3 -c 'import json,sys; print([(n["name"], "revoked" if n.get("revoked") else "active") for n in json.load(sys.stdin)])')"
echo "   coordinator node list after uninstall: $state_d"
[[ "$state_d" == *"('fresh-debian', 'revoked')"* && "$state_d" == *"('fresh-ubuntu', 'revoked')"* ]] \
  || fail "both nodes should be revoked: $state_d"
echo "clean install lab passed in $((SECONDS - T0))s (cosign: $COSIGN)"
