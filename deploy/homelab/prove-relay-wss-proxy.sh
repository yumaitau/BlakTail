#!/usr/bin/env bash
# WSS relay fallback behind a TLS-terminating reverse proxy, as deployed on
# AWS: the relay serves plain WebSocket on 8080
# (BLAKTAIL_RELAY_WSS_BEHIND_TLS_PROXY=true) and nginx terminates TLS on 443
# for a separate host name, with a 60-second idle timeout like an ALB. UDP
# 3478 goes straight to the relay. Direct UDP between the agents is dropped
# so they must relay.
#
# Variants (first argument, default `midsession`):
#   midsession     agents relay over UDP first; then every non-DNS UDP
#                  datagram on eth0 is dropped while they keep running. They
#                  must move to the WebSocket and overlay ping must recover,
#                  then promote back to UDP once it is restored.
#   blocked-first  non-DNS UDP is dropped before the agents enrol.
#
# Single Docker host, self-contained (deploy/homelab/relay-lab.sh). Run from
# a committed tree:
#   DOCKER_CONTEXT=m3-max deploy/homelab/prove-relay-wss-proxy.sh midsession
#   DOCKER_CONTEXT=m3-max deploy/homelab/prove-relay-wss-proxy.sh blocked-first
set -euo pipefail
VARIANT="${1:-midsession}"
case "$VARIANT" in
  midsession | blocked-first) ;;
  *) echo "usage: $0 [midsession|blocked-first]" >&2; exit 2 ;;
esac
source "$(dirname "$0")/relay-lab.sh"
PROXY_HOST="relay-wss.lab.example.au"
PROXY_IMAGE="${PROXY_IMAGE:-nginx:1.27-alpine}"
UDP_BUDGET_SECS="${UDP_BUDGET_SECS:-150}"
FALLBACK_BUDGET_SECS="${FALLBACK_BUDGET_SECS:-240}"
PROMOTE_BUDGET_SECS="${PROMOTE_BUDGET_SECS:-180}"

proxy_cleanup() {
  local status=$?
  if [[ $status -ne 0 ]]; then evidence >&2 || true; fi
  "${D[@]}" rm -f "${LAB_PREFIX}-proxy" >/dev/null 2>&1 || true
  # lab_cleanup reads the exit status from $?.
  set +e
  (exit $status)
  lab_cleanup
}
trap proxy_cleanup EXIT

evidence() {
  echo "== evidence"
  echo "relay: forwards=$(lab_relay_metric relay blaktail_relay_forwards_total) wss_connections=$(lab_relay_metric relay blaktail_relay_wss_connections)"
  "${D[@]}" exec "${LAB_PREFIX}-relay" curl -fsS http://127.0.0.1:9702/metrics 2>/dev/null \
    | grep -E 'registers_total|dropped_total|wss_rejected' || true
  for agent in a b; do
    echo "-- agent ${agent}: relay_link=$(lab_status "$agent" | lab_field relay_link)"
    "${D[@]}" exec "${LAB_PREFIX}-${agent}" wg show blaktail0 latest-handshakes 2>/dev/null || true
    "${D[@]}" exec "${LAB_PREFIX}-${agent}" wg show blaktail0 endpoints 2>/dev/null || true
    # A forwarder that stopped reading shows a growing Recv-Q on 127.0.0.1.
    "${D[@]}" exec "${LAB_PREFIX}-${agent}" ss -uanp 2>/dev/null | grep -E '127\.0\.0\.1|Recv-Q' || true
    "${D[@]}" exec "${LAB_PREFIX}-${agent}" grep -E 'relay link|forwarder|WebSocket' /tmp/blaktaild.log 2>/dev/null | tail -n 10 || true
  done
  "${D[@]}" logs --tail 10 "${LAB_PREFIX}-proxy" 2>&1 || true
}

drop_direct_udp() {
  "${D[@]}" exec "${LAB_PREFIX}-$1" sh -ceu "
    iptables -I OUTPUT -d $2 -p udp -j DROP
    iptables -I INPUT -s $2 -p udp -j DROP
  "
}
# The production firewall: every UDP datagram on eth0 except DNS.
block_udp() {
  "${D[@]}" exec "${LAB_PREFIX}-$1" sh -ceu '
    iptables -I OUTPUT -o eth0 -p udp ! --dport 53 -j DROP
    iptables -I INPUT -i eth0 -p udp ! --sport 53 -j DROP
  '
}
unblock_udp() {
  "${D[@]}" exec "${LAB_PREFIX}-$1" sh -ceu '
    iptables -D OUTPUT -o eth0 -p udp ! --dport 53 -j DROP
    iptables -D INPUT -i eth0 -p udp ! --sport 53 -j DROP
  '
}

# wait_both LINK BUDGET: both agents on LINK and overlay ping both ways.
wait_both() {
  local link="$1" budget="$2" started=$SECONDS link_a link_b
  while (( SECONDS - started < budget )); do
    link_a="$(lab_status a | lab_field relay_link)"
    link_b="$(lab_status b | lab_field relay_link)"
    if [[ "$link_a" == "$link" && "$link_b" == "$link" ]] && lab_ping a "$ip_b" && lab_ping b "$ip_a"; then
      echo $((SECONDS - started))
      return 0
    fi
    sleep 2
  done
  echo "FAIL not both on relay_link=${link} with overlay ping within ${budget}s (a=${link_a} b=${link_b})" >&2
  return 1
}

lab_build
lab_secrets
lab_network
# A leaf for the proxy's host name, signed by the lab CA.
"${D[@]}" run --rm --name "${LAB_PREFIX}-certgen" -v "$CERTS:/certs" "$IMAGE" sh -ceu "
  cd /certs
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout proxy.key -out proxy.csr -subj /CN=${PROXY_HOST} 2>/dev/null
  printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' ${PROXY_HOST} >proxy.ext
  openssl x509 -req -in proxy.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out proxy.crt -days 2 -extfile proxy.ext 2>/dev/null
  rm -f proxy.csr proxy.ext
  chmod 644 proxy.crt proxy.key
"
# Relay: UDP 3478 plus plain WebSocket on 8080 for the proxy.
"${D[@]}" run -d --name "${LAB_PREFIX}-relay" --network "$NET" --network-alias "$RELAY_HOST" \
  --network-alias relay-backend --env-file "$LAB_ENV" \
  -e BLAKTAIL_REGION=ap-southeast-2 \
  -e BLAKTAIL_RELAY_WSS_BIND=0.0.0.0:8080 \
  -e BLAKTAIL_RELAY_WSS_BEHIND_TLS_PROXY=true \
  "$IMAGE" blaktail-relay >/dev/null
# TLS-terminating proxy with WebSocket upgrade and an ALB-like idle timeout.
"${D[@]}" run -d --name "${LAB_PREFIX}-proxy" --network "$NET" --network-alias "$PROXY_HOST" \
  -v "$CERTS:/certs:ro" "$PROXY_IMAGE" sh -ceu '
cat >/etc/nginx/conf.d/default.conf <<EOF
server {
  listen 443 ssl;
  server_name _;
  ssl_certificate /certs/proxy.crt;
  ssl_certificate_key /certs/proxy.key;
  location /v1/relay {
    proxy_pass http://relay-backend:8080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-For \$remote_addr;
    proxy_read_timeout 60s;
    proxy_send_timeout 60s;
    proxy_buffering off;
  }
}
EOF
exec nginx -g "daemon off;"
' >/dev/null
lab_coord "${RELAY_HOST}:3478#ap-southeast-2;wss=wss://${PROXY_HOST}/v1/relay"
org="$(lab_bootstrap)"
echo "== organisation ${org}; variant ${VARIANT}"
lab_agent_start a
lab_agent_start b
lan_a="$(lab_eth0 a)"
lan_b="$(lab_eth0 b)"
drop_direct_udp a "$lan_b"
drop_direct_udp b "$lan_a"
if [[ "$VARIANT" == blocked-first ]]; then
  block_udp a
  block_udp b
  echo "== non-DNS UDP on eth0 dropped before enrolment"
fi
lab_enrol "$org" a
lab_enrol "$org" b
ip_a="$(lab_overlay_ip a)"
ip_b="$(lab_overlay_ip b)"
echo "== overlay a=${ip_a} b=${ip_b}"

if [[ "$VARIANT" == midsession ]]; then
  took="$(wait_both udp "$UDP_BUDGET_SECS")"
  echo "ok both agents relay over UDP after ${took}s"
  "${D[@]}" exec "${LAB_PREFIX}-a" ping -c 10 -i 0.2 -q "$ip_b" | tail -n 2
  forwards_udp="$(lab_relay_metric relay blaktail_relay_forwards_total)"
  echo "== drop non-DNS UDP on eth0 in both running agents (relay forwards so far: ${forwards_udp})"
  block_udp a
  block_udp b
  # Keep WireGuard busy while the ladder moves, as live traffic would.
  "${D[@]}" exec -d "${LAB_PREFIX}-a" ping -i 0.5 -w 90 -q "$ip_b"
fi

took="$(wait_both wss "$FALLBACK_BUDGET_SECS")"
echo "ok overlay ping both ways over the proxied WebSocket after ${took}s"
before="$(lab_relay_metric relay blaktail_relay_forwards_total)"
"${D[@]}" exec "${LAB_PREFIX}-a" ping -c 20 -i 0.2 -q "$ip_b" | tail -n 2
after="$(lab_relay_metric relay blaktail_relay_forwards_total)"
wss_connections="$(lab_relay_metric relay blaktail_relay_wss_connections)"
echo "ok relay metrics: wss_connections=${wss_connections} forwards ${before} -> ${after}"
[[ "$wss_connections" == 2 && "${after:-0}" -gt "${before:-0}" ]] \
  || { echo "FAIL relay metrics do not show two WSS clients relaying" >&2; exit 1; }

# Outlive the proxy's 60-second idle timeout on an otherwise idle link.
echo "== idle 75s, then ping again over the WebSocket"
sleep 75
lab_ping a "$ip_b" || lab_ping a "$ip_b" || { echo "FAIL overlay ping lost after an idle minute" >&2; exit 1; }
echo "ok overlay ping after idle: relay_link a=$(lab_status a | lab_field relay_link) b=$(lab_status b | lab_field relay_link)"

echo "== restore UDP; agents must promote back to the UDP relay"
unblock_udp a
unblock_udp b
took="$(wait_both udp "$PROMOTE_BUDGET_SECS")"
echo "ok promoted back to the UDP relay after ${took}s"
echo "relay_wss_proxy ${VARIANT} passed"
