#!/usr/bin/env bash
# HTTPS relay fallback proof (ADR 0004, draft 21). Two agents whose networks
# drop every outbound and inbound UDP datagram on eth0 (so neither direct
# WireGuard nor the UDP relay works) must reach each other through the
# relay's WebSocket-over-TLS listener on TCP 443. Then UDP is restored and
# both agents must promote back to the UDP relay (hysteresis: three answered
# probe rounds).
#
# Single Docker host, self-contained (deploy/homelab/relay-lab.sh). It proves
# the transport ladder and the relay's WSS path, not a real corporate proxy
# or independent-ISP NAT. Run from a committed tree:
#   DOCKER_CONTEXT=m3-max deploy/homelab/prove-relay-wss.sh
set -euo pipefail
source "$(dirname "$0")/relay-lab.sh"
trap lab_cleanup EXIT
FALLBACK_BUDGET_SECS="${FALLBACK_BUDGET_SECS:-180}"
PROMOTE_BUDGET_SECS="${PROMOTE_BUDGET_SECS:-180}"

block_udp() {
  "${D[@]}" exec "${LAB_PREFIX}-$1" sh -ceu '
    iptables -I OUTPUT -o eth0 -p udp -j DROP
    iptables -I INPUT -i eth0 -p udp -j DROP
  '
}
unblock_udp() {
  "${D[@]}" exec "${LAB_PREFIX}-$1" sh -ceu '
    iptables -D OUTPUT -o eth0 -p udp -j DROP
    iptables -D INPUT -i eth0 -p udp -j DROP
  '
}
dropped_udp() {
  "${D[@]}" exec "${LAB_PREFIX}-$1" iptables -vnx -L OUTPUT \
    | awk '$3 == "DROP" && ($4 == "udp" || $4 == "17") { print $1; exit }'
}

lab_build
lab_secrets
lab_network
lab_relay relay "$RELAY_HOST" relay
lab_coord "${RELAY_HOST}:3478#ap-southeast-2;wss=wss://${RELAY_HOST}/v1/relay"
org="$(lab_bootstrap)"
echo "== organisation ${org}"
for agent in a b; do
  lab_agent_start "$agent"
  # Block UDP before the agent first speaks: no direct path, no UDP relay.
  block_udp "$agent"
done
for agent in a b; do lab_enrol "$org" "$agent"; done

ip_a="$(lab_overlay_ip a)"
ip_b="$(lab_overlay_ip b)"
echo "== overlay a=${ip_a} b=${ip_b}; UDP on eth0 dropped both ways in both agents"

started=$SECONDS
reached=""
while (( SECONDS - started < FALLBACK_BUDGET_SECS )); do
  link_a="$(lab_status a | lab_field relay_link)"
  link_b="$(lab_status b | lab_field relay_link)"
  if [[ "$link_a" == wss && "$link_b" == wss ]] && lab_ping a "$ip_b" && lab_ping b "$ip_a"; then
    reached=$((SECONDS - started))
    break
  fi
  sleep 2
done
[[ -n "$reached" ]] || { echo "FAIL agents did not converge over the WSS relay within ${FALLBACK_BUDGET_SECS}s" >&2; exit 1; }
echo "ok overlay ping both ways over relay-wss after ${reached}s"

"${D[@]}" exec "${LAB_PREFIX}-a" ping -c 20 -i 0.2 -q "$ip_b" | tail -n 2
wss_connections="$(lab_relay_metric relay blaktail_relay_wss_connections)"
forwards="$(lab_relay_metric relay blaktail_relay_forwards_total)"
echo "ok relay metrics: wss_connections=${wss_connections} forwards=${forwards}"
[[ "$wss_connections" == 2 && "${forwards:-0}" -gt 0 ]] || { echo "FAIL relay metrics do not show two WSS clients relaying" >&2; exit 1; }
echo "ok UDP datagrams dropped on eth0: a=$(dropped_udp a) b=$(dropped_udp b)"
# Only TCP should leave eth0 now: sample it while traffic flows.
"${D[@]}" exec "${LAB_PREFIX}-a" sh -c "ping -c 10 -i 0.2 -q $ip_b >/dev/null & timeout 3 tcpdump -ni eth0 -c 200 'not arp' 2>/dev/null || true" \
  | awk '{ for (i = 1; i <= NF; i++) if ($i == "UDP," || $i == "udp") udp++; else if ($i ~ /\.443[:,]?$/) tls++ } END { printf "ok eth0 sample: tls443=%d udp=%d\n", tls, udp; exit (udp > 0) }'

echo "== restore UDP; agents must promote back to the UDP relay"
unblock_udp a
unblock_udp b
started=$SECONDS
promoted=""
while (( SECONDS - started < PROMOTE_BUDGET_SECS )); do
  link_a="$(lab_status a | lab_field relay_link)"
  link_b="$(lab_status b | lab_field relay_link)"
  if [[ "$link_a" == udp && "$link_b" == udp ]] && lab_ping a "$ip_b"; then
    promoted=$((SECONDS - started))
    break
  fi
  sleep 2
done
[[ -n "$promoted" ]] || { echo "FAIL agents did not promote back to UDP within ${PROMOTE_BUDGET_SECS}s (a=${link_a} b=${link_b})" >&2; lab_status a >&2 || true; lab_status b >&2 || true; exit 1; }
echo "ok promoted back to the UDP relay after ${promoted}s"
echo "relay_wss passed"
