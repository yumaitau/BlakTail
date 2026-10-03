#!/usr/bin/env bash
# Two agents with direct UDP between them dropped (the failure mode of two
# sites that can only meet at the relay). Overlay ping must succeed through
# the UDP relay: WireGuard endpoints point at the local relay forwarder
# (127.0.0.1) and the agents report relay_link=udp.
#
# Single Docker host, self-contained (deploy/homelab/relay-lab.sh); it does
# not prove independent-ISP NAT traversal. Run from a committed tree:
#   DOCKER_CONTEXT=m3-max deploy/homelab/prove-relay-nat.sh
set -euo pipefail
source "$(dirname "$0")/relay-lab.sh"
trap lab_cleanup EXIT
BUDGET_SECS="${BUDGET_SECS:-150}"

drop_direct_udp() {
  "${D[@]}" exec "${LAB_PREFIX}-$1" sh -ceu "
    iptables -I OUTPUT -d $2 -p udp -j DROP
    iptables -I INPUT -s $2 -p udp -j DROP
  "
}

lab_build
lab_secrets
lab_network
lab_relay relay "$RELAY_HOST" relay
lab_coord "${RELAY_HOST}:3478#ap-southeast-2;wss=wss://${RELAY_HOST}/v1/relay"
org="$(lab_bootstrap)"
lab_agent_start a
lab_agent_start b
lan_a="$(lab_eth0 a)"
lan_b="$(lab_eth0 b)"
echo "== drop direct UDP ${lan_a} <-> ${lan_b}"
drop_direct_udp a "$lan_b"
drop_direct_udp b "$lan_a"
lab_enrol "$org" a
lab_enrol "$org" b
ip_a="$(lab_overlay_ip a)"
ip_b="$(lab_overlay_ip b)"

started=$SECONDS
while (( SECONDS - started < BUDGET_SECS )); do
  eps_a="$("${D[@]}" exec "${LAB_PREFIX}-a" wg show blaktail0 endpoints 2>/dev/null || true)"
  eps_b="$("${D[@]}" exec "${LAB_PREFIX}-b" wg show blaktail0 endpoints 2>/dev/null || true)"
  link_a="$(lab_status a | lab_field relay_link)"
  link_b="$(lab_status b | lab_field relay_link)"
  if [[ "$eps_a" == *127.0.0.1* && "$eps_b" == *127.0.0.1* && "$link_a" == udp && "$link_b" == udp ]] \
    && lab_ping a "$ip_b" && lab_ping b "$ip_a"; then
    echo "ok relay path ${ip_a} <-> ${ip_b} with direct UDP dropped after $((SECONDS - started))s"
    "${D[@]}" exec "${LAB_PREFIX}-a" ping -c 20 -i 0.2 -q "$ip_b" | tail -n 2
    echo "ok relay metrics: forwards=$(lab_relay_metric relay blaktail_relay_forwards_total) wss_connections=$(lab_relay_metric relay blaktail_relay_wss_connections)"
    echo "relay_nat passed"
    exit 0
  fi
  sleep 3
done
echo "FAIL overlay did not converge through the relay within ${BUDGET_SECS}s" >&2
exit 1
