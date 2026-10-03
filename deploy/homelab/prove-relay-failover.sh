#!/usr/bin/env bash
# Relay failover drill (draft 21). Two agents with direct UDP between them
# dropped, two Australian relays advertised in priority order. Stop the
# primary relay: overlay traffic must continue through the secondary within
# the failover budget. Start the primary again: both agents must fail back to
# it (deterministic selection keeps them on the same relay).
#
# Single Docker host, self-contained (deploy/homelab/relay-lab.sh). It proves
# the agent's selection and failover logic, not independent-ISP NAT
# traversal. Run from a committed tree:
#   DOCKER_CONTEXT=m3-max deploy/homelab/prove-relay-failover.sh
set -euo pipefail
source "$(dirname "$0")/relay-lab.sh"
trap lab_cleanup EXIT
FAILOVER_BUDGET_SECS="${FAILOVER_BUDGET_SECS:-150}"
FAILBACK_BUDGET_SECS="${FAILBACK_BUDGET_SECS:-180}"

drop_direct_udp() {
  "${D[@]}" exec "${LAB_PREFIX}-$1" sh -ceu "
    iptables -I OUTPUT -d $2 -p udp -j DROP
    iptables -I INPUT -s $2 -p udp -j DROP
  "
}
container_ip() {
  "${D[@]}" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${LAB_PREFIX}-$1"
}
both_on() {
  [[ "$(lab_status a | lab_field active_relay)" == "$1" && "$(lab_status b | lab_field active_relay)" == "$1" ]]
}

lab_build
lab_secrets
lab_network
lab_relay relay "$RELAY_HOST" relay
lab_relay relay2 "$RELAY2_HOST" relay2
lab_coord "${RELAY_HOST}:3478#ap-southeast-2,${RELAY2_HOST}:3478#australia-southeast1"
org="$(lab_bootstrap)"
lab_agent_start a
lab_agent_start b
lan_a="$(lab_eth0 a)"
lan_b="$(lab_eth0 b)"
drop_direct_udp a "$lan_b"
drop_direct_udp b "$lan_a"
lab_enrol "$org" a
lab_enrol "$org" b
ip_b="$(lab_overlay_ip b)"
primary="$(container_ip relay):3478"
secondary="$(container_ip relay2):3478"
echo "== primary ${primary}, secondary ${secondary}"

started=$SECONDS
until both_on "$primary" && lab_ping a "$ip_b"; do
  (( SECONDS - started < 150 )) || { echo "FAIL agents never converged on the primary relay" >&2; exit 1; }
  sleep 2
done
echo "ok both agents relay through the primary after $((SECONDS - started))s"

echo "== stop primary relay"
"${D[@]}" stop -t 1 "${LAB_PREFIX}-relay" >/dev/null
stopped_at=$SECONDS
first_ping=""
recovered=""
while (( SECONDS - stopped_at < FAILOVER_BUDGET_SECS )); do
  if lab_ping a "$ip_b"; then
    [[ -n "$first_ping" ]] || first_ping=$((SECONDS - stopped_at))
    if both_on "$secondary"; then
      recovered=$((SECONDS - stopped_at))
      break
    fi
  fi
  sleep 1
done
[[ -n "$recovered" ]] || { echo "FAIL no failover within ${FAILOVER_BUDGET_SECS}s" >&2; exit 1; }
echo "ok failover: first overlay ping after ${first_ping}s, both agents on the secondary after ${recovered}s (budget ${FAILOVER_BUDGET_SECS}s)"
echo "ok failovers recorded: a=$(lab_status a | lab_field relay_failovers) b=$(lab_status b | lab_field relay_failovers)"

echo "== start primary relay; agents must fail back together"
"${D[@]}" start "${LAB_PREFIX}-relay" >/dev/null
primary="$(container_ip relay):3478"
started_at=$SECONDS
failed_back=""
while (( SECONDS - started_at < FAILBACK_BUDGET_SECS )); do
  if both_on "$primary" && lab_ping a "$ip_b"; then
    failed_back=$((SECONDS - started_at))
    break
  fi
  sleep 2
done
[[ -n "$failed_back" ]] || { echo "FAIL no fail-back within ${FAILBACK_BUDGET_SECS}s" >&2; exit 1; }
echo "ok fail-back to the primary in ${failed_back}s"
echo "relay_failover passed"
