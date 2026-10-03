#!/usr/bin/env bash
# Relay failover drill (draft 21). Two agents with direct UDP between them
# dropped, two Australian relays advertised in priority order. Stop the
# primary relay: overlay traffic must continue through the secondary within
# the failover budget. Start the primary again: both agents must fail back to
# it (deterministic selection keeps them on the same relay).
#
# This is a single-Docker-host lab. It proves the agent's selection and
# failover logic, not independent-ISP NAT traversal. It has not been run as
# part of this change; record the output in docs/relay.md when it passes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
CTX="${DOCKER_CONTEXT:-homelab}"
FAILOVER_BUDGET_SECS="${FAILOVER_BUDGET_SECS:-150}"
FAILBACK_BUDGET_SECS="${FAILBACK_BUDGET_SECS:-180}"
ENV_SOURCE="${BLAKTAIL_ENV_FILE:-}"
WORK_ENV="$(mktemp /tmp/blaktail-failover-env.XXXXXX)"
chmod 600 "$WORK_ENV"
cleanup_files() { rm -f "$WORK_ENV" "${FETCHED_ENV:-}"; }
if [[ -z "$ENV_SOURCE" ]]; then
  FETCHED_ENV="$(mktemp /tmp/blaktail-env.XXXXXX)"
  chmod 600 "$FETCHED_ENV"
  scp -o BatchMode=yes -q homelab:/home/justinmiddler/apps/BlakTail/.env "$FETCHED_ENV"
  ENV_SOURCE="$FETCHED_ENV"
fi
# Same secrets, but advertise both relays by compose name, primary first.
grep -v '^BLAKTAIL_RELAY_ENDPOINT=' "$ENV_SOURCE" >"$WORK_ENV"
printf 'BLAKTAIL_RELAY_ENDPOINT=relay:3478#ap-southeast-2,relay-secondary:3478#ap-southeast-2\n' >>"$WORK_ENV"

BASE=(docker --context "$CTX" compose -p blaktail -f compose.yaml -f compose.homelab.yml)
COMPOSE=("${BASE[@]}" --env-file "$WORK_ENV" --profile acl-prove --profile relay-failover)
ORIGINAL=("${BASE[@]}" --env-file "$ENV_SOURCE")

restore() {
  echo "== restore original coordinator relay list and stop the secondary relay"
  "${COMPOSE[@]}" start relay >/dev/null 2>&1 || true
  "${COMPOSE[@]}" rm -sf relay-secondary >/dev/null 2>&1 || true
  "${ORIGINAL[@]}" up -d --force-recreate --no-deps coord >/dev/null 2>&1 || true
  cleanup_files
}
trap restore EXIT

agent_json() {
  "${COMPOSE[@]}" exec -T "$1" blaktaild --coord-ca /certs/ca.crt status --json
}
json_field() {
  python3 -c 'import json,sys; v=json.load(sys.stdin).get(sys.argv[1]); print("" if v is None else v)' "$1"
}
overlay_ip() { agent_json "$1" | json_field address | cut -d/ -f1; }
relay_ip_of() {
  docker --context "$CTX" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "$("${COMPOSE[@]}" ps -q "$1")"
}
ping_ok() { "${COMPOSE[@]}" exec -T agent-office ping -c 1 -W 1 "$1" >/dev/null 2>&1; }

echo "== start secondary relay and point the coordinator at both relays"
"${COMPOSE[@]}" up -d relay relay-secondary
"${COMPOSE[@]}" up -d --force-recreate --no-deps coord

echo "== enrol two agents with direct UDP dropped (reuses prove-relay-nat.sh)"
BLAKTAIL_ENV_FILE="$WORK_ENV" DOCKER_CONTEXT="$CTX" "$ROOT/deploy/homelab/prove-relay-nat.sh"

primary_ip="$(relay_ip_of relay)"
secondary_ip="$(relay_ip_of relay-secondary)"
store_ip="$(overlay_ip agent-store)"
echo "== primary ${primary_ip}, secondary ${secondary_ip}, store overlay ${store_ip}"
for agent in agent-office agent-store; do
  active="$(agent_json "$agent" | json_field active_relay)"
  [[ "$active" == "${primary_ip}:3478" ]] || { echo "FAIL $agent not on primary relay ($active)" >&2; exit 1; }
done

echo "== stop primary relay"
stopped_at=$SECONDS
"${COMPOSE[@]}" stop relay
recovered=""
while (( SECONDS - stopped_at < FAILOVER_BUDGET_SECS )); do
  if ping_ok "$store_ip"; then
    office_relay="$(agent_json agent-office | json_field active_relay)"
    store_relay="$(agent_json agent-store | json_field active_relay)"
    if [[ "$office_relay" == "${secondary_ip}:3478" && "$store_relay" == "${secondary_ip}:3478" ]]; then
      recovered=$((SECONDS - stopped_at))
      break
    fi
  fi
  sleep 1
done
[[ -n "$recovered" ]] || { echo "FAIL no failover within ${FAILOVER_BUDGET_SECS}s" >&2; exit 1; }
echo "ok failover to secondary in ${recovered}s (budget ${FAILOVER_BUDGET_SECS}s)"

echo "== start primary relay; agents must fail back together"
started_at=$SECONDS
"${COMPOSE[@]}" start relay
failed_back=""
while (( SECONDS - started_at < FAILBACK_BUDGET_SECS )); do
  office_relay="$(agent_json agent-office | json_field active_relay)"
  store_relay="$(agent_json agent-store | json_field active_relay)"
  if [[ "$office_relay" == "${primary_ip}:3478" && "$store_relay" == "${primary_ip}:3478" ]] && ping_ok "$store_ip"; then
    failed_back=$((SECONDS - started_at))
    break
  fi
  sleep 2
done
[[ -n "$failed_back" ]] || { echo "FAIL no fail-back within ${FAILBACK_BUDGET_SECS}s" >&2; exit 1; }
echo "ok fail-back to primary in ${failed_back}s"
echo "relay_failover passed"
