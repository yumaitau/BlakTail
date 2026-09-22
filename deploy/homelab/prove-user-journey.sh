#!/usr/bin/env bash
# Prove the operator journey against the homelab console and coordinator.
# Sign in, approve a device enrolment, join, and see the device in inventory.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.bun/bin:${PATH}"

DOCKER=(docker --context homelab)
WORKDIR="$(mktemp -d /tmp/blaktail-journey.XXXXXX)"
chmod 700 "$WORKDIR"
cleanup() {
  if [[ -n "${TUNNEL_PID:-}" ]]; then
    kill "$TUNNEL_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

"${DOCKER[@]}" run --rm -v blaktail_coordcerts:/certs:ro alpine cat /certs/ca.crt >"$WORKDIR/ca.crt"
scp -o BatchMode=yes -o ConnectTimeout=10 \
  homelab:/home/justinmiddler/apps/BlakTail/owner-password \
  "$WORKDIR/owner-password" >/dev/null
chmod 600 "$WORKDIR/owner-password"
email="$("${DOCKER[@]}" exec blaktail-postgres-1 psql -U blaktail -d blaktail -tA -c 'select email from "user" order by created_at limit 1')"
email="$(printf '%s' "$email" | tr -d '[:space:]')"
if [[ -z "$email" ]]; then
  echo "homelab console has no owner" >&2
  exit 1
fi

ssh -o BatchMode=yes -o ExitOnForwardFailure=yes -N \
  -L 127.0.0.1:3443:127.0.0.1:3443 \
  -L 127.0.0.1:18443:192.168.1.19:8443 \
  homelab &
TUNNEL_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if nc -z 127.0.0.1 3443 && nc -z 127.0.0.1 18443; then
    break
  fi
  sleep 0.3
done

CONSOLE_URL=https://127.0.0.1:3443 \
COORD_URL=https://coord:18443 \
COORD_RESOLVE=coord:18443:127.0.0.1 \
COORD_CA_FILE="$WORKDIR/ca.crt" \
CONSOLE_EMAIL="$email" \
CONSOLE_PASSWORD_FILE="$WORKDIR/owner-password" \
bun apps/console/scripts/user-journey-e2e.mjs
