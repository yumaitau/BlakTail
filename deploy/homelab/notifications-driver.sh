#!/usr/bin/env bash
# Runs inside the notifications lab driver container (see
# prove-notifications.sh): creates an organisation and an email channel,
# raises a test send and a real warning alert, and reads them back from
# Mailpit's API.
set -euo pipefail

COORD="https://notify-lab-coord:8443"
MAILPIT="http://notify-lab-mailpit:8025"
SECRET="$(cat /lab/hmac)"
CURL=(curl -sS --cacert /lab/ca.crt -H 'content-type: application/json')

b64url() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
uuid() { cat /proc/sys/kernel/random/uuid; }

sign() {
  local role="$1" action="${2:-}" now payload extra=""
  now="$(date +%s)"
  [[ -n "$action" ]] && extra=",\"action\":\"${action}\""
  payload="$(printf '{"sub":"lab-%s","org_id":"%s","role":"%s","name":"Lab %s","email":"%s@lab.test","iss":"blaktail-console","aud":"blaktail-coord","iat":%d,"exp":%d,"jti":"%s"%s}' \
    "$role" "$ORG" "$role" "$role" "$role" "$now" "$((now + 60))" "$(uuid)" "$extra" | b64url)"
  printf '%s.%s' "$payload" "$(printf '%s' "$payload" | openssl dgst -sha256 -hmac "$SECRET" -binary | b64url)"
}

as() { # role method path [body] -> body, status in /tmp/status
  local role="$1" method="$2" path="$3" body=()
  [[ $# -ge 4 ]] && body=(-d "$4")
  "${CURL[@]}" -o /tmp/body -w '%{http_code}' -X "$method" "${COORD}/v1/orgs/${ORG}${path}" \
    -H "authorization: Bearer $(sign "$role")" "${body[@]}" > /tmp/status
  cat /tmp/body
}

expect_status() { # want label
  local got
  got="$(cat /tmp/status)"
  if [[ "$got" != "$1" ]]; then echo "FAIL $2: wanted $1 got $got: $(cat /tmp/body)" >&2; exit 1; fi
  echo "ok $2 ($got)"
}

wait_mail() { # subject-substring
  for _ in $(seq 1 60); do
    id="$(curl -fsS "$MAILPIT/api/v1/messages" | jq -r --arg s "$1" '[.messages[] | select(.Subject | contains($s))][0].ID // empty')"
    if [[ -n "$id" ]]; then echo "$id"; return 0; fi
    sleep 0.5
  done
  echo "FAIL no email with subject containing '$1'" >&2
  curl -fsS "$MAILPIT/api/v1/messages" | jq -c '[.messages[] | .Subject]' >&2
  exit 1
}

ORG="$(uuid)"
"${CURL[@]}" -fX POST "$COORD/v1/orgs" -H "authorization: Bearer $(sign service bootstrap.prepare)" \
  -d "{\"id\":\"$ORG\",\"name\":\"Notifications lab\",\"acl\":{\"version\":1,\"defaults\":\"same_tag\",\"rules\":[]}}" >/dev/null
"${CURL[@]}" -fX POST "$COORD/v1/orgs/$ORG/bootstrap-commit" -H "authorization: Bearer $(sign service bootstrap.commit)" -d '{}' >/dev/null
echo "ok organisation $ORG"

caps="$(as admin GET /notification-channels/capabilities)"
expect_status 200 "capabilities"
echo "   $(jq -c . <<<"$caps")"

as admin POST /notification-channels '{"kind":"slack","name":"chat","url":"https://hooks.slack.com/services/T0/B0/lab","residency_acknowledged":true}' >/dev/null
expect_status 403 "admin cannot add an offshore Slack channel"
as owner POST /notification-channels '{"kind":"slack","name":"chat","url":"https://hooks.slack.com/services/T0/B0/lab"}' >/dev/null
expect_status 400 "owner must acknowledge Slack residency"

channel="$(as admin POST /notification-channels '{"kind":"email","name":"ops-email","recipients":["ops@notify-lab.test"],"quiet_hours":{"timezone":"Australia/Sydney","start":"22:00","end":"07:00"}}')"
expect_status 201 "email channel created by an admin"
CHANNEL="$(jq -r .id <<<"$channel")"

as admin POST "/notification-channels/$CHANNEL/test" >/dev/null
expect_status 202 "test send queued"
test_id="$(wait_mail "notification.test")"
echo "ok test email arrived: $(curl -fsS "$MAILPIT/api/v1/message/$test_id" | jq -c '{Subject, From: .From.Address, To: [.To[].Address]}')"

join="$(as owner POST /join-keys '{"expires_in_seconds":300}' | jq -r .key)"
node="$("${CURL[@]}" -fX POST "$COORD/v1/nodes/register" -d "{\"join_key\":\"$join\",\"name\":\"lab-laptop\",\"wg_public_key\":\"lab-$(uuid)\"}")"
NODE_ID="$(jq -r .id <<<"$node")"
jq -r .node_token <<<"$node" > /lab/node-token
as owner DELETE "/nodes/$NODE_ID" >/dev/null
echo "ok device enrolled and revoked ($NODE_ID)"
alert_id="$(wait_mail "warning device.revoked")"
alert="$(curl -fsS "$MAILPIT/api/v1/message/$alert_id")"
echo "ok alert email arrived: $(jq -c '{Subject}' <<<"$alert")"
echo "--- alert body ---"
jq -r .Text <<<"$alert"
echo "------------------"
curl -fsS "$MAILPIT/api/v1/message/$alert_id/raw" > /lab/alert.eml
curl -fsS "$MAILPIT/api/v1/message/$test_id/raw" > /lab/test.eml

deliveries="$(as owner GET "/webhooks/$CHANNEL/deliveries")"
echo "ok outbox rows: $(jq -c '[.[] | {event_type, delivered: (.delivered_at != null), attempts}]' <<<"$deliveries")"
