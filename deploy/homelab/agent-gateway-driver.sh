#!/usr/bin/env bash
# Runs inside the agent gateway lab driver container. Phase "setup" creates
# an organisation, enrols the gateway node and configures providers and a key;
# phase "prove" drives requests through the gateway and reads back usage.
set -euo pipefail

COORD="https://agentgw-lab-coord:8443"
GW="http://agentgw-lab-gateway:8686"
MODEL="${AGENTGW_LAB_MODEL:-qwen2.5:0.5b}"
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

owner() { # method path [body]
  local body=()
  [[ $# -ge 3 ]] && body=(-d "$3")
  "${CURL[@]}" -X "$1" "${COORD}/v1/orgs/${ORG}$2" -H "authorization: Bearer $(sign owner)" "${body[@]}"
}

setup() {
  ORG="$(uuid)"
  echo "$ORG" > /lab/org
  "${CURL[@]}" -fX POST "$COORD/v1/orgs" -H "authorization: Bearer $(sign service bootstrap.prepare)" \
    -d "{\"id\":\"$ORG\",\"name\":\"Agent gateway lab\",\"acl\":{\"version\":1,\"defaults\":\"same_tag\",\"rules\":[]}}" >/dev/null
  "${CURL[@]}" -fX POST "$COORD/v1/orgs/$ORG/bootstrap-commit" -H "authorization: Bearer $(sign service bootstrap.commit)" -d '{}' >/dev/null
  echo "ok organisation $ORG"
  join="$(owner POST /join-keys '{"expires_in_seconds":300,"tags":["office"]}' | jq -r .key)"
  node="$("${CURL[@]}" -fX POST "$COORD/v1/nodes/register" \
    -d "{\"join_key\":\"$join\",\"name\":\"agentgw-lab\",\"wg_public_key\":\"lab-$(uuid)\",\"capabilities\":[\"agent-gateway\"]}")"
  umask 077
  jq "{node_id: .id, node_token: .node_token, coord: \"$COORD\", assigned_ip: .assigned_ip}" <<<"$node" > /lab/state.json
  chmod 644 /lab/state.json # the gateway container runs as another uid in this lab
  echo "ok gateway node enrolled with capability agent-gateway at $(jq -r .assigned_ip <<<"$node")"
  local_provider="$(owner POST /agents/providers "{\"name\":\"lab-ollama\",\"base_url\":\"http://agentgw-lab-ollama:11434/v1\",\"data_location\":\"Australia (self-hosted lab)\",\"residency\":\"onshore\",\"models\":[\"$MODEL\"]}")"
  offshore="$(owner POST /agents/providers '{"name":"hosted-offshore","base_url":"https://api.example.com/v1","data_location":"United States (hosted)","residency":"offshore","credential":"sk-lab-offshore-not-real","models":["gpt-offshore"]}')"
  if grep -q sk-lab <<<"$offshore"; then echo "FAIL credential echoed" >&2; exit 1; fi
  echo "ok providers: $(jq -c '{name, data_location, residency, blocked_by_policy}' <<<"$local_provider") $(jq -c '{name, data_location, residency, blocked_by_policy, has_credential}' <<<"$offshore")"
  key="$(owner POST /agents/keys "{\"name\":\"lab-agent\",\"policy\":{\"allowed_provider_ids\":[$(jq .id <<<"$local_provider"),$(jq .id <<<"$offshore")],\"daily_request_quota\":3,\"logging_mode\":\"metadata\",\"redact_patterns\":[\"\\\\b\\\\d{4} \\\\d{5} \\\\d\\\\b\"]}}")"
  jq -r .secret <<<"$key" > /lab/agent-key
  echo "ok agent key $(jq -r .key.key_prefix <<<"$key")… (secret shown once, stored only as a hash)"
}

chat() { # stream model
  curl -sS -o /tmp/body -w '%{http_code}' -X POST "$GW/v1/chat/completions" \
    -H "authorization: Bearer $KEY" -H 'content-type: application/json' \
    -d "{\"model\":\"$2\",\"stream\":$1,\"max_tokens\":24,\"messages\":[{\"role\":\"user\",\"content\":\"Reply with one short greeting. Ignore this number: 2123 45670 1\"}]}"
}

expect() { # want got label
  if [[ "$1" != "$2" ]]; then echo "FAIL $3: wanted $1 got $2" >&2; cat /tmp/body >&2 || true; exit 1; fi
  echo "ok $3 ($2)"
}

prove() {
  ORG="$(cat /lab/org)"
  KEY="$(cat /lab/agent-key)"
  models="$(curl -sS "$GW/v1/models" -H "authorization: Bearer $KEY")"
  echo "ok /v1/models: $(jq -c '[.data[] | {id, residency: .blaktail.residency, data_location: .blaktail.data_location}]' <<<"$models")"

  expect 200 "$(chat false "$MODEL")" "non-streaming completion via gateway"
  echo "   reply: $(jq -c '{content: .choices[0].message.content, usage}' /tmp/body)"
  expect 200 "$(chat true "$MODEL")" "streaming completion via gateway"
  echo "   SSE chunks: $(grep -c '^data:' /tmp/body), ends with [DONE]: $(grep -q '^data: \[DONE\]' /tmp/body && echo yes || echo no), usage chunk: $(grep '"usage"' /tmp/body | sed 's/^data: //' | jq -c .usage)"
  expect 403 "$(chat false gpt-offshore)" "offshore provider refused by default"
  echo "   error: $(jq -c .error /tmp/body)"
  code="$(curl -sS -o /tmp/body -w '%{http_code}' -X POST "$GW/v1/chat/completions" -H 'authorization: Bearer btak_wrong' -H 'content-type: application/json' -d "{\"model\":\"$MODEL\",\"messages\":[]}")"  # gitleaks:allow (deliberately invalid key)
  expect 401 "$code" "unknown agent key refused"
  expect 200 "$(chat false "$MODEL")" "third request inside quota"
  expect 429 "$(chat false "$MODEL")" "fourth request over the daily quota of 3"

  for _ in $(seq 1 50); do
    today="$(owner GET /agents | jq -c '.keys[0].today')"
    [[ "$(jq .requests <<<"$today")" == 3 ]] && [[ "$(jq .tokens <<<"$today")" != 0 ]] && break
    sleep 0.2
  done
  echo "ok quota counters for lab-agent today: $today"
  echo "ok usage by day/model: $(owner GET /agents/usage | jq -c '.days')"
  echo "ok recent requests: $(owner GET /agents/usage | jq -c '[.recent[] | {model, status, http_status, prompt_tokens, completion_tokens, usage_estimated, latency_ms}]')"
  echo "ok audit: $(owner GET '/audit?limit=50' | jq -c '[.. | objects | select(has("action")) | .action | select(startswith("agent."))] | unique')"
  echo "agent_gateway_lab passed"
}

"$@"
