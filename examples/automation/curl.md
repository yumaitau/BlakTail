# curl walkthrough

Set `BLAKTAIL_URL`, `BLAKTAIL_ORG` and `BLAKTAIL_CLIENT_SECRET` as in the
[README](README.md). `jq` is used only to pick fields.

## 1. Exchange the client secret for a short-lived token

```sh
CLIENT_ID=00000000-0000-0000-0000-000000000000   # the automation client's id
TOKEN=$(curl -fsS "$BLAKTAIL_URL/oauth/token" \
  -u "$CLIENT_ID:$BLAKTAIL_CLIENT_SECRET" \
  -d grant_type=client_credentials | jq -r .access_token)

bt() {  # bt METHOD PATH [curl args…]
  method=$1; path=$2; shift 2
  curl -fsS -X "$method" "$BLAKTAIL_URL$path" \
    -H "Authorization: Bearer $TOKEN" \
    -H "X-BlakTail-Organisation: $BLAKTAIL_ORG" \
    -H 'content-type: application/json' "$@"
}
```

## 2. Read-only tour

```sh
bt GET /api/v1/status
bt GET /api/v1/devices | jq '.data[] | {id, name, online}'
bt GET /api/v1/posture-checks | jq '.data[] | {id, name, version, referenced_by}'
bt GET /api/v1/keys | jq '.data[] | {id, name, state, remaining_uses}'   # no secrets
bt GET /api/v1/events/catalogue | jq -r '.data[] | "\(.severity)\t\(.event_type)"'

# Audit: newest 100 node events, then the next page.
page=$(bt GET '/api/v1/audit?limit=100&action=node.*')
echo "$page" | jq '.data | length'
cursor=$(echo "$page" | jq -r '.next_cursor // empty')
[ -n "$cursor" ] && bt GET "/api/v1/audit?limit=100&action=node.*&before=$cursor" | jq '.data | length'

# Is the audit chain intact inside the retention window?
bt GET /api/v1/audit/verify | jq '.data | {intact, chained_events, problems}'

# Check a DNS draft without publishing it.
bt POST /api/v1/dns/validate -d '{"dns":{"global_resolvers":["1.1.1.1"]}}' | jq '.data.warnings'
```

## 3. Export (needs `audit:export`; the export is itself audited)

```sh
since=$(date -u -d '7 days ago' +%s 2>/dev/null || date -u -v-7d +%s)
bt GET "/api/v1/audit/export?format=csv&since=$since" -o audit-last-7-days.csv -D - | grep -i truncated
```

## 4. Writes (opt in; needs `policy:write` / `keys:write`)

```sh
# Create a posture check. Policy only uses it once a rule names it.
id=$(bt POST /api/v1/posture-checks \
  -d '{"name":"baseline","definition":{"min_agent_version":"0.2.0"}}' | jq -r .data.id)

# Update with the version you read; a stale version returns 412 — re-read and retry.
version=$(bt GET /api/v1/posture-checks | jq --arg id "$id" '.data[] | select(.id==$id) | .version')
bt PUT "/api/v1/posture-checks/$id" \
  -d "{\"version\":$version,\"definition\":{\"min_agent_version\":\"0.3.0\"}}"

# Remove it (409 while a policy rule still references it).
bt DELETE "/api/v1/posture-checks/$id"

# Revoke a join key by id (idempotent).
bt DELETE "/api/v1/keys/00000000-0000-0000-0000-000000000000"
```

Errors return JSON `{"error": "...", "code": "..."}`. A token for another
organisation, or the wrong `X-BlakTail-Organisation`, returns `401`; a
missing scope returns `403`.
