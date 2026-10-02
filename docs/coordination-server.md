# Coordination server

`blaktail-coord` is the organisation-hosted control plane. It stores only coordination metadata: organisations, ACL JSON, hashed join keys and node tokens, credential expiries, nodes, WireGuard public keys, allowed IPs, and actor-attributed administration audit events. There is no file-content or general blob table.

## Run on an Australian host

TLS and an explicit region are mandatory. The process refuses to start when `BLAKTAIL_REGION` is missing or empty.
`BLAKTAIL_CONSOLE_URL` is also required so the coordinator can return a complete
browser-enrollment link. Use HTTPS for every non-local deployment.

```sh
# Start from config/blaktail.toml.example, then set operator-owned paths/URLs.
blaktail-config --config /etc/blaktail/config.toml check-config --service coordinator
blaktail-coord --config /etc/blaktail/config.toml migrate
blaktail-coord --config /etc/blaktail/config.toml serve
```

The default database is `blaktail-coord.sqlite3`, suitable for a single office
box. SQLite WAL mode and foreign keys are enabled. Multi-replica deployments use
the SQLx PostgreSQL backend: set `database_backend = "postgres"`,
`database_storage = "network"`, and provide `database_url` as a secret file or
environment reference. The URL is never accepted as a command-line value.
Set `RUST_LOG=info` for startup, registration, and revocation events. Startup logs
include the configured region; public health responses contain status only.

## Migrations, backups, and recovery

The coordinator records an ordered schema version in SQLite's
`PRAGMA user_version`. `blaktail-coord migrate` advances a version-zero or older
database through ordered schema versions inside one transaction per version and
is idempotent. Normal `serve` startup never migrates: it refuses missing, older,
or newer schema state before opening listeners.

Before upgrading, take a consistent backup while the coordinator is stopped, or use
SQLite's online backup command:

```sh
sqlite3 /var/lib/blaktail-coord/coordinator.sqlite3 \
  ".backup '/var/lib/blaktail-coord/coordinator-before-upgrade.sqlite3'"
```

Check the backup off-host, run the explicit migration command, then start the new
coordinator and inspect `/livez`, `/readyz`, and its startup log. Database downgrade
is unsupported; restore the snapshot before starting the old binary. Future schema
changes must append an ordered migration and advance `CURRENT_SCHEMA_VERSION`, not
add an unconditional startup mutation.

PostgreSQL records the same ordered versions in
`coordinator_schema_migrations`. `blaktail-coord migrate` holds a transaction-level
advisory lock, so two deployment jobs can be started safely; one applies each
migration and the other observes the committed versions. Normal replicas call
`serve`, verify every version is present and contiguous, and refuse traffic for an
old, future, or gapped schema.

Use a protected libpq service/password file or cloud-native database identity for
operator commands; do not put a URL containing credentials in shell history. A
portable backup/restore drill is:

```sh
# PGHOST, PGDATABASE, PGUSER and PGPASSFILE point at the active database.
pg_dump --format=custom --no-owner --no-acl \
  --file coordinator-$(date -u +%Y%m%dT%H%M%SZ).dump
pg_restore --list coordinator-*.dump >/dev/null

# Restore into a new, empty recovery database; never over the active database.
createdb blaktail_coord_recovery
pg_restore --exit-on-error --no-owner --no-acl \
  --dbname blaktail_coord_recovery coordinator-*.dump
```

Point a one-off coordinator at the restored database with a protected
`database_url` reference. `serve` must reach `/readyz`; confirm organisation, node,
ACL, nonce, and audit-event counts before promoting it. On RDS, enable automated
backups/Multi-AZ, restore a snapshot to a new instance, run the same readiness and
count checks from a private task, then delete the recovery instance. Never test
recovery by overwriting the source instance. Database downgrade is restore-only.

The repository exercises legacy SQLite fixtures on every Rust test run and a
dedicated PostgreSQL database when `BLAKTAIL_COORD_TEST_DATABASE_URL` is set. That
integration test starts two independent pools, races concurrent migrations and a
single-use registration, proves cross-replica reads, closes one replica, and
rechecks the survivor.

## HTTP API

- `POST /v1/orgs` — on-host bootstrap service assertion with action
  `bootstrap.prepare`; reserves but does not activate
  `{ "id": "uuid", "name": "org", "acl": { "rules": [] } }`
- `POST /v1/orgs/{org_id}/bootstrap-commit` — separate one-use service assertion
  with action `bootstrap.commit`; activates the matching unexpired reservation
- `POST /v1/orgs/{org_id}/join-keys` — owner/admin bearer session; `{ "name": "Ranger tablets", "description": "", "expires_in_seconds": 3600, "single_use": true, "tags": ["office"] }`. Reusable keys set `"single_use": false` and may set `"max_uses": 1..10000` (omit for no limit before expiry). Each enrolment or reauth consumes one use in a single conditional `UPDATE`, so concurrent requests cannot overspend a key.
- `GET /v1/orgs/{org_id}/join-keys` — owner/admin; inventory of operator keys (name, creator, one-use/reusable, max/remaining uses, expiry, tags, last use, revoke state). Never returns the secret or its hash; browser-approval grants are excluded.
- `DELETE /v1/orgs/{org_id}/join-keys/{key_id}` — owner/admin; revoke a key (idempotent, audited as `join_key.revoked`)
- `POST /v1/device-authorizations` — begin a ten-minute browser enrollment for a bound node name and WireGuard key
- `GET /v1/device-authorizations/{device_code}` — agent poll; reveals only
  pending/approved state and enforces the returned poll interval with `429` plus
  `Retry-After`
- `GET|POST /v1/orgs/{org_id}/device-authorizations/{user_code}` — signed-in console preview and approval
- `GET /v1/orgs/{org_id}/nodes` — any org user session; list devices
- `PUT /v1/orgs/{org_id}/nodes/{node_id}/friendly-name` — any org user session;
  set a unique friendly device name
- `PUT /v1/orgs/{org_id}/nodes/{node_id}/routes` — owner/admin approval of an exact subset of advertised routes
- `GET /v1/orgs/{org_id}/security` — any org user session; read node-key lifetime policy
- `PUT /v1/orgs/{org_id}/security` — owner/admin session; set node-key lifetime from 1 to 365 days
- `GET /v1/orgs/{org_id}/audit` — any org user session; latest audit events (`limit=1..200`, optional `before=created_at:id`)
- `DELETE /v1/orgs/{org_id}/nodes/{node_id}` — owner/admin session; revoke a device
- `POST /v1/orgs/{org_id}/nodes/{node_id}/tombstone` — owner/admin session; remove a device from default inventory
- `GET /v1/orgs/{org_id}/nodes/{node_id}` — any org user session; peer detail with heartbeat state computed from coordinator time, agent-reported transport, version guidance, lifecycle state and the latest audit events for that node
- `POST /v1/orgs/{org_id}/nodes/{node_id}/suspend` (`{ "reason": "" }`) and `.../resume` — owner/admin; reversible suspension. A suspended node keeps its identity, addresses, tags, routes and memberships but is removed from every peer map (control revision bumps), and its `peers`, `updates` and `reauth` calls return `403` with code `suspended`. Audited as `node.suspended` / `node.resumed`; webhooks `device.suspended` / `device.resumed`.
- `GET/POST /v1/orgs/{org_id}/api-clients` and `DELETE /v1/orgs/{org_id}/api-clients/{id}` — owner-created automation credentials
- `/api/v1/*` — versioned admin API; `Authorization: Bearer bta_…` or a short-lived `bto_` access token plus `X-BlakTail-Organisation`; OpenAPI in [docs/openapi/admin-v1.yaml](openapi/admin-v1.yaml); compatibility policy in [admin-api.md](admin-api.md)
- `POST /oauth/token` — OAuth client-credentials exchange that mints a hashed `bto_` access token from a `bta_` automation secret
- `POST /v1/nodes/register` — join key, name, WG public key, and optional public endpoint; the server allocates a tailnet IP
- `GET /v1/nodes/{node_id}/peers` — bearer node token; active peers only
- `PUT /v1/nodes/{node_id}/routes` — bearer node token; replace route advertisements and drop stale approvals
- `POST /v1/nodes/{node_id}/reauth` — node token plus a fresh join key; rotate credentials without changing the tailnet IP
- `PUT /v1/nodes/{node_id}/relay-endpoint` — bearer node token; refresh this node's reflexive UDP candidate
- `DELETE /v1/nodes/{node_id}` — bearer node token; self-revocation
- `GET /v1/orgs/{org_id}/acl` — any org user session
- `PUT /v1/orgs/{org_id}/acl` — owner/admin only
- `GET /livez` — status-only process liveness
- `GET /readyz` — status-only database connectivity plus exact schema readiness
- `GET /health` — compatibility alias for readiness

Prometheus metrics are served as plain HTTP on the separate
`BLAKTAIL_COORD_METRICS_BIND` listener. It defaults to `127.0.0.1:9701`; a
non-loopback bind needs explicit acknowledgement plus a 32-byte diagnostics bearer
token. Do not publish it through the public coordinator TLS listener. See
[observability.md](observability.md) for metric names, Compose scraping, audit
coverage, and alerts.

Join and node credentials are returned once; only SHA-256 hashes are stored. Join keys expire after at most 30 days and default to single-use. Node credentials default to 90 days, with a per-organisation policy between 1 and 365 days. An expired node receives an actionable `401`, disappears from other nodes' peer responses, and can run `blaktaild reauth` with its old node secret plus a fresh join key. Re-authentication rotates the node token and expiry while preserving the node id, WireGuard key, DNS name, and tailnet IP. Peer polling has no cache, so revocation or expiry is visible on the next request (within 60 seconds).

Each organisation gets a deterministic ULA `/64` under `fd00::/8`, derived
from its UUID. Each node receives both its existing `100.64.0.x/32` address and
a unique `/128` in that organisation prefix. Existing version-zero SQLite rows are
backfilled by migration. Agents request the `ipv6=true` peer capability; responses without
that query remain IPv4-only so an upgraded coordinator does not hand IPv6 routes
to an older agent. Registration and peer responses include `assigned_ips`, while
the singular `assigned_ip` remains as the IPv4 compatibility field.

Headless browser enrollment stores hashes of both device and user codes. The console
approves the high-entropy device code as a short-lived, single-use join grant bound
to the requesting node name and WireGuard public key. The raw device secret remains
only in `blaktaild`; a copied browser link cannot register a different device.

The console verifies Better Auth sessions in onshore Postgres, maps the user to an
organisation and role, then issues a new HMAC assertion for each request using the
shared `BLAKTAIL_AUTH_HMAC_SECRET`. Rust requires exact issuer and audience, a
maximum 60-second lifetime, actor, role, organisation, and a 32–128 character
nonce; each nonce is hashed and consumed once. Service assertions additionally
bind one exact action. Organisation prepare/commit accepts only the on-host
`service` role and never an ordinary owner session. Pending reservations expire
after one hour and are not visible to node or management routes. Use independent,
randomly generated values of at least 32 bytes for this secret and
`BETTER_AUTH_SECRET`. Roles are
`owner`, `admin`, and `member`. Members can read ACLs and device lists but
cannot mint join keys, update ACLs, or revoke devices. A join key binds its
creator's user identity and role plus zero or more of the fixed device tags
`office`, `ranger`, and `store` to the enrolled node.

The current HMAC keyring contains one key, so rotation needs a brief management
outage: stop console traffic, wait 65 seconds for every old assertion to expire,
replace `BLAKTAIL_AUTH_HMAC_SECRET` with the same new random value on coordinator
and console, restart coordinator then console, and verify one read plus one audited
write. Never rotate only one side. Already consumed nonces remain hashed in the selected database
until their expiry cleanup; restarting either service does not make a captured
assertion reusable.

ACL JSON uses optional `groups` plus `rules`. A group is a lowercase name mapped to
people (login emails and/or the user ids stored on enrolled nodes). Rules use
`action` (`allow` or `deny`) and optional `src_roles`, `src_tags`, `src_groups`,
`dst_roles`, `dst_tags`, and `dst_groups` arrays. A blank selector matches all.
Explicit deny wins over allow. Without a matching rule, tagged nodes can see only
peers sharing a tag (default deny across tags); legacy untagged nodes can see other
untagged nodes.
Peer results include a stable MagicDNS name in the form `<node>.<org-prefix>.blaktail`.
They include approved subnet CIDRs in that router peer's `allowed_ips`. An approved
`0.0.0.0/0` is returned only when the requesting node supplies a matching
`exit_node` query value; merely approving an exit node never changes every client's
default route. Non-default advertisements must be canonical, network-aligned RFC1918
private IPv4 subnets. A node may advertise at most 32 routes; routes cannot overlap
the tailnet pool or another active node's approved subnet. Approving a replacement
router removes overlapping approval from expired routers, preventing stale approval
from reviving after credential renewal.
They also include a node-reported relay-socket candidate only while its coordinator
timestamp is less than 180 seconds old. Agents use that candidate for a bounded,
nonce-confirmed UDP hole punch while keeping relayed WireGuard traffic available.

## Storage schemas

The canonical current schema is [`blaktail-coord/schema.sql`](../blaktail-coord/schema.sql).
It is applied only through the versioned migration runner. Its principal tables are:

```sql
CREATE TABLE orgs (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
  acl_json TEXT NOT NULL, created_at TEXT NOT NULL,
  node_key_ttl_seconds INTEGER NOT NULL DEFAULT 7776000);
CREATE TABLE join_keys (id TEXT PRIMARY KEY, org_id TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL,
  single_use INTEGER NOT NULL, used_at TEXT, revoked_at TEXT, created_at TEXT NOT NULL);
CREATE TABLE device_authorizations (id TEXT PRIMARY KEY,
  device_code_hash TEXT NOT NULL UNIQUE, user_code_hash TEXT NOT NULL UNIQUE,
  requested_name TEXT NOT NULL, wg_public_key TEXT NOT NULL,
  expires_at INTEGER NOT NULL, approved_at INTEGER, consumed_at INTEGER,
  last_polled_at INTEGER,
  org_id TEXT, user_id TEXT, user_role TEXT, tags_json TEXT NOT NULL);
CREATE TABLE nodes (id TEXT PRIMARY KEY, org_id TEXT NOT NULL, name TEXT NOT NULL,
  wg_public_key TEXT NOT NULL, endpoint TEXT, allowed_ips_json TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, revoked_at TEXT,
  advertised_routes_json TEXT NOT NULL, approved_routes_json TEXT NOT NULL,
  credential_expires_at INTEGER NOT NULL, relay_endpoint TEXT,
  relay_endpoint_updated_at INTEGER);
CREATE TABLE audit_events (id TEXT PRIMARY KEY, org_id TEXT NOT NULL,
  actor_user_id TEXT NOT NULL, actor_name TEXT NOT NULL,
  actor_email TEXT NOT NULL, actor_role TEXT NOT NULL, action TEXT NOT NULL,
  target_type TEXT NOT NULL, target_id TEXT, details_json TEXT NOT NULL,
  created_at INTEGER NOT NULL);
CREATE TABLE console_assertion_nonces (
  jti_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
CREATE TABLE pending_bootstrap_orgs (id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE, acl_json TEXT NOT NULL,
  node_key_ttl_seconds INTEGER NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
```

The full schema includes foreign keys, JSON checks, uniqueness constraints, and indexes.
PostgreSQL uses the matching ordered files in
[`blaktail-coord/migrations/postgres`](../blaktail-coord/migrations/postgres); IDs
and JSON remain text at the storage boundary so both backends share one query path.
