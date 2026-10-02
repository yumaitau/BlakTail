# Operator configuration

BlakTail configuration schema v1 is defined by
[`config/schema-v1.json`](../config/schema-v1.json), implemented by the
`blaktail-config` crate, and illustrated by
[`config/blaktail.toml.example`](../config/blaktail.toml.example). Coordinator,
relay, agent, and console containers all ship the same `blaktail-config` binary.

## Precedence and failure behavior

Effective values are resolved in this fixed order:

1. schema defaults;
2. the TOML file selected by `--config` or `BLAKTAIL_CONFIG`;
3. documented environment overrides;
4. non-secret legacy daemon flags, when a daemon was launched with them.

An explicit TOML file must contain `schema_version = 1`. Unknown TOML fields,
unknown schema versions, malformed environment values, and simultaneous canonical
and deprecated aliases are errors. Deprecated aliases warn for schema v1 and will
be removed in schema v2.

Every daemon resolves and validates configuration before opening a listener,
changing the network, or opening coordinator state. Coordinator schema changes
run only through `blaktail-coord migrate`; `serve` opens an already-migrated
database and fails otherwise. Console migrations likewise run only through the
explicit Drizzle migration command, never from the normal image command.

## TOML field reference

`Required` means validation fails when the selected service has no effective
value. Defaults apply when a section or field is absent.

| Field | Default or requirement | Contract |
| --- | --- | --- |
| `deployment.profile` | `production` | `production`, `development`, or guarded `e2e` |
| `diagnostics.log_filter` | `info` | Non-empty tracing filter; daemon-reloadable |
| `diagnostics.support_log_lines` | `200` | 1-500; daemon-reloadable |
| `coordinator.region` | Required | Approved Australian region |
| `coordinator.bind` | `0.0.0.0:8443` | IP socket, non-zero port |
| `coordinator.metrics_bind` | `127.0.0.1:9701` | Loopback unless exposure acknowledged |
| `coordinator.allow_public_metrics` | `false` | Non-loopback acknowledgement |
| `coordinator.diagnostics_token` | Required for acknowledged exposure | Secret reference, at least 32 bytes |
| `coordinator.database_backend` | `sqlite` | `sqlite` for one coordinator, or `postgres` for concurrent replicas |
| `coordinator.database` | `blaktail-coord.sqlite3` | Non-empty path when the backend is SQLite; systemd example uses isolated `/var/lib/blaktail-coord` |
| `coordinator.database_url` | Required for PostgreSQL | Secret reference containing a `postgres://` or `postgresql://` URL; never accepted on argv |
| `coordinator.database_storage` | `local` | `local` or guarded E2E-only `efs` for SQLite; `network` for PostgreSQL |
| `coordinator.allow_unsafe_efs_sqlite` | `false` | Valid only with E2E profile and EFS storage |
| `coordinator.tls_mode` | `files` | Only file-backed TLS exists in schema v1 |
| `coordinator.tls_cert` | Required | Readable certificate path |
| `coordinator.tls_key` | Required | Secret file reference |
| `coordinator.auth_hmac_secret` | Required | Console assertion secret, at least 32 bytes |
| `coordinator.relay_auth_secret` | Required when relays exist | Relay capability secret, at least 32 bytes |
| `coordinator.relays` | Empty list | UDP host/IP and non-zero port entries in priority order; optional `#region` suffix (for example `relay-a.example.org.au:3478#australiaeast`) must be an approved Australian region, untagged entries inherit `coordinator.region` |
| `coordinator.console_url` | Required | HTTPS URL, except loopback development |
| `relay.region` | Required | Approved Australian region |
| `relay.bind` | `0.0.0.0:3478` | UDP IP socket, non-zero port |
| `relay.metrics_bind` | `127.0.0.1:9702` | Loopback unless exposure acknowledged |
| `relay.allow_public_metrics` | `false` | Non-loopback acknowledgement |
| `relay.diagnostics_token` | Required for acknowledged exposure | Secret reference, at least 32 bytes |
| `relay.auth_secret` | Required | Relay capability secret, at least 32 bytes |
| `relay.idle_seconds` | `120` | 10-86400 |
| `relay.rate_per_second` | `100` | 1-100000 |
| `relay.rate_burst` | `200` | Sustained rate or greater, maximum 1000000 |
| `agent.state_dir` | `/var/lib/blaktail` | Absolute path |
| `agent.coordinator_url` | Required by `up` unless flag supplied | HTTPS URL, except loopback development |
| `agent.interface` | `blaktail0` | 1-15 characters |
| `agent.poll_seconds` | `30` | 1-3600; recovery interval when the 25s control long-poll fails. Agents request control `version=2` so the coordinator can send a coalesced peer delta instead of a full snapshot. |
| `agent.advertised_routes` | Empty list | IPv4/IPv6 CIDRs |
| `console.region` | Required | Approved Australian region |
| `console.port` | `3000` | 1-65535 |
| `console.database_url` | Required | Secret PostgreSQL URL reference |
| `console.base_url` | Required | Exact HTTPS origin, except loopback development |
| `console.trusted_origins` | Required | Exact origins; must include base origin |
| `console.coordinator_url` | Required | HTTPS URL, except loopback development |
| `console.coordinator_ca_file` | Optional | Absolute readable CA path |
| `console.auth_secret` | Required | Better Auth secret, at least 32 bytes |
| `console.coordinator_auth_secret` | Required | Coordinator assertion secret, at least 32 bytes |

## Secrets

TOML accepts only `file:/absolute/path` secret references. It never accepts a
literal password, token, key, cookie, or database URL. Container platforms may
inject a secret through the matching value environment variable or its `_FILE`
variant, but setting both is an ambiguity error. The loader copies only documented
environment keys, retains only referenced secret overrides, and zeroes its secret
buffers on drop. Values remain omitted from debug output and appear only as
`<redacted:file>` or `<redacted:environment>` in dumps.

Do not pass secrets as daemon flags. `blaktail-coord` and `blaktail-relay` no
longer define secret-valued CLI options. The coordinator container adapter accepts
`BLAKTAIL_TLS_CERT_PEM` and `BLAKTAIL_TLS_KEY_PEM`, writes mode-0600 temporary
material, and passes file references to the daemon. The console image uses an
internal `run-console` adapter so effective TOML values and file-backed secrets
become the Node child's expected environment without printing them.

## Commands

These commands are offline: they open no listener, run no migration, and make no
network call.

```sh
blaktail-config --config /etc/blaktail/config.toml check-config --service coordinator
blaktail-config --config /etc/blaktail/config.toml dump-config --service coordinator --redacted
blaktail-config --config /etc/blaktail/config.toml reload-check \
  --service coordinator --candidate /etc/blaktail/config.next.toml
```

Non-redacted dump output is deliberately unsupported. Dumps include final values,
the source of each effective field (`default`, `file`, or environment variable),
and deprecation warnings.

Coordinator migration is a separate operator gate:

```sh
blaktail-config --config /etc/blaktail/config.toml check-config --service coordinator
blaktail-coord --config /etc/blaktail/config.toml migrate
blaktail-coord --config /etc/blaktail/config.toml serve
```

## Validation contract

Validation returns field paths and all detected errors in one run. Schema v1
checks:

- approved Australian region identifiers;
- valid IP socket binds and non-zero ports;
- loopback-only metrics by default; explicit public exposure requires a separate
  32-byte diagnostics token;
- HTTPS URLs and exact trusted origins, allowing HTTP only for loopback
  development;
- TLS file mode, certificate/key references, and contradictory TLS settings;
- separate 32-byte console assertion, relay capability, Better Auth, and
  diagnostics secrets;
- relay endpoint host/port form and rate/idle ranges;
- absolute state paths, WireGuard interface length, polling range, and IPv4/IPv6
  advertised CIDRs;
- PostgreSQL console and coordinator URLs without printing their contents;
- SQLite storage safety. `database_storage = "efs"` is rejected except for an
  explicitly labelled `e2e` profile with `allow_unsafe_efs_sqlite = true`.

That EFS exception is smoke-only. Persistent multi-replica deployments use the
PostgreSQL backend; labelling a long-lived deployment `e2e` is not supported.
MagicDNS suffixes remain coordinator-derived and are not operator-configurable.
Organisation split DNS, upstreams, search domains, and extra records are a
separate published snapshot; see [org-dns.md](org-dns.md).

## Reload

`SIGHUP` makes coordinator, relay, and agent re-read the same file and environment.
Only `diagnostics.log_filter` and `diagnostics.support_log_lines` are atomically
reloadable in schema v1. Any bind, TLS, database, identity, relay, route, region,
secret-reference, or in-place secret-content change returns an exact
restart-required field list and leaves the active snapshot unchanged. Private
secret fingerprints are never dumped. Invalid candidates also leave the active
snapshot unchanged. Packaged systemd units map `systemctl reload` to `SIGHUP`.
Console changes require restart.

## Health and diagnostics

Coordinator public endpoints expose no region, version, path, database error,
organisation, or peer data:

- `/livez`: process liveness;
- `/readyz`: required database query and exact schema-version readiness;
- `/health`: compatibility alias for readiness.

Relay exposes minimal `/livez` and `/readyz` responses on its metrics listener.
Metrics and `/diagnostics/readiness` stay on loopback by default. If public metrics
are explicitly enabled, bearer authentication with the service-specific
diagnostics token is mandatory. Infrastructure security groups remain required;
the token is not a replacement for network isolation.

## Support bundles

Support export is a two-step local operator action. Preview first:

```sh
blaktail-config --config /etc/blaktail/config.toml support-bundle \
  --service coordinator --log-file /var/log/blaktail/coord.log
```

Review service, listeners, and log count, then pass the printed digest unchanged:

```sh
blaktail-config --config /etc/blaktail/config.toml support-bundle \
  --service coordinator --log-file /var/log/blaktail/coord.log \
  --output ./blaktail-support.json --confirm SHA256_FROM_PREVIEW
```

The mode-0600 JSON bundle contains CLI/schema versions, offline readiness scope,
configured listener summary, redacted effective configuration, and at most 500
bounded log lines. Redaction removes bearer credentials, secret-like assignments,
database URLs, enrollment codes, email addresses, UUIDs, and IPv4/IPv6 addresses.
It never includes packets, database dumps, raw DNS queries, cookies, join keys, or
private keys. Review the generated file before sharing it.

## Environment overrides

Lists are comma-separated. Boolean values accept `true`/`false`, `yes`/`no`, or
`1`/`0`. Secret pairs are mutually exclusive.

| Environment variable | Effective field | Notes |
| --- | --- | --- |
| `BLAKTAIL_CONFIG` | config file | Common path selector |
| `BLAKTAIL_DEPLOYMENT_PROFILE` | `deployment.profile` | `production`, `development`, or `e2e` |
| `RUST_LOG` | `diagnostics.log_filter` | Atomically reloadable |
| `BLAKTAIL_SUPPORT_LOG_LINES` | `diagnostics.support_log_lines` | 1-500 |
| `BLAKTAIL_REGION` | coordinator, relay, and console `region` | Australian allow-list |
| `BLAKTAIL_BIND` | `coordinator.bind` | IP socket |
| `BLAKTAIL_COORD_METRICS_BIND` | `coordinator.metrics_bind` | Loopback by default |
| `BLAKTAIL_COORD_ALLOW_PUBLIC_METRICS` | `coordinator.allow_public_metrics` | Requires diagnostics token |
| `BLAKTAIL_COORD_DIAGNOSTICS_TOKEN` / `BLAKTAIL_COORD_DIAGNOSTICS_TOKEN_FILE` | `coordinator.diagnostics_token` | Secret pair |
| `BLAKTAIL_DATABASE_BACKEND` | `coordinator.database_backend` | `sqlite` or `postgres` |
| `BLAKTAIL_DATABASE` | `coordinator.database` | Canonical path |
| `BLAKTAIL_DB_PATH` | `coordinator.database` | Deprecated schema-v1 alias; conflicts with canonical variable |
| `BLAKTAIL_DATABASE_URL` / `BLAKTAIL_DATABASE_URL_FILE` | `coordinator.database_url` | Secret pair for the PostgreSQL backend |
| `BLAKTAIL_DATABASE_STORAGE` | `coordinator.database_storage` | SQLite `local`/guarded `efs`, or PostgreSQL `network` |
| `BLAKTAIL_ALLOW_UNSAFE_EFS_SQLITE` | `coordinator.allow_unsafe_efs_sqlite` | E2E-only acknowledgement |
| `BLAKTAIL_TLS_MODE` | `coordinator.tls_mode` | `files` only in v1 |
| `BLAKTAIL_TLS_CERT` | `coordinator.tls_cert` | Certificate path |
| `BLAKTAIL_TLS_KEY` | `coordinator.tls_key` | Private-key file reference |
| `BLAKTAIL_TLS_CERT_PEM` / `BLAKTAIL_TLS_KEY_PEM` | container TLS adapter | Converted to file references before validation |
| `BLAKTAIL_AUTH_HMAC_SECRET` / `BLAKTAIL_AUTH_HMAC_SECRET_FILE` | coordinator/console assertion secret | Secret pair |
| `BLAKTAIL_RELAY_AUTH_SECRET` / `BLAKTAIL_RELAY_AUTH_SECRET_FILE` | coordinator/relay capability secret | Secret pair |
| `BLAKTAIL_RELAYS` | `coordinator.relays` | Comma-separated UDP endpoints |
| `BLAKTAIL_BACKUP_PROOF_FILE` | (coordinator environment only) | Optional path to the operator's backup marker JSON shown on Operator health; see [upgrades.md](upgrades.md#record-the-backup-proof) |
| `BLAKTAIL_CONSOLE_URL` | `coordinator.console_url` | HTTPS except loopback |
| `BLAKTAIL_RELAY_BIND` | `relay.bind` | UDP IP socket |
| `BLAKTAIL_RELAY_METRICS_BIND` | `relay.metrics_bind` | Loopback by default |
| `BLAKTAIL_RELAY_ALLOW_PUBLIC_METRICS` | `relay.allow_public_metrics` | Requires diagnostics token |
| `BLAKTAIL_RELAY_DIAGNOSTICS_TOKEN` / `BLAKTAIL_RELAY_DIAGNOSTICS_TOKEN_FILE` | `relay.diagnostics_token` | Secret pair |
| `BLAKTAIL_RELAY_IDLE_SECONDS` | `relay.idle_seconds` | 10-86400 |
| `BLAKTAIL_RELAY_RATE_PER_SECOND` | `relay.rate_per_second` | 1-100000 |
| `BLAKTAIL_RELAY_RATE_BURST` | `relay.rate_burst` | At least sustained rate |
| `BLAKTAIL_AGENT_STATE_DIR` | `agent.state_dir` | Absolute path |
| `BLAKTAIL_AGENT_COORD_URL` | `agent.coordinator_url` | Canonical URL |
| `BLAKTAIL_COORDINATOR_URL` | `agent.coordinator_url` | Deprecated schema-v1 alias |
| `BLAKTAIL_AGENT_INTERFACE` | `agent.interface` | 1-15 characters |
| `BLAKTAIL_AGENT_POLL_SECONDS` | `agent.poll_seconds` | 1-3600 |
| `BLAKTAIL_AGENT_ADVERTISE_ROUTES` | `agent.advertised_routes` | Comma-separated CIDRs |
| `DATABASE_URL` / `DATABASE_URL_FILE` | `console.database_url` | Secret PostgreSQL URL pair |
| `BLAKTAIL_REGION` | `console.region` | Same residency boundary |
| `PORT` | `console.port` | 1-65535 |
| `BETTER_AUTH_URL` | `console.base_url` | Exact public origin |
| `BETTER_AUTH_TRUSTED_ORIGINS` | `console.trusted_origins` | Comma-separated exact origins |
| `COORD_BASE_URL` | `console.coordinator_url` | HTTPS except loopback |
| `NODE_EXTRA_CA_CERTS` | `console.coordinator_ca_file` | Optional CA path |
| `BETTER_AUTH_SECRET` / `BETTER_AUTH_SECRET_FILE` | `console.auth_secret` | Secret pair |

Run `blaktail-config schema` for the same machine-readable environment map.

## Schema lifecycle

Schema v1 is the initial contract. A field is warned as deprecated for at least one
release before removal. A newer `schema_version` always fails closed; operators
must upgrade the binary before using a newer file. Release notes must list added,
deprecated, removed, and restart-required fields.
