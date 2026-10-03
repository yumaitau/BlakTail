# Upgrade and version-skew policy

Which versions work together, and what rollback can undo, is in
[compatibility.md](compatibility.md).

BlakTail is pre-1.0. The only unconditional compatibility guarantee is that the
coordinator, relay, console, and agents use the same release tag. Arbitrary version
skew is unsupported.

For a rolling upgrade, a release may explicitly support the immediately previous
agent release for 30 days. Its release notes must name that compatibility window;
silence means same-version only. This is an operator-enforced policy because the
current protocol does not negotiate a semantic version. Current additive IPv6 peer
data is capability-gated with `?ipv6=true`, so the version-one schema migration does
not force IPv6 routes onto older agents.

The coordinator defines a minimum supported agent version
(`MINIMUM_AGENT_VERSION` in `blaktail-coord/src/peer_lifecycle.rs`, currently
`0.1.0`). The console device detail page flags agents that report an older
version and links here. Raise it in the release that breaks compatibility.

Agents built after October 2026 no longer accept `--join-key`; pipe the key on
stdin or set `BLAKTAIL_JOIN_KEY`. Update automation before upgrading agents.
They also report a measured transport summary (`direct`, `relay`, `mixed`) with
each peer-map heartbeat; older agents show "not measured" in the console.

Upgrade in this order:

1. Back up console Postgres, the configured coordinator store, configuration, and TLS material.
2. Run `blaktail-config check-config` and `dump-config --redacted`. Preview the
   reload plan; stop if any undocumented field or deprecation appears.
3. Run `blaktail-coord migrate` as a separate stopped-service gate, then upgrade
   one coordinator and its relay. Check `/livez`, `/readyz`, authenticated metrics,
   and peer polling before continuing.
4. Upgrade one canary agent. Confirm IPv4, IPv6, MagicDNS, direct/relay paths, and
   persisted enrollment after a service restart.
5. Upgrade remaining agents in small batches. End any advertised skew window within
   30 days.
6. Run console Drizzle migrations as a separate stopped-service gate, then upgrade
   the console tasks.

The Debian and RPM packages do not restart or enable `blaktaild` automatically:

```sh
sudo BLAKTAIL_VERSION=0.1.1 sh install-agent.sh
sudo systemctl restart blaktaild
sudo blaktaild status
```

On macOS, install the pinned package, then restart the existing LaunchDaemon and
check status. Enrollment state remains under `/var/lib/blaktail` and is not part of
the package.

Coordinator migrations run only through `blaktail-coord migrate`. SQLite uses one
transaction per schema step and `PRAGMA user_version`; PostgreSQL uses one
transaction, an advisory lock, and `coordinator_schema_migrations`. Normal `serve`
startup never migrates and refuses missing, older, newer, or gapped schema state.
Database downgrade is unsupported: restore the pre-upgrade snapshot with the old
binary. Agent rollback is supported only when that release's notes confirm its state
format is compatible.

## Live upgrade drill (3 October 2026)

`deploy/homelab/prove-upgrade.sh` rehearses steps 3 to 5 on one Docker host
(`docker --context m3-max`, OrbStack, Linux). For SQLite and then PostgreSQL 16
it starts the round-1 coordinator (`main` at `cab5fe4`, schema 28) with two
round-1 Linux agents on kernel WireGuard, seeds a policy (2 groups, tag owners,
a named host, 6 rules, 1 SSH rule), a friendly name, an approved subnet route
(`10.77.0.0/24`), one-use, reusable and revoked join keys, an API client and an
open change draft, and snapshots everything through the console API. It then
stops the old coordinator, runs this tree's `blaktail-coord migrate` and
`serve` on the same database, and compares.

```sh
BACKENDS="sqlite postgres" deploy/homelab/prove-upgrade.sh
```

| Check | SQLite | PostgreSQL 16 |
| --- | --- | --- |
| Schema before → after | 28 → 40 | 28 → 40 |
| Coordinator stop → `/readyz` (migrate included) | 2 s | 2 s |
| Pre-upgrade API fields unchanged (2 devices with detail, policy and revision, DNS, 4 join keys, 1 API client, 1 draft) | yes | yes |
| Round-1 agents reach each other after the upgrade (ping, TCP 8080) | 2 s | 2 s |
| Approved route still distributed | yes | yes |
| Agents replaced by this release's binary, `blaktaild run` | ping/TCP after 2–7 s, reverse ping | same |
| State after agent upgrade | unchanged except newly reported capabilities (`pq-psk`) | same |

Whole run for both backends: about 3 minutes 15 seconds including image builds
from cache. Only liveness fields (last seen, heartbeat age, server time,
credential renewal) were excluded from the comparison; the full list is printed
by the script.

The drill found one round-1 bug, fixed in this release: approving or
withdrawing a device's subnet route (console and `/api/v1/devices/{id}/routes`)
did not bump the organisation's control revision, so long-polling clients and
the router's forward filter did not learn the change until an unrelated policy
or device change. After the fix the lab sees a withdrawal and a re-approval
reach the client within one poll (under a second). Round-1 coordinators still
have the bug; until upgraded, republish the policy after a route approval.

Not covered: console (Drizzle) migrations and Better Auth sign-in, relays,
macOS and mobile agents, failed-migration rollback, and restore into a new
environment.

## Backup and restore

This runbook covers what an operator must back up and how to prove a restore.
BlakTail does not run backups for you; the numbers below are targets you set
and prove, not guarantees the software makes.

### What to back up, together

| Data | Where | Notes |
| --- | --- | --- |
| Console identity (people, memberships, sessions, SSO providers, invitations) | Console Postgres | Holds OIDC client secrets; encrypt the backup |
| Coordinator state (organisations, devices, keys' public halves, policy, DNS, audit, outbox) | Coordinator SQLite file or Postgres | Node tokens are stored hashed; sealed service CA keys need the coordinator secret to open |
| Secrets | `BLAKTAIL_AUTH_HMAC_SECRET`, `BLAKTAIL_RELAY_AUTH_SECRET`, `BETTER_AUTH_SECRET`, database credentials, TLS keys | Store in your secret manager, separately from data backups |
| Configuration | `blaktail.toml`, env files, Compose/Terraform | Version-controlled, without secrets |
| Logs and object stores you added | Your log platform | Only if your retention policy requires them |

Take the console and coordinator backups at the same point in time (stop
writes, or snapshot both within the same minute). A console backup newer than
the coordinator can show devices the coordinator no longer knows, and the
reverse.

### Recovery objectives

Set and write down, per deployment:

- **RPO** (how much change you can lose): equal to your backup interval. With
  nightly `pg_dump` it is up to 24 hours of enrolments, policy edits and audit
  events. Devices enrolled after the backup must re-enrol after a restore.
  Managed PostgreSQL with point-in-time recovery (PITR) can lower this to
  minutes; SQLite file copies cannot.
- **RTO** (how long until people can connect again): the time to provision a
  database, restore, start coordinator and console, and pass the checks below.
  Measure it in a drill; do not quote a number you have not timed. Existing
  WireGuard tunnels keep their last configuration while the coordinator is
  down, so already-connected devices usually keep working during the outage;
  new enrolments, policy changes and credential renewals wait.

### Residency

Keep backups, snapshots, PITR logs and secret-manager copies in Australian
regions you control. BlakTail cannot see or enforce where your backup tooling,
DNS provider, IdP, telemetry or support channels store data; those are your
choices and need their own residency review. Do not describe a deployment as
onshore unless each of them is.

### Record the backup proof

After each successful backup, have the backup job write a small JSON marker
readable by the coordinator and point `BLAKTAIL_BACKUP_PROOF_FILE` at it:

```json
{"completed_at": 1790000000, "restore_verified_at": 1789900000, "label": "nightly pg_dump"}
```

`completed_at` and `restore_verified_at` are Unix seconds. The **Operator
health** page (owners and auditors) shows these times and the label; it never
shows paths, bucket names or keys, and labels are reduced to letters, digits,
spaces, `.`, `_` and `-`. Without the variable the page says "not recorded".
The marker is the operator's claim: BlakTail does not open or verify the backup.

### Restore drill

1. Restore both databases into **new, empty** databases in a private
   environment. Never overwrite the source.
2. Start the coordinator with the restored database and the original
   `BLAKTAIL_AUTH_HMAC_SECRET` and `BLAKTAIL_RELAY_AUTH_SECRET`; start the
   console against the restored console database.
3. Confirm `/readyz`, then open **Operator health**: schema must show
   "Current", and relay probes must succeed.
4. Sign in as an owner through the restored console. Counting rows is not a
   restore test.
5. Enrol or reconnect two test devices against the restored coordinator and
   prove two-way reachability (the [two-node drill](two-node-drill.md)).
6. Record the elapsed time as your measured RTO and update
   `restore_verified_at` in the marker.
7. Destroy the recovery environment, including its copies of secrets.

Export and deletion: an organisation's data can be exported with the audit
export and `/api/v1` inventory endpoints. Deleting an organisation from the
live databases does not remove it from earlier backups; expire backups on a
schedule that matches your retention promise.
