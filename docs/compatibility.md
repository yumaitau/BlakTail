# Version compatibility and rollback

BlakTail is pre-1.0. This page states what is supported between components and
what a rollback can and cannot undo. When this page and a release's notes
disagree, the release notes win; silence in the notes means "same version only".

## Matrix

| From \ talks to | Console | Coordinator | Relay | Agents (Linux, macOS, Windows*) | iPhone / Android* |
| --- | --- | --- | --- | --- | --- |
| **Console N** | — | N only | — | — | N only (desktop/phone bridge) |
| **Coordinator N** | N only | — | Any relay sharing the capability secret | N; N−1 only if the release notes name a window (max 30 days) | N; N−1 only if named |
| **Relay N** | — | Shares only the capability secret; same release recommended | — | Same release; relay frames carry no version field | Same release |

\* Windows and Android are experimental (see [platform-support.md](platform-support.md)).

Rules behind the table:

- **Coordinator and console move together.** The console signs assertions the
  coordinator verifies and calls routes added in the same release. Upgrade the
  coordinator first, then the console.
- **Agents tolerate newer coordinators only additively.** New response fields
  are optional (`#[serde(default)]`): for example `relay_endpoints` (declared
  relay regions) is ignored by older agents, which keep using `relays`. An
  older agent therefore does not apply Australian-region filtering on its own;
  the coordinator still never advertises an offshore relay.
- **Minimum agent version.** `MINIMUM_AGENT_VERSION` in
  `blaktail-coord/src/peer_lifecycle.rs` (currently `0.1.0`) is flagged in the
  console. Raise it in the release that breaks agent compatibility.
- **Relays are stateless** apart from in-memory registrations. Restarting or
  replacing a relay drops registrations; agents re-register within 30 seconds.

## Schema changes: expand, then contract

Coordinator migrations are forward-only and numbered (`PRAGMA user_version` on
SQLite, `coordinator_schema_migrations` on PostgreSQL). Releases follow
expand/contract:

1. **Expand** (release N): add tables or nullable/defaulted columns. Code in N
   writes both old and new shapes where a later release will drop the old one.
2. **Migrate data** inside the same numbered migration, in one transaction.
3. **Contract** (release N+1 or later): drop or tighten only after every
   supported coordinator replica runs code that no longer reads the old shape.

`serve` refuses a database whose schema is older, newer or gapped compared with
the binary, so a half-upgraded fleet fails closed instead of corrupting data.
The operator health page shows applied and supported schema versions.

Proof in code: `schema_18_database_upgrades_without_losing_devices_ownership_or_policy`
(`blaktail-coord/src/tests/operations.rs`) builds a database exactly as schema 18
left it, migrates it to the current schema and reads devices, ownership, tags,
approved routes, join-key limits and policy back through the console API. That
is a disposable in-memory proof; it is not a substitute for rehearsing the
upgrade on a restored copy of your own database.

Live proof (3 October 2026, `deploy/homelab/prove-upgrade.sh`): a database
written by the round-1 release (`main` at `cab5fe4`, schema 28) on SQLite and
on PostgreSQL 16 was migrated in place to schema 40 and served by the new
coordinator. Round-1 Linux agents (`blaktaild` built from `cab5fe4`) kept
reaching each other through the new coordinator without re-enrolling, and
again after their binary was replaced by this release's agent (`blaktaild run`,
persisted enrolment). That is one observed N−1 pairing on Linux, not a
declared compatibility window; see [upgrades.md](upgrades.md#live-upgrade-drill-3-october-2026).

## Rollback limits

| Component | Roll back by | Limit |
| --- | --- | --- |
| Coordinator binary, same schema | Redeploy the previous binary | Only if the previous release supports the same schema version (check `/v1/orgs/:org/operations/health` → `schema.supported_version`) |
| Coordinator after a migration | Restore the pre-upgrade database snapshot and run the previous binary | Database downgrade is unsupported; anything written after the snapshot is lost (see RPO in [upgrades.md](upgrades.md#backup-and-restore)) |
| Console | Previous image plus restored console Postgres if its Drizzle migrations ran | Drizzle migrations are forward-only |
| Relay | Previous image | None beyond dropped registrations |
| Agent | Previous package | Only when that release's notes say the local state format is compatible; enrolment state in `/var/lib/blaktail` is not part of the package |

A failed migration rolls back its own transaction (SQLite per step, PostgreSQL
the whole run under an advisory lock), so the database stays at the last
complete version. Rehearse in a disposable clone before production.
