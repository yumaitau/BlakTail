# Upgrade and version-skew policy

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
