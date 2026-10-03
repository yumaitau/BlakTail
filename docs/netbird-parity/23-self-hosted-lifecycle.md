# Release-ready self-hosted control plane: upgrades, backup, observability and documented HA

**Priority:** P0 release, P1 operations UI. **Depends on:** existing #27/#33/#34 and #41 configuration. **Area:** deployment, packaging, operator diagnostics.

## Gap and outcome

NetBird documents self-hosting versus managed operation and provides client installation paths. BlakTail is source-build pre-release: its Sydney AWS smoke proved a particular commit, Postgres coordinator HA and backup restore, not published release or generic self-hosted upgrade safety. A Status page reports coordinator availability, not operational readiness.

## Scope

- Publish reproducible signed releases and clean-host installs; version compatibility matrix for console/coordinator/relay/agents, staged migration, expand/contract schema, rollback constraints and disaster recovery. Prove on Linux and macOS Compose and guarded Sydney production-shaped environment separately.
- Onshore backup/restore for console identity plus coordinator state, logs and object stores; verify encryption, PITR, secrets rotation, RPO/RTO and data export/deletion. No automatic residency claim for operator-selected DNS, telemetry, IdP or support.
- Protected operator health view for component version, DB migration, queue/outbox, relay capacity, cert expiry, DNS/SSO and last backup proof, with role-safe redaction and no key material. Keep public `/status` narrow.

## Acceptance / proof

Version N to N+1 and failed migration rollback in disposable clone preserve devices, memberships and policy. Restore into new private environment and prove login plus two-node reachability, not just SQL counts. Signed package downloaded and installed on clean hosts; support bundle contains no secrets. Failure injection validates HA and recovery documentation.

**Evidence:** `docs/releases.md`, `docs/project-status.md`, `docs/e2e/aws-fargate-run.md`, `apps/console/src/app/status/page.tsx`; https://docs.netbird.io/about-netbird/self-hosted-vs-cloud.

## Status (2 October 2026)

**Done:**
- Protected operator health view: `GET /v1/orgs/:org_id/operations/health`
  (`blaktail-coord/src/operations.rs`), console-session auth with new
  `view_operations` permission (owner and auditor only; admin, network admin and
  member get 403). Reports coordinator version/region/backend, applied vs
  supported schema and latest migration name, relay list with declared region
  and an authenticated REGISTER+PING probe from the coordinator, this
  organisation's webhook outbox (pending, due, dead letters, oldest age),
  expiry counts (node credentials, service certificates and CA, automation
  clients), and the operator's backup marker (`BLAKTAIL_BACKUP_PROOF_FILE`,
  timestamps plus a sanitised label only). Public `/status` is unchanged.
- Console page `/operations` ("Operator health", Settings group) adds console
  version, Drizzle migrations applied vs packaged, and per-org SSO provider
  counts (no issuer, client id or secret).
- Migration helper `apply_sqlite_migrations_to(pool, target)` and an upgrade
  test from a schema-18 database.
- Release engineering: Sigstore keyless `cosign sign-blob` of `SHA256SUMS` in
  `agent-release.yml` (verified before upload and after re-download), optional
  or required (`BLAKTAIL_REQUIRE_SIGNATURE=1`) verification in
  `scripts/install-agent.sh`, `SOURCE_DATE_EPOCH`, `CARGO_INCREMENTAL=0` and
  `--remap-path-prefix` pinned for builds.
- Docs: `docs/compatibility.md` (version matrix, expand/contract, rollback
  limits), signing and reproducibility in `docs/releases.md`, backup/restore
  runbook with RPO/RTO and residency limits in `docs/upgrades.md`.

**Proven by tests:**
- `tests::operations::operator_health_is_owner_and_auditor_only_org_scoped_and_redacted`
  (role gating, missing token 401, another org's owner 401, only this org's
  outbox counted, real relay reachable and closed port unreachable, offshore
  relay never listed, no secrets/webhook URLs/node tokens in the body).
- `tests::operations::schema_18_database_upgrades_without_losing_devices_ownership_or_policy`
  (devices, ownership, tags, approved routes, revocation, join-key limit and
  ACL read back through the console API after migrating 18 → current).
- `operations::tests::backup_proof_reports_only_timestamps_and_a_safe_label`,
  `permissions::tests::matrix_matches_shared_fixture`, console `roles.test.mjs`.

**Still needs live/field proof or a decision:**
- No release tag has been cut, so signed packages, the Sigstore bundle and
  clean-host installs on Linux and macOS are unproven; bit-for-bit
  reproducibility by an independent builder is not demonstrated.
- Failed-migration rollback and restore into a new private environment with
  login and two-node reachability must be drilled on real infrastructure;
  PostgreSQL upgrade from 18 is covered only by the existing optional
  Postgres test, not by a schema-18 fixture.
- Relay and agent versions are not reported to the coordinator; the TLS
  certificate of the coordinator is not inspected. Support bundle, HA failure
  injection and Compose-on-macOS proofs remain open.

### Live lab (3 October 2026)

**Proven live:** `deploy/homelab/prove-clean-install.sh` (Docker context `m3-max`, 245 s) builds the release packages with `deploy/docker/agent-package.Dockerfile`, serves them from a lab HTTPS release server, and runs the unmodified `scripts/install-agent.sh` on fresh `debian:bookworm` and `ubuntu:24.04` systemd containers. A tampered package, `BLAKTAIL_REQUIRE_SIGNATURE=1` without cosign, and (cosign v2.4.1 installed) a bundle that does not verify were all refused before anything was installed; the genuine package installed through the checksum path (6 s Debian, 13 s Ubuntu). Debian enrolled with the join key on stdin, Ubuntu with `BLAKTAIL_JOIN_KEY`; about 1,200 snapshots of every `/proc/*/cmdline` per host, taken every 50 ms during enrolment, never contained the key. Under `blaktaild.service` the hosts pinged each other over the overlay, again after `systemctl restart` with unchanged addresses; owner revocation of Ubuntu removed it from Debian's peers within 1 s and cut traffic both ways; uninstall left no binary, unit, state, interface, iptables chain or policy rule, and both nodes show as revoked.
**Bugs found and fixed:** `install-agent.sh` used bare `dpkg -i`, which leaves the package unconfigured on a host without its dependencies (now `apt-get install`, or `dnf install` for RPMs); `blaktaild down` on a node already revoked from the console failed with 401 and left `blaktail0` and `BLAKTAIL-ACL` behind (now cleans up locally and says so; `blaktaild` test `revoke_reports_a_credential_the_coordinator_no_longer_accepts`); a failed `/etc/resolv.conf` rewrite left the agent's backup (and a temporary file in `/etc`) behind, so every later attempt and `down` misreported that the file had "changed after BlakTail configured it" (test `failed_resolv_conf_write_leaves_no_backup_or_temporary_file`, Linux only).
**Still unproven:** a Sigstore bundle that verifies (needs a tagged GitHub release), RPM hosts, macOS packages, x86_64, a real VM reboot. The lab pins the WireGuard listen port with `wg set` (the agent picks a random port and the lab has no relay). Under the hardened unit, MagicDNS cannot rewrite `/etc/resolv.conf` on hosts without `systemd-resolved` or `resolvconf` (documented in `docs/linux-agent.md`).
