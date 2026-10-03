# Enrollment workspace: reusable setup keys, approval and managed rollout

**Priority:** P1. **Depends on:** existing join-key and browser-enrollment paths, draft 12 peer detail. **Area:** coordinator credentials, console, installer docs.

## Gap and outcome

NetBird setup keys offer reusable/one-off enrollment, expiry, auto-groups and ephemeral-device workflows. BlakTail already has browser approval and Join keys; this issue targets complete operator management and rollout evidence, not a second raw key type.

## Scope

- Inventory keys by name, creator, organisation, one-use/reusable, remaining uses, expiry, assigned tags/groups, last use and revoke state. Secret shown once; only hash/metadata stored. Define idempotent and concurrent use limits, replay defence, allowed installers and safe output for automation. Never put key in argv, shell history, QR URLs or logs.
- Browser wizard for macOS/Linux/iPhone with signed published artifact prerequisites; managed deployment profiles for supported MDM only after first secure install path works. Service account, user-linked, server and unmanaged WireGuard peers must have distinct labels and policy semantics.
- Optional device approval and ephemeral lifecycle need separate bounded rules and audit; enrolling with a key never bypasses tag ownership or a required approval policy. Show copy-safe instructions with platform and network preselected.

## Acceptance / proof

Two concurrent enroll attempts against a one-use key yield one node; revoked/expired key cannot enroll, including restart. Wrong-org key fails. CLI, console and mobile flows expose no secret in process argv or browser analytics. Fresh-host install/enroll/restart drill validates claimed platforms; until release exists, UI says build from source.

**Evidence:** `apps/console/src/app/join-keys/page.tsx`, `docs/getting-started.md`, `docs/releases.md`; https://docs.netbird.io/manage/peers/register-machines-using-setup-keys, https://docs.netbird.io/manage/peers/approve-peers.

## Status (2 October 2026)

**Done:**
- Join-key schema (slot 25) adds `name`, `description`, `max_uses`, `use_count` and `last_used_at`. Existing one-use keys are backfilled to `max_uses=1`, and used keys to `use_count=1`.
- Mint (`POST /v1/orgs/{org}/join-keys`) takes a name, description, expiry, tags, and either one-use or reusable with optional `max_uses` (1..10000). Tag ownership is still checked.
- Inventory `GET` and revoke `DELETE /v1/orgs/{org}/join-keys/{id}` live in `blaktail-coord/src/peer_lifecycle.rs` (ManageJoinKeys; revoke is audited as `join_key.revoked`). The inventory never returns the secret or its hash, and leaves out browser-approval grants.
- Concurrency: every enrolment and reauth consumes one use through a single conditional `UPDATE ... WHERE revoked_at IS NULL AND expires_at>now AND use_count<max_uses` inside the registration transaction. Neither backend can overspend a key, and a failed node insert rolls the use back.
- Wrong-org: a key only ever enrols into its own organisation, and reauth requires the key's org to match the node's (`k.org_id=$2`).
- Secret handling:
  - Verified that only `SHA-256(secret)` is stored (`key_hash`).
  - `blaktaild` previously accepted `--join-key` on argv. That argument is removed; keys now come only from stdin or `BLAKTAIL_JOIN_KEY`.
  - The macOS app already used stdin, and the iPhone app registers itself.
- Console `/join-keys` enrolment workspace:
  - Mint form, and a show-once secret with copy and hide.
  - Inventory showing name, description, creator, one-use or reusable, uses and uses left, expiry, tags, last use, and revoked/expired/used-up state, with revoke behind a confirmation.
  - Linux and macOS install steps; the key itself fixes the network. The steps read the key with `read -rs` and pipe it on stdin, so it never appears in argv, history, URLs or QR codes.
  - Labelled "build from source" because no signed release exists. iPhone points at in-app enrolment.

**Proven by tests:**
- `one_use_and_reusable_keys_hold_their_limits_under_concurrency`:
  - Two concurrent enrolments on a one-use key create exactly one node.
  - Eight concurrent enrolments on a `max_uses=3` key create exactly three.
  - The inventory counts and `used_up` state are correct, and the output contains no secret or hash.
- `key_validation_revocation_member_and_wrong_org`: input validation; member 403 on mint, list and revoke; wrong-org revoke 404; revoked key rejected; no cross-org listing.
- `revoked_and_expired_keys_stay_rejected_after_restart`: file-backed SQLite is reopened, and the stored value is the hash only.
- Agent: `join_key_is_never_a_command_line_argument`.
- The existing env-gated Postgres replica test still covers cross-replica single-use races. The new reusable-limit race runs on SQLite only, where the pool has a single connection, so requests are serialised.

**Still needs live/field proof or a decision:**
- A Postgres run of the reusable-key race.
- **Not done:** "require device approval for key enrolments". It needs a pending-approval node state and an approval UI, and must not be folded into suspend, because a pending device has never been trusted.
- Ephemeral-by-key policy.
- A per-key enrolment history view.
- MDM profiles.
- A signed installer and the fresh-host install/enrol/restart drill.
- Separate labels for service-account, user-linked and server peers; they stay as they are today.

### Live lab (3 October 2026)

**Proven live:** `deploy/homelab/prove-clean-install.sh` (Docker context `m3-max`, 245 s) builds the release packages with `deploy/docker/agent-package.Dockerfile`, serves them from a lab HTTPS release server, and runs the unmodified `scripts/install-agent.sh` on fresh `debian:bookworm` and `ubuntu:24.04` systemd containers. A tampered package, `BLAKTAIL_REQUIRE_SIGNATURE=1` without cosign, and (cosign v2.4.1 installed) a bundle that does not verify were all refused before anything was installed; the genuine package installed through the checksum path (6 s Debian, 13 s Ubuntu). Debian enrolled with the join key on stdin, Ubuntu with `BLAKTAIL_JOIN_KEY`; about 1,200 snapshots of every `/proc/*/cmdline` per host, taken every 50 ms during enrolment, never contained the key. Under `blaktaild.service` the hosts pinged each other over the overlay, again after `systemctl restart` with unchanged addresses; owner revocation of Ubuntu removed it from Debian's peers within 1 s and cut traffic both ways; uninstall left no binary, unit, state, interface, iptables chain or policy rule, and both nodes show as revoked.
**Bugs found and fixed:** `install-agent.sh` used bare `dpkg -i`, which leaves the package unconfigured on a host without its dependencies (now `apt-get install`, or `dnf install` for RPMs); `blaktaild down` on a node already revoked from the console failed with 401 and left `blaktail0` and `BLAKTAIL-ACL` behind (now cleans up locally and says so; `blaktaild` test `revoke_reports_a_credential_the_coordinator_no_longer_accepts`); a failed `/etc/resolv.conf` rewrite left the agent's backup (and a temporary file in `/etc`) behind, so every later attempt and `down` misreported that the file had "changed after BlakTail configured it" (test `failed_resolv_conf_write_leaves_no_backup_or_temporary_file`, Linux only).
**Still unproven:** a Sigstore bundle that verifies (needs a tagged GitHub release), RPM hosts, macOS packages, x86_64, a real VM reboot. The lab pins the WireGuard listen port with `wg set` (the agent picks a random port and the lab has no relay). Under the hardened unit, MagicDNS cannot rewrite `/etc/resolv.conf` on hosts without `systemd-resolved` or `resolvconf` (documented in `docs/linux-agent.md`).
