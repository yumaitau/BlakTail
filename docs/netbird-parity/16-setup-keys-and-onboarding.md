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
