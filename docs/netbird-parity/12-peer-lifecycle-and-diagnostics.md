# Rich peer detail: approvals, health, versions, connectivity and safe lifecycle

**Priority:** P1. **Depends on:** existing device inventory #39 and draft 01 navigation. **Area:** agent telemetry, coordinator read model, console.

## Gap and outcome

NetBird peer UI distinguishes user/server peers and exposes OS, version, approval, update and connection details. BlakTail's Devices page is a strong cross-network inventory, but administration is compressed into expandable rows; `/status` reports coordinator health only. Preserve cross-account search, audited friendly names and stable cryptographic identity while making troubleshooting actionable.

## Scope

- Scoped peer detail with node/owner identity, public key fingerprint, friendly/technical/MagicDNS name, address(es), approved routes/tags, last heartbeat, agent/OS version, credential expiry, connection candidates/transport, observed latency and last failure (only if measured). Show telemetry timestamp and source; avoid false “online” from stale heartbeat.
- Separate approve, suspend, revoke, tombstone, re-enrol and key rotation with impact preview, role gating and audit; preserve existing routes and memberships deliberately. Define whether self-serve user approval, service-managed/server peer and zero-agent peers are supported.
- Version-aware upgrade guidance, changelog and recovery link to local diagnostics without collecting packet contents. Bulk actions require explicit per-org scope and dry-run/confirmation.

## Acceptance / proof

Peer behind failed NAT shows correct relay/direct/unknown state from two-node measurement; revoke removes effective map and disconnects within bounded time. Expired/re-enrolled peer retains history but not old credential. Browser/API tests cover wrong-org mutation and stale list; accessibility/keyboard tests cover destructive confirmation.

**Evidence:** `apps/console/src/app/devices/page.tsx`, `apps/console/src/components/device-actions.tsx`, `docs/project-status.md`; https://docs.netbird.io/manage/peers/approve-peers, https://docs.netbird.io/manage/peers/auto-update.
