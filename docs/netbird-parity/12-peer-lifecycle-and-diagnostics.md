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

## Status (2 October 2026)

**Done:**
- Peer detail page `/devices/[nodeId]` (`apps/console/src/app/devices/[nodeId]/page.tsx`). The All networks inventory on `/devices` stays, and each device name links to the detail page. The page shows:
  - node id, owner, WireGuard key fingerprint (first 12 hex characters of SHA-256)
  - friendly, technical and MagicDNS names; addresses; tags; advertised and approved routes
  - last heartbeat as `online`/`stale`/`never`, computed from coordinator time (90 s window)
  - agent and OS version, credential expiry, transport, and the relay-observed UDP endpoint with its timestamp
  - the 20 latest audit entries for the node, plus links to `/acls` and `/audit`
- Coordinator `GET /v1/orgs/{org}/nodes/{node}` in `blaktail-coord/src/peer_lifecycle.rs` (ViewNetwork, org-scoped, 404 across orgs).
- Transport:
  - `relay_endpoint` is only the reflexive address the relay observes, not the path in use, so it is not treated as a transport signal.
  - `blaktaild` now summarises its own paths from fresh WireGuard handshakes as `direct`, `relay` or `mixed`. Peers without a fresh handshake, or mid-probe, are not counted.
  - The agent sends the summary as `?transport=` on the existing `GET /v1/nodes/{id}/peers` heartbeat. The coordinator stores it with `transport_reported_at` (slot 25) and ignores unknown values.
  - With no report the page shows "Not measured". Latency and last failure are not measured and not shown.
- Suspend and resume (`POST .../suspend` with an optional audited reason, and `.../resume`), ManagePeers only:
  - Suspended nodes are left out of every peer map. Their `peers`, `updates` and `reauth` calls return `403 suspended`.
  - Identity, addresses, tags, routes, approvals and owner are untouched.
  - Separate from revoke and tombstone: revoked or deleted nodes cannot be suspended or resumed.
  - Each change bumps the control revision, writes `node.suspended`/`node.resumed` to the audit log, and emits a `device.suspended`/`device.resumed` webhook.
  - The console lifecycle panel has impact preview text, role gating with reasons and a confirmation dialog that Escape closes. Existing revoke, tombstone and rename are reused.
- Version guidance: `MINIMUM_AGENT_VERSION` (`0.1.0`) in `peer_lifecycle.rs`. The detail page flags older agents and links to `docs/upgrades.md`.
- Schema slot 25 (`0025_peer_lifecycle.sql`, SQLite and Postgres): `nodes.suspended_at`, `nodes.transport`, `nodes.transport_reported_at`.

**Proven by tests:**
- `peer_lifecycle::tests::suspended_peer_leaves_maps_and_resume_restores_it`: peer map exclusion; `peers`, `updates` and `reauth` blocked; audit entry; conflict on a second suspend; resume restores the same identity and addresses.
- `suspend_rejects_members_wrong_org_and_revoked_nodes`: member 403, wrong-org 404, forged org assertion 401, conflict on a revoked node.
- `detail_reports_heartbeat_transport_and_version` and `heartbeat_and_version_rules`.
- Agent: `transport_summary_reports_only_measured_paths`.

**Still needs live/field proof or a decision:**
- A two-node relay/direct/unknown measurement behind a failed NAT.
- Measured revoke- and suspend-to-disconnect time on real nodes. A suspended agent keeps its local WireGuard config, but its peers drop it at their next update. Its existing relay token stays valid until expiry, but no peer will accept its traffic.
- Accessibility and keyboard browser tests for the destructive dialogs.
- Latency and last-failure telemetry.
- Semantics for approve-on-enrol, self-serve user approval, server/service-managed peers and zero-agent peers.
- Re-enrol and key rotation as one console action.
- Bulk actions with dry-run.
- A changelog surface.
