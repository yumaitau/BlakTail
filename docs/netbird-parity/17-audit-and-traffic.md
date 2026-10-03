# Separate administrative audit from privacy-controlled traffic diagnostics

**Priority:** P1 for audit UX; P2 for traffic. **Depends on:** closed #31/#50, explicit privacy review. **Area:** coordinator event store, optional endpoint telemetry, console.

## Gap and outcome

BlakTail `/audit` displays the latest 100 combined coordinator/console changes and raw JSON detail. NetBird separates activity/audit and traffic events. Closed #50 and `blaktail-coord/src/flows.rs` describe optional flow visibility; they do not prove an operator-facing, opt-in end-to-end traffic pipeline.

## Scope

- Admin audit: paginated immutable organisation-scoped event timeline with actor, action, target, request ID, outcome, timestamp and safe diff. Filter/export by role and date; redact credentials and sensitive content. Define retention, deletion and integrity chain/forwarding contract.
- Traffic diagnostics: explicitly opt-in per org and off by default, sampled/aggregated at endpoint, no payloads/URLs/queries. Show allow/deny where known, bytes, service class, transport, time bucket, gaps and source confidence. Clarify if macOS/iOS cannot collect equivalent signals.
- UX warns when data absent, stale or disabled; admin events cannot silently substitute for flow events. Access and exports are independently permissioned and audited. Keep storage/backups in operator-selected onshore environment.

## Acceptance / proof

Search and export only return authorised org records across linked accounts; page 2 works beyond 100 events. Turning traffic off stops ingestion within bound; no payload/secret appears in sampled records. Load test bounds retention/storage and does not impact tunnel throughput. Privacy notice and DSAR/deletion process documented.

**Evidence:** `apps/console/src/app/audit/page.tsx`, closed #31/#50, `blaktail-coord/src/flows.rs`; https://docs.netbird.io/manage/activity, https://docs.netbird.io/manage/activity/traffic-events-logging.

## Status (2 October 2026)

**Done:**
- Audit: `load_audit_events` now filters by actor, action (exact or `node.*` prefix), target type/id and `since`/`until` (`blaktail-coord/src/audit_log.rs`); read-time redaction by key name and value shape on every read path; CSV/JSON export (`/v1/orgs/{org}/audit/export`, `/api/v1/audit/export`) gated by `ExportAudit`, capped at 10,000 rows, formula-safe CSV, audited as `audit.exported`. Console `/audit` merges coordinator and console events on one cursor (seconds, then coordinator-before-console, then each store's id order — `apps/console/src/lib/audit-view.ts`, `listConsoleAuditPage`), pages of 50 with filters, redacted collapsible details, export links for `export_audit` roles and chain status; `/audit/export` route merges both stores.
- Integrity: migration 0027 adds `chain_seq`/`prev_hash`/`entry_hash` and an org head; every `append_audit` row is chained under the org row lock; `/audit/verify` (console and `/api/v1`) reports edits, gaps and a removed tail.
- Traffic: owner-only (`ManageSecurity`) opt-in with sampling 1–100 % and retention 1–30 days, off by default (`blaktail-coord/src/traffic.rs`); node-token ingest `POST /v1/nodes/{id}/flows` refuses disabled orgs (re-checked in the write transaction), foreign org/device records, unknown and payload-shaped keys (URL, DNS query, host, SNI…), non-label service names; batch/size/rate/storage bounds; retention purge on upload and every 15 minutes; summary with allowed/denied, transport, service class, hourly buckets, `disabled`/`no_data`/`stale`/`current` states and data-source confidence. Console `/traffic` under Events.
- Retention, chain limits, privacy and DSAR handling documented in `docs/audit-and-traffic.md`, `docs/privacy.md`, `docs/console.md`.

**Proven by tests:** `tests::events_audit::audit_pages_beyond_one_hundred_with_filters_redaction_and_chain` (231 events paged at 100 with no duplicate or gap despite equal timestamps; filters; redaction; chain intact, then detects an edit and a deletion); `audit_export_is_permissioned_audited_and_org_scoped` (auditor and owner export, member and network admin refused, other org's owner refused, export audited, `audit:read` token refused and `audit:export` token allowed, token cannot reach another org); `traffic_is_owner_opt_in_and_ingest_rejects_disabled_foreign_and_payload_uploads`; unit tests for redaction, CSV, chain hash, flow validation, traffic state/confidence; bun `scripts/audit-view.test.mjs` (merged cursor returns every row once for page sizes 1–10).

**Still needs live/field proof or a decision:**
- No BlakTail agent reports traffic records yet. A minimal agent reporter (per-peer tunnel bytes/transport from `wg show transfer` on Linux, boringtun UAPI on macOS/iOS/Windows) was judged too broad for this change; the UI says "no data" and why. Allow/deny per connection needs the agent packet filter to count decisions.
- Load test of retention/storage bounds and proof that reporting does not affect tunnel throughput.
- The chain is tamper-evident, not tamper-proof (a DB admin can rewrite the tail and head); external anchoring or forwarding is an operator decision. Console-side audit rows are not chained.
- Privacy notice wording and DSAR process need the operator's legal review; traffic export is deliberately not offered.

### Agent traffic reporting (3 October 2026)

**Done:**
- The peer map carries `traffic` (`enabled`, `sampling_rate`, `org_id`) while the organisation has diagnostics on. Toggling, or changing the rate, bumps the control revision, so agents start or stop within seconds. Turning off discards agent counters at once; a `409 … turned off` answer also stops the agent.
- Ingest accepts optional `peer_id` (must be a device of the same organisation) and `direction` (`inbound`/`outbound`), plus protocols `other` and `all` with port 0. These are stored in migration slot 36 (`0036_traffic_agents.sql`). The summary adds `by_direction`, and `/traffic` shows it.
- Shared record builder `blaktail-ios-wg/src/flow_report.rs` (used verbatim by `blaktaild` through `#[path]`): one record per peer, direction, protocol, port class and decision, per one-minute bucket. Ports ≥ 49152 are folded, records carry service class labels, and the coordinator's own deterministic sampling draw is applied before upload. The batch is capped at 500 and the bucket at an hour.
- Counter sources: Linux uses `BLAKTAIL-ACL` per-rule counters (allowed/denied new inbound attempts by peer/protocol/port) and `wg show transfer` (per-peer tunnel bytes); this is cheap because the kernel keeps both counters anyway. macOS uses pf anchor rule counters. Windows and iOS use the shared filter's per-flow counters. Android does not report.

**Proven by tests:** `tests::events_audit::agents_learn_traffic_settings_and_report_peer_and_direction` (opt-in wakes agents and appears in the peer map with `org_id`, a retention-only change does not, peer and direction stored, foreign-org peer `403`, address-shaped peer and bad direction `400`, `by_direction`, opt-out removes `traffic`); `flows` validation tests; `flow_report` tests (merge, classes, forbidden fields, bucket clamp, batch cap, sampling parity); `blaktaild::traffic` tests (reporter starts, reports each minute, stops at once, never starts without an org id; iptables/wg parsing with deltas and chain rebuilds; uploads contain no addresses, keys or names); filter tests (counting off by default, discard on disable, key bound with overflow, no addresses in JSON, C ABI upload body). Live lab `deploy/homelab/prove-traffic.sh` on `m3-max` passed. Off: 0 rows. On: records within 108 s, with allowed and denied counts, an hourly bucket, `by_direction` and high confidence. No addresses were stored, and denials were attributed to the peer. Off again: no rows for 90 s and agents logged the stop. The lab found and fixed a gap: unattributed Linux denials. Per-source catch-all rejects (Linux) and blocks (pf) now name the peer. See `docs/audit-and-traffic.md` (Lab proof).

**Still needs live/field proof or a decision:** macOS, Windows and iOS reporting was not exercised on real hosts. There is no load test of storage bounds or of tunnel throughput with counting on. Linux counts first packets of new inbound flows (not their bytes); bytes come from per-peer tunnel totals, so they are lower bounds.
