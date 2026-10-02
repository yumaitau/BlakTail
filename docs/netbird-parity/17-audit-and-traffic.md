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
