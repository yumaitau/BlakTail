# Policy-enforced device posture with optional MDM/EDR integration

**Priority:** P1 for baseline, P2 for vendor integrations. **Depends on:** draft 07 enforcement model; draft 15 identity assurance. **Area:** agent attestation, coordinator policy, console.

## Gap and outcome

BlakTail records OS, version, agent version and online/last-seen as inventory. This is **not** NetBird-style posture checks enforced during network access. NetBird also documents CrowdStrike, Intune, SentinelOne, FleetDM and Huntress connectors. Start with trustworthy low-privilege signals and make each integration optional; do not claim compliance from self-reported metadata.

## Scope

- Versioned checks for supported OS/agent version, approved peer state, last authentication and optional network location; specify freshness/expiry, attestation source, unsupported-platform behaviour and fail-closed/fail-open decisions per rule. Never trust arbitrary client claims as admin proof.
- Policy editor and device detail show current assessment, source, last evaluation, reason, affected resources and remediation; re-evaluate on expiry/revocation. Keep break-glass operator path controlled and audited.
- Separate MDM/EDR adapter design: per-organisation credentials encrypted at rest, least-privilege scopes, webhook/polling reconciliation, residency/retention review, outage handling, and no endpoint secrets in logs. Do not ship all vendor logos as unsupported UI.

## Acceptance / proof

An outdated/revoked device loses only the configured access within stated deadline; another organisation's signal cannot satisfy the check. Offline and unsupported agents behave as declared; forged status is rejected. Integration tests include provider outage and recovery; documented privacy notice precedes collection.

**Evidence:** `docs/project-status.md`, `docs/policy.md`, `apps/console/src/app/devices/page.tsx`; https://docs.netbird.io/manage/access-control/posture-checks, https://docs.netbird.io/manage/access-control/endpoint-detection-and-response.

## Status (2 October 2026)

**Done:**
- Migration slot 21 (`0021_policy_posture.sql`, SQLite and Postgres): `posture_checks` (versioned per organisation), `nodes.credential_issued_at`, `nodes.inventory_reported_at`, `orgs.posture_next_eval_at`.
- `blaktail-coord/src/posture.rs`: definitions (min agent version, allowed OS families, min OS version per family, max credential age, max inventory-report age, require active peer, `on_missing_data` fail/pass), evaluation with per-reason source (`agent_reported` vs `coordinator_observed`), CRUD with version-based 412 conflicts, 409 when the published policy references a check, audit for create/update/delete, and per-org and per-device assessment APIs that include affected policy locations, next lapse time and a self-reported-data notice.
- Policy `posture` on allow rules and SSH allow/check rules, evaluated against the **source** device at peer-map compile time. A failing device loses only the grants of rules that name the check. Unknown or deleted checks never pass. Time-based lapses fire one control-revision bump; inventory changes, check edits and credential renewal also bump it.
- Agents report agent version, real OS version (`/etc/os-release` / `sw_vers`, replacing the CPU architecture previously sent) and capabilities on every poll.
- Console: `/posture` (nav under Access) with create/edit/delete, role and organisation shown, disabled controls explaining why, and a device assessment table with reasons, sources, remediation and lapse time.
- ADR: `docs/adr/0005-posture-integrations.md` (adapter contract, sealed credentials, least privilege, residency/retention, polling/webhooks, outage and break-glass). No vendor UI.

**Proven by tests:** `posture::tests` (version parsing, OS/agent gates, missing/stale data fail-closed vs configured pass, credential-age deadline, validation, enforcement profile) and integration tests in `blaktail-coord/src/tests/policy_posture.rs`: posture failure removes only the referencing rule's port; another organisation's same-named lenient check and its devices' reports cannot satisfy this organisation's check; members can read and explain but get 403 on writes; version conflicts, duplicate names, deny-rule posture and referenced deletes are rejected; a lapsed deadline bumps the revision exactly once and removes the grant.

**Still needs live/field proof or a decision:**
- All OS/agent signals are self-reported by the node token holder; this is not attestation and must not be presented as compliance. Hardware-backed attestation is out of scope.
- "Approved peer" currently means active, not revoked or removed, with an unexpired credential; suspension/pending-approval states from draft 12 should extend it.
- Deadline-to-enforcement latency depends on agents' long-poll interval (≤25 s plus apply time) and was not measured on devices.
- Break-glass exemptions, network-location checks and every MDM/EDR adapter are design-only (ADR 0005). Privacy notice wording for any future provider collection is not written.
- No `/api/v1` automation endpoints for posture or explain yet.
