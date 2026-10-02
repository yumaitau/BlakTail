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
