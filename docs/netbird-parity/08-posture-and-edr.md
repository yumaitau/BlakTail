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

## Status (2 October 2026)

Second round: MDM/EDR vendor integrations (ADR 0005 accepted 3 October 2026).

**Done:**
- Migration slot 33 (`0033_edr_integrations.sql`, SQLite and Postgres): `posture_integrations` (per-organisation provider, non-secret config, sealed secret, fingerprint, interval, privacy acknowledgement, lease, last attempt/success, failure count, `outage_since`, last error category), `posture_integration_devices` (latest record per provider device), and `nodes.serial_number` / `nodes.mac_addresses_json`.
- `blaktail-coord/src/posture_integrations.rs`: the ADR 0005 adapter trait with adapters for Microsoft Intune (Entra client credentials, Graph `deviceManagement/managedDevices` with `$select` and same-origin `@odata.nextLink`), CrowdStrike Falcon (OAuth2 client credentials, `devices-scroll` + `devices/entities/devices/v2`, region list), SentinelOne (`ApiToken`, `/web/api/v2.1/agents` cursor paging), FleetDM (Bearer, `/api/v1/fleet/hosts` page/per_page, failing-policy count) and Huntress (Basic key:secret, `/v1/agents` page tokens). Outbound calls use the webhook address policy with IP pinning, no redirects, size/page/device caps, in-place retry for short `Retry-After`, and fixed error categories.
- Matching inside the organisation only: serial, then physical MAC, hostname opt-in; placeholder serials and randomised MACs ignored; a record matched by two devices, or two records for one device, is ambiguous and fails.
- Posture `integration` requirement with per-rule `max_age_secs`, optional `max_last_seen_secs` and `on_outage` (`fail` default). Evaluation feeds the existing lapse deadline; integration reasons carry source `provider_reported`; device assessments list each integration's match, key, status, sync time and outage.
- Polling loop (default 15 min, jittered, max 4 concurrent, lease-claimed), exponential jittered backoff honouring `Retry-After`, per-integration outage state; outage start and recovery bump the control revision once.
- Console API: list (providers catalogue, status, matched/ambiguous/unmatched counts, references), create (owner-only `manage_security`, privacy acknowledgement required), update (enable/disable, interval, secret rotation; settings changes need the secret), delete (409 while referenced), sync now. All mutations audited without secrets.
- Agent (`blaktaild`): reports serial number (`/sys/class/dmi/id/product_serial` on Linux, `ioreg IOPlatformExpertDevice` on macOS) and physical MACs (Linux `/sys/class/net/*/device`, macOS `networksetup -listallhardwareports`) with its inventory, read once per process.
- Console `/posture`: Integrations section (provider-specific fields, write-only secret, data/residency notice and acknowledgement, test connection, enable/disable, replace secret, remove, last sync, counts, outage state, last error); posture check form gains a provider requirement; device assessments show vendor signal and source. Only the five implemented providers are listed, from the coordinator's catalogue.
- Docs: `docs/policy.md` (integration requirement), `docs/privacy.md` (per-vendor data and residency), `docs/threat-model.md`, `docs/console.md`, `docs/project-status.md`, ADR 0005 updated and accepted.

**Proven by tests:** `posture_integrations::tests` run each adapter against a local axum mock of the vendor's documented response shapes: pagination (Graph nextLink, Falcon scroll offset + detail POST, SentinelOne cursor, Fleet short-page stop, Huntress page token), compliance mapping, auth failure as a category without echoing the secret or body, 429 `Retry-After: 1` retried for every adapter, long `Retry-After` and 503 surfaced as errors, a Graph nextLink to another host rejected, config validation (SSRF targets, foreign fields, path injection, unknown region), sealing round-trip and redacted `Debug`, identifier normalisation, matching priority and ambiguity, outage fail-closed/fail-open and last-seen deadlines, and bounded backoff. `tests::posture_integrations` (router-level): owner-only credential handling and privacy acknowledgement, secret absent from create/list responses, stored row, audit and captured logs; a provider verdict removes only the gated port and restores it; fresh data survives an outage, stale data fails closed, fail-open restores access, recovery clears the outage; another organisation can neither reference, sync nor delete the integration and a foreign check id stored directly still cannot pass; a copied serial makes both devices fail; leases are exclusive; referenced integrations cannot be deleted and endpoint changes require the secret.

**Still needs live/field proof or a decision:**
- No live vendor tenants were available. Every adapter is proven only against mocks written from current public API docs; real field names, pagination limits, rate limits and token behaviour need a run against each vendor before relying on them.
- CrowdStrike and Huntress clouds used here are outside Australia; residency for Intune, SentinelOne and Fleet-managed cloud depends on the tenant and is not verified by BlakTail.
- Serials and MACs are self-reported; a stolen node token on an already-compliant device is not detected. Wi-Fi MAC randomisation can stop MAC matching; serial is preferred.
- Vendor webhooks, an operator alert event for repeated failures, and the ADR's 24-hour audited break-glass exemption are not implemented. FleetDM on a private network is refused by the outbound address policy.
- Linux serial reading assumes the agent runs as root; containers and some VMs report placeholder serials, which never match.
