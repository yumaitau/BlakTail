# ADR 0005 — Optional MDM/EDR posture integrations

- Status: Accepted (3 October 2026). Implemented in
  `blaktail-coord/src/posture_integrations.rs` for Microsoft Intune,
  CrowdStrike Falcon, SentinelOne, FleetDM and Huntress, tested against
  local mocks of each vendor's documented API only.
- Date: 2026-10-02 (proposed), 2026-10-03 (accepted)

## Context

Posture checks (`docs/policy.md#posture-checks`) gate policy rules on
signals the coordinator already has: self-reported agent/OS version and
coordinator-observed credential state. Self-reported data is a hygiene
signal, not attestation. Organisations that run an MDM (for example Intune,
FleetDM) or an EDR (for example CrowdStrike, SentinelOne, Huntress) hold
stronger device-health signals and may want access to depend on them.

BlakTail is self-hosted, onshore by deployment, and Indigenous-organisation
first. Integrations must stay optional, keep each organisation's credentials
and data under its control, and must not imply data residency the operator
has not arranged. No vendor appears in the console unless its adapter is
implemented and tested.

## Decision

### Adapter contract

One Rust adapter per provider, run only by the coordinator:

```rust
trait PostureAdapter {
    /// Stable kind, e.g. "fleetdm". Never shown as a logo.
    fn kind(&self) -> Kind;
    /// Pull the provider's current view of the organisation's devices.
    async fn reconcile(&self, http: &Http, secret: &Secret)
        -> Result<Vec<DeviceSignal>, AdapterError>;
}

struct DeviceSignal {
    external_id: String,          // provider device id
    hostname: Option<String>,
    serial_number: Option<String>,
    mac_addresses: Vec<String>,
    compliant: Option<bool>,      // provider verdict; None = no verdict
    status: String,               // short provider status label
    last_seen_at: Option<i64>,    // provider timestamp, not ours
}
```

`Http` connects only to addresses that pass the webhook address policy,
pins the checked IP, follows no redirects, caps page size, device count and
page count, and retries a 429 in place when `Retry-After` is 30 seconds or
less. `AdapterError` is a fixed category (auth, rate-limited, status,
unreachable, blocked, bad response, too large); provider bodies are never
surfaced.

- Signals are stored per `(org_id, integration_id, external_id)` and matched
  to a node only inside the same organisation. Vendors do not record the
  WireGuard public key, so matching uses the agent-reported serial number,
  then physical MAC addresses; hostname matching is off unless the owner
  enables it per integration (hostname alone never matches by default).
  A device matches only when exactly one record matches its strongest key
  and no other device claims that record; ambiguous matches fail. Unmatched
  records are counted for review, never applied.
- A posture check gains an optional `integration` requirement
  (`{"integration_id": "<uuid>", "max_age_secs": 3600,
  "max_last_seen_secs": 86400, "on_outage": "fail"}`). It reuses the
  existing evaluation, and freshness feeds the same re-evaluation deadline
  that bumps the control revision.
- Another organisation's integration, credentials or signals can never
  satisfy a check: creation rejects foreign integration ids and evaluation
  only loads the checking organisation's integrations.

### Credentials

- Per-organisation provider secrets (client secrets, API tokens) are sealed
  at rest with a key derived from the coordinator secret (same construction
  as webhook signing secrets, separate key domain) and are write-only. The
  console shows a short SHA-256 fingerprint and timestamps, never the value.
  Non-secret identifiers (tenant ID, client ID, region, console URL, API key
  ID) are stored as configuration.
- Least privilege, documented per provider: Intune
  `DeviceManagementManagedDevices.Read.All`; CrowdStrike `Hosts: Read`;
  SentinelOne Viewer service user; FleetDM Observer API-only user; Huntress
  key pair (account-wide by Huntress's design; only `GET /v1/agents` is
  called). Scope detection is not possible through these APIs, so the
  adapters cannot refuse over-privileged credentials; the console tells
  owners which scope to grant.
- Credentials and raw provider payloads never appear in logs, audit
  `details_json`, metrics labels, or error messages returned to the console.
  Audit records who created, changed, rotated, tested or removed an
  integration. Changing provider settings requires re-entering the secret.
- Owner-only (`Permission::ManageSecurity`) to create, change, test or
  remove; `ManagePolicy` to reference an integration from a check;
  `ViewNetwork` to see status.

### Residency and retention

- Provider calls leave the deployment. The console shows each provider's
  residency note and a general notice; it never labels an integration
  "onshore". BlakTail does not verify where a vendor hosts a tenant.
- Store only the fields in `DeviceSignal`; discard the rest of each payload
  after parsing. Retention is latest-only: each successful reconcile
  replaces the integration's records; changing settings or deleting the
  integration deletes them.
- Connecting requires the owner to acknowledge a notice describing what is
  pulled and where it comes from, before the first call. `docs/privacy.md`
  lists each provider's endpoint and fields.

### Polling and outage

- Reconcile by polling (default every 15 minutes, 5 minutes to 24 hours,
  ±10% jitter), at most four reconciles at once per coordinator, claimed
  with a lease so replicas never duplicate a poll. Vendor webhooks are not
  accepted; polling is the only path that changes stored signals.
- Outage: a provider error never changes stored signals. The integration
  records `outage_since`, the error category and a failure count, and backs
  off exponentially with jitter (never sooner than `Retry-After`). When data
  is older than `max_age_secs` during an outage, `on_outage` decides:
  `fail` (default) or `pass`, which only keeps devices whose last known
  record was passing. Stale data without an outage always fails.
- Recovery: the next successful reconcile replaces stale signals, clears the
  outage and bumps the control revision once. Entering an outage also bumps
  it once so fail-open checks re-evaluate.
- Requirements still open: repeated failures should raise an operator alert
  event (today they are logged with the category and visible in the
  console), and break-glass — an owner may exempt one device from one
  provider requirement for at most 24 hours with a mandatory, audited
  reason shown on the device assessment — is not implemented yet. Until it
  is, an owner can set `on_outage` to `pass` or edit the check, both of
  which are versioned and audited.

## Consequences

- Each adapter has tests against a mock of the vendor's documented response
  shapes covering pagination, auth failure and 429 `Retry-After`; the
  coordinator tests cover matching, cross-organisation isolation, outage
  fail-closed/open and recovery, and secrets absent from responses, audit
  and logs. No adapter has been run against a live vendor tenant.
- Self-reported posture remains available and clearly labelled for
  organisations without an MDM/EDR.
- See `docs/threat-model.md#mdmedr-integration-abuse`.
