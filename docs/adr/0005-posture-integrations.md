# ADR 0005 — Optional MDM/EDR posture integrations

- Status: proposed (design only; nothing in this ADR is implemented)
- Date: 2026-10-02

## Context

Posture checks (`docs/policy.md#posture-checks`) gate policy rules on
signals the coordinator already has: self-reported agent/OS version and
coordinator-observed credential state. Self-reported data is a hygiene
signal, not attestation. Organisations that run an MDM (for example Intune,
Jamf, FleetDM) or an EDR (for example CrowdStrike, SentinelOne, Huntress)
hold stronger device-health signals and may want access to depend on them.

BlakTail is self-hosted, onshore by deployment, and Indigenous-organisation
first. Integrations must stay optional, keep each organisation's credentials
and data under its control, and must not imply data residency the operator
has not arranged. Vendor connectors are not shipped, and no vendor names or
logos appear in the console until one is implemented and tested.

## Decision

### Adapter contract

One Rust trait per provider kind, run only by the coordinator:

```rust
trait PostureAdapter {
    /// Stable kind, e.g. "fleetdm". Never shown as a logo.
    fn kind(&self) -> &'static str;
    /// Pull the provider's current view of the organisation's devices.
    async fn reconcile(&self, org: OrgId, creds: &SealedCredential)
        -> Result<Vec<DeviceSignal>, AdapterError>;
    /// Verify and parse a push notification (HMAC/JWT per provider).
    fn verify_webhook(&self, org: OrgId, headers: &HeaderMap, body: &[u8])
        -> Result<Vec<DeviceSignal>, AdapterError>;
}

struct DeviceSignal {
    external_id: String,          // provider device id
    match_keys: MatchKeys,        // serial, hostname, WireGuard public key
    compliant: Option<bool>,
    risk: Option<RiskLevel>,
    observed_at: i64,             // provider timestamp, not ours
}
```

- Signals are stored per `(org_id, provider_id, external_id)` and matched to
  a node only inside the same organisation. Matching prefers the WireGuard
  public key the provider recorded (if an agent extension reports it), then
  serial number; hostname alone never matches. Unmatched signals are kept
  for review, never applied.
- A posture check gains an optional `provider` requirement
  (`{"provider": "<id>", "require": "compliant", "max_age_secs": 3600}`).
  It reuses the existing evaluation: missing or stale provider data obeys
  the check's `on_missing_data`, and freshness feeds the same re-evaluation
  deadline that bumps the control revision.
- Another organisation's provider, credentials or signals can never satisfy
  a check: every query is keyed by the check's `org_id`.

### Credentials

- Per-organisation provider credentials (API tokens, OAuth client secrets,
  webhook signing secrets) are sealed at rest with the coordinator's
  envelope key, exactly as webhook secrets are, and are write-only through
  the API. The console shows a prefix and last-used time, never the value.
- Least privilege: read-only device inventory/compliance scopes. Adapters
  must refuse to start if the provider reports broader scopes it can detect.
- Credentials and raw provider payloads never appear in logs, audit
  `details_json`, metrics labels, or error messages returned to the console.
  Audit records who created, rotated or removed an integration.
- Owner-only (`Permission::ManageIntegrations` plus policy permission) to
  create; admins may view status.

### Residency and retention

- Provider calls leave the deployment. The console must state the provider's
  region as configured by the operator and must not label a provider
  integration "onshore" unless the operator records that the tenant is
  hosted in Australia. BlakTail does not verify that claim.
- Store only the fields in `DeviceSignal`; discard the rest of each payload
  after parsing. Default retention: the latest signal per device plus 30 days
  of history, configurable down to latest-only.
- Enabling an integration requires the owner to acknowledge a privacy notice
  describing what is pulled and where it is stored, before the first call.
  `docs/privacy.md` must be updated in the same change that ships an adapter.

### Polling, webhooks and outage

- Reconcile by polling (default every 15 minutes, jittered, per
  organisation) and accept signed webhooks for faster updates. Webhooks
  only mark a device for re-fetch; the adapter re-reads the provider before
  trusting the change.
- Outage: a provider error never changes stored signals. Signals age out by
  `max_age_secs`, after which the check's `on_missing_data` applies, so an
  organisation chooses per check whether an outage fails closed (default)
  or open. Repeated failures raise an operator alert and an audit event; no
  access change happens without a fresh signal or an expiry.
- Recovery: the next successful reconcile replaces stale signals and bumps
  the control revision once.
- Break-glass: an owner may exempt one device from one provider requirement
  for a bounded time (maximum 24 hours), with a mandatory reason, recorded in
  the audit log and shown on the device's assessment.

## Consequences

- No vendor UI or logos until an adapter has integration tests covering
  happy path, provider outage and recovery, forged webhook rejection, and
  cross-organisation isolation.
- Each adapter is a separate change with its own threat-model entry.
- Self-reported posture remains available and clearly labelled for
  organisations without an MDM/EDR.
