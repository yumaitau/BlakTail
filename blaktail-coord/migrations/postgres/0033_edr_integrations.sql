-- Optional MDM/EDR posture integrations (draft 08, ADR 0005): per-organisation
-- provider credentials sealed at rest, the latest provider signal per device,
-- and the hardware identifiers agents report for matching.
CREATE TABLE IF NOT EXISTS posture_integrations (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    config_json TEXT NOT NULL,
    sealed_secret TEXT NOT NULL,
    secret_hint TEXT NOT NULL,
    interval_secs BIGINT NOT NULL,
    enabled BIGINT NOT NULL DEFAULT 1,
    privacy_ack_at BIGINT NOT NULL,
    privacy_ack_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    next_sync_at BIGINT NOT NULL,
    lease_until BIGINT,
    last_attempt_at BIGINT,
    last_success_at BIGINT,
    consecutive_failures BIGINT NOT NULL DEFAULT 0,
    outage_since BIGINT,
    last_error TEXT,
    device_count BIGINT NOT NULL DEFAULT 0,
    UNIQUE(org_id, name)
);
CREATE INDEX IF NOT EXISTS posture_integrations_due ON posture_integrations(next_sync_at);
CREATE TABLE IF NOT EXISTS posture_integration_devices (
    integration_id TEXT NOT NULL REFERENCES posture_integrations(id) ON DELETE CASCADE,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    external_id TEXT NOT NULL,
    hostname TEXT,
    serial_number TEXT,
    mac_addresses_json TEXT NOT NULL DEFAULT '[]',
    compliant BIGINT,
    status TEXT NOT NULL,
    last_seen_at BIGINT,
    synced_at BIGINT NOT NULL,
    PRIMARY KEY (integration_id, external_id)
);
CREATE INDEX IF NOT EXISTS posture_integration_devices_org ON posture_integration_devices(org_id);
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS serial_number TEXT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS mac_addresses_json TEXT;
-- Identifiers are pinned at first report; a later change waits in
-- hardware_pending_json for an admin's approval.
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS hardware_pinned_at BIGINT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS hardware_pending_json TEXT;
