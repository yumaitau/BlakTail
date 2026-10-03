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
    interval_secs INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    privacy_ack_at INTEGER NOT NULL,
    privacy_ack_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    next_sync_at INTEGER NOT NULL,
    lease_until INTEGER,
    last_attempt_at INTEGER,
    last_success_at INTEGER,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    outage_since INTEGER,
    last_error TEXT,
    device_count INTEGER NOT NULL DEFAULT 0,
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
    compliant INTEGER,
    status TEXT NOT NULL,
    last_seen_at INTEGER,
    synced_at INTEGER NOT NULL,
    PRIMARY KEY (integration_id, external_id)
);
CREATE INDEX IF NOT EXISTS posture_integration_devices_org ON posture_integration_devices(org_id);
ALTER TABLE nodes ADD COLUMN serial_number TEXT;
ALTER TABLE nodes ADD COLUMN mac_addresses_json TEXT;
