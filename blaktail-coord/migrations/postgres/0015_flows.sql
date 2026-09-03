CREATE TABLE IF NOT EXISTS flow_settings (
    org_id TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    sampling_rate DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    retention_days INTEGER NOT NULL DEFAULT 7,
    updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS flow_records (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    service TEXT NOT NULL DEFAULT '',
    start_bucket BIGINT NOT NULL,
    end_bucket BIGINT NOT NULL,
    proto TEXT NOT NULL,
    port INTEGER NOT NULL,
    bytes BIGINT NOT NULL DEFAULT 0,
    packets BIGINT NOT NULL DEFAULT 0,
    transport TEXT NOT NULL,
    decision TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS flow_records_org_bucket_idx
    ON flow_records(org_id, start_bucket);
