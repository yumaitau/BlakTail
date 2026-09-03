-- Admission root secrets live in config/KMS, never in the DB; this table
-- tracks rotation state (hash + epoch) so replicas can enforce monotonicity.
CREATE TABLE IF NOT EXISTS org_admission_roots (
    org_id TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    secret_hash TEXT NOT NULL,
    epoch BIGINT NOT NULL DEFAULT 1,
    created_at BIGINT NOT NULL,
    rotated_at BIGINT
);
CREATE TABLE IF NOT EXISTS admission_signatures (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL,
    pubkey_b64 TEXT NOT NULL,
    epoch BIGINT NOT NULL,
    valid_from BIGINT NOT NULL,
    valid_to BIGINT NOT NULL,
    signature TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    UNIQUE (org_id, node_id, epoch)
);
CREATE INDEX IF NOT EXISTS admission_signatures_org_idx
    ON admission_signatures(org_id, valid_to);
