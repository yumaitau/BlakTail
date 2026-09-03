CREATE TABLE IF NOT EXISTS ipam_pools (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    cidr TEXT NOT NULL,
    exclusions_json TEXT NOT NULL DEFAULT '[]',
    created_at BIGINT NOT NULL,
    UNIQUE (org_id, name)
);
CREATE TABLE IF NOT EXISTS ipam_reservations (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    pool_id TEXT NOT NULL REFERENCES ipam_pools(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    node_id TEXT,
    enrol_key_hash TEXT,
    state TEXT NOT NULL DEFAULT 'active',
    reason TEXT NOT NULL DEFAULT '',
    expires_at BIGINT,
    created_at BIGINT NOT NULL,
    UNIQUE (pool_id, address)
);
CREATE INDEX IF NOT EXISTS ipam_pools_org_idx
    ON ipam_pools(org_id);
CREATE INDEX IF NOT EXISTS ipam_reservations_org_idx
    ON ipam_reservations(org_id, state);
