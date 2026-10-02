-- Server-side, organisation-bound change drafts (draft 03). A draft holds
-- proposed policy, DNS and network-resource documents plus the live
-- etags they were based on; publish applies them in one transaction.
-- The topology view (draft 02) is a read model and needs no table.
CREATE TABLE IF NOT EXISTS change_drafts (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','published','discarded','expired')),
    version BIGINT NOT NULL DEFAULT 1,
    surfaces_json TEXT NOT NULL DEFAULT '[]',
    payload_json TEXT NOT NULL,
    base_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_by_name TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    closed_at BIGINT,
    closed_by TEXT,
    result_json TEXT
);
CREATE INDEX IF NOT EXISTS change_drafts_org_idx ON change_drafts(org_id, status);
