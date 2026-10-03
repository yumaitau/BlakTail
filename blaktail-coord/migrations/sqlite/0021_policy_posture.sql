-- Versioned posture checks referenced by policy rules (draft 08), plus the
-- node facts and re-evaluation deadline the peer-map compiler needs.
CREATE TABLE IF NOT EXISTS posture_checks (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    definition_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(org_id, name)
);
ALTER TABLE nodes ADD COLUMN credential_issued_at INTEGER;
ALTER TABLE nodes ADD COLUMN inventory_reported_at INTEGER;
ALTER TABLE orgs ADD COLUMN posture_next_eval_at INTEGER;
