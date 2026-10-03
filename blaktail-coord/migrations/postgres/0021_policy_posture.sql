-- Versioned posture checks referenced by policy rules (draft 08), plus the
-- node facts and re-evaluation deadline the peer-map compiler needs.
CREATE TABLE IF NOT EXISTS posture_checks (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1,
    definition_json TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE (org_id, name)
);
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS credential_issued_at BIGINT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS inventory_reported_at BIGINT;
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS posture_next_eval_at BIGINT;
