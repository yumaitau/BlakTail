-- Peer lifecycle: suspension is reversible and distinct from revoke/tombstone.
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS suspended_at BIGINT;
-- Agent-reported transport summary (direct, relay, mixed); NULL = not measured.
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS transport TEXT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS transport_reported_at BIGINT;

-- Enrolment keys: operator metadata and atomic use counting.
ALTER TABLE join_keys ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '';
ALTER TABLE join_keys ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
ALTER TABLE join_keys ADD COLUMN IF NOT EXISTS max_uses BIGINT;
ALTER TABLE join_keys ADD COLUMN IF NOT EXISTS use_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE join_keys ADD COLUMN IF NOT EXISTS last_used_at BIGINT;
UPDATE join_keys SET max_uses=1 WHERE single_use=1 AND max_uses IS NULL;
UPDATE join_keys SET use_count=1,last_used_at=used_at WHERE used_at IS NOT NULL AND use_count=0;
CREATE INDEX IF NOT EXISTS join_keys_org_created_idx ON join_keys(org_id, created_at);
