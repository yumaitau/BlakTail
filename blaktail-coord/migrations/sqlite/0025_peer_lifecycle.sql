-- Peer lifecycle: suspension is reversible and distinct from revoke/tombstone.
ALTER TABLE nodes ADD COLUMN suspended_at INTEGER;
-- Agent-reported transport summary (direct, relay, mixed); NULL = not measured.
ALTER TABLE nodes ADD COLUMN transport TEXT;
ALTER TABLE nodes ADD COLUMN transport_reported_at INTEGER;

-- Enrolment keys: operator metadata and atomic use counting.
ALTER TABLE join_keys ADD COLUMN name TEXT NOT NULL DEFAULT '';
ALTER TABLE join_keys ADD COLUMN description TEXT NOT NULL DEFAULT '';
ALTER TABLE join_keys ADD COLUMN max_uses INTEGER;
ALTER TABLE join_keys ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE join_keys ADD COLUMN last_used_at INTEGER;
UPDATE join_keys SET max_uses=1 WHERE single_use=1;
UPDATE join_keys SET use_count=1,last_used_at=used_at WHERE used_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS join_keys_org_created_idx ON join_keys(org_id, created_at);
