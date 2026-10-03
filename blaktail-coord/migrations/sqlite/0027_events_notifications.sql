-- Audit, traffic diagnostics and notifications (drafts 17, 18).

-- Per-organisation hash chain over new coordinator audit rows. Rows written
-- before this migration keep NULL chain columns and are reported unchained.
ALTER TABLE audit_events ADD COLUMN chain_seq INTEGER;
ALTER TABLE audit_events ADD COLUMN prev_hash TEXT;
ALTER TABLE audit_events ADD COLUMN entry_hash TEXT;
ALTER TABLE orgs ADD COLUMN audit_chain_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE orgs ADD COLUMN audit_chain_head TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS audit_events_org_chain_idx
    ON audit_events(org_id, chain_seq) WHERE chain_seq IS NOT NULL;
CREATE INDEX IF NOT EXISTS audit_events_org_action_idx
    ON audit_events(org_id, action, created_at);

-- Traffic diagnostics stay off until an owner opts the organisation in.
ALTER TABLE flow_settings ADD COLUMN enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE flow_settings ADD COLUMN updated_by TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS flow_records_org_created_idx
    ON flow_records(org_id, created_at);

-- Webhook subscriptions: '["*"]' keeps existing destinations on every event.
ALTER TABLE webhook_destinations ADD COLUMN event_types_json TEXT NOT NULL DEFAULT '["*"]';
