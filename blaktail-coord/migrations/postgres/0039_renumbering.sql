-- IPAM pool growth and staged renumbering (NetBird-parity draft 26).
-- Existing organisations keep the original /24, so no address changes.
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS ipv4_pool_cidr TEXT NOT NULL DEFAULT '100.64.0.0/24';
-- A renumber plan moves devices to new overlay addresses in a dual-address
-- window: moves_json holds each device's old and new addresses. At most one
-- plan per organisation is staged at a time.
CREATE TABLE IF NOT EXISTS ipam_renumber_plans (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('devices','pool')),
    state TEXT NOT NULL CHECK (state IN ('staged','completed','rolled_back')),
    previous_pool_cidr TEXT NOT NULL,
    target_pool_cidr TEXT NOT NULL,
    moves_json TEXT NOT NULL,
    window_seconds BIGINT NOT NULL,
    window_ends_at BIGINT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    finished_by TEXT,
    finished_at BIGINT,
    revision BIGINT NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ipam_renumber_plans_org_idx ON ipam_renumber_plans(org_id, state, window_ends_at);
CREATE UNIQUE INDEX IF NOT EXISTS ipam_renumber_plans_one_staged ON ipam_renumber_plans(org_id) WHERE state='staged';
