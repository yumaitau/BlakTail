-- Opt-in hybrid post-quantum WireGuard PSKs (draft 25, ADR 0009).
-- The coordinator stores policy and what agents report they negotiated.
-- There is deliberately no column for key material: PSKs never leave agents.
CREATE TABLE IF NOT EXISTS pq_policies (
    org_id TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    mode TEXT NOT NULL DEFAULT 'off',
    block_unestablished BIGINT NOT NULL DEFAULT 1,
    rules_json TEXT NOT NULL DEFAULT '[]',
    revision BIGINT NOT NULL DEFAULT 0,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS pq_peer_states (
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL,
    peer_id TEXT NOT NULL,
    state TEXT NOT NULL,
    mode TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT '',
    epoch BIGINT NOT NULL DEFAULT 0,
    last_rotation_at BIGINT,
    blocked BIGINT NOT NULL DEFAULT 0,
    reason TEXT NOT NULL DEFAULT '',
    reported_at BIGINT NOT NULL,
    PRIMARY KEY (node_id, peer_id)
);
CREATE INDEX IF NOT EXISTS pq_peer_states_org_idx ON pq_peer_states(org_id, node_id);
