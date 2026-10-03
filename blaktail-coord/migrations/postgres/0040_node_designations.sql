-- Devices an owner or admin designated for a privileged role (AI gateway,
-- public ingress). A reported capability alone never grants the role.
CREATE TABLE IF NOT EXISTS node_designations (
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL,
    role TEXT NOT NULL,
    designated_by TEXT NOT NULL,
    designated_at BIGINT NOT NULL,
    PRIMARY KEY (org_id, node_id, role)
);
CREATE INDEX IF NOT EXISTS node_designations_node_idx ON node_designations(node_id, role);
-- Tokens reserved against the daily quota at authorisation, settled when the
-- gateway reports usage.
ALTER TABLE agent_requests ADD COLUMN reserved_tokens BIGINT NOT NULL DEFAULT 0;
