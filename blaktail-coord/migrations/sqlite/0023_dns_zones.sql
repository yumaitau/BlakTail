-- Nameserver groups and zones live in orgs.dns_json; this keeps the
-- published documents so operators can diff and roll back past revisions.
CREATE TABLE IF NOT EXISTS org_dns_revisions (
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    dns_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (org_id, revision)
);
