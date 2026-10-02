ALTER TABLE org_services ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1;
ALTER TABLE org_services ADD COLUMN protocol TEXT NOT NULL DEFAULT 'http';
ALTER TABLE org_services ADD COLUMN access_tags_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE org_services ADD COLUMN description TEXT NOT NULL DEFAULT '';
-- One name-constrained CA per organisation. The CA key is sealed with the
-- coordinator secret; service keys never reach the coordinator.
CREATE TABLE IF NOT EXISTS service_cas (
    org_id TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    cert_pem TEXT NOT NULL,
    sealed_key TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    not_after INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS service_certificates (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    service_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    serial TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    issued_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS service_certificates_service_idx
    ON service_certificates(org_id, service_id, issued_at);
