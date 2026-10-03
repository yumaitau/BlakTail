ALTER TABLE org_services ADD COLUMN IF NOT EXISTS enabled BIGINT NOT NULL DEFAULT 1;
ALTER TABLE org_services ADD COLUMN IF NOT EXISTS protocol TEXT NOT NULL DEFAULT 'http';
ALTER TABLE org_services ADD COLUMN IF NOT EXISTS access_tags_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE org_services ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
-- One name-constrained CA per organisation. The CA key is sealed with the
-- coordinator secret; service keys never reach the coordinator.
CREATE TABLE IF NOT EXISTS service_cas (
    org_id TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    cert_pem TEXT NOT NULL,
    sealed_key TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    not_after BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS service_certificates (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    service_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    serial TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    not_before BIGINT NOT NULL,
    not_after BIGINT NOT NULL,
    issued_at BIGINT NOT NULL,
    revoked_at BIGINT
);
CREATE INDEX IF NOT EXISTS service_certificates_service_idx
    ON service_certificates(org_id, service_id, issued_at);
