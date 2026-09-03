CREATE TABLE IF NOT EXISTS org_services (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    service_name TEXT NOT NULL,
    target_node TEXT NOT NULL,
    port INTEGER NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE (org_id, service_name)
);
CREATE TABLE IF NOT EXISTS service_csrs (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    service_name TEXT NOT NULL,
    target_node TEXT NOT NULL,
    csr_pem TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS service_csrs_org_service_idx
    ON service_csrs(org_id, service_name, created_at);
