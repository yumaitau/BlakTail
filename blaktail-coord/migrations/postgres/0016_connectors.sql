CREATE TABLE IF NOT EXISTS domain_apps (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    hostnames_json TEXT NOT NULL DEFAULT '[]',
    ports_json TEXT NOT NULL DEFAULT '[]',
    protocols_json TEXT NOT NULL DEFAULT '[]',
    created_at BIGINT NOT NULL,
    UNIQUE (org_id, name)
);
CREATE TABLE IF NOT EXISTS app_connector_assignments (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    app_id TEXT NOT NULL REFERENCES domain_apps(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    UNIQUE (app_id, node_id)
);
CREATE TABLE IF NOT EXISTS app_resolutions (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    app_id TEXT NOT NULL REFERENCES domain_apps(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    addrs_json TEXT NOT NULL DEFAULT '[]',
    resolved_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS app_resolutions_app_host_idx
    ON app_resolutions(app_id, host, resolved_at);
