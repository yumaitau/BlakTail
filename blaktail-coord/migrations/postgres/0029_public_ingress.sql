-- Public HTTPS ingress (draft 11, ADR 0007). Off per organisation until an
-- owner enables it; every route is separately created and enabled by an owner.
CREATE TABLE IF NOT EXISTS public_ingress_settings (
    org_id TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    enabled BIGINT NOT NULL DEFAULT 0,
    abuse_contact TEXT NOT NULL DEFAULT '',
    updated_at BIGINT NOT NULL,
    updated_by TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS public_routes (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    fqdn TEXT NOT NULL,
    target_service_id TEXT,
    target_node_id TEXT NOT NULL,
    target_port BIGINT NOT NULL,
    tls_mode TEXT NOT NULL DEFAULT 'operator_files',
    auth_mode TEXT NOT NULL DEFAULT 'none',
    allowed_email_domains_json TEXT NOT NULL DEFAULT '[]',
    allowed_source_cidrs_json TEXT NOT NULL DEFAULT '[]',
    rate_limit_per_minute BIGINT NOT NULL DEFAULT 600,
    max_body_bytes BIGINT NOT NULL DEFAULT 10485760,
    max_connections BIGINT NOT NULL DEFAULT 256,
    log_retention_days BIGINT NOT NULL DEFAULT 30,
    enabled BIGINT NOT NULL DEFAULT 0,
    emergency_disabled_at BIGINT,
    emergency_disabled_by TEXT,
    emergency_reason TEXT,
    revision BIGINT NOT NULL DEFAULT 1,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE (org_id, fqdn)
);
-- What each ingress last fetched and reported (certificate expiry, errors).
CREATE TABLE IF NOT EXISTS public_ingress_nodes (
    node_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    last_config_at BIGINT NOT NULL,
    config_revision BIGINT NOT NULL DEFAULT 0,
    report_json TEXT NOT NULL DEFAULT '[]',
    reported_at BIGINT
);
CREATE INDEX IF NOT EXISTS public_ingress_nodes_org_idx ON public_ingress_nodes(org_id);
