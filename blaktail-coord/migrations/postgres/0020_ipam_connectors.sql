-- IPAM: one row per handed-out overlay IPv4 address. The primary key is the
-- concurrency guard: two enrolments can never both insert the same address.
-- released_at starts the reuse grace period once the owning node is gone.
CREATE TABLE IF NOT EXISTS ipam_leases (
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    node_id TEXT,
    allocated_at BIGINT NOT NULL,
    released_at BIGINT,
    PRIMARY KEY (org_id, address)
);
INSERT INTO ipam_leases(org_id,address,node_id,allocated_at,released_at)
    SELECT n.org_id, j.value, n.id, n.created_at, n.deleted_at
    FROM nodes n CROSS JOIN LATERAL json_array_elements_text(n.allowed_ips_json::json) AS j(value)
    WHERE j.value LIKE '100.64.0.%/32'
    ON CONFLICT DO NOTHING;
-- Operator reservations: held addresses are never auto-allocated; a bound
-- reservation is handed to the enrolling device with that name or key.
CREATE TABLE IF NOT EXISTS ipam_address_reservations (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    bound_name TEXT,
    bound_wg_public_key TEXT,
    reason TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    UNIQUE (org_id, address)
);
-- App connectors: host-route leases a connector resolved for a DNS resource.
CREATE TABLE IF NOT EXISTS connector_leases (
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    resource_id TEXT NOT NULL REFERENCES network_resources(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL,
    route TEXT NOT NULL,
    ttl BIGINT NOT NULL,
    resolved_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (resource_id, node_id, route)
);
CREATE INDEX IF NOT EXISTS connector_leases_org_idx ON connector_leases(org_id, expires_at);
CREATE TABLE IF NOT EXISTS connector_reports (
    resource_id TEXT NOT NULL REFERENCES network_resources(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    state TEXT NOT NULL CHECK (state IN ('resolved','empty','blocked','error')),
    reason TEXT NOT NULL DEFAULT '',
    reported_at BIGINT NOT NULL,
    PRIMARY KEY (resource_id, node_id)
);
