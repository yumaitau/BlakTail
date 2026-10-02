-- Named, organisation-scoped network resources. Device-level
-- nodes.approved_routes_json is left untouched, so existing approved routes
-- keep distributing exactly as before this migration.
CREATE TABLE IF NOT EXISTS network_resources (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL CHECK (kind IN ('cidr','dns')),
    cidr TEXT,
    dns_target TEXT,
    ports_json TEXT NOT NULL DEFAULT '[]',
    protocols_json TEXT NOT NULL DEFAULT '[]',
    routing_peers_json TEXT NOT NULL DEFAULT '[]',
    access_json TEXT NOT NULL DEFAULT '{}',
    enabled BIGINT NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    allow_nested_overlap BIGINT NOT NULL DEFAULT 0 CHECK (allow_nested_overlap IN (0,1)),
    public_route_confirmed_by TEXT,
    revision BIGINT NOT NULL DEFAULT 1,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE (org_id, name)
);
CREATE INDEX IF NOT EXISTS network_resources_org_idx ON network_resources(org_id);
