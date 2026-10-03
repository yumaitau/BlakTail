-- Opt-in per-flow traffic events (draft 17). One row per start, end or drop
-- of a connection as one device saw it: overlay addresses and ports, the
-- identities the coordinator resolved for them, the matched policy rule and
-- byte/packet counters. Never a payload, URL, DNS name or HTTP data.
CREATE TABLE IF NOT EXISTS flow_events (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    reporter_id TEXT NOT NULL,
    flow_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('start','end','drop')),
    event_at BIGINT NOT NULL,
    window_start BIGINT NOT NULL,
    window_end BIGINT NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('inbound','outbound')),
    protocol TEXT NOT NULL,
    protocol_number BIGINT NOT NULL DEFAULT 0,
    icmp_type BIGINT,
    icmp_code BIGINT,
    src_ip TEXT NOT NULL,
    src_port BIGINT NOT NULL DEFAULT 0,
    dst_ip TEXT NOT NULL,
    dst_port BIGINT NOT NULL DEFAULT 0,
    src_kind TEXT NOT NULL,
    src_id TEXT,
    src_name TEXT NOT NULL DEFAULT '',
    src_user TEXT,
    dst_kind TEXT NOT NULL,
    dst_id TEXT,
    dst_name TEXT NOT NULL DEFAULT '',
    dst_user TEXT,
    dst_route TEXT,
    router_id TEXT,
    router_name TEXT,
    rule_basis TEXT NOT NULL DEFAULT 'unknown',
    rule_index BIGINT,
    rule_label TEXT NOT NULL DEFAULT '',
    rule_hint TEXT,
    connection_type TEXT NOT NULL CHECK (connection_type IN ('p2p','routed','relay')),
    rx_bytes BIGINT NOT NULL DEFAULT 0,
    tx_bytes BIGINT NOT NULL DEFAULT 0,
    rx_packets BIGINT NOT NULL DEFAULT 0,
    tx_packets BIGINT NOT NULL DEFAULT 0,
    aggregated BIGINT NOT NULL DEFAULT 0 CHECK (aggregated IN (0,1)),
    created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS flow_events_org_time_idx
    ON flow_events(org_id, event_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS flow_events_org_flow_idx
    ON flow_events(org_id, reporter_id, flow_id);
CREATE INDEX IF NOT EXISTS flow_events_org_created_idx
    ON flow_events(org_id, created_at);
