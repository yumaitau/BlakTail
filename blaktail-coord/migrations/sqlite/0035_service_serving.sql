-- Serving-agent state for private services (draft 10). Health is what the
-- target node last reported; the coordinator publishes a service name only
-- while that report is fresh, healthy and names a live certificate.
ALTER TABLE org_services ADD COLUMN health_state TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE org_services ADD COLUMN health_detail TEXT NOT NULL DEFAULT '';
ALTER TABLE org_services ADD COLUMN health_node TEXT;
ALTER TABLE org_services ADD COLUMN health_reported_at INTEGER;
ALTER TABLE org_services ADD COLUMN listen_port INTEGER;
ALTER TABLE org_services ADD COLUMN served_serial TEXT;
