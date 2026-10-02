-- Service-user lifecycle: suspension blocks token minting and every
-- outstanding OAuth access token immediately; rotation is recorded.
ALTER TABLE api_clients ADD COLUMN suspended_at INTEGER;
ALTER TABLE api_clients ADD COLUMN rotated_at INTEGER;
