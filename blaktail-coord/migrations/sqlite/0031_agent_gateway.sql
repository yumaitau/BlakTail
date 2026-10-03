-- Agent network (organisation-run AI model gateway). Provider credentials
-- are sealed with the coordinator secret; agent keys are stored only as
-- SHA-256 hashes. Prompt content is stored only for keys an owner switched
-- to full logging, sealed, and purged after at most 30 days.
CREATE TABLE IF NOT EXISTS agent_settings (
    org_id TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    allow_offshore INTEGER NOT NULL DEFAULT 0,
    updated_by TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_providers (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    base_url TEXT NOT NULL,
    data_location TEXT NOT NULL,
    residency TEXT NOT NULL,
    sealed_credential TEXT,
    models_json TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1,
    revision INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS agent_providers_name_idx ON agent_providers(org_id, name);
CREATE TABLE IF NOT EXISTS agent_keys (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    bound_node_id TEXT,
    allowed_providers_json TEXT NOT NULL DEFAULT '[]',
    allowed_models_json TEXT NOT NULL DEFAULT '[]',
    daily_request_quota INTEGER NOT NULL,
    daily_token_quota INTEGER NOT NULL,
    max_request_bytes INTEGER NOT NULL,
    logging_mode TEXT NOT NULL DEFAULT 'off',
    log_retention_days INTEGER NOT NULL DEFAULT 0,
    redact_patterns_json TEXT NOT NULL DEFAULT '[]',
    revision INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS agent_keys_org_idx ON agent_keys(org_id, created_at);
-- One row per key per UTC day; quota checks are a conditional UPDATE here.
CREATE TABLE IF NOT EXISTS agent_quota_days (
    key_id TEXT NOT NULL,
    day TEXT NOT NULL,
    org_id TEXT NOT NULL,
    requests INTEGER NOT NULL DEFAULT 0,
    tokens INTEGER NOT NULL DEFAULT 0,
    denied INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (key_id, day)
);
CREATE TABLE IF NOT EXISTS agent_usage_days (
    org_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    model TEXT NOT NULL,
    day TEXT NOT NULL,
    requests INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (org_id, key_id, model, day)
);
CREATE TABLE IF NOT EXISTS agent_requests (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    model TEXT NOT NULL,
    gateway_node_id TEXT NOT NULL,
    caller_node_id TEXT,
    day TEXT NOT NULL,
    logging_mode TEXT NOT NULL,
    status TEXT NOT NULL,
    http_status INTEGER,
    request_bytes INTEGER NOT NULL,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    usage_estimated INTEGER NOT NULL DEFAULT 0,
    latency_ms INTEGER,
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    expires_at INTEGER,
    sealed_content TEXT,
    content_expires_at INTEGER
);
CREATE INDEX IF NOT EXISTS agent_requests_org_idx ON agent_requests(org_id, started_at);
