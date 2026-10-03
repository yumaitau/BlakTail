-- Browser remote access and remote jobs (draft 13, ADR 0006).

-- One gateway node and one SSH user CA per organisation. The CA private key
-- is sealed with a key derived from the coordinator secret.
CREATE TABLE IF NOT EXISTS remote_access_settings (
    org_id TEXT PRIMARY KEY,
    gateway_node_id TEXT,
    gateway_url TEXT NOT NULL DEFAULT '',
    ca_public_key TEXT NOT NULL,
    ca_private_sealed TEXT NOT NULL,
    updated_at BIGINT NOT NULL,
    updated_by TEXT NOT NULL DEFAULT ''
);

-- SSH host keys reported by each target agent. A changed key is held as
-- pending and blocks sessions until an administrator acknowledges it.
CREATE TABLE IF NOT EXISTS remote_host_keys (
    node_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    reported_at BIGINT NOT NULL,
    pending_key TEXT,
    pending_fingerprint TEXT,
    pending_reported_at BIGINT,
    acknowledged_at BIGINT,
    acknowledged_by TEXT
);
CREATE INDEX IF NOT EXISTS remote_host_keys_org_idx ON remote_host_keys(org_id);

-- Session metadata only: never keystrokes, output or credentials.
CREATE TABLE IF NOT EXISTS remote_sessions (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    user_id TEXT NOT NULL,
    user_name TEXT NOT NULL DEFAULT '',
    user_email TEXT NOT NULL DEFAULT '',
    user_role TEXT NOT NULL,
    gateway_node_id TEXT NOT NULL,
    target_node_id TEXT NOT NULL,
    os_user TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL,
    ticket_hash TEXT NOT NULL UNIQUE,
    created_at BIGINT NOT NULL,
    ticket_expires_at BIGINT NOT NULL,
    max_end_at BIGINT NOT NULL,
    redeemed_at BIGINT,
    last_report_at BIGINT,
    ended_at BIGINT,
    end_reason TEXT,
    revoked_at BIGINT,
    revoked_by TEXT,
    bytes_to_target BIGINT NOT NULL DEFAULT 0,
    bytes_from_target BIGINT NOT NULL DEFAULT 0,
    cert_serial TEXT
);
CREATE INDEX IF NOT EXISTS remote_sessions_org_created_idx ON remote_sessions(org_id, created_at);
CREATE INDEX IF NOT EXISTS remote_sessions_user_target_idx ON remote_sessions(org_id, user_id, target_node_id);

-- Owner-defined job templates: a fixed argv, never a shell string.
CREATE TABLE IF NOT EXISTS remote_job_templates (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    name TEXT NOT NULL,
    argv_json TEXT NOT NULL,
    timeout_secs BIGINT NOT NULL,
    output_cap_bytes BIGINT NOT NULL,
    target_json TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    created_by TEXT NOT NULL,
    disabled_at BIGINT
);
CREATE UNIQUE INDEX IF NOT EXISTS remote_job_templates_org_name_idx
    ON remote_job_templates(org_id, name) WHERE disabled_at IS NULL;

CREATE TABLE IF NOT EXISTS remote_job_runs (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    template_id TEXT NOT NULL,
    template_name TEXT NOT NULL,
    node_id TEXT NOT NULL,
    argv_json TEXT NOT NULL,
    timeout_secs BIGINT NOT NULL,
    output_cap_bytes BIGINT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    requested_at BIGINT NOT NULL,
    decided_by TEXT,
    decided_at BIGINT,
    claim_expires_at BIGINT,
    signature TEXT,
    claimed_at BIGINT,
    cancel_requested_at BIGINT,
    finished_at BIGINT,
    exit_code BIGINT,
    output TEXT,
    output_truncated BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS remote_job_runs_org_requested_idx ON remote_job_runs(org_id, requested_at);
CREATE INDEX IF NOT EXISTS remote_job_runs_node_status_idx ON remote_job_runs(node_id, status);
