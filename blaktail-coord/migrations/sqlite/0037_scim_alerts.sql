-- Notification channels on the webhook outbox (draft 18): email, Slack and
-- Microsoft Teams destinations, quiet hours and digests. Existing rows stay
-- signed HTTPS webhooks. Chat webhook URLs are sealed in target_sealed; SMTP
-- credentials come from the operator's environment and are never stored.
ALTER TABLE webhook_destinations ADD COLUMN kind TEXT NOT NULL DEFAULT 'webhook';
ALTER TABLE webhook_destinations ADD COLUMN target_sealed TEXT;
ALTER TABLE webhook_destinations ADD COLUMN recipients_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE webhook_destinations ADD COLUMN quiet_timezone TEXT;
ALTER TABLE webhook_destinations ADD COLUMN quiet_start_minute INTEGER;
ALTER TABLE webhook_destinations ADD COLUMN quiet_end_minute INTEGER;
ALTER TABLE webhook_destinations ADD COLUMN digest_minutes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE webhook_destinations ADD COLUMN residency_ack_by TEXT;
ALTER TABLE webhook_destinations ADD COLUMN residency_ack_at INTEGER;
CREATE INDEX IF NOT EXISTS webhook_outbox_destination_pending_idx
    ON webhook_outbox(destination_id, delivered_at, dead_lettered_at);
