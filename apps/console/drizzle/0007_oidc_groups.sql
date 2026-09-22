ALTER TABLE identity_provider
  ADD COLUMN IF NOT EXISTS allow_groups_json jsonb NOT NULL DEFAULT '[]'::jsonb;
