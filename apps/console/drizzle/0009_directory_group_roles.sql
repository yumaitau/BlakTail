ALTER TABLE membership ADD COLUMN IF NOT EXISTS role_source text NOT NULL DEFAULT 'manual';
--> statement-breakpoint
ALTER TABLE membership DROP CONSTRAINT IF EXISTS membership_role_source_check;
--> statement-breakpoint
ALTER TABLE membership ADD CONSTRAINT membership_role_source_check
  CHECK (role_source in ('manual', 'directory'));
--> statement-breakpoint
ALTER TABLE membership ADD COLUMN IF NOT EXISTS deprovision_at timestamptz;
--> statement-breakpoint
ALTER TABLE membership ADD COLUMN IF NOT EXISTS tombstoned_at timestamptz;
--> statement-breakpoint
ALTER TABLE membership ADD COLUMN IF NOT EXISTS idp_groups_json jsonb NOT NULL DEFAULT '[]'::jsonb;
--> statement-breakpoint
ALTER TABLE membership ADD COLUMN IF NOT EXISTS idp_groups_seen_at timestamptz;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS membership_deprovision_idx
  ON membership (organisation_id, deprovision_at) WHERE tombstoned_at IS NULL;
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS scim_group (
  id text PRIMARY KEY,
  organisation_id text NOT NULL REFERENCES organisation(id) ON DELETE CASCADE,
  display_name text NOT NULL,
  external_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS scim_group_org_idx ON scim_group (organisation_id);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS scim_group_org_name_unique
  ON scim_group (organisation_id, lower(display_name));
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS scim_group_member (
  group_id text NOT NULL REFERENCES scim_group(id) ON DELETE CASCADE,
  user_id text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS scim_group_member_unique ON scim_group_member (group_id, user_id);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS directory_group_role_mapping (
  id text PRIMARY KEY,
  organisation_id text NOT NULL REFERENCES organisation(id) ON DELETE CASCADE,
  source text NOT NULL,
  group_name text NOT NULL,
  role text NOT NULL,
  created_by_user_id text REFERENCES "user"(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT directory_group_role_mapping_source_check CHECK (source in ('scim', 'oidc')),
  CONSTRAINT directory_group_role_mapping_role_check
    CHECK (role in ('owner', 'admin', 'network_admin', 'auditor', 'member'))
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS directory_group_role_mapping_unique
  ON directory_group_role_mapping (organisation_id, source, lower(group_name));
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS directory_sync_settings (
  organisation_id text PRIMARY KEY REFERENCES organisation(id) ON DELETE CASCADE,
  allow_owner_mapping boolean NOT NULL DEFAULT false,
  deprovision_grace_days integer NOT NULL DEFAULT 7,
  updated_by_user_id text REFERENCES "user"(id) ON DELETE SET NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT directory_sync_settings_grace_check CHECK (deprovision_grace_days BETWEEN 0 AND 90)
);
