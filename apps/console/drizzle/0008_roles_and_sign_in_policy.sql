ALTER TABLE membership DROP CONSTRAINT IF EXISTS membership_role_check;
--> statement-breakpoint
ALTER TABLE membership ADD CONSTRAINT membership_role_check
  CHECK (role in ('owner', 'admin', 'network_admin', 'auditor', 'member'));
--> statement-breakpoint
ALTER TABLE invitation DROP CONSTRAINT IF EXISTS invitation_role_check;
--> statement-breakpoint
ALTER TABLE invitation ADD CONSTRAINT invitation_role_check
  CHECK (role in ('admin', 'network_admin', 'auditor', 'member'));
--> statement-breakpoint
ALTER TABLE identity_provider DROP CONSTRAINT IF EXISTS identity_provider_role_check;
--> statement-breakpoint
ALTER TABLE identity_provider ADD CONSTRAINT identity_provider_role_check
  CHECK (default_role in ('admin', 'network_admin', 'auditor', 'member'));
--> statement-breakpoint
ALTER TABLE identity_link_conflict DROP CONSTRAINT IF EXISTS identity_link_conflict_roles_check;
--> statement-breakpoint
ALTER TABLE identity_link_conflict ADD CONSTRAINT identity_link_conflict_roles_check
  CHECK (
    requester_role in ('owner', 'admin', 'network_admin', 'auditor', 'member')
    AND target_role in ('owner', 'admin', 'network_admin', 'auditor', 'member')
    AND (resolved_role IS NULL OR resolved_role in ('owner', 'admin', 'network_admin', 'auditor', 'member'))
  );
--> statement-breakpoint
ALTER TABLE membership_role_resolution DROP CONSTRAINT IF EXISTS membership_role_resolution_role_check;
--> statement-breakpoint
ALTER TABLE membership_role_resolution ADD CONSTRAINT membership_role_resolution_role_check
  CHECK (effective_role in ('owner', 'admin', 'network_admin', 'auditor', 'member'));
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS organisation_sign_in_policy (
  organisation_id text PRIMARY KEY REFERENCES organisation(id) ON DELETE CASCADE,
  step_up_max_age_minutes integer,
  require_mfa_for_privileged boolean NOT NULL DEFAULT false,
  updated_by_user_id text REFERENCES "user"(id) ON DELETE SET NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT organisation_sign_in_policy_step_up_check
    CHECK (step_up_max_age_minutes IS NULL OR step_up_max_age_minutes BETWEEN 5 AND 1440)
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS organisation_domain (
  id text PRIMARY KEY,
  organisation_id text NOT NULL REFERENCES organisation(id) ON DELETE CASCADE,
  domain text NOT NULL,
  verification_token text NOT NULL,
  created_by_user_id text REFERENCES "user"(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_checked_at timestamptz,
  verified_at timestamptz
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS organisation_domain_org_domain_unique
  ON organisation_domain (organisation_id, domain);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS organisation_domain_verified_unique
  ON organisation_domain (domain) WHERE verified_at IS NOT NULL;
--> statement-breakpoint
ALTER TABLE "user" ADD COLUMN IF NOT EXISTS two_factor_enabled boolean NOT NULL DEFAULT false;
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS two_factor (
  id text PRIMARY KEY,
  secret text NOT NULL,
  backup_codes text NOT NULL,
  user_id text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  verified boolean NOT NULL DEFAULT true,
  failed_verification_count integer NOT NULL DEFAULT 0,
  locked_until timestamp
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS two_factor_user_idx ON two_factor (user_id);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS two_factor_secret_idx ON two_factor (secret);
