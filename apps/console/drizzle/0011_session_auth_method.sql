-- How each session signed in (password, password_mfa, sso). Existing
-- sessions stay NULL and never satisfy a privileged-role MFA rule.
ALTER TABLE session ADD COLUMN IF NOT EXISTS auth_method text;
--> statement-breakpoint
ALTER TABLE session DROP CONSTRAINT IF EXISTS session_auth_method_check;
--> statement-breakpoint
ALTER TABLE session ADD CONSTRAINT session_auth_method_check
  CHECK (auth_method IS NULL OR auth_method in ('password', 'password_mfa', 'sso'));
--> statement-breakpoint
-- Single sign-on counts as MFA only when an owner says so.
ALTER TABLE organisation_sign_in_policy
  ADD COLUMN IF NOT EXISTS trust_idp_mfa boolean NOT NULL DEFAULT false;
