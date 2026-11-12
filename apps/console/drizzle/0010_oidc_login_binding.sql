-- Pending single sign-on attempts live ten minutes; drop any created before
-- browser binding existed instead of letting them complete unbound.
DELETE FROM oidc_login_state;
--> statement-breakpoint
ALTER TABLE oidc_login_state ADD COLUMN IF NOT EXISTS binding_hash text NOT NULL;
--> statement-breakpoint
ALTER TABLE oidc_login_state ADD COLUMN IF NOT EXISTS link_user_id text
  REFERENCES "user"(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE oidc_login_state ADD COLUMN IF NOT EXISTS link_session_id text;
