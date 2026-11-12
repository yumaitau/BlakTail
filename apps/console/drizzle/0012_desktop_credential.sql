-- Desktop and mobile app sign-in (PKCE). Codes and credentials are stored as
-- SHA-256 hashes. Both die with the browser session that approved them.
CREATE TABLE IF NOT EXISTS desktop_auth_code (
  id text PRIMARY KEY,
  code_hash text NOT NULL UNIQUE,
  user_id text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  session_id text NOT NULL REFERENCES session(id) ON DELETE CASCADE,
  code_challenge text NOT NULL,
  redirect_uri text NOT NULL,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS desktop_auth_code_expiry_idx ON desktop_auth_code (expires_at);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS desktop_credential (
  id text PRIMARY KEY,
  token_hash text NOT NULL UNIQUE,
  user_id text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  session_id text NOT NULL REFERENCES session(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  last_used_at timestamptz,
  revoked_at timestamptz
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS desktop_credential_user_idx ON desktop_credential (user_id);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS desktop_credential_session_idx ON desktop_credential (session_id);
