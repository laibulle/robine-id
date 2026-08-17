CREATE TABLE refresh_tokens (
  token_hash BYTEA PRIMARY KEY,
  family_id BYTEA NOT NULL,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  client_id TEXT NOT NULL,
  scopes TEXT[] NOT NULL,
  auth_time BIGINT,
  claims JSONB NOT NULL DEFAULT '{}'::jsonb,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX refresh_tokens_family_idx
  ON refresh_tokens (family_id);

CREATE INDEX refresh_tokens_expires_at_idx
  ON refresh_tokens (expires_at);
