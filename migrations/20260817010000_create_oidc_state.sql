CREATE TABLE IF NOT EXISTS authorization_codes (
  code_hash BYTEA PRIMARY KEY,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  scopes TEXT[] NOT NULL,
  nonce TEXT,
  code_challenge TEXT,
  claims JSONB NOT NULL DEFAULT '{}'::jsonb,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS authorization_codes_expires_at_idx
  ON authorization_codes (expires_at);

CREATE TABLE IF NOT EXISTS access_tokens (
  token_hash BYTEA PRIMARY KEY,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  client_id TEXT NOT NULL,
  scopes TEXT[] NOT NULL,
  claims JSONB NOT NULL DEFAULT '{}'::jsonb,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS access_tokens_expires_at_idx
  ON access_tokens (expires_at);

CREATE TABLE IF NOT EXISTS authentication_rate_limits (
  key_hash BYTEA PRIMARY KEY,
  attempts INTEGER NOT NULL,
  window_started_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS signing_keys (
  issuer TEXT PRIMARY KEY,
  kid TEXT NOT NULL UNIQUE,
  private_key_ciphertext BYTEA NOT NULL,
  private_key_nonce BYTEA NOT NULL,
  modulus TEXT NOT NULL,
  exponent TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
