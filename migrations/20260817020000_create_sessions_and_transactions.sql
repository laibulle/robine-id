CREATE TABLE authenticated_sessions (
  session_hash BYTEA PRIMARY KEY,
  subject TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  absolute_expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);

CREATE INDEX authenticated_sessions_subject_idx
  ON authenticated_sessions (subject, created_at DESC);

CREATE TABLE pending_authorizations (
  transaction_hash BYTEA PRIMARY KEY,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  scopes TEXT[] NOT NULL,
  state TEXT NOT NULL,
  nonce TEXT,
  code_challenge TEXT,
  claims JSONB NOT NULL DEFAULT '{}'::jsonb,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX pending_authorizations_expires_at_idx
  ON pending_authorizations (expires_at);

CREATE TABLE logout_transactions (
  transaction_hash BYTEA PRIMARY KEY,
  return_to TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
