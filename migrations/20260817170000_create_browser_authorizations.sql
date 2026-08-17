CREATE TABLE browser_authorizations (
  transaction_hash BYTEA PRIMARY KEY,
  issuer TEXT NOT NULL,
  request JSONB NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX browser_authorizations_expires_at_idx
  ON browser_authorizations (expires_at);
