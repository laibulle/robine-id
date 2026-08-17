CREATE TABLE pushed_authorizations (
  request_hash BYTEA PRIMARY KEY,
  issuer TEXT NOT NULL,
  client_id TEXT NOT NULL,
  request JSONB NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX pushed_authorizations_expires_at_idx
  ON pushed_authorizations (expires_at);
