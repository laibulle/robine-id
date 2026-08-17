CREATE TABLE oauth_client_assertions (
  issuer TEXT NOT NULL,
  client_id TEXT NOT NULL,
  jti_hash BYTEA NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (issuer, client_id, jti_hash)
);

CREATE INDEX oauth_client_assertions_expires_at_idx
  ON oauth_client_assertions (expires_at);
