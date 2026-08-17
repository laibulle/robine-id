CREATE TABLE oauth_request_objects (
  issuer TEXT NOT NULL,
  client_id TEXT NOT NULL,
  jti_hash BYTEA NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (issuer, client_id, jti_hash)
);

CREATE INDEX oauth_request_objects_expires_at_idx
  ON oauth_request_objects (expires_at);
