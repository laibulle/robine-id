CREATE TABLE oauth_dpop_nonces (
  nonce_hash BYTEA PRIMARY KEY,
  issuer TEXT NOT NULL,
  context TEXT NOT NULL CHECK (context IN ('authorization_server', 'userinfo')),
  jkt TEXT NOT NULL CHECK (jkt ~ '^[A-Za-z0-9_-]{43}$'),
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX oauth_dpop_nonces_lookup_idx
  ON oauth_dpop_nonces (issuer, context, jkt, expires_at);

CREATE INDEX oauth_dpop_nonces_expires_at_idx
  ON oauth_dpop_nonces (expires_at);
