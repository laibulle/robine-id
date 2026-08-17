ALTER TABLE authorization_codes
  ADD COLUMN dpop_jkt TEXT,
  ADD CONSTRAINT authorization_codes_dpop_jkt_check
    CHECK (dpop_jkt IS NULL OR dpop_jkt ~ '^[A-Za-z0-9_-]{43}$');

ALTER TABLE pending_authorizations
  ADD COLUMN dpop_jkt TEXT,
  ADD CONSTRAINT pending_authorizations_dpop_jkt_check
    CHECK (dpop_jkt IS NULL OR dpop_jkt ~ '^[A-Za-z0-9_-]{43}$');

ALTER TABLE access_tokens
  ADD COLUMN dpop_jkt TEXT,
  ADD CONSTRAINT access_tokens_dpop_jkt_check
    CHECK (dpop_jkt IS NULL OR dpop_jkt ~ '^[A-Za-z0-9_-]{43}$');

ALTER TABLE refresh_tokens
  ADD COLUMN dpop_jkt TEXT,
  ADD CONSTRAINT refresh_tokens_dpop_jkt_check
    CHECK (dpop_jkt IS NULL OR dpop_jkt ~ '^[A-Za-z0-9_-]{43}$');

CREATE TABLE oauth_dpop_proofs (
  jkt TEXT NOT NULL CHECK (jkt ~ '^[A-Za-z0-9_-]{43}$'),
  jti_hash BYTEA NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (jkt, jti_hash)
);

CREATE INDEX oauth_dpop_proofs_expires_at_idx
  ON oauth_dpop_proofs (expires_at);
