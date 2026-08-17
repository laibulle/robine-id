CREATE TABLE device_authorizations (
  device_code_hash BYTEA PRIMARY KEY,
  user_code_hash BYTEA NOT NULL UNIQUE,
  verification_hash BYTEA UNIQUE,
  issuer TEXT NOT NULL,
  client_id TEXT NOT NULL,
  scopes TEXT[] NOT NULL,
  resource TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  subject TEXT,
  claims JSONB NOT NULL DEFAULT '{}'::jsonb,
  auth_time BIGINT,
  poll_interval INTEGER NOT NULL,
  last_polled_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ NOT NULL,
  decision_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT device_authorizations_issuer_length_check
    CHECK (char_length(issuer) BETWEEN 1 AND 4096),
  CONSTRAINT device_authorizations_client_length_check
    CHECK (char_length(client_id) BETWEEN 1 AND 256),
  CONSTRAINT device_authorizations_scope_check
    CHECK (cardinality(scopes) BETWEEN 1 AND 256),
  CONSTRAINT device_authorizations_resource_length_check
    CHECK (resource IS NULL OR char_length(resource) BETWEEN 1 AND 4096),
  CONSTRAINT device_authorizations_status_check
    CHECK (status IN ('pending', 'approved', 'denied')),
  CONSTRAINT device_authorizations_poll_interval_check
    CHECK (poll_interval BETWEEN 5 AND 300),
  CONSTRAINT device_authorizations_decision_check
    CHECK (
      (status = 'pending' AND subject IS NULL AND decision_at IS NULL) OR
      (status = 'approved' AND subject IS NOT NULL AND auth_time IS NOT NULL AND decision_at IS NOT NULL) OR
      (status = 'denied' AND subject IS NOT NULL AND auth_time IS NOT NULL AND decision_at IS NOT NULL)
    )
);

CREATE INDEX device_authorizations_expires_at_idx
  ON device_authorizations (expires_at);

