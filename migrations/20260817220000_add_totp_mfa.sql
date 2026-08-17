ALTER TABLE authenticated_sessions
  ADD COLUMN mfa_verified BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE authorization_codes
  ADD COLUMN mfa_verified BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE pending_authorizations
  ADD COLUMN mfa_verified BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE refresh_tokens
  ADD COLUMN mfa_verified BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE device_authorizations
  ADD COLUMN mfa_verified BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE totp_challenges (
  transaction_hash BYTEA PRIMARY KEY,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  purpose TEXT NOT NULL,
  payload JSONB NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT totp_challenges_issuer_length_check
    CHECK (length(issuer) BETWEEN 1 AND 4096),
  CONSTRAINT totp_challenges_subject_length_check
    CHECK (length(subject) BETWEEN 1 AND 256),
  CONSTRAINT totp_challenges_purpose_check
    CHECK (purpose IN ('authorization', 'device')),
  CONSTRAINT totp_challenges_payload_object_check
    CHECK (jsonb_typeof(payload) = 'object')
);

CREATE INDEX totp_challenges_expires_at_idx
  ON totp_challenges (expires_at);

CREATE TABLE totp_replay_counters (
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  last_counter BIGINT NOT NULL CHECK (last_counter >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (issuer, subject),
  CONSTRAINT totp_replay_counters_issuer_length_check
    CHECK (length(issuer) BETWEEN 1 AND 4096),
  CONSTRAINT totp_replay_counters_subject_length_check
    CHECK (length(subject) BETWEEN 1 AND 256)
);
