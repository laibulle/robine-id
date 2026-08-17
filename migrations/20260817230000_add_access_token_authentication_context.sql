ALTER TABLE access_tokens
  ADD COLUMN auth_time BIGINT,
  ADD COLUMN mfa_verified BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE access_tokens
  ADD CONSTRAINT access_tokens_auth_time_check
    CHECK (auth_time IS NULL OR auth_time >= 0),
  ADD CONSTRAINT access_tokens_mfa_context_check
    CHECK (NOT mfa_verified OR auth_time IS NOT NULL);
