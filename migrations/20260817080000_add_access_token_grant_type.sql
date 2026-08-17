ALTER TABLE access_tokens
  ADD COLUMN IF NOT EXISTS grant_type TEXT NOT NULL DEFAULT 'authorization_code';

CREATE INDEX IF NOT EXISTS access_tokens_client_grant_idx
  ON access_tokens (issuer, client_id, grant_type);
