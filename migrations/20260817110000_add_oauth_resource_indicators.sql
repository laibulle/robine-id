ALTER TABLE authorization_codes ADD COLUMN resource TEXT;
ALTER TABLE pending_authorizations ADD COLUMN resource TEXT;
ALTER TABLE access_tokens ADD COLUMN resource TEXT;
ALTER TABLE refresh_tokens ADD COLUMN resource TEXT;

ALTER TABLE authorization_codes
  ADD CONSTRAINT authorization_codes_resource_length_check
  CHECK (resource IS NULL OR length(resource) BETWEEN 1 AND 4096);
ALTER TABLE pending_authorizations
  ADD CONSTRAINT pending_authorizations_resource_length_check
  CHECK (resource IS NULL OR length(resource) BETWEEN 1 AND 4096);
ALTER TABLE access_tokens
  ADD CONSTRAINT access_tokens_resource_length_check
  CHECK (resource IS NULL OR length(resource) BETWEEN 1 AND 4096);
ALTER TABLE refresh_tokens
  ADD CONSTRAINT refresh_tokens_resource_length_check
  CHECK (resource IS NULL OR length(resource) BETWEEN 1 AND 4096);

CREATE INDEX access_tokens_issuer_resource_idx
  ON access_tokens (issuer, resource)
  WHERE resource IS NOT NULL;
