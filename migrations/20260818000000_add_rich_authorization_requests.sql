ALTER TABLE authorization_codes
  ADD COLUMN authorization_details JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE pending_authorizations
  ADD COLUMN authorization_details JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE access_tokens
  ADD COLUMN authorization_details JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE refresh_tokens
  ADD COLUMN authorization_details JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE device_authorizations
  ADD COLUMN authorization_details JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE authorization_codes
  ADD CONSTRAINT authorization_codes_authorization_details_check
  CHECK (jsonb_typeof(authorization_details) = 'array' AND pg_column_size(authorization_details) <= 16384);
ALTER TABLE pending_authorizations
  ADD CONSTRAINT pending_authorizations_authorization_details_check
  CHECK (jsonb_typeof(authorization_details) = 'array' AND pg_column_size(authorization_details) <= 16384);
ALTER TABLE access_tokens
  ADD CONSTRAINT access_tokens_authorization_details_check
  CHECK (jsonb_typeof(authorization_details) = 'array' AND pg_column_size(authorization_details) <= 16384);
ALTER TABLE refresh_tokens
  ADD CONSTRAINT refresh_tokens_authorization_details_check
  CHECK (jsonb_typeof(authorization_details) = 'array' AND pg_column_size(authorization_details) <= 16384);
ALTER TABLE device_authorizations
  ADD CONSTRAINT device_authorizations_authorization_details_check
  CHECK (jsonb_typeof(authorization_details) = 'array' AND pg_column_size(authorization_details) <= 16384);
