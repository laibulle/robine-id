ALTER TABLE access_tokens
  DROP CONSTRAINT access_tokens_grant_type_check;

ALTER TABLE access_tokens
  ADD CONSTRAINT access_tokens_grant_type_check
  CHECK (grant_type IN (
    'authorization_code',
    'refresh_token',
    'client_credentials',
    'urn:ietf:params:oauth:grant-type:token-exchange'
  ));
