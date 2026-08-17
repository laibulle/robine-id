ALTER TABLE authorization_codes
  DROP CONSTRAINT authorization_codes_response_mode_check;

ALTER TABLE authorization_codes
  ADD CONSTRAINT authorization_codes_response_mode_check
  CHECK (
    response_mode IS NULL
    OR response_mode IN ('query', 'form_post', 'jwt', 'query.jwt', 'form_post.jwt')
  );

ALTER TABLE pending_authorizations
  DROP CONSTRAINT pending_authorizations_response_mode_check;

ALTER TABLE pending_authorizations
  ADD CONSTRAINT pending_authorizations_response_mode_check
  CHECK (
    response_mode IS NULL
    OR response_mode IN ('query', 'form_post', 'jwt', 'query.jwt', 'form_post.jwt')
  );
