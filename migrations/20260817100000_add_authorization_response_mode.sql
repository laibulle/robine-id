ALTER TABLE authorization_codes
  ADD COLUMN response_mode TEXT;

ALTER TABLE pending_authorizations
  ADD COLUMN response_mode TEXT;

ALTER TABLE authorization_codes
  ADD CONSTRAINT authorization_codes_response_mode_check
  CHECK (response_mode IS NULL OR response_mode IN ('query', 'form_post'));

ALTER TABLE pending_authorizations
  ADD CONSTRAINT pending_authorizations_response_mode_check
  CHECK (response_mode IS NULL OR response_mode IN ('query', 'form_post'));
