ALTER TABLE pending_authorizations
  ADD COLUMN requested_claims TEXT;

ALTER TABLE pending_authorizations
  ADD CONSTRAINT pending_authorizations_requested_claims_length_check
  CHECK (requested_claims IS NULL OR char_length(requested_claims) <= 8192);
