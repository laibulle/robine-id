ALTER TABLE authorization_codes
  ADD COLUMN auth_time BIGINT;

ALTER TABLE pending_authorizations
  ADD COLUMN auth_time BIGINT;
