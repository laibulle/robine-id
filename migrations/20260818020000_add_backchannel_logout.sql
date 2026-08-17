ALTER TABLE authenticated_sessions
  ADD COLUMN session_id TEXT;

UPDATE authenticated_sessions
SET session_id = encode(session_hash, 'hex')
WHERE session_id IS NULL;

ALTER TABLE authenticated_sessions
  ALTER COLUMN session_id SET NOT NULL,
  ADD CONSTRAINT authenticated_sessions_session_id_unique UNIQUE (session_id);

ALTER TABLE authorization_codes
  ADD COLUMN session_id TEXT;

ALTER TABLE pending_authorizations
  ADD COLUMN session_id TEXT;

ALTER TABLE refresh_tokens
  ADD COLUMN session_id TEXT;

ALTER TABLE device_authorizations
  ADD COLUMN session_id TEXT;

CREATE TABLE authenticated_session_clients (
  session_id TEXT NOT NULL REFERENCES authenticated_sessions (session_id) ON DELETE CASCADE,
  issuer TEXT NOT NULL,
  client_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (session_id, issuer, client_id)
);
