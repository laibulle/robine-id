CREATE TABLE mfa_recovery_code_uses (
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  code_hash_digest BYTEA NOT NULL CHECK (octet_length(code_hash_digest) = 32),
  used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (issuer, subject, code_hash_digest)
);
