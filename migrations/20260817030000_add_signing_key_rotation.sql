ALTER TABLE signing_keys
  ADD COLUMN IF NOT EXISTS rotation_id TEXT;

CREATE TABLE IF NOT EXISTS retained_signing_keys (
  issuer TEXT NOT NULL,
  kid TEXT NOT NULL,
  private_key_ciphertext BYTEA NOT NULL,
  private_key_nonce BYTEA NOT NULL,
  modulus TEXT NOT NULL,
  exponent TEXT NOT NULL,
  retired_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (issuer, kid)
);

CREATE INDEX IF NOT EXISTS retained_signing_keys_issuer_idx
  ON retained_signing_keys (issuer);
