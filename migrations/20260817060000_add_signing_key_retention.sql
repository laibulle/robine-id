ALTER TABLE retained_signing_keys
  ADD COLUMN IF NOT EXISTS retain_until TIMESTAMPTZ;

UPDATE retained_signing_keys
SET retain_until = retired_at + interval '7 days'
WHERE retain_until IS NULL;

ALTER TABLE retained_signing_keys
  ALTER COLUMN retain_until SET NOT NULL;

CREATE INDEX IF NOT EXISTS retained_signing_keys_retain_until_idx
  ON retained_signing_keys (retain_until);
