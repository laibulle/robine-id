ALTER TABLE device_authorizations
  DROP CONSTRAINT device_authorizations_decision_check;

UPDATE device_authorizations
SET subject = NULL, auth_time = NULL, claims = '{}'::jsonb
WHERE status = 'denied';

ALTER TABLE device_authorizations
  ADD CONSTRAINT device_authorizations_decision_check
  CHECK (
    (status = 'pending' AND subject IS NULL AND auth_time IS NULL AND decision_at IS NULL) OR
    (status = 'approved' AND subject IS NOT NULL AND auth_time IS NOT NULL AND decision_at IS NOT NULL) OR
    (status = 'denied' AND subject IS NULL AND auth_time IS NULL AND decision_at IS NOT NULL)
  );
