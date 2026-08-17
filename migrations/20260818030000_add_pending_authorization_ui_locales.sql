ALTER TABLE pending_authorizations
  ADD COLUMN ui_locales TEXT;

ALTER TABLE pending_authorizations
  ADD CONSTRAINT pending_authorizations_ui_locales_length_check
  CHECK (ui_locales IS NULL OR char_length(ui_locales) <= 256);
