ALTER TABLE logout_transactions
  ADD COLUMN issuer TEXT,
  ADD COLUMN client_id TEXT,
  ADD COLUMN post_logout_redirect_uri TEXT,
  ADD COLUMN state TEXT,
  ADD COLUMN ui_locales TEXT;

ALTER TABLE logout_transactions
  ADD CONSTRAINT logout_transactions_issuer_length_check
    CHECK (issuer IS NULL OR char_length(issuer) <= 4096),
  ADD CONSTRAINT logout_transactions_client_id_length_check
    CHECK (client_id IS NULL OR char_length(client_id) <= 256),
  ADD CONSTRAINT logout_transactions_redirect_uri_length_check
    CHECK (
      post_logout_redirect_uri IS NULL
      OR char_length(post_logout_redirect_uri) <= 4096
    ),
  ADD CONSTRAINT logout_transactions_state_length_check
    CHECK (state IS NULL OR char_length(state) <= 1024),
  ADD CONSTRAINT logout_transactions_ui_locales_length_check
    CHECK (ui_locales IS NULL OR char_length(ui_locales) <= 256);
