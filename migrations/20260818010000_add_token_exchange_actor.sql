ALTER TABLE access_tokens
  ADD COLUMN actor JSONB;

ALTER TABLE access_tokens
  ADD CONSTRAINT access_tokens_actor_shape_check
    CHECK (
      actor IS NULL OR (
        jsonb_typeof(actor) = 'object' AND
        jsonb_typeof(actor -> 'sub') = 'string'
      )
    );
