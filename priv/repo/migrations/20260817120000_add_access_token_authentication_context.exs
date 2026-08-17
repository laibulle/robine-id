defmodule RobineId.Repo.Migrations.AddAccessTokenAuthenticationContext do
  use Ecto.Migration

  def change do
    alter table(:access_tokens) do
      add :auth_time, :bigint
      add :mfa_verified, :boolean, null: false, default: false
    end

    execute(
      """
      CREATE TRIGGER access_tokens_authentication_context_insert
      BEFORE INSERT ON access_tokens
      FOR EACH ROW
      WHEN (NEW.auth_time IS NOT NULL AND NEW.auth_time < 0)
        OR (NEW.mfa_verified <> 0 AND NEW.auth_time IS NULL)
      BEGIN
        SELECT RAISE(ABORT, 'invalid access token authentication context');
      END
      """,
      "DROP TRIGGER access_tokens_authentication_context_insert"
    )

    execute(
      """
      CREATE TRIGGER access_tokens_authentication_context_update
      BEFORE UPDATE OF auth_time, mfa_verified ON access_tokens
      FOR EACH ROW
      WHEN (NEW.auth_time IS NOT NULL AND NEW.auth_time < 0)
        OR (NEW.mfa_verified <> 0 AND NEW.auth_time IS NULL)
      BEGIN
        SELECT RAISE(ABORT, 'invalid access token authentication context');
      END
      """,
      "DROP TRIGGER access_tokens_authentication_context_update"
    )
  end
end
