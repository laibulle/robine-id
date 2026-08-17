defmodule RobineId.Repo.Migrations.AddAccessTokenAuthenticationContext do
  use Ecto.Migration

  def change do
    alter table(:access_tokens) do
      add :auth_time, :bigint
      add :mfa_verified, :boolean, null: false, default: false
    end

    create constraint(:access_tokens, :access_tokens_auth_time_check,
             check: "auth_time IS NULL OR auth_time >= 0"
           )

    create constraint(:access_tokens, :access_tokens_mfa_context_check,
             check: "NOT mfa_verified OR auth_time IS NOT NULL"
           )
  end
end
