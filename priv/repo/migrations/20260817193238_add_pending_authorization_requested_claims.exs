defmodule RobineId.Repo.Migrations.AddPendingAuthorizationRequestedClaims do
  use Ecto.Migration

  def change do
    alter table(:pending_authorizations) do
      add :requested_claims, :text
    end
  end
end
