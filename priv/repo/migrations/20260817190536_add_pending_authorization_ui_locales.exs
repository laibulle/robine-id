defmodule RobineId.Repo.Migrations.AddPendingAuthorizationUiLocales do
  use Ecto.Migration

  def change do
    alter table(:pending_authorizations) do
      add :ui_locales, :text
    end
  end
end
