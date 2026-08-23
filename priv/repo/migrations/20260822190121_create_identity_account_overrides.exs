defmodule RobineId.Repo.Migrations.CreateIdentityAccountOverrides do
  use Ecto.Migration

  def change do
    create table(:identity_account_overrides) do
      add :user_id, :string, null: false
      add :name, :string, null: false
      add :email, :string, null: false
      add :password_hash, :string, null: false
      add :claims, :map, null: false
      add :roles, :map, null: false
      add :enabled, :boolean, null: false, default: true

      timestamps(type: :utc_datetime)
    end

    create unique_index(:identity_account_overrides, [:user_id])
  end
end
