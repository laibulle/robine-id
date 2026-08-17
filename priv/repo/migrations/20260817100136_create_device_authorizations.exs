defmodule RobineId.Repo.Migrations.CreateDeviceAuthorizations do
  use Ecto.Migration

  def change do
    create table(:device_authorizations, primary_key: false) do
      add :device_code_hash, :binary, primary_key: true
      add :user_code_hash, :binary, null: false
      add :verification_hash, :binary
      add :issuer, :text, null: false
      add :client_id, :text, null: false
      add :scopes, {:array, :text}, null: false
      add :resource, :text
      add :status, :text, null: false, default: "pending"
      add :subject, :text
      add :claims, :map, null: false, default: %{}
      add :auth_time, :bigint
      add :poll_interval, :integer, null: false
      add :last_polled_at, :utc_datetime_usec
      add :expires_at, :utc_datetime_usec, null: false
      add :decision_at, :utc_datetime_usec
      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create unique_index(:device_authorizations, [:user_code_hash])
    create unique_index(:device_authorizations, [:verification_hash])
    create index(:device_authorizations, [:expires_at])
  end
end
