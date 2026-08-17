defmodule RobineId.Repo.Migrations.AddTotpMfa do
  use Ecto.Migration

  def change do
    alter table(:authenticated_sessions) do
      add :mfa_verified, :boolean, null: false, default: false
    end

    alter table(:authorization_codes) do
      add :mfa_verified, :boolean, null: false, default: false
    end

    alter table(:pending_authorizations) do
      add :mfa_verified, :boolean, null: false, default: false
    end

    alter table(:refresh_tokens) do
      add :mfa_verified, :boolean, null: false, default: false
    end

    alter table(:device_authorizations) do
      add :mfa_verified, :boolean, null: false, default: false
    end

    create table(:totp_challenges, primary_key: false) do
      add :transaction_hash, :binary, primary_key: true
      add :issuer, :text, null: false
      add :subject, :text, null: false
      add :purpose, :text, null: false
      add :payload, :map, null: false
      add :expires_at, :utc_datetime_usec, null: false
      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create index(:totp_challenges, [:expires_at])

    create table(:totp_replay_counters, primary_key: false) do
      add :issuer, :text, primary_key: true
      add :subject, :text, primary_key: true
      add :last_counter, :bigint, null: false
      timestamps(type: :utc_datetime_usec, inserted_at: false)
    end
  end
end
