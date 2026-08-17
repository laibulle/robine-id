defmodule RobineId.Repo.Migrations.CreateLegacyProtocolState do
  use Ecto.Migration

  def change do
    create table(:authenticated_sessions, primary_key: false) do
      add :session_hash, :binary, primary_key: true
      add :subject, :text, null: false
      add :created_at, :utc_datetime_usec, null: false
      add :last_seen_at, :utc_datetime_usec, null: false
      add :absolute_expires_at, :utc_datetime_usec, null: false
      add :revoked_at, :utc_datetime_usec
    end

    create index(:authenticated_sessions, [:subject, :created_at])

    create table(:authorization_codes, primary_key: false) do
      add :code_hash, :binary, primary_key: true
      add :issuer, :text, null: false
      add :subject, :text, null: false
      add :client_id, :text, null: false
      add :redirect_uri, :text, null: false
      add :scopes, {:array, :text}, null: false
      add :nonce, :text
      add :code_challenge, :text
      add :claims, :map, null: false, default: %{}
      add :auth_time, :bigint
      add :expires_at, :utc_datetime_usec, null: false
      add :created_at, :utc_datetime_usec, null: false
    end

    create index(:authorization_codes, [:expires_at])

    create table(:access_tokens, primary_key: false) do
      add :token_hash, :binary, primary_key: true
      add :issuer, :text, null: false
      add :subject, :text, null: false
      add :client_id, :text, null: false
      add :scopes, {:array, :text}, null: false
      add :claims, :map, null: false, default: %{}
      add :expires_at, :utc_datetime_usec, null: false
      add :created_at, :utc_datetime_usec, null: false
    end

    create index(:access_tokens, [:expires_at])

    create table(:pending_authorizations, primary_key: false) do
      add :transaction_hash, :binary, primary_key: true
      add :issuer, :text, null: false
      add :subject, :text, null: false
      add :client_id, :text, null: false
      add :redirect_uri, :text, null: false
      add :scopes, {:array, :text}, null: false
      add :state, :text, null: false
      add :nonce, :text
      add :code_challenge, :text
      add :claims, :map, null: false, default: %{}
      add :auth_time, :bigint
      add :expires_at, :utc_datetime_usec, null: false
      add :created_at, :utc_datetime_usec, null: false
    end

    create index(:pending_authorizations, [:expires_at])

    create table(:refresh_tokens, primary_key: false) do
      add :token_hash, :binary, primary_key: true
      add :family_id, :binary, null: false
      add :issuer, :text, null: false
      add :subject, :text, null: false
      add :client_id, :text, null: false
      add :scopes, {:array, :text}, null: false
      add :auth_time, :bigint
      add :claims, :map, null: false, default: %{}
      add :expires_at, :utc_datetime_usec, null: false
      add :consumed_at, :utc_datetime_usec
      add :revoked_at, :utc_datetime_usec
      add :created_at, :utc_datetime_usec, null: false
    end

    create index(:refresh_tokens, [:family_id])
    create index(:refresh_tokens, [:expires_at])
  end
end
