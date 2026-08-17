defmodule RobineId.Repo.Migrations.AddLogoutTransactionBindings do
  use Ecto.Migration

  def change do
    create table(:logout_transactions, primary_key: false) do
      add :transaction_hash, :binary, primary_key: true
      add :return_to, :text
      add :issuer, :text
      add :client_id, :text
      add :post_logout_redirect_uri, :text
      add :state, :text
      add :ui_locales, :text
      add :expires_at, :utc_datetime_usec, null: false
      add :created_at, :utc_datetime_usec, null: false
    end
  end
end
