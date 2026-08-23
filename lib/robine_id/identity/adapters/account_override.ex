defmodule RobineId.Identity.Adapters.AccountOverride do
  @moduledoc false

  use Ecto.Schema
  import Ecto.Changeset

  schema "identity_account_overrides" do
    field :user_id, :string
    field :name, :string
    field :email, :string
    field :password_hash, :string
    field :claims, :map
    field :roles, :map
    field :enabled, :boolean, default: true

    timestamps(type: :utc_datetime)
  end

  def changeset(override, attrs) do
    override
    |> cast(attrs, [:user_id, :name, :email, :password_hash, :claims, :roles, :enabled])
    |> validate_required([:user_id, :name, :email, :password_hash, :claims, :roles, :enabled])
    |> unique_constraint(:user_id)
  end
end
