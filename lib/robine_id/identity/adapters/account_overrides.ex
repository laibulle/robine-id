defmodule RobineId.Identity.Adapters.AccountOverrides do
  @moduledoc "Persistent, writable overlays for declaratively provisioned identities."

  alias RobineId.Identity.Adapters.AccountOverride
  alias RobineId.Identity.Entities.User
  alias RobineId.Repo

  def apply(%User{} = user) do
    case Repo.get_by(AccountOverride, user_id: user.id) do
      nil -> {:ok, user}
      override when override.enabled -> {:ok, merge(user, override)}
      _override -> {:error, :not_found}
    end
  end

  def apply_including_disabled(%User{} = user) do
    case Repo.get_by(AccountOverride, user_id: user.id) do
      nil -> {:ok, user}
      override -> {:ok, merge(user, override)}
    end
  end

  def upsert(%User{} = user, attrs) when is_map(attrs) do
    values = %{
      user_id: user.id,
      name: Map.get(attrs, :name, user.name),
      email: Map.get(attrs, :email, user.email),
      password_hash: Map.get(attrs, :password_hash, user.password_hash),
      claims: Map.get(attrs, :claims, user.claims || %{}),
      roles: %{"values" => Map.get(attrs, :roles, user.roles)},
      enabled: Map.get(attrs, :enabled, user.enabled)
    }

    %AccountOverride{}
    |> AccountOverride.changeset(values)
    |> Repo.insert(
      on_conflict:
        {:replace, [:name, :email, :password_hash, :claims, :roles, :enabled, :updated_at]},
      conflict_target: [:user_id],
      returning: true
    )
    |> case do
      {:ok, override} -> {:ok, merge(user, override)}
      error -> error
    end
  end

  defp merge(%User{} = user, override) do
    %User{
      user
      | name: override.name,
        email: override.email,
        password_hash: override.password_hash,
        claims: override.claims,
        roles: Map.get(override.roles, "values", []),
        enabled: override.enabled
    }
  end
end
