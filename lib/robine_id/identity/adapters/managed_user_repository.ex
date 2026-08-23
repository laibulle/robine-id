defmodule RobineId.Identity.Adapters.ManagedUserRepository do
  @moduledoc "Resolves configured users with their persistent account overrides."
  @behaviour RobineId.Identity.Ports.UserRepository

  alias RobineId.Identity.Adapters.{AccountOverrides, ConfigurationUserRepository}

  @impl true
  def get_by_identifier(identifier) do
    with {:ok, user} <- ConfigurationUserRepository.get_by_identifier(identifier) do
      AccountOverrides.apply(user)
    end
  end

  @impl true
  def get_by_id(id) do
    with {:ok, user} <- ConfigurationUserRepository.get_by_id(id) do
      AccountOverrides.apply(user)
    end
  end
end
