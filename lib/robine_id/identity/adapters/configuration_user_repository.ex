defmodule RobineId.Identity.Adapters.ConfigurationUserRepository do
  @moduledoc "User repository backed by active file configuration."
  @behaviour RobineId.Identity.Ports.UserRepository

  alias RobineId.Identity.Entities.User

  @impl true
  def get_by_identifier(identifier) do
    find_user(&(&1["identifier"] == identifier))
  end

  @impl true
  def get_by_id(id) do
    find_user(&(&1["id"] == id))
  end

  def list do
    with {:ok, snapshot} <-
           RobineId.Configuration.active(RobineId.Runtime.adapter(:configuration_store)) do
      snapshot.data
      |> Map.get("users", [])
      |> Enum.map(&User.from_config/1)
      |> Enum.reduce_while({:ok, []}, fn
        {:ok, user}, {:ok, users} -> {:cont, {:ok, [user | users]}}
        {:error, reason}, _acc -> {:halt, {:error, reason}}
      end)
      |> case do
        {:ok, users} -> {:ok, Enum.reverse(users)}
        error -> error
      end
    end
  end

  defp find_user(predicate) do
    with {:ok, snapshot} <-
           RobineId.Configuration.active(RobineId.Runtime.adapter(:configuration_store)),
         data when is_map(data) <-
           Enum.find(snapshot.data["users"] || [], predicate),
         {:ok, user} <- User.from_config(data) do
      {:ok, user}
    else
      nil -> {:error, :not_found}
      {:error, reason} -> {:error, reason}
    end
  end
end
