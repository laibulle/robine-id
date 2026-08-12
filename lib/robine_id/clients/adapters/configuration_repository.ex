defmodule RobineId.Clients.Adapters.ConfigurationRepository do
  @moduledoc "Client repository backed by the active declarative configuration."
  @behaviour RobineId.Clients.Ports.Repository

  alias RobineId.Clients.Entities.Client

  @impl true
  def get(client_id) do
    with {:ok, snapshot} <-
           RobineId.Configuration.active(RobineId.Runtime.adapter(:configuration_store)),
         data when is_map(data) <- Enum.find(snapshot.data["clients"], &(&1["id"] == client_id)),
         {:ok, client} <- Client.from_config(data) do
      {:ok, client}
    else
      nil -> {:error, :not_found}
      {:error, reason} -> {:error, reason}
    end
  end
end
