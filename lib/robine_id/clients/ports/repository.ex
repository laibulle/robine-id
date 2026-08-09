defmodule RobineId.Clients.Ports.Repository do
  @moduledoc "Port for retrieving relying-party clients."
  alias RobineId.Clients.Entities.Client

  @callback get(String.t()) :: {:ok, Client.t()} | {:error, :not_found | term()}
end
