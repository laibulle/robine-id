defmodule RobineId.Clients.Ports.SecretResolver do
  @moduledoc "Port for resolving typed client secret references."
  @callback resolve(map()) :: {:ok, String.t()} | {:error, term()}
end
