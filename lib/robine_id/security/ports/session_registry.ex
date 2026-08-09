defmodule RobineId.Security.Ports.SessionRegistry do
  @moduledoc "Port for concurrent authenticated-session tracking."
  @callback register(String.t(), String.t(), pos_integer()) :: :ok
  @callback active?(String.t(), String.t()) :: boolean()
  @callback revoke(String.t(), String.t()) :: :ok
end
