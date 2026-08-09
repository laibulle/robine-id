defmodule RobineId.Operations.Ports.DependencyHealth do
  @moduledoc "Port for checking a required infrastructure dependency."
  @callback check() :: :ok | {:error, term()}
end
