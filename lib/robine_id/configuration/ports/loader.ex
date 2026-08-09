defmodule RobineId.Configuration.Ports.Loader do
  @moduledoc "Port for reading configuration documents."
  @callback read(Path.t()) :: {:ok, map()} | {:error, term()}
end
