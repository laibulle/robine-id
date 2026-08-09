defmodule RobineId.Test.Configuration.MemoryLoader do
  @behaviour RobineId.Configuration.Ports.Loader

  @impl true
  def read(_path), do: Process.get({__MODULE__, :result}, {:error, :not_configured})

  def put(result), do: Process.put({__MODULE__, :result}, result)
end
