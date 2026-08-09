defmodule RobineId.Test.Clients.MemoryRepository do
  @behaviour RobineId.Clients.Ports.Repository

  @impl true
  def get(id) do
    Process.get({__MODULE__, id}, {:error, :not_found})
  end

  def put(client), do: Process.put({__MODULE__, client.id}, {:ok, client})
end
