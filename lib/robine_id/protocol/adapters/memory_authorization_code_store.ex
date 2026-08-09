defmodule RobineId.Protocol.Adapters.MemoryAuthorizationCodeStore do
  @moduledoc "Atomic in-memory authorization-code adapter."
  use GenServer
  @behaviour RobineId.Protocol.Ports.AuthorizationCodeStore

  def start_link(options), do: GenServer.start_link(__MODULE__, options, name: __MODULE__)

  @impl RobineId.Protocol.Ports.AuthorizationCodeStore
  def issue(grant), do: GenServer.call(__MODULE__, {:issue, grant})

  @impl RobineId.Protocol.Ports.AuthorizationCodeStore
  def consume(code), do: GenServer.call(__MODULE__, {:consume, digest(code)})

  @impl GenServer
  def init(_options), do: {:ok, %{}}

  @impl GenServer
  def handle_call({:issue, grant}, _from, state) do
    code = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    {:reply, {:ok, code}, Map.put(state, digest(code), grant)}
  end

  def handle_call({:consume, digest}, _from, state) do
    case Map.pop(state, digest) do
      {nil, state} -> {:reply, {:error, :invalid_grant}, state}
      {grant, state} -> {:reply, {:ok, grant}, state}
    end
  end

  defp digest(code), do: :crypto.hash(:sha256, code)
end
