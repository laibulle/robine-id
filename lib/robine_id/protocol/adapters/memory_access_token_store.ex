defmodule RobineId.Protocol.Adapters.MemoryAccessTokenStore do
  @moduledoc "Hashed in-memory bearer-token adapter."
  use GenServer
  @behaviour RobineId.Protocol.Ports.AccessTokenStore

  def start_link(options), do: GenServer.start_link(__MODULE__, options, name: __MODULE__)

  @impl RobineId.Protocol.Ports.AccessTokenStore
  def issue(grant), do: GenServer.call(__MODULE__, {:issue, grant})

  @impl RobineId.Protocol.Ports.AccessTokenStore
  def get(token), do: GenServer.call(__MODULE__, {:get, digest(token)})

  @impl RobineId.Protocol.Ports.AccessTokenStore
  def revoke(token), do: GenServer.call(__MODULE__, {:revoke, digest(token)})

  @impl GenServer
  def init(_options), do: {:ok, %{}}

  @impl GenServer
  def handle_call({:issue, grant}, _from, state) do
    token = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    {:reply, {:ok, token}, Map.put(state, digest(token), grant)}
  end

  def handle_call({:get, digest}, _from, state) do
    case Map.fetch(state, digest) do
      {:ok, grant} -> {:reply, {:ok, grant}, state}
      :error -> {:reply, {:error, :invalid_token}, state}
    end
  end

  def handle_call({:revoke, digest}, _from, state),
    do: {:reply, :ok, Map.delete(state, digest)}

  defp digest(token), do: :crypto.hash(:sha256, token)
end
