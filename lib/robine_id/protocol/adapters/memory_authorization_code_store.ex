defmodule RobineId.Protocol.Adapters.MemoryAuthorizationCodeStore do
  @moduledoc "Atomic in-memory authorization-code adapter."
  use GenServer
  @behaviour RobineId.Protocol.Ports.AuthorizationCodeStore

  def start_link(options), do: GenServer.start_link(__MODULE__, options, name: __MODULE__)

  @impl RobineId.Protocol.Ports.AuthorizationCodeStore
  def issue(grant), do: GenServer.call(__MODULE__, {:issue, grant})

  @impl RobineId.Protocol.Ports.AuthorizationCodeStore
  def consume(code), do: GenServer.call(__MODULE__, {:consume, digest(code)})

  @impl RobineId.Protocol.Ports.AuthorizationCodeStore
  def mark_exchanged(code, access_token),
    do: GenServer.call(__MODULE__, {:mark_exchanged, digest(code), access_token})

  @impl GenServer
  def init(_options), do: {:ok, %{active: %{}, consumed: %{}}}

  @impl GenServer
  def handle_call({:issue, grant}, _from, state) do
    code = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    active = Map.put(state.active, digest(code), grant)
    {:reply, {:ok, code}, %{state | active: active}}
  end

  def handle_call({:consume, digest}, _from, state) do
    case Map.pop(state.active, digest) do
      {nil, active} ->
        reply =
          case Map.fetch(state.consumed, digest) do
            {:ok, access_token} -> {:error, {:authorization_code_reused, access_token}}
            :error -> {:error, :invalid_grant}
          end

        {:reply, reply, %{state | active: active}}

      {grant, active} ->
        consumed = Map.put(state.consumed, digest, nil)
        {:reply, {:ok, grant}, %{state | active: active, consumed: consumed}}
    end
  end

  def handle_call({:mark_exchanged, digest, access_token}, _from, state) do
    consumed =
      if Map.has_key?(state.consumed, digest),
        do: Map.put(state.consumed, digest, access_token),
        else: state.consumed

    {:reply, :ok, %{state | consumed: consumed}}
  end

  defp digest(code), do: :crypto.hash(:sha256, code)
end
