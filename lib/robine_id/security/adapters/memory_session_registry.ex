defmodule RobineId.Security.Adapters.MemorySessionRegistry do
  @moduledoc "In-memory concurrent session registry."
  use GenServer
  @behaviour RobineId.Security.Ports.SessionRegistry

  def start_link(options), do: GenServer.start_link(__MODULE__, options, name: __MODULE__)

  @impl RobineId.Security.Ports.SessionRegistry
  def register(subject, session_id, maximum),
    do: GenServer.call(__MODULE__, {:register, subject, session_id, maximum})

  @impl RobineId.Security.Ports.SessionRegistry
  def active?(subject, session_id),
    do: GenServer.call(__MODULE__, {:active?, subject, session_id})

  @impl RobineId.Security.Ports.SessionRegistry
  def revoke(subject, session_id), do: GenServer.call(__MODULE__, {:revoke, subject, session_id})

  @impl GenServer
  def init(_options), do: {:ok, %{}}

  @impl GenServer
  def handle_call({:register, subject, session_id, maximum}, _from, state) do
    sessions = [session_id | Map.get(state, subject, [])] |> Enum.uniq() |> Enum.take(maximum)
    {:reply, :ok, Map.put(state, subject, sessions)}
  end

  def handle_call({:active?, subject, session_id}, _from, state),
    do: {:reply, session_id in Map.get(state, subject, []), state}

  def handle_call({:revoke, subject, session_id}, _from, state) do
    sessions = state |> Map.get(subject, []) |> List.delete(session_id)
    {:reply, :ok, Map.put(state, subject, sessions)}
  end
end
