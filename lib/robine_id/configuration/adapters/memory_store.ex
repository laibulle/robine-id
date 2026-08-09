defmodule RobineId.Configuration.Adapters.MemoryStore do
  @moduledoc "Atomic runtime configuration store."
  use GenServer
  @behaviour RobineId.Configuration.Ports.Store

  alias RobineId.Configuration.Entities.Snapshot

  def start_link(options),
    do: GenServer.start_link(__MODULE__, options, name: Keyword.get(options, :name, __MODULE__))

  @impl RobineId.Configuration.Ports.Store
  def get, do: GenServer.call(__MODULE__, :get)

  @impl RobineId.Configuration.Ports.Store
  def activate(%Snapshot{} = snapshot), do: GenServer.call(__MODULE__, {:activate, snapshot})

  @impl RobineId.Configuration.Ports.Store
  def record_failure(diagnostics), do: GenServer.call(__MODULE__, {:record_failure, diagnostics})

  @impl RobineId.Configuration.Ports.Store
  def history, do: GenServer.call(__MODULE__, :history)

  def reload, do: GenServer.call(__MODULE__, :reload)

  @impl GenServer
  def init(options) do
    state = %{
      active: nil,
      history: [],
      last_reload_error: nil,
      path: Keyword.get(options, :path, Application.get_env(:robine_id, :configuration_path)),
      loader:
        Keyword.get(
          options,
          :loader,
          RobineId.Configuration.Adapters.ApplicationDirectoryLoader
        ),
      reload_interval:
        Keyword.get(
          options,
          :reload_interval,
          Application.get_env(:robine_id, :configuration_reload_interval, 1_000)
        )
    }

    {:ok, state, {:continue, :load}}
  end

  @impl GenServer
  def handle_continue(:load, state) do
    case load_source(state) do
      {{:ok, _outcome}, state} -> {:noreply, schedule_reload(state)}
      {{:error, reason}, state} -> {:stop, {:invalid_configuration, reason}, state}
    end
  end

  @impl GenServer
  def handle_call(:get, _from, %{active: nil} = state),
    do: {:reply, {:error, :not_configured}, state}

  def handle_call(:get, _from, %{active: snapshot} = state),
    do: {:reply, {:ok, snapshot}, state}

  def handle_call(:history, _from, state), do: {:reply, state.history, state}

  def handle_call(:reload, _from, state) do
    {result, state} = load_source(state)
    {:reply, result, state}
  end

  def handle_call({:record_failure, diagnostics}, _from, state) do
    {:reply, :ok, record_failure_state(state, diagnostics)}
  end

  def handle_call(
        {:activate, %Snapshot{fingerprint: hash}},
        _from,
        %{active: %Snapshot{fingerprint: hash}} = state
      ),
      do: {:reply, {:ok, :unchanged}, activate_state(state, state.active, :unchanged)}

  def handle_call({:activate, snapshot}, _from, state),
    do: {:reply, {:ok, :activated}, activate_state(state, snapshot, :activated)}

  @impl GenServer
  def handle_info(:reload_configuration, state) do
    {_result, state} = load_source(state)
    {:noreply, schedule_reload(state)}
  end

  defp load_source(state) do
    case RobineId.Configuration.load(state.path, state.loader) do
      {:ok, %Snapshot{fingerprint: fingerprint}}
      when not is_nil(state.active) and state.active.fingerprint == fingerprint ->
        {{:ok, :unchanged}, %{state | last_reload_error: nil}}

      {:ok, snapshot} ->
        state = state |> activate_state(snapshot, :activated) |> Map.put(:last_reload_error, nil)
        {{:ok, :activated}, state}

      {:error, diagnostics} ->
        state =
          if diagnostics == state.last_reload_error do
            state
          else
            state
            |> record_failure_state(diagnostics)
            |> Map.put(:last_reload_error, diagnostics)
          end

        {{:error, diagnostics}, state}
    end
  end

  defp schedule_reload(%{reload_interval: interval} = state)
       when is_integer(interval) and interval > 0 do
    Process.send_after(self(), :reload_configuration, interval)
    state
  end

  defp schedule_reload(state), do: state

  defp record_failure_state(state, diagnostics) do
    audit = %{
      revision: nil,
      outcome: :failed,
      diagnostics: diagnostics,
      applied_at: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()
    }

    :telemetry.execute(
      [:robine_id, :configuration, :reconciliation],
      %{count: 1},
      %{outcome: :failed}
    )

    %{state | history: [audit | state.history]}
  end

  defp activate_state(state, snapshot, outcome) do
    :telemetry.execute(
      [:robine_id, :configuration, :reconciliation],
      %{count: 1},
      %{outcome: outcome}
    )

    audit = %{
      revision: snapshot.fingerprint,
      outcome: outcome,
      applied_at: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()
    }

    %{state | active: snapshot, history: [audit | state.history]}
  end
end
