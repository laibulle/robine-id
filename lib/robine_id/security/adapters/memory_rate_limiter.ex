defmodule RobineId.Security.Adapters.MemoryRateLimiter do
  @moduledoc "Privacy-preserving in-memory fixed-window limiter."
  use GenServer
  @behaviour RobineId.Security.Ports.RateLimiter

  def start_link(options), do: GenServer.start_link(__MODULE__, options, name: __MODULE__)

  @impl RobineId.Security.Ports.RateLimiter
  def check(key, limit, window, now),
    do: GenServer.call(__MODULE__, {:check, digest(key), limit, window, now})

  @impl GenServer
  def init(_options), do: {:ok, %{}}

  @impl GenServer
  def handle_call({:check, key, limit, window, now}, _from, state) do
    {count, started_at} = Map.get(state, key, {0, now})
    {count, started_at} = if now - started_at >= window, do: {0, now}, else: {count, started_at}
    retry_after = max(window - (now - started_at), 1)

    if count >= limit do
      {:reply, {:error, :rate_limited, retry_after}, state}
    else
      next = count + 1
      {:reply, {:ok, limit - next}, Map.put(state, key, {next, started_at})}
    end
  end

  defp digest(key), do: :crypto.hash(:sha256, :erlang.term_to_binary(key))
end
