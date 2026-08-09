defmodule RobineId.Test.Configuration.MemoryStore do
  @behaviour RobineId.Configuration.Ports.Store

  @impl true
  def get, do: Process.get({__MODULE__, :snapshot}, {:error, :not_configured})

  @impl true
  def activate(snapshot) do
    case get() do
      {:ok, %{fingerprint: fingerprint}} when fingerprint == snapshot.fingerprint ->
        {:ok, :unchanged}

      _ ->
        Process.put({__MODULE__, :snapshot}, {:ok, snapshot})
        {:ok, :activated}
    end
  end

  @impl true
  def history, do: []

  @impl true
  def record_failure(_diagnostics), do: :ok
end
