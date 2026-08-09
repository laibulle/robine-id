defmodule RobineIdWeb.HealthController do
  use RobineIdWeb, :controller

  def live(conn, _params), do: json(conn, %{status: "live"})

  def ready(conn, _params) do
    case RobineId.Operations.readiness(
           RobineId.Configuration.Adapters.MemoryStore,
           [RobineId.Operations.Adapters.DatabaseHealth]
         ) do
      {:ok, %{revision: revision}} ->
        json(conn, %{status: "ready", revision: revision})

      {:error, _reason} ->
        conn |> put_status(:service_unavailable) |> json(%{status: "not_ready"})
    end
  end
end
