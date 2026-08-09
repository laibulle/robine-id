defmodule RobineId.Operations.Adapters.DatabaseHealth do
  @moduledoc "Ecto database readiness adapter."
  @behaviour RobineId.Operations.Ports.DependencyHealth

  @impl true
  def check do
    case Ecto.Adapters.SQL.query(RobineId.Repo, "SELECT 1", []) do
      {:ok, _result} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end
end
