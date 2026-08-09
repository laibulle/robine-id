defmodule RobineId.Configuration.UseCases.Preview do
  @moduledoc "Previews reconciliation without mutating active state."
  alias RobineId.Configuration.Entities.{Plan, Snapshot}

  def execute(%Snapshot{} = desired, store) do
    current =
      case store.get() do
        {:ok, snapshot} -> snapshot.data
        {:error, :not_configured} -> nil
      end

    {:ok, Plan.build(current, desired.data)}
  end
end
