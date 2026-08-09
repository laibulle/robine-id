defmodule RobineId.Configuration.UseCases.Reconcile do
  @moduledoc "Atomically reconciles a validated snapshot."
  alias RobineId.Configuration.Entities.Snapshot

  def execute(%Snapshot{} = snapshot, store), do: store.activate(snapshot)
end
