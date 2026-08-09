defmodule RobineId.Configuration.Ports.Store do
  @moduledoc "Port for atomically activating configuration snapshots."
  alias RobineId.Configuration.Entities.Snapshot

  @callback get() :: {:ok, Snapshot.t()} | {:error, :not_configured}
  @callback activate(Snapshot.t()) :: {:ok, :activated | :unchanged}
  @callback record_failure([String.t()]) :: :ok
  @callback history() :: [map()]
end
