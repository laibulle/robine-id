defmodule RobineId.Configuration.UseCases.GetHistory do
  @moduledoc "Returns non-secret reconciliation audit records."
  def execute(store), do: store.history()
end
