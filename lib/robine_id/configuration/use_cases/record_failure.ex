defmodule RobineId.Configuration.UseCases.RecordFailure do
  @moduledoc "Records a failed apply without mutating active configuration."
  def execute(diagnostics, store) when is_list(diagnostics), do: store.record_failure(diagnostics)
end
