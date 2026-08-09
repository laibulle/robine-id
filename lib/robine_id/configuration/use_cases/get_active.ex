defmodule RobineId.Configuration.UseCases.GetActive do
  @moduledoc "Returns the active configuration snapshot."
  def execute(store), do: store.get()
end
