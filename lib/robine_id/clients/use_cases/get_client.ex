defmodule RobineId.Clients.UseCases.GetClient do
  @moduledoc "Retrieves a client by its stable identifier."
  def execute(client_id, repository) when is_binary(client_id), do: repository.get(client_id)
end
