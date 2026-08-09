defmodule RobineId.Protocol.UseCases.GetJwks do
  @moduledoc "Returns all public verification keys retained for an issuer."

  def execute(issuer_id, key_store) do
    with {:ok, keys} <- key_store.public_keys(issuer_id), do: {:ok, %{"keys" => keys}}
  end
end
