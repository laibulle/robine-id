defmodule RobineId.Configuration.UseCases.GetIssuer do
  @moduledoc "Returns one issuer's effective non-secret settings."

  def execute(issuer_id, store) do
    with {:ok, snapshot} <- store.get(),
         issuer when is_map(issuer) <-
           Enum.find(snapshot.data["issuers"], &(&1["id"] == issuer_id)) do
      {:ok, issuer}
    else
      nil -> {:error, :not_found}
      {:error, reason} -> {:error, reason}
    end
  end
end
