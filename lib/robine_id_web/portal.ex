defmodule RobineIdWeb.Portal do
  @moduledoc false

  def theme do
    store = RobineId.Runtime.adapter(:configuration_store)

    with {:ok, snapshot} <- RobineId.Configuration.active(store),
         issuer when is_map(issuer) <- List.first(snapshot.data["issuers"]),
         {:ok, theme} <- RobineId.Experience.theme(issuer["id"], nil, store) do
      theme
    else
      _ ->
        %{
          product_name: "Robine ID",
          primary_color: "#176b70",
          logo: nil,
          favicon: nil
        }
    end
  end
end
