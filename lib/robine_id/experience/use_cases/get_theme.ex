defmodule RobineId.Experience.UseCases.GetTheme do
  @moduledoc "Resolves deterministic global, issuer, and client branding precedence."

  alias RobineId.Experience.Entities.Theme

  def execute(issuer_id, client_id, configuration_store) do
    with {:ok, snapshot} <- RobineId.Configuration.active(configuration_store) do
      issuer = Enum.find(snapshot.data["issuers"], &(&1["id"] == issuer_id)) || %{}
      client = Enum.find(snapshot.data["clients"], &(&1["id"] == client_id)) || %{}

      branding =
        (snapshot.data["branding"] || %{})
        |> Map.merge(issuer["branding"] || %{})
        |> Map.merge(client["branding"] || %{})

      {:ok,
       %Theme{
         product_name: branding["product_name"] || "Robine ID",
         primary_color: branding["primary_color"] || "#2855d9",
         font_family: branding["font_family"],
         logo: versioned(branding["logo"], snapshot.fingerprint),
         favicon: versioned(branding["favicon"], snapshot.fingerprint),
         support_url: branding["support_url"],
         privacy_url: branding["privacy_url"],
         terms_url: branding["terms_url"],
         default_locale: branding["default_locale"] || "en",
         messages: branding["messages"] || %{},
         revision: snapshot.fingerprint
       }}
    end
  end

  defp versioned(nil, _revision), do: nil

  defp versioned(path, revision) do
    separator = if String.contains?(path, "?"), do: "&", else: "?"
    path <> separator <> "rev=" <> String.slice(revision, 0, 12)
  end
end
