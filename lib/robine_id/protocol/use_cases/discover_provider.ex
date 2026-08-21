defmodule RobineId.Protocol.UseCases.DiscoverProvider do
  @moduledoc "Builds standards-oriented discovery metadata from active configuration."

  def execute(issuer_id, configuration_store) do
    with {:ok, snapshot} <- RobineId.Configuration.active(configuration_store),
         {:ok, issuer} <- find_issuer(snapshot.data["issuers"], issuer_id) do
      base = String.trim_trailing(issuer["url"], "/")

      claims_supported =
        ["sub", "iss", "aud", "iat", "exp", "auth_time", "nonce"] ++
          Map.keys(snapshot.data["claims"] || %{})

      metadata =
        %{
          "issuer" => base,
          "authorization_endpoint" => base <> "/authorize",
          "token_endpoint" => base <> "/token",
          "userinfo_endpoint" => base <> "/userinfo",
          "jwks_uri" => base <> "/jwks.json",
          "end_session_endpoint" => base <> "/logout",
          "response_types_supported" => ["code"],
          "response_modes_supported" => ["query"],
          "grant_types_supported" => ["authorization_code"],
          "subject_types_supported" => ["public"],
          "id_token_signing_alg_values_supported" => ["RS256"],
          "code_challenge_methods_supported" => ["S256"],
          "token_endpoint_auth_methods_supported" => [
            "client_secret_basic",
            "client_secret_post",
            "none"
          ],
          "scopes_supported" => issuer["scopes"] || ["openid", "profile", "email"],
          "claims_supported" => Enum.uniq(claims_supported),
          "claims_parameter_supported" => true,
          "request_parameter_supported" => true,
          "request_uri_parameter_supported" => false,
          "request_object_signing_alg_values_supported" => ["none"]
        }
        |> maybe_put_locales(snapshot.data)

      {:ok, metadata}
    end
  end

  defp maybe_put_locales(metadata, data) do
    case get_in(data, ["branding", "locales"]) do
      locales when is_list(locales) and locales != [] ->
        Map.put(metadata, "ui_locales_supported", locales)

      _ ->
        metadata
    end
  end

  defp find_issuer(issuers, id) do
    case Enum.find(issuers, &(&1["id"] == id)) do
      nil -> {:error, :unknown_issuer}
      issuer -> {:ok, issuer}
    end
  end
end
