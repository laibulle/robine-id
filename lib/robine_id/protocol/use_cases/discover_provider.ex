defmodule RobineId.Protocol.UseCases.DiscoverProvider do
  @moduledoc "Builds standards-oriented discovery metadata from active configuration."

  def execute(issuer_id, configuration_store) do
    with {:ok, snapshot} <- RobineId.Configuration.active(configuration_store),
         {:ok, issuer} <- find_issuer(snapshot.data["issuers"], issuer_id) do
      base = String.trim_trailing(issuer["url"], "/")
      branding = Map.merge(snapshot.data["branding"] || %{}, issuer["branding"] || %{})

      metadata =
        %{
          "issuer" => base,
          "authorization_endpoint" => base <> "/authorize",
          "token_endpoint" => base <> "/token",
          "userinfo_endpoint" => base <> "/userinfo",
          "jwks_uri" => base <> "/jwks.json",
          "end_session_endpoint" => base <> "/logout",
          "response_types_supported" => ["code"],
          "grant_types_supported" => ["authorization_code"],
          "subject_types_supported" => ["public"],
          "id_token_signing_alg_values_supported" => ["RS256"],
          "code_challenge_methods_supported" => ["S256"],
          "token_endpoint_auth_methods_supported" => [
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
            "none"
          ],
          "token_endpoint_auth_signing_alg_values_supported" => ["RS256"],
          "service_documentation" => URI.merge(base <> "/", "/docs") |> URI.to_string(),
          "scopes_supported" => issuer["scopes"] || ["openid", "profile", "email"],
          "claims_supported" => ["sub", "iss", "aud", "iat", "exp", "nonce", "name", "email"]
        }
        |> put_if_present("op_policy_uri", branding["privacy_url"])
        |> put_if_present("op_tos_uri", branding["terms_url"])

      {:ok, metadata}
    end
  end

  defp find_issuer(issuers, id) do
    case Enum.find(issuers, &(&1["id"] == id)) do
      nil -> {:error, :unknown_issuer}
      issuer -> {:ok, issuer}
    end
  end

  defp put_if_present(metadata, _key, nil), do: metadata
  defp put_if_present(metadata, key, value), do: Map.put(metadata, key, value)
end
