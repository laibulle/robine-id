defmodule RobineId.Identity.UseCases.MapClaims do
  @moduledoc "Maps configured identity fields into scope-constrained OIDC claims."

  @reserved ~w(iss sub aud iat exp nbf jti nonce auth_time at_hash c_hash acr amr azp)

  def execute(user, mappings, scopes) when is_map(mappings) and is_list(scopes) do
    mappings
    |> Enum.reduce(%{}, fn {claim, mapping}, claims ->
      source = mapping["source"]
      required_scope = mapping["scope"]

      if claim not in @reserved and is_binary(source) and required_scope in scopes do
        case source_value(user, source) do
          nil -> claims
          value -> Map.put(claims, claim, value)
        end
      else
        claims
      end
    end)
  end

  defp source_value(user, "name"), do: user.name
  defp source_value(user, "email"), do: user.email
  defp source_value(user, source), do: (user.claims || %{})[source]
end
