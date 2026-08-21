defmodule RobineId.Identity.UseCases.MapClaims do
  @moduledoc "Maps configured identity fields into scope-constrained OIDC claims."

  @reserved ~w(iss sub aud iat exp auth_time nonce)

  def execute(user, mappings, scopes) when is_map(mappings) and is_list(scopes) do
    execute(user, mappings, scopes, [])
  end

  def execute(user, mappings, scopes, requested_claims)
      when is_map(mappings) and is_list(scopes) and is_list(requested_claims) do
    mappings
    |> Enum.reduce(%{}, fn {claim, mapping}, claims ->
      source = mapping["source"]
      required_scope = mapping["scope"]

      if claim not in @reserved and is_binary(source) and
           (required_scope in scopes or claim in requested_claims) do
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
