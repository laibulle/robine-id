defmodule RobineId.Protocol.UseCases.IssueIdToken do
  @moduledoc "Issues a signed OpenID Connect ID token."

  @required_claims ~w(iss sub aud)

  def execute(claims, key_store, options \\ []) when is_map(claims) do
    with :ok <- validate_claims(claims),
         {:ok, %{kid: kid, jwk: jwk}} <- key_store.signing_key(claims["iss"]) do
      now = Keyword.get(options, :now, System.system_time(:second))
      lifetime = Keyword.get(options, :lifetime, 300)

      claims =
        claims
        |> Map.put_new("iat", now)
        |> Map.put_new("exp", now + lifetime)

      headers = %{"alg" => "RS256", "kid" => kid, "typ" => "JWT"}
      {_jws, compact} = JOSE.JWT.sign(jwk, headers, claims) |> JOSE.JWS.compact()
      {:ok, compact}
    end
  end

  defp validate_claims(claims) do
    case Enum.find(@required_claims, &(not is_binary(claims[&1]) or claims[&1] == "")) do
      nil -> :ok
      claim -> {:error, {:invalid_claims, "#{claim} is required"}}
    end
  end
end
