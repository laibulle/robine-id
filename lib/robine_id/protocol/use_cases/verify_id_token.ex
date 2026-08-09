defmodule RobineId.Protocol.UseCases.VerifyIdToken do
  @moduledoc "Verifies an ID token against retained issuer keys and time constraints."

  def execute(token, issuer, key_store, options \\ []) do
    now = Keyword.get(options, :now, System.system_time(:second))
    clock_skew = Keyword.get(options, :clock_skew, 0)

    with {:ok, keys} <- key_store.public_keys(issuer),
         {:ok, claims} <- verify_with_any_key(token, keys),
         :ok <- validate_claims(claims, issuer, now, clock_skew) do
      {:ok, claims}
    end
  end

  defp verify_with_any_key(token, keys) do
    Enum.find_value(keys, {:error, :invalid_token}, fn key ->
      case JOSE.JWT.verify_strict(JOSE.JWK.from_map(key), ["RS256"], token) do
        {true, jwt, _jws} -> {:ok, jwt.fields}
        _ -> nil
      end
    end)
  rescue
    _ -> {:error, :invalid_token}
  end

  defp validate_claims(
         %{"iss" => issuer, "sub" => sub, "aud" => aud, "exp" => exp},
         issuer,
         now,
         clock_skew
       )
       when is_binary(sub) and is_binary(aud) and is_integer(exp) and exp + clock_skew > now,
       do: :ok

  defp validate_claims(_, _, _, _), do: {:error, :invalid_token}
end
