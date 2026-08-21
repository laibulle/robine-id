defmodule RobineId.Protocol.UseCases.GetUserInfo do
  @moduledoc "Returns subject claims allowed by an access token's scopes."

  def execute(token, access_token_store, user_repository, options \\ []) do
    now = Keyword.get(options, :now, System.system_time(:second))

    with {:ok, grant} <- access_token_store.get(token),
         :ok <- not_expired(grant.expires_at, now),
         :ok <- expected_issuer(grant.issuer, Keyword.get(options, :issuer)),
         {:ok, user} <- user_repository.get_by_id(grant.subject) do
      {:ok, claims(user, grant)}
    else
      _ -> {:error, :invalid_token}
    end
  end

  defp not_expired(expires_at, now) when expires_at > now, do: :ok
  defp not_expired(_, _), do: {:error, :invalid_token}

  defp expected_issuer(_actual, nil), do: :ok
  defp expected_issuer(issuer, issuer), do: :ok
  defp expected_issuer(_actual, _expected), do: {:error, :invalid_token}

  defp claims(user, grant) do
    %{"sub" => user.id}
    |> Map.merge(grant.claims)
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.new()
  end
end
