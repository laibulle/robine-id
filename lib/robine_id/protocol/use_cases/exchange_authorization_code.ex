defmodule RobineId.Protocol.UseCases.ExchangeAuthorizationCode do
  @moduledoc "Consumes a code once and returns tokens when all bindings are valid."

  alias RobineId.Protocol.Entities.AccessGrant

  def execute(params, code_store, key_store, access_token_store, options \\ []) do
    now = Keyword.get(options, :now, System.system_time(:second))
    id_token_lifetime = Keyword.get(options, :id_token_lifetime, 300)
    access_token_lifetime = Keyword.get(options, :access_token_lifetime, 300)

    with :ok <- required(params),
         :ok <- grant_type(params["grant_type"]),
         {:ok, grant} <- code_store.consume(params["code"]),
         :ok <- not_expired(grant.expires_at, now),
         :ok <- equal(grant.issuer, params["_issuer"]),
         :ok <- equal(grant.client_id, params["client_id"]),
         :ok <- equal(grant.redirect_uri, params["redirect_uri"]),
         :ok <- verify_pkce(grant.code_challenge, params["code_verifier"]),
         {:ok, id_token} <- issue_id_token(grant, key_store, now, id_token_lifetime),
         {:ok, access_token} <-
           issue_access_token(grant, access_token_store, now, access_token_lifetime),
         :ok <- code_store.mark_exchanged(params["code"], access_token) do
      {:ok,
       %{
         "access_token" => access_token,
         "token_type" => "Bearer",
         "expires_in" => access_token_lifetime,
         "scope" => Enum.join(grant.scope, " "),
         "id_token" => id_token
       }}
    else
      {:error, {:authorization_code_reused, access_token}} ->
        revoke_reused_code_token(access_token, access_token_store)
        {:error, {:invalid_grant, "authorization code is invalid"}}

      {:error, :invalid_grant} ->
        {:error, {:invalid_grant, "authorization code is invalid"}}

      {:error, {:invalid_grant, _} = reason} ->
        {:error, reason}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp revoke_reused_code_token(access_token, store) when is_binary(access_token),
    do: store.revoke(access_token)

  defp revoke_reused_code_token(_access_token, _store), do: :ok

  defp required(params) do
    fields = ~w(grant_type code client_id redirect_uri)

    case Enum.find(fields, &(not is_binary(params[&1]) or params[&1] == "")) do
      nil -> :ok
      field -> {:error, {:invalid_request, "missing #{field}"}}
    end
  end

  defp grant_type("authorization_code"), do: :ok

  defp grant_type(_),
    do: {:error, {:unsupported_grant_type, "only authorization_code is supported"}}

  defp not_expired(expires_at, now) when expires_at > now, do: :ok
  defp not_expired(_, _), do: {:error, {:invalid_grant, "authorization code expired"}}

  defp equal(value, value), do: :ok
  defp equal(_, _), do: {:error, {:invalid_grant, "authorization code binding mismatch"}}

  defp verify_pkce(nil, verifier) when verifier in [nil, ""], do: :ok

  defp verify_pkce(_challenge, verifier) when not is_binary(verifier) or verifier == "",
    do: {:error, {:invalid_grant, "PKCE code_verifier is required"}}

  defp verify_pkce(challenge, verifier) do
    calculated = :crypto.hash(:sha256, verifier) |> Base.url_encode64(padding: false)

    if Plug.Crypto.secure_compare(challenge, calculated),
      do: :ok,
      else: {:error, {:invalid_grant, "PKCE verification failed"}}
  end

  defp issue_id_token(grant, key_store, now, lifetime) do
    claims =
      %{
        "iss" => grant.issuer,
        "sub" => grant.subject,
        "aud" => grant.client_id
      }
      |> maybe_put_nonce(grant.nonce)
      |> maybe_put_auth_time(grant.auth_time)
      |> Map.merge(grant.id_token_claims)

    RobineId.Protocol.issue_id_token(claims, key_store,
      now: now,
      lifetime: lifetime
    )
  end

  defp maybe_put_nonce(claims, nonce) when is_binary(nonce) and nonce != "",
    do: Map.put(claims, "nonce", nonce)

  defp maybe_put_nonce(claims, _nonce), do: claims

  defp maybe_put_auth_time(claims, auth_time) when is_integer(auth_time),
    do: Map.put(claims, "auth_time", auth_time)

  defp maybe_put_auth_time(claims, _auth_time), do: claims

  defp issue_access_token(grant, store, now, lifetime) do
    store.issue(%AccessGrant{
      issuer: grant.issuer,
      subject: grant.subject,
      client_id: grant.client_id,
      scope: grant.scope,
      expires_at: now + lifetime,
      claims: grant.claims
    })
  end
end
