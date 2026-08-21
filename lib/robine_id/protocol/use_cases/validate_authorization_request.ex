defmodule RobineId.Protocol.UseCases.ValidateAuthorizationRequest do
  @moduledoc "Validates an OIDC Authorization Code request against client and provider policy."

  alias RobineId.Protocol.Entities.AuthorizationRequest

  @required ~w(client_id redirect_uri response_type scope)
  @displays ~w(page popup touch wap)
  @prompts ~w(none login consent select_account)
  @jwt_claims ~w(iss aud exp nbf iat jti)

  def execute(issuer_id, params, client_repository) when is_map(params) do
    with {:ok, params} <- request_object(params),
         :ok <- unsupported_request_uri(params),
         :ok <- required(params),
         :ok <- response_type(params["response_type"]),
         {:ok, client} <- fetch_client(params["client_id"], client_repository),
         :ok <- grant_type(client.grant_types),
         :ok <- redirect_uri(params["redirect_uri"], client.redirect_uris),
         {:ok, scopes} <- scopes(params["scope"], client.scopes),
         :ok <- nonce(client, params["nonce"]),
         :ok <- pkce(client, params["code_challenge"], params["code_challenge_method"]),
         {:ok, prompts} <- prompt(params["prompt"]),
         {:ok, max_age} <- max_age(params["max_age"]),
         :ok <- display(params["display"]),
         {:ok, claims} <- claims(params["claims"]) do
      {:ok,
       %AuthorizationRequest{
         issuer_id: issuer_id,
         client_id: client.id,
         redirect_uri: params["redirect_uri"],
         scope: scopes,
         state: optional_string(params["state"]),
         nonce: optional_string(params["nonce"]),
         code_challenge: optional_string(params["code_challenge"]),
         code_challenge_method: optional_string(params["code_challenge_method"]),
         locale: requested_locale(params["ui_locales"]),
         display: optional_string(params["display"]),
         prompt: prompts,
         login_hint: optional_string(params["login_hint"]),
         id_token_hint: optional_string(params["id_token_hint"]),
         max_age: max_age,
         claims: claims
       }}
    end
  end

  defp request_object(%{"request" => token} = outer)
       when is_binary(token) and byte_size(token) <= 16_384 do
    with {:ok, request_params} <- decode_unsecured_request_object(token),
         :ok <- matching_outer_parameters(outer, request_params) do
      params =
        request_params
        |> Map.drop(@jwt_claims)
        |> Map.merge(Map.drop(outer, ["request"]))

      {:ok, params}
    end
  end

  defp request_object(%{"request" => _value}),
    do: {:error, {:request_not_supported, "only unsecured request objects are supported"}}

  defp request_object(params), do: {:ok, params}

  defp decode_unsecured_request_object(token) do
    with [encoded_header, encoded_payload, ""] <- String.split(token, ".", parts: 3),
         {:ok, header_json} <- Base.url_decode64(encoded_header, padding: false),
         {:ok, payload_json} <- Base.url_decode64(encoded_payload, padding: false),
         {:ok, %{"alg" => "none"}} <- Jason.decode(header_json),
         {:ok, payload} when is_map(payload) <- Jason.decode(payload_json) do
      {:ok, payload}
    else
      _ -> {:error, {:request_not_supported, "only unsecured request objects are supported"}}
    end
  end

  defp matching_outer_parameters(outer, request_params) do
    mismatched? =
      outer
      |> Map.drop(["request"])
      |> Enum.any?(fn {key, value} ->
        Map.has_key?(request_params, key) and request_params[key] != value
      end)

    if mismatched?,
      do: {:error, {:invalid_request, "request object parameters do not match the request"}},
      else: :ok
  end

  defp unsupported_request_uri(%{"request_uri" => value})
       when is_binary(value) and value != "",
       do: {:error, {:request_uri_not_supported, "request_uri is not supported"}}

  defp unsupported_request_uri(_params), do: :ok

  defp required(params) do
    case Enum.find(@required, &(not is_binary(params[&1]) or params[&1] == "")) do
      nil -> :ok
      field -> {:error, {:invalid_request, "missing or invalid #{field}"}}
    end
  end

  defp response_type("code"), do: :ok
  defp response_type(_), do: {:error, {:unsupported_response_type, "only code is supported"}}

  defp fetch_client(id, repository) do
    case RobineId.Clients.get(id, repository) do
      {:ok, client} -> {:ok, client}
      {:error, :not_found} -> {:error, {:invalid_request, "unknown client"}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp redirect_uri(uri, allowed) do
    if uri in allowed,
      do: :ok,
      else: {:error, {:invalid_request, "redirect_uri is not registered"}}
  end

  defp grant_type(grants) do
    if "authorization_code" in grants,
      do: :ok,
      else: {:error, {:unauthorized_client, "authorization_code is not allowed"}}
  end

  defp scopes(value, allowed) do
    requested = String.split(value, " ", trim: true)

    cond do
      "openid" not in requested ->
        {:error, {:invalid_scope, "openid scope is required"}}

      length(requested) != MapSet.size(MapSet.new(requested)) ->
        {:error, {:invalid_scope, "scope values must not be repeated"}}

      not MapSet.subset?(MapSet.new(requested), MapSet.new(allowed)) ->
        {:error, {:invalid_scope, "one or more scopes are not allowed"}}

      true ->
        {:ok, requested}
    end
  end

  defp pkce(%{pkce_required: false}, challenge, method)
       when challenge in [nil, ""] and method in [nil, ""],
       do: :ok

  defp pkce(_client, challenge, "S256") when is_binary(challenge) do
    if String.match?(challenge, ~r/^[A-Za-z0-9_-]{43,128}$/),
      do: :ok,
      else: {:error, {:invalid_request, "invalid PKCE challenge"}}
  end

  defp pkce(_, _, _), do: {:error, {:invalid_request, "PKCE S256 is required"}}

  # nonce is optional in the Authorization Code Flow. Operators may still require it
  # for individual clients as a defense-in-depth policy.
  defp nonce(%{nonce_required: false}, value) when value in [nil, ""], do: :ok
  defp nonce(_client, value) when is_binary(value) and value != "", do: :ok
  defp nonce(_, _), do: {:error, {:invalid_request, "missing or invalid nonce"}}

  defp prompt(nil), do: {:ok, []}
  defp prompt(""), do: {:error, {:invalid_request, "prompt must not be empty"}}

  defp prompt(value) when is_binary(value) do
    values = String.split(value, " ", trim: true)

    cond do
      Enum.any?(values, &(&1 not in @prompts)) ->
        {:error, {:invalid_request, "prompt contains an unsupported value"}}

      "none" in values and length(values) != 1 ->
        {:error, {:invalid_request, "prompt none cannot be combined with another value"}}

      true ->
        {:ok, Enum.uniq(values)}
    end
  end

  defp prompt(_), do: {:error, {:invalid_request, "prompt is invalid"}}

  defp max_age(nil), do: {:ok, nil}
  defp max_age(value) when is_integer(value) and value >= 0, do: {:ok, value}

  defp max_age(value) when is_binary(value) do
    case Integer.parse(value) do
      {seconds, ""} when seconds >= 0 -> {:ok, seconds}
      _ -> {:error, {:invalid_request, "max_age must be a non-negative integer"}}
    end
  end

  defp max_age(_), do: {:error, {:invalid_request, "max_age must be a non-negative integer"}}

  defp display(nil), do: :ok
  defp display(value) when value in @displays, do: :ok
  defp display(_), do: {:error, {:invalid_request, "display is unsupported"}}

  defp claims(nil), do: {:ok, %{}}
  defp claims(""), do: {:error, {:invalid_request, "claims must be a JSON object"}}

  defp claims(value) when is_binary(value) do
    case Jason.decode(value) do
      {:ok, claims} when is_map(claims) -> validate_claims_object(claims)
      _ -> {:error, {:invalid_request, "claims must be a JSON object"}}
    end
  end

  defp claims(value) when is_map(value), do: validate_claims_object(value)

  defp claims(_), do: {:error, {:invalid_request, "claims must be a JSON object"}}

  defp validate_claims_object(claims) do
    valid? =
      Enum.all?(claims, fn
        {section, requested} when section in ["userinfo", "id_token"] and is_map(requested) ->
          Enum.all?(requested, fn
            {claim, nil} when is_binary(claim) -> true
            {claim, options} when is_binary(claim) and is_map(options) -> true
            _ -> false
          end)

        _ ->
          false
      end)

    if valid?,
      do: {:ok, claims},
      else: {:error, {:invalid_request, "claims contains an invalid claim request"}}
  end

  defp optional_string(value) when is_binary(value) and value != "", do: value
  defp optional_string(_), do: nil

  defp requested_locale(value) when is_binary(value),
    do: value |> String.split(" ", trim: true) |> List.first()

  defp requested_locale(_), do: nil
end
