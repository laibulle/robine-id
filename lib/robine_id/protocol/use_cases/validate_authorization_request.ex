defmodule RobineId.Protocol.UseCases.ValidateAuthorizationRequest do
  @moduledoc "Validates an OIDC Authorization Code Flow request against client policy."

  alias RobineId.Protocol.Entities.AuthorizationRequest

  @required ~w(client_id redirect_uri response_type scope state)

  def execute(issuer_id, params, client_repository) when is_map(params) do
    with :ok <- required(params),
         :ok <- response_type(params["response_type"]),
         {:ok, client} <- fetch_client(params["client_id"], client_repository),
         :ok <- nonce(client, params["nonce"]),
         :ok <- grant_type(client.grant_types),
         :ok <- redirect_uri(params["redirect_uri"], client.redirect_uris),
         :ok <- resource(params["resource"], client.resources),
         {:ok, scopes} <- scopes(params["scope"], client.scopes),
         :ok <- pkce(client, params["code_challenge"], params["code_challenge_method"]) do
      {:ok,
       %AuthorizationRequest{
         issuer_id: issuer_id,
         client_id: client.id,
         redirect_uri: params["redirect_uri"],
         scope: scopes,
         state: params["state"],
         nonce: params["nonce"],
         code_challenge: params["code_challenge"],
         code_challenge_method: "S256",
         locale: requested_locale(params["ui_locales"]),
         resource: params["resource"]
       }}
    end
  end

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

  defp resource(nil, _allowed), do: :ok

  defp resource(resource, allowed) do
    if resource in allowed,
      do: :ok,
      else: {:error, {:invalid_target, "resource is not registered"}}
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

      not MapSet.subset?(MapSet.new(requested), MapSet.new(allowed)) ->
        {:error, {:invalid_scope, "one or more scopes are not allowed"}}

      true ->
        {:ok, requested}
    end
  end

  defp pkce(%{pkce_required: false}, nil, nil), do: :ok
  defp pkce(%{pkce_required: false}, "", nil), do: :ok

  defp pkce(_client, challenge, "S256") do
    if String.match?(challenge, ~r/^[A-Za-z0-9_-]{43,128}$/),
      do: :ok,
      else: {:error, {:invalid_request, "invalid PKCE challenge"}}
  end

  defp pkce(_, _, _), do: {:error, {:invalid_request, "PKCE S256 is required"}}

  defp nonce(%{nonce_required: false}, value) when value in [nil, ""], do: :ok
  defp nonce(_client, value) when is_binary(value) and value != "", do: :ok
  defp nonce(_, _), do: {:error, {:invalid_request, "missing or invalid nonce"}}

  defp requested_locale(value) when is_binary(value),
    do: value |> String.split(" ", trim: true) |> List.first()

  defp requested_locale(_), do: nil
end
