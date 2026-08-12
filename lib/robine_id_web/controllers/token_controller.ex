defmodule RobineIdWeb.TokenController do
  use RobineIdWeb, :controller

  alias RobineId.Runtime

  def create(conn, %{"issuer_id" => _issuer_id} = params) do
    {client_id, authentication_method, secret} = client_credentials(conn, params)
    params = Map.put(params, "client_id", client_id || "")

    result =
      with {:ok, metadata} <-
             RobineId.Protocol.discovery(
               params["issuer_id"],
               adapter(:configuration_store)
             ),
           {:ok, _client} <-
             RobineId.Clients.authenticate(
               client_id || "",
               authentication_method,
               secret,
               adapter(:client_repository),
               adapter(:secret_resolver)
             ) do
        RobineId.Protocol.exchange_authorization_code(
          Map.put(params, "_issuer", metadata["issuer"]),
          adapter(:authorization_code_store),
          adapter(:key_store),
          adapter(:access_token_store),
          token_options(params["issuer_id"])
        )
      else
        {:error, :invalid_client} -> {:error, {:invalid_client, "client authentication failed"}}
        {:error, :unknown_issuer} -> {:error, {:invalid_request, "unknown issuer"}}
      end

    case result do
      {:ok, tokens} ->
        :telemetry.execute(
          [:robine_id, :protocol, :token],
          %{count: 1},
          %{outcome: :success}
        )

        RobineId.Operations.audit(
          :token_exchange,
          %{outcome: :success, issuer_id: params["issuer_id"], client_id: params["client_id"]},
          adapter(:audit_sink)
        )

        conn
        |> put_resp_header("cache-control", "no-store")
        |> put_resp_header("pragma", "no-cache")
        |> json(tokens)

      {:error, {error, description}} ->
        :telemetry.execute(
          [:robine_id, :protocol, :token],
          %{count: 1},
          %{outcome: :failure}
        )

        RobineId.Operations.audit(
          :token_exchange,
          %{outcome: :failure, issuer_id: params["issuer_id"], client_id: params["client_id"]},
          adapter(:audit_sink)
        )

        conn =
          if error == :invalid_client do
            conn
            |> put_status(:unauthorized)
            |> put_resp_header("www-authenticate", ~s(Basic realm="Robine ID token endpoint"))
          else
            put_status(conn, :bad_request)
          end

        conn
        |> put_resp_header("cache-control", "no-store")
        |> json(%{
          error: error,
          error_description: description,
          correlation_id: List.first(get_resp_header(conn, "x-request-id"))
        })
    end
  end

  defp client_credentials(conn, params) do
    case get_req_header(conn, "authorization") do
      ["Basic " <> encoded] -> decode_basic(encoded)
      _ -> {params["client_id"], body_authentication_method(params), params["client_secret"]}
    end
  end

  defp decode_basic(encoded) do
    with {:ok, decoded} <- Base.decode64(encoded),
         [client_id, secret] <- String.split(decoded, ":", parts: 2) do
      {URI.decode_www_form(client_id), "client_secret_basic", URI.decode_www_form(secret)}
    else
      _ -> {nil, "client_secret_basic", nil}
    end
  end

  defp body_authentication_method(%{"client_secret" => secret}) when is_binary(secret),
    do: "client_secret_post"

  defp body_authentication_method(_params), do: "none"

  defp token_options(issuer_id) do
    {:ok, issuer} =
      RobineId.Configuration.issuer(issuer_id, adapter(:configuration_store))

    policy = issuer["token_policy"] || %{}

    [
      id_token_lifetime: policy["id_token_lifetime"] || 300,
      access_token_lifetime: policy["access_token_lifetime"] || 300
    ]
  end

  defp adapter(name), do: Runtime.adapter(name)
end
