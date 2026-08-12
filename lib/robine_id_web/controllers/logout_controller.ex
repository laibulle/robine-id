defmodule RobineIdWeb.LogoutController do
  use RobineIdWeb, :controller

  def new(conn, %{"issuer_id" => issuer_id} = params) do
    case validate_return(issuer_id, params) do
      {:ok, return_to} ->
        {:ok, theme} =
          RobineId.Experience.theme(
            issuer_id,
            nil,
            RobineId.Runtime.adapter(:configuration_store)
          )

        conn
        |> put_session(:logout_return_to, return_to)
        |> render(:new, page_title: "Sign out", issuer_id: issuer_id, theme: theme)

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "invalid_request", error_description: reason})
    end
  end

  def create(conn, %{"issuer_id" => issuer_id}) do
    return_to = get_session(conn, :logout_return_to)
    subject = get_session(conn, :subject)
    session_id = get_session(conn, :authenticated_session_id)

    :ok =
      RobineId.Security.end_session(
        subject,
        session_id,
        RobineId.Runtime.adapter(:session_registry)
      )

    conn =
      conn
      |> clear_session()
      |> configure_session(drop: true)

    if is_binary(return_to) do
      redirect(conn, external: return_to)
    else
      {:ok, theme} =
        RobineId.Experience.theme(issuer_id, nil, RobineId.Runtime.adapter(:configuration_store))

      render(conn, :done, page_title: "Signed out", issuer_id: issuer_id, theme: theme)
    end
  end

  defp validate_return(_issuer_id, params)
       when not is_map_key(params, "post_logout_redirect_uri"),
       do: {:ok, nil}

  defp validate_return(
         issuer_id,
         %{
           "id_token_hint" => token,
           "post_logout_redirect_uri" => redirect_uri
         } = params
       ) do
    with {:ok, metadata} <-
           RobineId.Protocol.discovery(
             issuer_id,
             RobineId.Runtime.adapter(:configuration_store)
           ),
         {:ok, claims} <-
           RobineId.Protocol.verify_id_token(
             token,
             metadata["issuer"],
             RobineId.Runtime.adapter(:key_store),
             token_options(issuer_id)
           ),
         {:ok, client} <-
           RobineId.Clients.get(claims["aud"], RobineId.Runtime.adapter(:client_repository)),
         true <- redirect_uri in client.post_logout_redirect_uris do
      {:ok, append_state(redirect_uri, params["state"])}
    else
      _ -> {:error, "post_logout_redirect_uri is not registered for the token client"}
    end
  end

  defp validate_return(_issuer_id, _params),
    do: {:error, "id_token_hint is required when a post-logout redirect is requested"}

  defp append_state(uri, nil), do: uri

  defp append_state(uri, state) do
    parsed = URI.parse(uri)
    query = (parsed.query || "") |> URI.decode_query() |> Map.put("state", state)
    %{parsed | query: URI.encode_query(query)} |> URI.to_string()
  end

  defp token_options(issuer_id) do
    {:ok, issuer} =
      RobineId.Configuration.issuer(issuer_id, RobineId.Runtime.adapter(:configuration_store))

    [clock_skew: get_in(issuer, ["token_policy", "clock_skew"]) || 0]
  end
end
