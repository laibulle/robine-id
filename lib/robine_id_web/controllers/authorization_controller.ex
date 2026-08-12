defmodule RobineIdWeb.AuthorizationController do
  use RobineIdWeb, :controller

  alias RobineId.Runtime

  def new(conn, %{"issuer_id" => issuer_id} = params) do
    result =
      with {:ok, _metadata} <-
             RobineId.Protocol.discovery(issuer_id, adapter(:configuration_store)) do
        RobineId.Protocol.validate_authorization_request(
          issuer_id,
          params,
          adapter(:client_repository)
        )
      end

    case result do
      {:ok, request} ->
        {:ok, client} = RobineId.Clients.get(request.client_id, adapter(:client_repository))
        theme = theme(issuer_id, request.client_id)
        {:ok, messages} = RobineId.Experience.messages(theme, request.locale)

        conn
        |> put_session(:authorization_request, request)
        |> render(:new,
          page_title: "Sign in",
          issuer_id: issuer_id,
          client_name: client.name,
          theme: theme,
          messages: messages,
          error: nil,
          correlation_id: nil
        )

      {:error, {error, description}} ->
        authorization_error(conn, params, error, description)

      {:error, :unknown_issuer} ->
        conn
        |> put_status(:not_found)
        |> browser_error(:not_found, "The requested identity provider is unavailable.")
    end
  end

  def create(conn, %{"issuer_id" => issuer_id, "login" => login}) do
    request = get_session(conn, :authorization_request)
    identifier = login["identifier"] || ""

    with %{issuer_id: ^issuer_id} <- request,
         {:ok, _remaining} <-
           RobineId.Security.check_rate_limit(
             {conn.remote_ip, String.downcase(String.trim(identifier))},
             adapter(:rate_limiter),
             rate_limit_options()
           ),
         {:ok, user} <-
           RobineId.Identity.authenticate(
             identifier,
             login["password"] || "",
             adapter(:user_repository),
             adapter(:password_hasher)
           ),
         {:ok, metadata} <- RobineId.Protocol.discovery(issuer_id, adapter(:configuration_store)),
         {:ok, client} <- RobineId.Clients.get(request.client_id, adapter(:client_repository)),
         {:ok, session_id} <-
           RobineId.Security.start_session(
             user.id,
             session_policy()["max_concurrent"],
             adapter(:session_registry)
           ) do
      identity_claims = configured_claims(user, request.scope)

      authenticated_conn =
        conn
        |> configure_session(renew: true)
        |> put_session(:subject, user.id)
        |> put_session(:authenticated_session_id, session_id)
        |> put_session(:identity_claims, identity_claims)

      audit(conn, :authentication, %{
        outcome: :success,
        issuer_id: issuer_id,
        client_id: request.client_id,
        subject_id: user.id
      })

      if RobineId.Clients.consent_required?(client) do
        render_consent(authenticated_conn, request, client)
      else
        complete_authorization(
          authenticated_conn,
          request,
          metadata["issuer"],
          user.id,
          identity_claims
        )
      end
    else
      {:error, :invalid_credentials} ->
        audit(conn, :authentication, %{
          outcome: :failure,
          issuer_id: issuer_id,
          client_id: request && request.client_id,
          reason: :invalid_credentials
        })

        render_invalid_credentials(conn, issuer_id, request)

      {:error, :rate_limited, retry_after} ->
        audit(conn, :rate_limit, %{
          outcome: :rejected,
          issuer_id: issuer_id,
          client_id: request && request.client_id
        })

        render_rate_limited(conn, issuer_id, request, retry_after)

      _ ->
        protocol_error(conn, :invalid_request, "authorization session is invalid or expired")
    end
  end

  def create(conn, _params),
    do: protocol_error(conn, :invalid_request, "missing login parameters")

  def consent(conn, %{"issuer_id" => issuer_id, "decision" => decision}) do
    request = get_session(conn, :authorization_request)
    subject = get_session(conn, :subject)
    claims = get_session(conn, :identity_claims) || %{}

    with %{issuer_id: ^issuer_id} <- request,
         true <- is_binary(subject),
         {:ok, metadata} <- RobineId.Protocol.discovery(issuer_id, adapter(:configuration_store)) do
      case decision do
        "approve" -> complete_authorization(conn, request, metadata["issuer"], subject, claims)
        "deny" -> deny_authorization(conn, request)
        _ -> protocol_error(conn, :invalid_request, "invalid consent decision")
      end
    else
      _ -> protocol_error(conn, :invalid_request, "authorization session is invalid or expired")
    end
  end

  def consent(conn, _params),
    do: protocol_error(conn, :invalid_request, "missing consent decision")

  defp render_invalid_credentials(conn, issuer_id, request) do
    client_name =
      case request && RobineId.Clients.get(request.client_id, adapter(:client_repository)) do
        {:ok, client} -> client.name
        _ -> "the application"
      end

    conn
    |> put_status(:unprocessable_entity)
    |> render(:new,
      page_title: "Sign in",
      issuer_id: issuer_id,
      client_name: client_name,
      theme: theme(issuer_id, request && request.client_id),
      messages: messages(issuer_id, request),
      error: "The email or password is incorrect.",
      correlation_id: correlation_id(conn)
    )
  end

  defp render_rate_limited(conn, issuer_id, request, retry_after) do
    client_name =
      case request && RobineId.Clients.get(request.client_id, adapter(:client_repository)) do
        {:ok, client} -> client.name
        _ -> "the application"
      end

    conn
    |> put_status(:too_many_requests)
    |> put_resp_header("retry-after", Integer.to_string(retry_after))
    |> render(:new,
      page_title: "Sign in",
      issuer_id: issuer_id,
      client_name: client_name,
      theme: theme(issuer_id, request && request.client_id),
      messages: messages(issuer_id, request),
      error: "Too many attempts. Please wait before trying again.",
      correlation_id: correlation_id(conn)
    )
  end

  defp render_consent(conn, request, client) do
    render(conn, :consent,
      page_title: "Authorize #{client.name}",
      issuer_id: request.issuer_id,
      client_name: client.name,
      theme: theme(request.issuer_id, request.client_id),
      messages: messages(request.issuer_id, request),
      scopes: consent_scopes(request.scope)
    )
  end

  defp complete_authorization(conn, request, issuer, subject, claims) do
    case RobineId.Protocol.issue_authorization_code(
           request,
           issuer,
           subject,
           adapter(:authorization_code_store),
           Keyword.put(code_options(request.issuer_id), :claims, claims)
         ) do
      {:ok, code} ->
        location = append_query(request.redirect_uri, %{"code" => code, "state" => request.state})

        conn
        |> delete_session(:authorization_request)
        |> delete_session(:identity_claims)
        |> redirect(external: location)

      {:error, _reason} ->
        protocol_error(conn, :server_error, "authorization could not be completed")
    end
  end

  defp deny_authorization(conn, request) do
    location =
      append_query(request.redirect_uri, %{
        "error" => "access_denied",
        "error_description" => "The user denied the request",
        "state" => request.state
      })

    conn
    |> delete_session(:authorization_request)
    |> delete_session(:identity_claims)
    |> redirect(external: location)
  end

  defp consent_scopes(scopes) do
    labels = %{
      "openid" => "Confirm your identity",
      "profile" => "View your name and profile information",
      "email" => "View your email address"
    }

    Enum.map(scopes, &Map.get(labels, &1, "Access #{&1}"))
  end

  defp code_options(issuer_id) do
    {:ok, issuer} = RobineId.Configuration.issuer(issuer_id, adapter(:configuration_store))
    policy = issuer["token_policy"] || %{}
    [lifetime: policy["authorization_code_lifetime"] || 60]
  end

  defp configured_claims(user, scopes) do
    {:ok, snapshot} = RobineId.Configuration.active(adapter(:configuration_store))
    RobineId.Identity.map_claims(user, snapshot.data["claims"] || %{}, scopes)
  end

  defp session_policy do
    {:ok, snapshot} = RobineId.Configuration.active(adapter(:configuration_store))
    get_in(snapshot.data, ["authentication", "session"]) || %{"max_concurrent" => 5}
  end

  defp rate_limit_options do
    {:ok, snapshot} = RobineId.Configuration.active(adapter(:configuration_store))
    policy = get_in(snapshot.data, ["authentication", "rate_limit"]) || %{}

    [
      limit: policy["attempts"] || 5,
      window_seconds: policy["window_seconds"] || 60
    ]
  end

  defp theme(issuer_id, client_id) do
    {:ok, theme} = RobineId.Experience.theme(issuer_id, client_id, adapter(:configuration_store))
    theme
  end

  defp messages(issuer_id, request) do
    resolved_theme = theme(issuer_id, request && request.client_id)
    {:ok, messages} = RobineId.Experience.messages(resolved_theme, request && request.locale)
    messages
  end

  defp append_query(uri, values) do
    parsed = URI.parse(uri)
    query = (parsed.query || "") |> URI.decode_query() |> Map.merge(values)
    %{parsed | query: URI.encode_query(query)} |> URI.to_string()
  end

  defp protocol_error(conn, error, description) do
    browser_error(conn, error, description)
  end

  defp browser_error(conn, error, description) do
    conn
    |> put_status(:bad_request)
    |> render(:protocol_error,
      page_title: "Unable to continue",
      error: to_string(error),
      description: description,
      correlation_id: correlation_id(conn)
    )
  end

  defp authorization_error(conn, params, error, description) do
    with client_id when is_binary(client_id) <- params["client_id"],
         redirect_uri when is_binary(redirect_uri) <- params["redirect_uri"],
         {:ok, client} <- RobineId.Clients.get(client_id, adapter(:client_repository)),
         true <- redirect_uri in client.redirect_uris do
      values = %{"error" => to_string(error), "error_description" => description}

      values =
        if is_binary(params["state"]), do: Map.put(values, "state", params["state"]), else: values

      redirect(conn, external: append_query(redirect_uri, values))
    else
      _ -> protocol_error(conn, error, description)
    end
  end

  defp audit(conn, event, attributes) do
    attributes = Map.put(attributes, :correlation_id, correlation_id(conn))
    RobineId.Operations.audit(event, attributes, adapter(:audit_sink))
  end

  defp adapter(name), do: Runtime.adapter(name)
  defp correlation_id(conn), do: List.first(get_resp_header(conn, "x-request-id"))
end
