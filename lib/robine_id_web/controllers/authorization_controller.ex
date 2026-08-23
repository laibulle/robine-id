defmodule RobineIdWeb.AuthorizationController do
  use RobineIdWeb, :controller

  alias RobineId.Runtime

  def new(conn, %{"issuer_id" => issuer_id} = params) do
    result =
      with {:ok, metadata} <-
             RobineId.Protocol.discovery(issuer_id, adapter(:configuration_store)),
           {:ok, request} <-
             RobineId.Protocol.validate_authorization_request(
               issuer_id,
               params,
               adapter(:client_repository)
             ) do
        {:ok, request, metadata}
      end

    case result do
      {:ok, request, metadata} ->
        {:ok, client} = RobineId.Clients.get(request.client_id, adapter(:client_repository))

        conn
        |> put_session(:authorization_request, request)
        |> continue_authorization(request, client, metadata["issuer"])

      {:error, {error, description}} ->
        authorization_error(conn, params, error, description)

      {:error, :unknown_issuer} ->
        conn
        |> put_status(:not_found)
        |> browser_error(:not_found, "The requested identity provider is unavailable.")
    end
  end

  def create(conn, %{"issuer_id" => issuer_id, "login" => login}) do
    conn = Plug.CSRFProtection.call(conn, Plug.CSRFProtection.init([]))
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
      {identity_claims, id_token_claims} = claim_sets(user, request)
      auth_time = System.system_time(:second)

      authenticated_conn =
        conn
        |> configure_session(renew: true)
        |> put_session(:subject, user.id)
        |> put_session(:authenticated_session_id, session_id)
        |> put_session(:authentication_time, auth_time)
        |> put_session(:identity_claims, identity_claims)
        |> put_session(:id_token_claims, id_token_claims)

      audit(conn, :authentication, %{
        outcome: :success,
        issuer_id: issuer_id,
        client_id: request.client_id,
        subject_id: user.id
      })

      if RobineId.Clients.consent_required?(client) or "consent" in request.prompt do
        render_consent(authenticated_conn, request, client)
      else
        complete_authorization(
          authenticated_conn,
          request,
          metadata["issuer"],
          user.id,
          identity_claims,
          id_token_claims,
          auth_time
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

  def create(conn, %{"issuer_id" => _issuer_id} = params), do: new(conn, params)

  def consent(conn, %{"issuer_id" => issuer_id, "decision" => decision}) do
    request = get_session(conn, :authorization_request)
    subject = get_session(conn, :subject)
    claims = get_session(conn, :identity_claims) || %{}
    id_token_claims = get_session(conn, :id_token_claims) || %{}

    with %{issuer_id: ^issuer_id} <- request,
         true <- is_binary(subject),
         {:ok, metadata} <- RobineId.Protocol.discovery(issuer_id, adapter(:configuration_store)) do
      case decision do
        "approve" ->
          complete_authorization(
            conn,
            request,
            metadata["issuer"],
            subject,
            claims,
            id_token_claims,
            get_session(conn, :authentication_time)
          )

        "deny" ->
          deny_authorization(conn, request)

        _ ->
          protocol_error(conn, :invalid_request, "invalid consent decision")
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
      correlation_id: correlation_id(conn),
      form: sign_in_form(request && request.login_hint)
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
      correlation_id: correlation_id(conn),
      form: sign_in_form(request && request.login_hint)
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

  defp continue_authorization(conn, request, client, issuer) do
    subject = get_session(conn, :subject)
    auth_time = get_session(conn, :authentication_time)

    if reusable_authentication?(request, subject, auth_time, issuer) do
      continue_with_authenticated_subject(conn, request, client, issuer, subject, auth_time)
    else
      if "none" in request.prompt do
        authorization_request_error(conn, request, :login_required, "authentication is required")
      else
        render_sign_in(conn, request, client)
      end
    end
  end

  defp continue_with_authenticated_subject(conn, request, client, issuer, subject, auth_time) do
    with {:ok, user} <- adapter(:user_repository).get_by_id(subject) do
      {claims, id_token_claims} = claim_sets(user, request)

      conn =
        conn
        |> put_session(:identity_claims, claims)
        |> put_session(:id_token_claims, id_token_claims)

      cond do
        "none" in request.prompt and RobineId.Clients.consent_required?(client) ->
          authorization_request_error(conn, request, :consent_required, "consent is required")

        RobineId.Clients.consent_required?(client) or "consent" in request.prompt ->
          render_consent(conn, request, client)

        true ->
          complete_authorization(
            conn,
            request,
            issuer,
            subject,
            claims,
            id_token_claims,
            auth_time
          )
      end
    else
      _ -> render_sign_in(conn, request, client)
    end
  end

  defp reusable_authentication?(request, subject, auth_time, issuer) do
    is_binary(subject) and is_integer(auth_time) and
      "login" not in request.prompt and "select_account" not in request.prompt and
      within_max_age?(auth_time, request.max_age) and
      id_token_hint_matches?(request.id_token_hint, subject, issuer)
  end

  defp within_max_age?(_auth_time, nil), do: true
  defp within_max_age?(_auth_time, 0), do: false

  defp within_max_age?(auth_time, max_age),
    do: System.system_time(:second) - auth_time <= max_age

  defp id_token_hint_matches?(nil, _subject, _issuer), do: true

  defp id_token_hint_matches?(token, subject, issuer) do
    case RobineId.Protocol.verify_id_token(token, issuer, adapter(:key_store), clock_skew: 30) do
      {:ok, %{"sub" => ^subject}} -> true
      _ -> false
    end
  end

  defp render_sign_in(conn, request, client) do
    resolved_theme = theme(request.issuer_id, request.client_id)
    {:ok, resolved_messages} = RobineId.Experience.messages(resolved_theme, request.locale)

    render(conn, :new,
      page_title: "Sign in",
      issuer_id: request.issuer_id,
      client_name: client.name,
      theme: resolved_theme,
      messages: resolved_messages,
      error: nil,
      correlation_id: nil,
      form: sign_in_form(request.login_hint)
    )
  end

  defp authorization_request_error(conn, request, error, description) do
    location =
      append_query(request.redirect_uri, %{
        "error" => to_string(error),
        "error_description" => description,
        "state" => request.state
      })

    conn
    |> delete_session(:authorization_request)
    |> delete_session(:identity_claims)
    |> delete_session(:id_token_claims)
    |> redirect(external: location)
  end

  defp complete_authorization(
         conn,
         request,
         issuer,
         subject,
         claims,
         id_token_claims,
         auth_time
       ) do
    case RobineId.Protocol.issue_authorization_code(
           request,
           issuer,
           subject,
           adapter(:authorization_code_store),
           code_options(request.issuer_id)
           |> Keyword.put(:claims, claims)
           |> Keyword.put(:id_token_claims, id_token_claims)
           |> Keyword.put(:auth_time, auth_time)
         ) do
      {:ok, code} ->
        location = append_query(request.redirect_uri, %{"code" => code, "state" => request.state})

        conn
        |> delete_session(:authorization_request)
        |> delete_session(:identity_claims)
        |> delete_session(:id_token_claims)
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
    |> delete_session(:id_token_claims)
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

  defp configured_claims(user, scopes, requested_claims) do
    {:ok, snapshot} = RobineId.Configuration.active(adapter(:configuration_store))

    RobineId.Identity.map_claims(
      user,
      snapshot.data["claims"] || %{},
      scopes,
      requested_claims
    )
  end

  defp requested_userinfo_claims(request) do
    request.claims
    |> Map.get("userinfo", %{})
    |> Map.keys()
  end

  defp requested_id_token_claims(request) do
    request.claims
    |> Map.get("id_token", %{})
    |> Map.keys()
  end

  defp claim_sets(user, request) do
    user_info_claims =
      configured_claims(user, request.scope, requested_userinfo_claims(request))

    id_token_claims = configured_claims(user, [], requested_id_token_claims(request))
    {user_info_claims, id_token_claims}
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
    values = values |> Enum.reject(fn {_key, value} -> is_nil(value) end) |> Map.new()
    query = (parsed.query || "") |> URI.decode_query() |> Map.merge(values)
    %{parsed | query: URI.encode_query(query)} |> URI.to_string()
  end

  defp protocol_error(conn, error, description) do
    browser_error(conn, error, description)
  end

  defp browser_error(conn, error, description) do
    conn = if is_nil(conn.status), do: put_status(conn, :bad_request), else: conn

    conn
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

  defp sign_in_form(identifier) do
    Phoenix.Component.to_form(%{"identifier" => identifier || "", "password" => ""}, as: :login)
  end
end
