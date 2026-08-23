defmodule RobineIdWeb.SessionController do
  use RobineIdWeb, :controller

  alias RobineId.Runtime

  def new(conn, _params) do
    if is_binary(get_session(conn, :subject)) do
      redirect(conn, to: Runtime.path("/account"))
    else
      render_sign_in(conn, %{})
    end
  end

  def create(conn, %{"login" => login}) do
    identifier = String.trim(login["identifier"] || "")

    with {:ok, _remaining} <-
           RobineId.Security.check_rate_limit(
             {conn.remote_ip, String.downcase(identifier)},
             Runtime.adapter(:rate_limiter),
             rate_limit_options()
           ),
         {:ok, user} <-
           RobineId.Identity.authenticate(
             identifier,
             login["password"] || "",
             Runtime.adapter(:user_repository),
             Runtime.adapter(:password_hasher)
           ),
         {:ok, session_id} <-
           RobineId.Security.start_session(
             user.id,
             session_policy()["max_concurrent"],
             Runtime.adapter(:session_registry)
           ) do
      return_to = get_session(conn, :return_to)
      conn = delete_session(conn, :return_to)
      destination = safe_destination(return_to)
      auth_time = System.system_time(:second)

      audit(conn, :portal_authentication, %{outcome: :success, subject_id: user.id})

      conn
      |> configure_session(renew: true)
      |> put_session(:subject, user.id)
      |> put_session(:authenticated_session_id, session_id)
      |> put_session(:authentication_time, auth_time)
      |> put_flash(:info, "Welcome back, #{user.name}.")
      |> redirect(to: destination)
    else
      {:error, :rate_limited, retry_after} ->
        audit(conn, :rate_limit, %{outcome: :rejected, surface: :account_portal})

        conn
        |> put_status(:too_many_requests)
        |> put_resp_header("retry-after", Integer.to_string(retry_after))
        |> render_sign_in(
          %{"identifier" => identifier},
          "Too many attempts. Please try again later."
        )

      _ ->
        audit(conn, :portal_authentication, %{outcome: :failure})

        conn
        |> put_status(:unprocessable_entity)
        |> render_sign_in(%{"identifier" => identifier}, "The email or password is incorrect.")
    end
  end

  def create(conn, _params) do
    conn
    |> put_status(:unprocessable_entity)
    |> render_sign_in(%{}, "The email or password is incorrect.")
  end

  def delete(conn, _params) do
    :ok =
      RobineId.Security.end_session(
        get_session(conn, :subject),
        get_session(conn, :authenticated_session_id),
        Runtime.adapter(:session_registry)
      )

    conn
    |> clear_session()
    |> configure_session(drop: true)
    |> redirect(to: Runtime.path("/login"))
  end

  defp render_sign_in(conn, values, error \\ nil) do
    render(conn, :new,
      page_title: "Account sign in",
      theme: RobineIdWeb.Portal.theme(),
      current_user: nil,
      form: Phoenix.Component.to_form(values, as: :login),
      error: error
    )
  end

  defp safe_destination(path) when is_binary(path) do
    base = Runtime.base_path()

    if String.starts_with?(path, base <> "/") and not String.starts_with?(path, "//"),
      do: path,
      else: Runtime.path("/account")
  end

  defp safe_destination(_path), do: Runtime.path("/account")

  defp session_policy do
    with {:ok, snapshot} <-
           RobineId.Configuration.active(Runtime.adapter(:configuration_store)) do
      get_in(snapshot.data, ["authentication", "session"]) || session_defaults()
    else
      _ -> session_defaults()
    end
  end

  defp rate_limit_options do
    with {:ok, snapshot} <-
           RobineId.Configuration.active(Runtime.adapter(:configuration_store)) do
      policy = get_in(snapshot.data, ["authentication", "rate_limit"]) || %{}
      [attempts: policy["attempts"] || 5, window_seconds: policy["window_seconds"] || 60]
    else
      _ -> [attempts: 5, window_seconds: 60]
    end
  end

  defp session_defaults,
    do: %{"idle_timeout" => 1_800, "absolute_timeout" => 28_800, "max_concurrent" => 5}

  defp audit(conn, event, attributes) do
    attributes =
      Map.put(attributes, :correlation_id, List.first(get_resp_header(conn, "x-request-id")))

    RobineId.Operations.audit(event, attributes, Runtime.adapter(:audit_sink))
  end
end
