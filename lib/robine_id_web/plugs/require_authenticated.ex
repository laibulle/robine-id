defmodule RobineIdWeb.Plugs.RequireAuthenticated do
  @moduledoc "Loads the authenticated account or redirects to the local sign-in page."

  import Phoenix.Controller
  import Plug.Conn

  def init(options), do: options

  def call(conn, _options) do
    with subject when is_binary(subject) <- get_session(conn, :subject),
         {:ok, user} <- RobineId.Runtime.adapter(:user_repository).get_by_id(subject) do
      assign(conn, :current_user, user)
    else
      _ -> require_sign_in(conn)
    end
  end

  defp require_sign_in(conn) do
    conn =
      if conn.method == "GET" do
        put_session(conn, :return_to, conn.request_path)
      else
        conn
      end

    conn
    |> delete_session(:subject)
    |> put_flash(:error, "Please sign in to continue.")
    |> redirect(to: RobineId.Runtime.path("/login"))
    |> halt()
  end
end
