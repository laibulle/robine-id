defmodule RobineIdWeb.Admin.UserController do
  use RobineIdWeb, :controller

  alias RobineId.Identity.Accounts

  def index(conn, _params) do
    case Accounts.list_users() do
      {:ok, users} ->
        render(conn, :index,
          page_title: "User administration",
          theme: RobineIdWeb.Portal.theme(),
          current_user: conn.assigns.current_user,
          users: users
        )

      {:error, _reason} ->
        conn
        |> put_status(:service_unavailable)
        |> text("User administration is temporarily unavailable")
    end
  end

  def edit(conn, %{"id" => id}) do
    case Accounts.get_user(id) do
      {:ok, user} -> render_edit(conn, user, Accounts.admin_changeset(user))
      {:error, :not_found} -> send_resp(conn, :not_found, "Not found")
      {:error, _reason} -> send_resp(conn, :service_unavailable, "Service unavailable")
    end
  end

  def update(conn, %{"id" => id, "user" => params}) do
    with {:ok, user} <- Accounts.get_user(id) do
      case Accounts.update_by_admin(conn.assigns.current_user, user, params) do
        {:ok, updated_user} ->
          audit(conn, :admin_account_update, %{
            outcome: :success,
            subject_id: updated_user.id,
            actor_id: conn.assigns.current_user.id
          })

          conn
          |> put_flash(:info, "#{updated_user.name} has been updated.")
          |> redirect(to: RobineIdWeb.Admin.UserHTML.user_edit_path(updated_user.id))

        {:error, %Ecto.Changeset{} = changeset} ->
          conn
          |> put_status(:unprocessable_entity)
          |> render_edit(user, changeset)

        {:error, _reason} ->
          audit(conn, :admin_account_update, %{
            outcome: :failure,
            subject_id: user.id,
            actor_id: conn.assigns.current_user.id
          })

          conn
          |> put_status(:service_unavailable)
          |> put_flash(:error, "The account could not be saved.")
          |> render_edit(user, Accounts.admin_changeset(user))
      end
    else
      {:error, :not_found} -> send_resp(conn, :not_found, "Not found")
      {:error, _reason} -> send_resp(conn, :service_unavailable, "Service unavailable")
    end
  end

  def update(conn, %{"id" => id}) do
    case Accounts.get_user(id) do
      {:ok, user} ->
        conn
        |> put_status(:unprocessable_entity)
        |> render_edit(user, Accounts.admin_changeset(user))

      _ ->
        send_resp(conn, :not_found, "Not found")
    end
  end

  defp render_edit(conn, user, changeset) do
    render(conn, :edit,
      page_title: "Manage #{user.name}",
      theme: RobineIdWeb.Portal.theme(),
      current_user: conn.assigns.current_user,
      user: user,
      form: Phoenix.Component.to_form(changeset, as: :user)
    )
  end

  defp audit(conn, event, attributes) do
    attributes =
      Map.put(attributes, :correlation_id, List.first(get_resp_header(conn, "x-request-id")))

    RobineId.Operations.audit(event, attributes, RobineId.Runtime.adapter(:audit_sink))
  end
end
